"""channel_router.py — Governed channel router for SelfConnect Enterprise.

Routes an HWND to the correct channel type under policy enforcement:
  - Terminal windows → WM_CHAR PostMessage (ConPTY-safe, background-safe)
  - Browser windows  → UIA Value/Invoke (no CDP, no extension)
  - Sidecar pipes    → DACL named pipe (OS-verified SID transport)
  - Unknown          → DENY (fail-closed, raises ChannelRoutingError)

This is the composition that SelfConnect's patent portfolio claims as a method:
  classify(hwnd) → channel_type
  route(hwnd, text, lease) → ActionReceipt

All routing decisions are logged to the audit ledger.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum

try:
    import win32api
    import win32con
    import win32gui
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False


class ChannelType(str, Enum):
    WM_CHAR = "wm_char"
    UIA = "uia"
    PIPE = "pipe"
    DENY = "deny"


class ChannelRoutingError(RuntimeError):
    """Raised when routing is denied or no channel can be determined."""


@dataclass
class RoutingDecision:
    hwnd: int
    channel: ChannelType
    window_class: str
    window_title: str
    pid: int
    reason: str
    timestamp: float


@dataclass
class ActionReceipt:
    receipt_id: str
    hwnd: int
    channel: ChannelType
    payload_hash: str
    readback_hash: str
    timestamp: float
    success: bool
    transport_enqueued: bool = False
    delivery_confirmed: bool = False


TERMINAL_CLASSES = frozenset({
    "CASCADIA_HOSTING_WINDOW_CLASS",
    "ConsoleWindowClass",
    "VirtualConsoleClass",
    "ConPTY",
    "mintty",
    "rxvt",
    "xterm",
})

WINDOWS_TERMINAL_HOST_CLASS = "CASCADIA_HOSTING_WINDOW_CLASS"
WINDOWS_TERMINAL_INPUT_CLASS = "Windows.UI.Input.InputSite.WindowClass"

BROWSER_CLASSES = frozenset({
    "Chrome_WidgetWin_1",
    "MozillaWindowClass",
    "ApplicationFrameWindow",
    "BrowserFrameView",
    "CabinetWClass",
})

SIDECAR_CLASSES = frozenset({
    "SELFCONNECT_SIDECAR",
    "SCENT_CONTROL",
})

# Maximum text payload length accepted by route().
# Win32 PostMessage queue default limit is ~10,000 messages per thread.
# Capping at 4096 chars keeps injection well inside the safe zone and
# prevents integrity lies on ActionReceipt (partial delivery reported as success).
MAX_PAYLOAD_LENGTH = 4096

# Valid HWND range on Win32: 1 .. 0xFFFF_FFFF (32-bit) or 0x0000_0000_0000_0001 .. 2^63-1 (64-bit).
# Negative values and zero are sentinel/broadcast handles (HWND_BROADCAST = -1, HWND_DESKTOP = 0, etc.)
# and must never be routed.
_HWND_MIN = 1


def _get_window_class(hwnd: int) -> str:
    if not _WIN32_AVAILABLE:
        return ""
    try:
        return win32gui.GetClassName(hwnd)
    except Exception:  # noqa: BLE001
        return ""


def _get_window_title(hwnd: int) -> str:
    if not _WIN32_AVAILABLE:
        return ""
    try:
        return win32gui.GetWindowText(hwnd)
    except Exception:  # noqa: BLE001
        return ""


def _get_window_pid(hwnd: int) -> int:
    if not _WIN32_AVAILABLE:
        return 0
    try:
        _, pid = win32gui.GetWindowThreadProcessId(hwnd)
        return pid
    except Exception:  # noqa: BLE001
        return 0


class ChannelRouter:
    """Classify an HWND and route actions through the appropriate channel."""

    def __init__(self) -> None:
        self._decisions: list[RoutingDecision] = []
        self._lock = threading.Lock()

    def classify(self, hwnd: int) -> RoutingDecision:
        """Classify hwnd → ChannelType. Fail-closed: unknown → DENY.

        Security invariants enforced here:
        - hwnd=0 is DENY (null handle).
        - hwnd<0 is DENY (Win32 sentinel/broadcast handles such as HWND_BROADCAST=-1).
        - All decisions, including DENY, are recorded in the audit log.
        """
        # --- FIX: validate HWND range before any Win32 call ---
        if not isinstance(hwnd, int) or hwnd < _HWND_MIN:
            reason = (
                "hwnd=0 is invalid"
                if hwnd == 0
                else f"hwnd={hwnd} is out of valid range (negative/sentinel handles forbidden)"
            )
            decision = RoutingDecision(
                hwnd=hwnd, channel=ChannelType.DENY, window_class="",
                window_title="", pid=0, reason=reason,
                timestamp=time.time(),
            )
            # FIX: record every DENY in the audit log, including early exits
            with self._lock:
                self._decisions.append(decision)
            return decision

        window_class = _get_window_class(hwnd)
        window_title = _get_window_title(hwnd)
        pid = _get_window_pid(hwnd)

        if window_class in TERMINAL_CLASSES:
            channel = ChannelType.WM_CHAR
            reason = f"terminal class: {window_class}"
        elif window_class in BROWSER_CLASSES:
            channel = ChannelType.UIA
            reason = f"browser class: {window_class}"
        elif window_class in SIDECAR_CLASSES:
            channel = ChannelType.PIPE
            reason = f"sidecar class: {window_class}"
        elif not window_class:
            channel = ChannelType.DENY
            reason = "cannot read window class (HWND stale or protected)"
        else:
            channel = ChannelType.DENY
            reason = f"unknown window class: {window_class!r}"

        decision = RoutingDecision(
            hwnd=hwnd, channel=channel, window_class=window_class,
            window_title=window_title, pid=pid, reason=reason,
            timestamp=time.time(),
        )
        # FIX: lock protects _decisions list under concurrent classify() calls
        with self._lock:
            self._decisions.append(decision)
        return decision

    def route(self, hwnd: int, text: str, lease_id: str | None = None) -> ActionReceipt:
        """Route text injection through the appropriate channel. Raises on DENY.

        Security invariants:
        - ``text`` must be a str; non-str types raise ValueError (prevents
          AttributeError stack leaks and type confusion).
        - ``text`` length is capped at MAX_PAYLOAD_LENGTH to prevent partial
          delivery being falsely reported as success on the ActionReceipt.
        - ``lease_id`` is validated: if supplied it must be a non-empty str.
          Callers that pass lease_id should not receive silent bypass if the
          value is malformed.  Full lease *enforcement* (revocation checking,
          binding to PID) is a higher-level concern; this layer ensures the
          field is structurally valid so that callers cannot accidentally pass
          an empty string and believe they have an authenticated session.
        """
        # FIX: validate text type before any use
        if not isinstance(text, str):
            raise ValueError(f"text must be str, got {type(text).__name__!r}")
        # FIX: cap payload length to prevent partial-delivery / audit integrity lies
        if len(text) > MAX_PAYLOAD_LENGTH:
            raise ValueError(
                f"text payload exceeds maximum allowed length "
                f"({len(text)} > {MAX_PAYLOAD_LENGTH})"
            )
        # FIX: lease_id structural validation — empty string is not a valid lease
        if lease_id is not None and not isinstance(lease_id, str):
            raise ValueError(f"lease_id must be str or None, got {type(lease_id).__name__!r}")
        if lease_id is not None and not lease_id.strip():
            raise ValueError("lease_id must not be empty or whitespace-only")

        decision = self.classify(hwnd)
        if decision.channel == ChannelType.DENY:
            raise ChannelRoutingError(
                f"Routing denied for HWND {hwnd}: {decision.reason}"
            )
        payload_hash = hashlib.sha256(text.encode()).hexdigest()
        readback_hash = ""
        success = False
        try:
            if decision.channel == ChannelType.WM_CHAR:
                success = self._inject_wm_char(hwnd, text)
            elif decision.channel == ChannelType.UIA:
                success = self._inject_uia(hwnd, text)
            elif decision.channel == ChannelType.PIPE:
                success = self._inject_pipe(hwnd, text)
        except Exception:  # noqa: BLE001
            success = False
        return ActionReceipt(
            receipt_id=str(uuid.uuid4()),
            hwnd=hwnd,
            channel=decision.channel,
            payload_hash=payload_hash,
            readback_hash=readback_hash,
            timestamp=time.time(),
            success=success,
            transport_enqueued=success,
            delivery_confirmed=False,
        )

    def _inject_wm_char(self, hwnd: int, text: str) -> bool:
        if not _WIN32_AVAILABLE:
            return False
        try:
            delivery_hwnd = hwnd
            if _get_window_class(hwnd) == WINDOWS_TERMINAL_HOST_CLASS:
                input_sites: list[int] = []

                def collect_input_site(child_hwnd: int, _context: object) -> bool:
                    if _get_window_class(child_hwnd) == WINDOWS_TERMINAL_INPUT_CLASS:
                        input_sites.append(child_hwnd)
                    return True

                win32gui.EnumChildWindows(hwnd, collect_input_site, None)
                if not input_sites:
                    return False
                delivery_hwnd = input_sites[0]
            for ch in text:
                if ch in ("\r", "\n"):
                    win32api.PostMessage(delivery_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                    win32api.PostMessage(delivery_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                else:
                    win32api.PostMessage(delivery_hwnd, win32con.WM_CHAR, ord(ch), 0)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _inject_uia(self, hwnd: int, text: str) -> bool:
        return False  # UIA injection requires comtypes CoCreateInstance — stub

    def _inject_pipe(self, hwnd: int, text: str) -> bool:
        return False  # Pipe injection requires DACL pipe setup — stub

    def last_decisions(self, n: int = 10) -> list[RoutingDecision]:
        # FIX: snapshot under lock so callers see a consistent list slice
        with self._lock:
            return list(self._decisions[-n:])
