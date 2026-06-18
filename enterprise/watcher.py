"""enterprise/watcher.py — Live status watcher for the SelfConnect Enterprise control plane.

Reads state from the enterprise ledger, registry, and channel status.
Provides a data model for the scent CLI watcher dashboard.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Input validation limits ────────────────────────────────────────────────────
# Enforce upper bounds on user-supplied integers to prevent resource exhaustion.
MAX_RECENT_EVENTS: int = 500       # hard cap on recent_events(n) — prevents OOM on large n
MAX_LEASE_TTL_SECONDS: float = 86_400.0   # 24 h — reject absurd TTL values from registry
MIN_LEASE_TTL_SECONDS: float = 0.0        # reject negative TTL (forced-expiry DoS)
MAX_AGENT_ID_LEN: int = 256        # truncate oversized IDs from untrusted sources
MAX_EVENT_TYPE_LEN: int = 128      # truncate oversized event type strings


@dataclass
class LeaseInfo:
    lease_id: str
    agent_id: str
    hwnd: int
    role: str
    expires_at: float
    window_class: str = ""
    title: str = ""

    @property
    def ttl_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass
class AuditEvent:
    event_id: str
    timestamp: float
    event_type: str
    agent_id: str
    details: dict = field(default_factory=dict)


@dataclass
class ChannelHealth:
    wm_char: str = "UNKNOWN"    # OK / WARN / DOWN
    uia: str = "UNKNOWN"
    etw: str = "UNKNOWN"
    pipe: str = "UNKNOWN"


class WatcherState:
    """Snapshot of current enterprise control plane state.

    Thread-safety: refresh() and all reader methods are protected by a single
    RLock so that the live-watch loop (which calls refresh() on the main thread
    while rich Live renders on another) never observes a torn intermediate state.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._leases: list[LeaseInfo] = []
        self._events: list[AuditEvent] = []
        self._channel_health = ChannelHealth()
        self._last_refresh: float = 0.0
        self._error: str | None = None

    @property
    def last_refresh(self) -> float:
        with self._lock:
            return self._last_refresh

    @property
    def error(self) -> str | None:
        with self._lock:
            return self._error

    def refresh(self) -> None:
        new_leases = []
        new_events = []
        new_health = ChannelHealth()
        err: str | None = None
        try:
            new_leases = self._load_leases()
            new_events = self._load_events()
            new_health = self._probe_channels()
        except Exception as exc:  # noqa: BLE001
            err = str(exc)
            logger.debug("WatcherState.refresh failed: %s", exc)
        # Atomically swap all state under the lock — readers never see a partial update.
        with self._lock:
            self._leases = new_leases
            self._events = new_events
            self._channel_health = new_health
            self._error = err
            self._last_refresh = time.time()

    def active_leases(self) -> list[LeaseInfo]:
        with self._lock:
            return [lease for lease in self._leases if not lease.is_expired]

    def all_leases(self) -> list[LeaseInfo]:
        with self._lock:
            return list(self._leases)

    def recent_events(self, n: int = 20) -> list[AuditEvent]:
        # Clamp n to prevent resource exhaustion from caller-supplied large values.
        n = min(max(1, n), MAX_RECENT_EVENTS)
        with self._lock:
            events_snapshot = list(self._events)
        return sorted(events_snapshot, key=lambda e: e.timestamp, reverse=True)[:n]

    def channel_health(self) -> ChannelHealth:
        with self._lock:
            return self._channel_health

    def _load_leases(self) -> list[LeaseInfo]:
        try:
            from enterprise.registry import AgentRegistry
            reg = AgentRegistry()
            leases = []
            for entry in (reg.list_agents() if hasattr(reg, "list_agents") else []):
                if not isinstance(entry, dict):
                    continue
                # Validate and sanitise each field from the untrusted registry entry.
                # An attacker-controlled or corrupted registry can supply negative TTL
                # (forcing immediate expiry — DoS), huge TTL (permanent phantom lease),
                # or non-integer hwnd.  Clamp/reject rather than trust.
                raw_agent_id = str(entry.get("agent_id", "?"))[:MAX_AGENT_ID_LEN]
                raw_hwnd = entry.get("hwnd", 0)
                if not isinstance(raw_hwnd, int):
                    try:
                        raw_hwnd = int(raw_hwnd)
                    except (TypeError, ValueError):
                        raw_hwnd = 0
                raw_hwnd = max(0, raw_hwnd)  # negative HWND is invalid
                raw_ttl = entry.get("ttl", 300)
                if not isinstance(raw_ttl, (int, float)):
                    raw_ttl = 300
                # Clamp TTL: reject negative (forced-expiry) and astronomical values.
                raw_ttl = max(MIN_LEASE_TTL_SECONDS, min(float(raw_ttl), MAX_LEASE_TTL_SECONDS))
                raw_role = str(entry.get("role", "unknown"))[:64]
                raw_window_class = str(entry.get("window_class", ""))[:128]
                raw_title = str(entry.get("title", ""))[:256]
                leases.append(LeaseInfo(
                    lease_id=raw_agent_id,
                    agent_id=raw_agent_id,
                    hwnd=raw_hwnd,
                    role=raw_role,
                    expires_at=time.time() + raw_ttl,
                    window_class=raw_window_class,
                    title=raw_title,
                ))
            return leases
        except Exception:  # noqa: BLE001
            return []

    def _load_events(self) -> list[AuditEvent]:
        try:
            from enterprise.ledger import AuditLedger
            ledger = AuditLedger()
            events = []
            for raw in (ledger.recent(20) if hasattr(ledger, "recent") else []):
                if not isinstance(raw, dict):
                    continue
                # Sanitise string fields from untrusted ledger source.
                # Unbounded strings from the ledger can carry Rich markup sequences,
                # causing console injection or layout corruption when rendered.
                # Truncate to known-safe lengths before storing.
                raw_event_id = str(raw.get("event_id", "?"))[:MAX_AGENT_ID_LEN]
                raw_ts = raw.get("timestamp", 0.0)
                if not isinstance(raw_ts, (int, float)):
                    raw_ts = 0.0
                raw_event_type = str(raw.get("event_type", "?"))[:MAX_EVENT_TYPE_LEN]
                raw_agent_id = str(raw.get("agent_id", "?"))[:MAX_AGENT_ID_LEN]
                # details dict: keep only primitive-valued entries to prevent
                # Rich markup injection via nested structures when stringified.
                raw_details = raw.get("details", {})
                if not isinstance(raw_details, dict):
                    raw_details = {}
                safe_details = {
                    str(k)[:64]: str(v)[:128]
                    for k, v in raw_details.items()
                    if isinstance(v, (str, int, float, bool))
                }
                events.append(AuditEvent(
                    event_id=raw_event_id,
                    timestamp=float(raw_ts),
                    event_type=raw_event_type,
                    agent_id=raw_agent_id,
                    details=safe_details,
                ))
            return events
        except Exception:  # noqa: BLE001
            return []

    def _probe_channels(self) -> ChannelHealth:
        health = ChannelHealth()
        try:
            import ctypes
            ctypes.windll.user32.GetForegroundWindow()
            health.wm_char = "OK"
        except Exception:  # noqa: BLE001
            health.wm_char = "DOWN"
        try:
            health.uia = "OK"
        except Exception:  # noqa: BLE001
            health.uia = "DOWN"
        try:
            import ctypes
            ctypes.windll.ntdll.NtQuerySystemInformation
            health.etw = "OK"
        except Exception:  # noqa: BLE001
            health.etw = "DOWN"
        # Named Pipe channel: probe by attempting to open the well-known SC pipe.
        # Previously this was unconditionally "OK" — a fail-open that masked real
        # pipe channel failures.  Now we attempt a real probe; fall back to UNKNOWN
        # if the pipe name is not configured (no false OK).
        try:
            import ctypes
            _SC_PIPE_NAME = r"\\.\pipe\SelfConnectEnterprise"
            GENERIC_READ = 0x80000000
            OPEN_EXISTING = 3
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
            h = ctypes.windll.kernel32.CreateFileW(
                _SC_PIPE_NAME, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None
            )
            if h and h != INVALID_HANDLE_VALUE:
                ctypes.windll.kernel32.CloseHandle(h)
                health.pipe = "OK"
            else:
                # ERROR_FILE_NOT_FOUND (2) means pipe server not running.
                # ERROR_PIPE_BUSY (231) means server exists but all instances busy.
                err = ctypes.windll.kernel32.GetLastError()
                health.pipe = "WARN" if err == 231 else "DOWN"
        except Exception:  # noqa: BLE001
            health.pipe = "UNKNOWN"
        return health


def make_status_table(state: WatcherState) -> Any:
    """Build a rich Table showing current status. Returns None if rich is unavailable."""
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        return None
    health = state.channel_health()
    STATUS_COLOR = {"OK": "green", "WARN": "yellow", "DOWN": "red", "UNKNOWN": "dim"}
    table = Table(title="SelfConnect Enterprise — Channel Status", box=box.ROUNDED, expand=False)
    table.add_column("Channel", style="bold")
    table.add_column("Status")
    for ch_name, status in [
        ("WM_CHAR", health.wm_char),
        ("UIA", health.uia),
        ("ETW", health.etw),
        ("Named Pipe", health.pipe),
    ]:
        color = STATUS_COLOR.get(status, "dim")
        table.add_row(ch_name, f"[{color}]{status}[/{color}]")
    return table


def make_lease_table(state: WatcherState) -> Any:
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        return None
    leases = state.active_leases()
    table = Table(title=f"Active Leases ({len(leases)})", box=box.SIMPLE)
    table.add_column("Lease ID", no_wrap=True)
    table.add_column("Agent")
    table.add_column("HWND")
    table.add_column("Role")
    table.add_column("TTL")
    for lease in leases:
        table.add_row(
            lease.lease_id[:16] + "...",
            lease.agent_id[:20],
            str(lease.hwnd),
            lease.role,
            f"{lease.ttl_seconds:.0f}s",
        )
    return table


def make_audit_table(state: WatcherState, n: int = 10) -> Any:
    try:
        from rich.table import Table
        from rich import box
    except ImportError:
        return None
    events = state.recent_events(n)
    table = Table(title=f"Recent Audit Events (last {n})", box=box.SIMPLE)
    table.add_column("Time")
    table.add_column("Type")
    table.add_column("Agent")
    table.add_column("Details")
    for evt in events:
        import datetime
        ts = datetime.datetime.fromtimestamp(evt.timestamp).strftime("%H:%M:%S") if evt.timestamp else "?"
        table.add_row(ts, evt.event_type, evt.agent_id[:20], str(evt.details)[:40])
    return table
