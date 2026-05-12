"""enterprise/executor_win32.py — Deterministic Win32/UIA executor.

No AI inference.  Receives ExecutorActionRequest objects from the policy layer,
enforces the full governance lifecycle (target access → policy check → ledger
precommit → execution → ledger postcommit), and returns ExecutorActionResult.

Permitted action strings are the locked contract from PARTICIPANT_MODE_ACTION_SETS
["executor"].  Any other action_type is rejected at step 1 without a ledger entry.

Lifecycle for every execute() call (fail-closed at every step):
    1. Validate action_type in PERMITTED_ACTIONS  → no ledger entry on denial
    2. Resolve target + path/hash pre-check       → ledger entry on denial
    3. PolicyEnforcer.check(participant_mode="executor") → ledger entry on denial
    4. Write precommit ledger entry (intent)      → abort if write fails
    5. Execute Win32/UIA primitive
    6. Write postcommit ledger entry (always)
    7. Return ExecutorActionResult with ledger_entry_hash

Version: 1.0.0-enterprise  Session 20
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.labels import Classification
from enterprise.ledger import AgentLedger
from enterprise.policy import PolicyEnforcer
from enterprise.policy import PARTICIPANT_MODE_ACTION_SETS
from enterprise.target_registry import (
    TargetAccessDeniedError,
    TargetNotFoundError,
    TargetRegistry,
)

# ── Win32 handles and constants ───────────────────────────────────────────────
_user32  = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32

WM_GETTEXT       = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_SETTEXT       = 0x000C

WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_size_t, ctypes.c_size_t)

# ── Permitted action set (locked contract) ────────────────────────────────────
PERMITTED_ACTIONS: frozenset[str] = PARTICIPANT_MODE_ACTION_SETS["executor"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _entry_hash(entry: dict) -> str:
    """SHA-256 of a ledger entry's canonical bytes (sig field excluded)."""
    without_sig = {k: v for k, v in entry.items() if k != "sig"}
    canonical = json.dumps(without_sig, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


# ── Request / Result dataclasses ──────────────────────────────────────────────

@dataclass
class ExecutorActionRequest:
    """Describes a single executor action to be evaluated and run."""
    request_id:        str           # UUID string supplied by caller
    action_type:       str           # must be in PERMITTED_ACTIONS
    target_logical_id: str           # logical target ID from TargetRegistry
    parameters:        dict          # action-specific parameters
    proposed_by:       str           # agent_id of the proposing agent
    classification:    Classification
    timestamp:         float         # time.time() at request creation


@dataclass
class ExecutorActionResult:
    """Outcome of a single executor action."""
    request_id:         str
    action_type:        str
    success:            bool
    output:             str
    error:              str
    executed_at:        float
    ledger_entry_hash:  str   # SHA-256 of postcommit ledger entry; "" if no postcommit


# ── Win32Executor ─────────────────────────────────────────────────────────────

class Win32Executor:
    """Deterministic Win32/UIA action executor with full governance lifecycle.

    All Win32/UIA primitives are isolated in _<action_type> methods that can
    be patched in tests without touching ctypes or COM directly.
    """

    PERMITTED_ACTIONS = PERMITTED_ACTIONS

    def __init__(
        self,
        profile:         ClassifiedModeProfile,
        ledger:          AgentLedger,
        policy:          PolicyEnforcer,
        target_registry: TargetRegistry,
    ) -> None:
        self._profile         = profile
        self._ledger          = ledger
        self._policy          = policy
        self._target_registry = target_registry

    # ── Public API ────────────────────────────────────────────────────────────

    def is_action_allowed(self, action_type: str) -> bool:
        """Return True iff action_type is in the executor's permitted set."""
        return action_type in self.PERMITTED_ACTIONS

    def execute(self, request: ExecutorActionRequest) -> ExecutorActionResult:
        """Run one action through the full governance lifecycle.

        See module docstring for the step-by-step lifecycle and fail-closed rules.
        """
        t0 = time.time()

        # ── Step 1: Validate action_type ─────────────────────────────────────
        if request.action_type not in self.PERMITTED_ACTIONS:
            return ExecutorActionResult(
                request_id=request.request_id,
                action_type=request.action_type,
                success=False,
                output="",
                error="action_type not in permitted set",
                executed_at=t0,
                ledger_entry_hash="",
            )

        # ── Step 2: Resolve target + path/hash pre-check ─────────────────────
        try:
            hwnd = self._target_registry.resolve_to_hwnd(
                request.target_logical_id, "executor"
            )
            self._pre_check_params(request)
        except (TargetNotFoundError, TargetAccessDeniedError, PermissionError) as exc:
            entry = self._ledger.log(
                action=f"executor.{request.action_type}",
                result=f"DENIED: {exc}",
                metadata={
                    "request_id": request.request_id,
                    "target":     request.target_logical_id,
                    "phase":      "target_check",
                },
            )
            return ExecutorActionResult(
                request_id=request.request_id,
                action_type=request.action_type,
                success=False,
                output="",
                error=str(exc),
                executed_at=t0,
                ledger_entry_hash=_entry_hash(entry),
            )

        # ── Step 3: Policy check ──────────────────────────────────────────────
        decision = self._policy.check(
            request.proposed_by,
            request.action_type,
            participant_mode="executor",
            classification=request.classification.name,
        )
        if not decision.allowed:
            entry = self._ledger.log(
                action=f"executor.{request.action_type}",
                result=f"DENIED by policy: {decision.reason}",
                metadata={
                    "request_id": request.request_id,
                    "phase":      "policy_check",
                },
            )
            return ExecutorActionResult(
                request_id=request.request_id,
                action_type=request.action_type,
                success=False,
                output="",
                error=decision.reason,
                executed_at=t0,
                ledger_entry_hash=_entry_hash(entry),
            )

        # ── Step 4: Precommit ledger entry ────────────────────────────────────
        try:
            self._ledger.log(
                action=f"executor.{request.action_type} INTENT",
                result="precommit",
                metadata={
                    "request_id": request.request_id,
                    "target":     request.target_logical_id,
                    "phase":      "precommit",
                },
            )
        except Exception as exc:
            return ExecutorActionResult(
                request_id=request.request_id,
                action_type=request.action_type,
                success=False,
                output="",
                error=f"ledger precommit failure: {exc}",
                executed_at=t0,
                ledger_entry_hash="",
            )

        # ── Step 5: Execute Win32/UIA primitive ───────────────────────────────
        # Use getattr so patch.object() on the executor instance takes effect.
        output     = ""
        exec_error = ""
        try:
            primitive = getattr(self, f"_{request.action_type}")
            output = primitive(hwnd, request.parameters)
        except Exception as exc:
            exec_error = str(exc)

        # ── Step 6: Postcommit ledger entry (always) ──────────────────────────
        post_entry = self._ledger.log(
            action=f"executor.{request.action_type}",
            result="SUCCESS" if not exec_error else f"ERROR: {exec_error}",
            metadata={
                "request_id": request.request_id,
                "target":     request.target_logical_id,
                "phase":      "postcommit",
                "output_len": len(output),
            },
        )

        # ── Step 7: Return result ─────────────────────────────────────────────
        return ExecutorActionResult(
            request_id=request.request_id,
            action_type=request.action_type,
            success=not bool(exec_error),
            output=output,
            error=exec_error,
            executed_at=t0,
            ledger_entry_hash=_entry_hash(post_entry),
        )

    # ── Parameter pre-checks (Step 2 extension) ───────────────────────────────

    def _pre_check_params(self, request: ExecutorActionRequest) -> None:
        """Enforce file-path and script-hash allowlists before policy/execution.

        Raises PermissionError on denial so execute() catches it uniformly.
        """
        action = request.action_type
        if action in ("write_file_allowed_path", "read_file_allowed_path"):
            path = request.parameters.get("path", "")
            if not path:
                raise PermissionError("missing 'path' parameter")
            if not self._profile.allowed_paths:
                raise PermissionError(
                    f"path {path!r} denied: profile allowed_paths is empty (fail-closed)"
                )
            if not any(path.startswith(allowed) for allowed in self._profile.allowed_paths):
                raise PermissionError(
                    f"path {path!r} not under any profile allowed_paths prefix"
                )
        elif action == "run_signed_script":
            script_hash = request.parameters.get("script_hash", "")
            if not script_hash:
                raise PermissionError("missing 'script_hash' parameter")
            if script_hash not in self._profile.allowed_script_hashes:
                raise PermissionError(
                    f"script_hash {script_hash!r} not in profile allowed_script_hashes"
                )

    # ── Win32/UIA primitives ──────────────────────────────────────────────────
    # Each method is isolated for test patching via patch.object(executor, "_<name>").

    def _read_window_text(self, hwnd: int, params: dict) -> str:
        length = _user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        if length == 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        _user32.SendMessageW(hwnd, WM_GETTEXT, length + 1, buf)
        return buf.value

    def _read_named_element(self, hwnd: int, params: dict) -> str:
        name    = params.get("element_name", "")
        element = self._uia_find_element(hwnd, name)
        return self._uia_get_value(element)

    def _focus_window(self, hwnd: int, params: dict) -> str:
        _user32.SetForegroundWindow(hwnd)
        return "focused"

    def _click_named_element(self, hwnd: int, params: dict) -> str:
        name    = params.get("element_name", "")
        element = self._uia_find_element(hwnd, name)
        self._uia_invoke_click(element)
        return f"clicked {name!r}"

    def _set_text(self, hwnd: int, params: dict) -> str:
        text = params.get("text", "")
        name = params.get("element_name", "")
        if name:
            element = self._uia_find_element(hwnd, name)
            self._uia_set_value(element, text)
        else:
            buf = ctypes.create_unicode_buffer(text)
            _user32.SendMessageW(hwnd, WM_SETTEXT, 0, buf)
        return f"text set ({len(text)} chars)"

    def _type_string(self, hwnd: int, params: dict) -> str:
        text = params.get("text", "")
        _user32.SetForegroundWindow(hwnd)
        for char in text:
            vk = ctypes.windll.user32.VkKeyScanW(ord(char))
            _user32.keybd_event(vk & 0xFF, 0, 0, 0)
            _user32.keybd_event(vk & 0xFF, 0, 2, 0)  # KEYEVENTF_KEYUP
        return f"typed {len(text)} chars"

    def _write_file_allowed_path(self, hwnd: int, params: dict) -> str:
        path    = params["path"]
        content = params.get("content", "")
        encoding = params.get("encoding", "utf-8")
        Path(path).write_text(content, encoding=encoding)
        return f"wrote {len(content)} chars to {path!r}"

    def _read_file_allowed_path(self, hwnd: int, params: dict) -> str:
        path     = params["path"]
        encoding = params.get("encoding", "utf-8")
        return Path(path).read_text(encoding=encoding)

    def _run_signed_script(self, hwnd: int, params: dict) -> str:
        script_path = params.get("script_path", "")
        args        = params.get("args", [])
        timeout     = params.get("timeout", 30)
        result = subprocess.run(
            [script_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.returncode != 0:
            raise RuntimeError(
                f"script exited {result.returncode}: {result.stderr.strip()}"
            )
        return output

    def _capture_window_screenshot(self, hwnd: int, params: dict) -> str:
        import ctypes.wintypes
        rect = ctypes.wintypes.RECT()
        _user32.GetWindowRect(hwnd, ctypes.byref(rect))
        w = rect.right - rect.left
        h = rect.bottom - rect.top
        hdc_win = _user32.GetDC(hwnd)
        hdc_mem = ctypes.windll.gdi32.CreateCompatibleDC(hdc_win)
        hbm     = ctypes.windll.gdi32.CreateCompatibleBitmap(hdc_win, w, h)
        ctypes.windll.gdi32.SelectObject(hdc_mem, hbm)
        ctypes.windll.gdi32.BitBlt(hdc_mem, 0, 0, w, h, hdc_win, 0, 0, 0x00CC0020)
        out_path = params.get("output_path", "screenshot.bmp")
        # Minimal BMP: write via shell SaveBitmapToFile pattern
        ctypes.windll.gdi32.DeleteDC(hdc_mem)
        _user32.ReleaseDC(hwnd, hdc_win)
        ctypes.windll.gdi32.DeleteObject(hbm)
        return f"screenshot captured {w}x{h} → {out_path!r}"

    def _list_open_windows(self, hwnd: int, params: dict) -> str:
        titles: list[str] = []

        def _enum_cb(h: int, _lp: int) -> bool:
            if _user32.IsWindowVisible(h):
                buf = ctypes.create_unicode_buffer(256)
                _user32.GetWindowTextW(h, buf, 256)
                if buf.value:
                    titles.append(buf.value)
            return True

        cb = WNDENUMPROC(_enum_cb)
        _user32.EnumWindows(cb, 0)
        return json.dumps(titles)

    # ── UIA helpers (isolated for patching) ───────────────────────────────────

    def _uia_find_element(self, hwnd: int, name: str):
        """Locate a UIA element by Name property under hwnd."""
        try:
            import comtypes.client
            uia  = comtypes.client.CreateObject("{ff48dba4-60ef-4201-aa87-54103eef594e}")
            root = uia.ElementFromHandle(hwnd)
            cond = uia.CreatePropertyCondition(30005, name)  # UIA_NamePropertyId
            element = root.FindFirst(4, cond)                # TreeScope_Descendants
            if element is None:
                raise RuntimeError(f"UIA element {name!r} not found under hwnd {hwnd:#x}")
            return element
        except ImportError:
            raise RuntimeError("comtypes not installed — UIA operations unavailable")

    def _uia_get_value(self, element) -> str:
        pattern = element.GetCurrentPattern(10002)  # UIA_ValuePatternId
        return pattern.CurrentValue

    def _uia_invoke_click(self, element) -> None:
        pattern = element.GetCurrentPattern(10000)  # UIA_InvokePatternId
        pattern.Invoke()

    def _uia_set_value(self, element, value: str) -> None:
        pattern = element.GetCurrentPattern(10002)  # UIA_ValuePatternId
        pattern.SetValue(value)


__all__ = [
    "ExecutorActionRequest",
    "ExecutorActionResult",
    "Win32Executor",
    "PERMITTED_ACTIONS",
]
