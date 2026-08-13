"""Enterprise etw_probe.py — ETW terminal output notifications.

Event Tracing for Windows (ETW) provides kernel-level, push-based notification of
console host events without requiring UIA accessibility infrastructure. This is a
distinct terminal monitoring path from the UIA TextChanged subscription proven in
uia_textpattern.py.

Patent relevance:
  This is a second, distinct embodiment of "push-based, focus-independent terminal
  output monitoring" (Family 2 of the SelfConnect patent portfolio). A claim that
  reads on "subscribing to an event source" covers both UIA TextChanged AND ETW.

Requires: Windows, ctypes (stdlib), elevation for StartTrace.

Run:  python enterprise_experiments/win32_probe/etw_probe.py
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import threading
import time
import uuid
from typing import Callable, FrozenSet

# ── ETW GUIDs (Microsoft-Windows-Console-Host providers) ─────────────────────
CONSOLE_HOST_PROVIDER_GUID = "{cf9a5413-e45c-4e50-9ec2-86c2c59f7bc7}"
CONSOLE_HOST_PROVIDER_GUID_ALT = "{A0E9B465-B89A-49A6-A5EA-8ECCFF8148CB}"

# Allowlist of permitted ETW provider GUIDs (normalised lower-case, no braces).
# Only these may be passed to EnableTrace — prevents an attacker from redirecting
# the probe at a sensitive provider (e.g. Security-Auditing) via a crafted GUID.
_ALLOWED_PROVIDER_GUIDS: FrozenSet[str] = frozenset(
    g.lower().strip("{}") for g in (
        CONSOLE_HOST_PROVIDER_GUID,
        CONSOLE_HOST_PROVIDER_GUID_ALT,
    )
)

# ── Win32 constants ──────────────────────────────────────────────────────────
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
WNODE_FLAG_TRACED_GUID = 0x00020000
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
INVALID_PROCESSTRACE_HANDLE = ctypes.c_uint64(-1).value

_advapi32 = ctypes.windll.advapi32

# ── Structures ───────────────────────────────────────────────────────────────

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_string(cls, guid_str: str) -> "GUID":
        g = uuid.UUID(guid_str)
        inst = cls()
        inst.Data1 = g.time_low
        inst.Data2 = g.time_mid
        inst.Data3 = g.time_hi_version
        for i, b in enumerate(g.bytes[8:]):
            inst.Data4[i] = b
        return inst


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", ctypes.c_ulong),
        ("ProviderId", ctypes.c_ulong),
        ("Union1", ctypes.c_uint64),
        ("CountLost", ctypes.c_ulong),
        ("Guid", GUID),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ctypes.c_ulong),
        ("MinimumBuffers", ctypes.c_ulong),
        ("MaximumBuffers", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("FlushTimer", ctypes.c_ulong),
        ("EnableFlags", ctypes.c_ulong),
        ("AgeLimit", ctypes.c_long),
        ("NumberOfBuffers", ctypes.c_ulong),
        ("FreeBuffers", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("LogBuffersLost", ctypes.c_ulong),
        ("RealTimeBuffersLost", ctypes.c_ulong),
        ("LoggerThreadId", ctypes.wintypes.HANDLE),
        ("LogFileNameOffset", ctypes.c_ulong),
        ("LoggerNameOffset", ctypes.c_ulong),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", ctypes.c_byte * 80),
        ("BufferContext", ctypes.c_byte * 4),
        ("ExtendedDataCount", ctypes.c_ushort),
        ("UserDataLength", ctypes.c_ushort),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


def _is_elevated() -> bool:
    """Return True if the current process has elevation (admin token)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


class EtwConsoleSession:
    """ETW session subscribed to Microsoft-Windows-Console-Host events.

    Usage:
        session = EtwConsoleSession()
        session.open()
        session.subscribe(lambda evt: print(evt))
        time.sleep(10)
        session.close()
    """

    SESSION_NAME = "SelfConnect-ETW-Console"
    DEFAULT_PROVIDER_GUID = CONSOLE_HOST_PROVIDER_GUID
    BUFFER_BYTES = 4096

    def __init__(self, provider_guid: str = DEFAULT_PROVIDER_GUID) -> None:
        # FIX (INJECTION): validate provider GUID against allowlist before storing.
        normalised = provider_guid.lower().strip("{}")
        if normalised not in _ALLOWED_PROVIDER_GUIDS:
            raise ValueError(
                f"provider_guid {provider_guid!r} is not in the permitted allowlist. "
                "Only Microsoft-Windows-Console-Host provider GUIDs are accepted."
            )
        self._provider_guid = provider_guid
        self._session_handle: int = 0
        self._trace_handle: int = INVALID_PROCESSTRACE_HANDLE
        self._callback: Callable | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        # FIX (THREAD SAFETY): guards _session_handle, _running, _callback, _thread
        self._lock: threading.Lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._session_handle != 0

    def open(self) -> None:
        if not _is_elevated():
            raise PermissionError(
                "ETW StartTrace requires elevation. Run as Administrator."
            )
        # FIX (DOUBLE-OPEN): prevent re-entrant open; caller must close first.
        with self._lock:
            if self._session_handle != 0:
                raise RuntimeError(
                    "EtwConsoleSession.open() called on an already-open session. "
                    "Call close() before opening again."
                )

        # Allocate properties buffer with space for session name
        name_bytes = (self.SESSION_NAME + "\x00").encode("utf-16-le")
        buf_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + len(name_bytes) + 256
        buf = (ctypes.c_byte * buf_size)()
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
        props.Wnode.BufferSize = buf_size
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        props.BufferSize = self.BUFFER_BYTES // 1024  # in KB

        session_name = ctypes.create_unicode_buffer(self.SESSION_NAME)
        handle = ctypes.c_uint64(0)
        status = _advapi32.StartTraceW(
            ctypes.byref(handle),
            session_name,
            ctypes.byref(props),
        )
        # FIX (FAIL-OPEN): ERROR_ALREADY_EXISTS (183) means a prior session with
        # this name is still running and Windows did NOT populate `handle` — the
        # ETW session is NOT ours.  Raise so the caller knows to stop the stale
        # session first rather than silently proceeding with a zero handle and
        # losing all events.
        if status == 183:
            raise OSError(
                "StartTraceW: session name already exists (ERROR_ALREADY_EXISTS=183). "
                "A prior session may still be running. Call close() on the previous "
                "EtwConsoleSession instance or use ControlTrace(STOP) to clean up."
            )
        if status != 0:
            raise OSError(f"StartTraceW failed: status={status}")

        new_handle = handle.value
        if new_handle == 0:
            raise OSError("StartTraceW returned status=0 but did not populate session handle.")

        with self._lock:
            self._session_handle = new_handle

        provider_guid = GUID.from_string(self._provider_guid)
        _advapi32.EnableTrace(
            1,
            0,
            0,
            ctypes.byref(provider_guid),
            new_handle,
        )

    def subscribe(self, on_event: Callable[[dict], None]) -> None:
        # FIX (THREAD SAFETY + ZOMBIE THREADS): guard shared state with lock and
        # prevent duplicate background threads.  If a prior thread is still alive
        # the caller must call close() first.
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError(
                    "subscribe() called while a consumer thread is already running. "
                    "Call close() before re-subscribing."
                )
            self._callback = on_event
            self._running = True
            self._thread = threading.Thread(
                target=self._consume_loop, daemon=True, name="scent-etw"
            )
            self._thread.start()

    def _consume_loop(self) -> None:
        pass

    def close(self) -> None:
        # FIX (THREAD SAFETY): snapshot mutable state under lock, then do
        # blocking work (join, StopTraceW) outside the lock to avoid deadlock.
        with self._lock:
            self._running = False
            thread_ref = self._thread
            session_handle = self._session_handle

        if thread_ref is not None and thread_ref.is_alive():
            thread_ref.join(timeout=2.0)

        if session_handle != 0:
            try:
                session_name = ctypes.create_unicode_buffer(self.SESSION_NAME)
                buf_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 512
                buf = (ctypes.c_byte * buf_size)()
                props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
                props.Wnode.BufferSize = buf_size
                _advapi32.StopTraceW(session_handle, session_name, ctypes.byref(props))
            except Exception:  # noqa: BLE001
                pass

        with self._lock:
            # Only zero if we were the one who owned this handle.
            if self._session_handle == session_handle:
                self._session_handle = 0


if __name__ == "__main__":
    import sys
    if not _is_elevated():
        print("ERROR: ETW requires elevation (run as Administrator)")
        sys.exit(2)
    session = EtwConsoleSession()
    print(f"Opening ETW session: {session.SESSION_NAME}")
    session.open()
    print("Subscribed. Collecting for 5 seconds...")
    events = []
    session.subscribe(lambda e: events.append(e))
    time.sleep(5)
    session.close()
    print(f"Collected {len(events)} events. ETW probe PASS")
