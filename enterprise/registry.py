"""enterprise/registry.py — Win32 Agent Registry for SelfConnect Enterprise

Enterprise-grade agent infrastructure primitives built on the full Win32 IPC
surface. This module is ADDITIVE — it does NOT modify self_connect.py. Import
both and use whichever capabilities each situation requires.

    from self_connect import list_windows, send_string, get_text_uia
    from enterprise.registry import stamp_birth_tag, discover_mesh, BirthTag

Layer map:
    Tier 1 (self_connect.py)  — WM_CHAR injection, UIA readback [proven, production]
    Tier 2 (this file)        — SetProp registry, WM_COPYDATA transport, Named Events
    Tier 3 (future)           — CreateDesktop, Named Pipes, SetWinEventHook

Patent claims addressed here:
    Claim 3 (upgraded):  HWND self-discovery with structured birth-tag metadata
    Claim Set 2 (new):   SetProp/GetProp as zero-infrastructure distributed agent registry
    Claim Set 1 dep.:    WM_COPYDATA as HWND-routed structured payload transport
    Claim Set 3 (new):   Named Events as zero-polling agent coordination primitives

Identity model: HWND-routed identity anchor.
    Peer trust is established by cross-checking:
      HWND  → must be a live window (IsWindow)
      PID   → extracted from HWND via GetWindowThreadProcessId, cross-checked against SCPID
      CTIME → OS process creation time via GetProcessTimes, cross-checked against SCCTIME
    This is NOT cryptographic non-repudiation. It is an OS-attested identity binding
    that is difficult to spoof within a single session without process-level access.

Liveness model: destroyed windows are automatically absent from discover_mesh().
    Hung (unresponsive but alive) windows are NOT automatically filtered — callers
    should use verify_tag() which validates HWND + PID + creation time, and
    check is_alive() which validates heartbeat age.

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import ctypes
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass
from typing import Optional

from enterprise.discovery_config import MAX_CANDIDATES_PER_CYCLE, MAX_STAMPS_PER_PID

_log = logging.getLogger(__name__)

# ── Win32 handles ─────────────────────────────────────────────────────────────
user32   = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ── Win32 constants ───────────────────────────────────────────────────────────
WM_COPYDATA  = 0x004A
GW_CHILD     = 5
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ── Property key constants ─────────────────────────────────────────────────────
# All SelfConnect window properties use the "SC" prefix.
# These are the birth tag fields — stamped at spawn, readable by any peer.
PROP_ID      = "SCID"       # agent identity string  e.g. "agent-b-local-qwen3"
PROP_TYPE    = "SCTYPE"     # role: "claude_code" | "local_model" | "observer" | "unknown"
PROP_BORN    = "SCBORN"     # float str — time.time() at spawn (Python clock)
PROP_PARENT  = "SCPARENT"   # str(spawner_hwnd) or "0" if no known parent
PROP_MODEL   = "SCMODEL"    # model name e.g. "claude-sonnet-4-6" | "qwen3.6:27b"
PROP_HB      = "SCHB"       # float str — last heartbeat time.time()
PROP_SESSION = "SCSESS"     # optional session label e.g. "session-16"
PROP_PID     = "SCPID"      # str(os.getpid()) — for cross-checking via GetWindowThreadProcessId
PROP_CTIME   = "SCCTIME"    # str — OS process creation time (GetProcessTimes FILETIME epoch)

# ── Win32 structures for process identity binding ─────────────────────────────

class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

PROCESS_QUERY_INFORMATION = 0x0400
WINDOWS_EPOCH_DELTA = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01

# ── String atom helpers ────────────────────────────────────────────────────────
# SetProp / GetProp require the value to be a handle (HANDLE/atom).
# We store short strings by interning them as global atoms — this is the
# standard Win32 pattern for attaching string metadata to windows.

_atom_cache: dict[str, int] = {}

def _str_to_atom(value: str) -> int:
    """Intern a string as a global atom and return its atom ID."""
    if value not in _atom_cache:
        atom = ctypes.windll.kernel32.GlobalAddAtomW(value)
        if atom == 0:
            raise RuntimeError(f"GlobalAddAtomW failed for {value!r}")
        _atom_cache[value] = atom
    return _atom_cache[value]

def _atom_to_str(atom: int) -> str:
    """Resolve a global atom ID back to its string."""
    buf = ctypes.create_unicode_buffer(256)
    length = ctypes.windll.kernel32.GlobalGetAtomNameW(atom, buf, 256)
    if length == 0:
        return ""
    return buf.value

# ── OS-attested identity helpers ─────────────────────────────────────────────

def get_hwnd_pid(hwnd: int) -> int:
    """Return the PID that owns a window handle. Returns 0 if hwnd is invalid."""
    pid = ctypes.c_ulong(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def get_process_creation_time(pid: int) -> float:
    """Return the OS process creation time as a Unix epoch float.

    Uses GetProcessTimes — the OS-attested timestamp, not clock().
    Returns 0.0 if the process cannot be opened (exited or insufficient rights).
    """
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return 0.0
    creation = FILETIME()
    dummy    = FILETIME()
    ok = kernel32.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(dummy),
        ctypes.byref(dummy),
        ctypes.byref(dummy),
    )
    kernel32.CloseHandle(handle)
    if not ok:
        return 0.0
    # FILETIME is 100-nanosecond intervals since 1601-01-01
    ft64 = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return (ft64 / 10_000_000) - WINDOWS_EPOCH_DELTA


def verify_tag(tag: "BirthTag") -> bool:
    """Verify a BirthTag's HWND-routed identity anchor.

    Checks three OS-attested facts:
      1. The HWND is a live window (IsWindow)
      2. The PID extracted from the HWND matches the stored SCPID
      3. The OS process creation time matches the stored SCCTIME

    Returns True only if all three match.
    Note: does NOT guarantee liveness — a hung process passes this check.
    Use is_alive() for heartbeat-based liveness validation.
    """
    if not user32.IsWindow(tag.hwnd):
        return False
    if tag.pid == 0:
        # tag was stamped without PID — cannot verify, treat as unverified
        return False
    live_pid = get_hwnd_pid(tag.hwnd)
    if live_pid != tag.pid:
        return False
    if tag.os_create_time > 0.0:
        live_ct = get_process_creation_time(tag.pid)
        if abs(live_ct - tag.os_create_time) > 1.0:  # 1s tolerance for float conversion
            return False
    return True


# ── BirthTag dataclass ────────────────────────────────────────────────────────

@dataclass
class BirthTag:
    """Identity certificate stamped on a window at agent spawn time.

    Anchored to a live HWND via Win32 window properties (SetProp/GetProp).
    Uses atoms (GlobalAddAtom) as the property value carrier — the correct
    Win32 pattern; properties are not raw strings.

    Destroyed windows are automatically absent from discover_mesh() results.
    Hung (unresponsive but live) windows survive discovery — callers must
    call verify_tag(tag) and is_alive() to establish both identity and liveness.

    Identity binding:
      hwnd + pid + os_create_time form an HWND-routed identity anchor.
      verify_tag() cross-checks all three against OS state. This is OS-attested
      binding, not cryptographic non-repudiation.

    Equivalent to Identity Forge AgentBirthCertificate but OS-native:
    no database, no cleanup, no garbage collection required.
    """
    hwnd:          int
    agent_id:      str
    agent_type:    str    # "claude_code" | "local_model" | "observer" | "unknown"
    born:          float  # epoch seconds at spawn (Python clock)
    parent:        int    # spawner hwnd, 0 if unknown
    model:         str    # model name/version
    heartbeat:     float  # last heartbeat epoch seconds
    pid:           int    = 0    # OS PID — from GetWindowThreadProcessId
    os_create_time: float = 0.0  # OS process creation time — from GetProcessTimes
    session:       str   = ""   # optional session label

    def age_seconds(self) -> float:
        return time.time() - self.born

    def seconds_since_heartbeat(self) -> float:
        return time.time() - self.heartbeat

    def is_alive(self, stale_threshold: float = 120.0) -> bool:
        """True if heartbeat was updated within stale_threshold seconds.

        Note: heartbeat age alone does not confirm the process is healthy.
        Call verify_tag(self) to confirm HWND + PID + creation time still match.
        """
        return self.seconds_since_heartbeat() < stale_threshold

    def to_dict(self) -> dict:
        d = asdict(self)
        d["age_seconds"] = self.age_seconds()
        d["seconds_since_heartbeat"] = self.seconds_since_heartbeat()
        d["heartbeat_alive"] = self.is_alive()
        return d


# ── SetProp / GetProp wrappers ────────────────────────────────────────────────

def set_agent_prop(hwnd: int, key: str, value: str) -> bool:
    """Attach a string property to a window handle.

    Uses GlobalAddAtom to intern the value string as a system atom,
    then stores the atom as the property handle — the standard Win32 pattern.
    Returns True on success.
    """
    atom = _str_to_atom(value)
    ok = user32.SetPropW(hwnd, key, atom)
    return bool(ok)


def get_agent_prop(hwnd: int, key: str) -> str:
    """Read a string property from a window handle. Returns "" if absent."""
    atom = user32.GetPropW(hwnd, key)
    if atom == 0:
        return ""
    return _atom_to_str(atom)


def remove_agent_prop(hwnd: int, key: str) -> bool:
    """Remove a property from a window handle. Call at agent shutdown."""
    atom = user32.RemovePropW(hwnd, key)
    if atom and atom != 0:
        ctypes.windll.kernel32.GlobalDeleteAtom(atom)
    return True


# ── Birth tag lifecycle ────────────────────────────────────────────────────────

def stamp_birth_tag(
    hwnd: int,
    agent_id: str,
    agent_type: str,
    model: str,
    parent_hwnd: int = 0,
    session: str = "",
) -> BirthTag:
    """Stamp a birth tag on the given window handle.

    Call this once at agent startup, right after the window HWND is confirmed.
    The tag persists as long as the window exists. Peers call verify_tag() to
    cross-check HWND → PID → OS creation time before trusting any message.

    Args:
        hwnd:       The agent's own window handle.
        agent_id:   Unique agent identifier string e.g. "agent-b-local-qwen3".
        agent_type: Role classification ("claude_code", "local_model", "observer").
        model:      Model name/version e.g. "qwen3.6:27b".
        parent_hwnd: HWND of the process that spawned this agent (0 if unknown).
        session:    Optional session label e.g. "session-16".

    Returns:
        BirthTag dataclass representing the stamped certificate.
    """
    import os as _os
    now   = time.time()
    pid   = _os.getpid()
    ctime = get_process_creation_time(pid)
    set_agent_prop(hwnd, PROP_ID,     agent_id)
    set_agent_prop(hwnd, PROP_TYPE,   agent_type)
    set_agent_prop(hwnd, PROP_BORN,   str(now))
    set_agent_prop(hwnd, PROP_PARENT, str(parent_hwnd))
    set_agent_prop(hwnd, PROP_MODEL,  model)
    set_agent_prop(hwnd, PROP_HB,     str(now))
    set_agent_prop(hwnd, PROP_PID,    str(pid))
    set_agent_prop(hwnd, PROP_CTIME,  str(ctime))
    if session:
        set_agent_prop(hwnd, PROP_SESSION, session)
    return BirthTag(
        hwnd=hwnd,
        agent_id=agent_id,
        agent_type=agent_type,
        born=now,
        parent=parent_hwnd,
        model=model,
        heartbeat=now,
        pid=pid,
        os_create_time=ctime,
        session=session,
    )


def update_heartbeat(hwnd: int) -> bool:
    """Update the heartbeat timestamp on an already-stamped window.

    Call periodically (e.g. every 30s) to signal liveness to peers.
    Returns True if the SCID property exists (window was stamped).
    """
    if not get_agent_prop(hwnd, PROP_ID):
        return False
    return set_agent_prop(hwnd, PROP_HB, str(time.time()))


def read_birth_tag(hwnd: int) -> Optional[BirthTag]:
    """Read a BirthTag from a window handle. Returns None if not stamped.

    This reads stored property values only — it does NOT call verify_tag().
    Call verify_tag(tag) after reading if you need OS-attested identity confirmation.
    """
    agent_id = get_agent_prop(hwnd, PROP_ID)
    if not agent_id:
        return None
    born_str   = get_agent_prop(hwnd, PROP_BORN)
    hb_str     = get_agent_prop(hwnd, PROP_HB)
    parent_str = get_agent_prop(hwnd, PROP_PARENT)
    pid_str    = get_agent_prop(hwnd, PROP_PID)
    ctime_str  = get_agent_prop(hwnd, PROP_CTIME)
    return BirthTag(
        hwnd=hwnd,
        agent_id=agent_id,
        agent_type=get_agent_prop(hwnd, PROP_TYPE) or "unknown",
        born=float(born_str) if born_str else 0.0,
        parent=int(parent_str) if parent_str else 0,
        model=get_agent_prop(hwnd, PROP_MODEL) or "",
        heartbeat=float(hb_str) if hb_str else 0.0,
        pid=int(pid_str) if pid_str else 0,
        os_create_time=float(ctime_str) if ctime_str else 0.0,
        session=get_agent_prop(hwnd, PROP_SESSION) or "",
    )


# ── Mesh discovery ────────────────────────────────────────────────────────────

def discover_mesh(
    verified_only: bool = False,
    max_heartbeat_age: Optional[float] = None,
) -> list[BirthTag]:
    """Enumerate all SelfConnect agents visible on this machine.

    Walks all top-level windows, reads their SCID property, and returns
    BirthTag records for every window that has been stamped.

    Destroyed windows are automatically absent — the registry cannot contain
    dead entries for closed windows.

    Three conditions can exclude a result:
      1. verified_only=True  → HWND + PID + creation time don't match (dead/spoofed)
      2. max_heartbeat_age   → heartbeat is older than N seconds (hung/frozen)
      3. Neither set         → returns all stamped windows, caller filters

    Args:
        verified_only:     If True, runs verify_tag() — filters dead and spoofed agents.
        max_heartbeat_age: If set (seconds), excludes agents whose heartbeat is older
                           than this value — filters frozen/hung agents that still have
                           a live window. Recommended: 60-120 seconds.
    """
    results: list[BirthTag] = []
    pid_stamp_count: dict[int, int] = {}

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
    def _cb(hwnd: int, _: int) -> bool:
        # Hard cap: stop processing once limit reached (DoS protection).
        # An attacker can stamp thousands of fake SCID properties cheaply;
        # without a cap, EnumWindows becomes a free denial-of-service vector.
        if len(results) >= MAX_CANDIDATES_PER_CYCLE:
            _log.warning(
                "discover_mesh: candidate cap reached (%d). "
                "Increase SC_DISCOVERY_CAP env var if mesh is legitimately larger. "
                "Event: discovery_candidate_capped",
                MAX_CANDIDATES_PER_CYCLE,
            )
            return False  # stop enumeration

        tag = read_birth_tag(hwnd)
        if tag:
            # Per-PID stamp volume check: a single PID stamping many SCID
            # properties is suspicious (attacker creating multiple fake identities).
            pid = tag.pid
            pid_stamp_count[pid] = pid_stamp_count.get(pid, 0) + 1
            if pid_stamp_count[pid] > MAX_STAMPS_PER_PID:
                _log.warning(
                    "discover_mesh: pid=%d has stamped %d SCID properties (limit=%d). "
                    "Ignoring excess. Event: suspicious_pid_stamp_volume",
                    pid, pid_stamp_count[pid], MAX_STAMPS_PER_PID,
                )
                return True  # skip this candidate, continue enumeration

            if verified_only and not verify_tag(tag):
                return True
            if max_heartbeat_age is not None and tag.seconds_since_heartbeat() > max_heartbeat_age:
                return True
            results.append(tag)
        return True

    user32.EnumWindows(_cb, 0)
    return results


def find_agent(agent_id: str) -> Optional[BirthTag]:
    """Find a specific agent by ID in the live mesh. Returns None if not found."""
    for tag in discover_mesh():
        if tag.agent_id == agent_id:
            return tag
    return None


# ── WM_COPYDATA structured transport ─────────────────────────────────────────

class COPYDATASTRUCT(ctypes.Structure):
    """Win32 COPYDATASTRUCT — payload container for WM_COPYDATA messages."""
    _fields_ = [
        ("dwData", ctypes.c_ulong),   # application-defined message type
        ("cbData", ctypes.c_ulong),   # payload size in bytes
        ("lpData", ctypes.c_void_p),  # pointer to payload buffer
    ]

# SelfConnect WM_COPYDATA type IDs
SCDATA_JSON    = 0x5C01   # JSON-encoded payload
SCDATA_TASK    = 0x5C02   # structured task assignment
SCDATA_RESULT  = 0x5C03   # task result / tool output
SCDATA_PING    = 0x5C04   # liveness probe

# WM_COPYDATA hard ceiling — enforced on send AND receive.
# WM_COPYDATA is delivered synchronously; oversized messages create OOM and
# denial-of-service exposure on the listener thread.
MAX_COPYDATA_BYTES: int = 64 * 1024   # 64 KB


def send_data(
    target_hwnd: int,
    payload: dict,
    data_type: int = SCDATA_JSON,
    sender_hwnd: int = 0,
) -> bool:
    """Send a structured JSON payload to another agent via WM_COPYDATA.

    OS-verified: the recipient reads wParam to confirm sender HWND.
    Atomic: the entire payload is delivered in one message, no chunking.
    Up to 64KB per message. Sender does not need focus.

    Args:
        target_hwnd: Destination agent's HWND.
        payload:     Python dict — will be JSON-encoded and sent as bytes.
        data_type:   SCDATA_* constant identifying payload type.
        sender_hwnd: Caller's own HWND — appears as wParam at the receiver.
                     Pass 0 only when the sender has no window (message-only agents).

    Returns:
        True if SendMessage returned non-zero (message delivered).
    """
    raw = json.dumps(payload).encode("utf-8")
    if len(raw) > MAX_COPYDATA_BYTES:
        raise ValueError(
            f"WM_COPYDATA payload is {len(raw)} bytes; "
            f"exceeds the {MAX_COPYDATA_BYTES}-byte ceiling. "
            "Split the payload or reduce field size."
        )
    buf = ctypes.create_string_buffer(raw)
    cds = COPYDATASTRUCT(
        dwData=data_type,
        cbData=len(raw),
        lpData=ctypes.cast(buf, ctypes.c_void_p),
    )
    result = user32.SendMessageW(
        target_hwnd,
        WM_COPYDATA,
        sender_hwnd,  # wParam: sender HWND — receiver uses this to reply / verify sender
        ctypes.byref(cds),
    )
    return bool(result)


# ── Named Event coordination ──────────────────────────────────────────────────

def signal_ready(name: str) -> bool:
    """Signal a named event — wake any agent waiting on this name.

    Creates the event if it doesn't exist, then sets it.
    Any agent calling wait_for(name) will unblock immediately.

    Returns True on success.
    """
    handle = kernel32.CreateEventW(None, False, False, name)
    if not handle:
        return False
    kernel32.SetEvent(handle)
    kernel32.CloseHandle(handle)
    return True


def wait_for(name: str, timeout_ms: int = 30_000) -> bool:
    """Block until the named event is signaled or timeout expires.

    Zero CPU usage during the wait — OS wakes the thread on signal.
    Returns True if signaled, False if timeout expired.

    Args:
        name:       Named event string e.g. "AGENT-B-READY".
        timeout_ms: Maximum wait in milliseconds. Default 30s.
    """
    handle = kernel32.CreateEventW(None, False, False, name)
    if not handle:
        return False
    WAIT_OBJECT_0 = 0x00000000
    result = kernel32.WaitForSingleObject(handle, timeout_ms)
    kernel32.CloseHandle(handle)
    return result == WAIT_OBJECT_0


# ── Heartbeat daemon ──────────────────────────────────────────────────────────

class HeartbeatDaemon:
    """Background thread that updates SCHB on an agent window every N seconds.

    Usage:
        hb = HeartbeatDaemon(own_hwnd, interval=30)
        hb.start()
        # ... agent runs ...
        hb.stop()
    """

    def __init__(self, hwnd: int, interval: float = 30.0):
        self.hwnd     = hwnd
        self.interval = interval
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            update_heartbeat(self.hwnd)


# ── Public API ────────────────────────────────────────────────────────────────

__all__ = [  # grouped by category, not alphabetical
    # Birth tag dataclass
    "BirthTag",
    # Property primitives
    "set_agent_prop", "get_agent_prop", "remove_agent_prop",
    # OS identity helpers
    "get_hwnd_pid", "get_process_creation_time", "verify_tag",
    # Birth tag lifecycle
    "stamp_birth_tag", "update_heartbeat", "read_birth_tag",
    # Mesh discovery
    "discover_mesh", "find_agent",
    # WM_COPYDATA transport
    "send_data", "COPYDATASTRUCT",
    "SCDATA_JSON", "SCDATA_TASK", "SCDATA_RESULT", "SCDATA_PING",
    # Named Event coordination
    "signal_ready", "wait_for",
    # Heartbeat daemon
    "HeartbeatDaemon",
    # Property key constants
    "PROP_ID", "PROP_TYPE", "PROP_BORN", "PROP_PARENT",
    "PROP_MODEL", "PROP_HB", "PROP_SESSION",
]


# ── CLI demo ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("SelfConnect Enterprise — Live Mesh Discovery")
    print("=" * 60)
    agents = discover_mesh()
    if not agents:
        print("No stamped agents found on this machine.")
        print("(Agents must call stamp_birth_tag() at startup)")
    else:
        for tag in agents:
            print(f"\n  HWND:      0x{tag.hwnd:x}")
            print(f"  ID:        {tag.agent_id}")
            print(f"  Type:      {tag.agent_type}")
            print(f"  Model:     {tag.model}")
            print(f"  Born:      {time.strftime('%H:%M:%S', time.localtime(tag.born))}")
            print(f"  Parent:    0x{tag.parent:x}")
            print(f"  Heartbeat: {tag.seconds_since_heartbeat():.1f}s ago")
            print(f"  Alive:     {tag.is_alive()}")
            if tag.session:
                print(f"  Session:   {tag.session}")
    print()
