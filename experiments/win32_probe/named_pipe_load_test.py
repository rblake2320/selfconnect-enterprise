"""Load test: 10 rapid sequential connections on the DACL-guarded named pipe.

What this verifies:
  1. Each iteration creates a fresh pipe instance, connects one client,
     impersonates, reads the OS-verified SID, reverts, and disconnects.
  2. All 10 connections resolve to the same SID (no identity drift).
  3. RevertToSelf is always called — even when the SID lookup raises.
  4. No handle leak: every HANDLE opened is closed before the next iteration.

Exit codes:
  0 = all 10 iterations PASS
  3 = one or more iterations FAIL

Run:
  PYTHONUTF8=1 C:/Python312/python.exe experiments/win32_probe/named_pipe_load_test.py
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Optional

import win32api
import win32con
import win32file
import win32pipe
import win32security

# ---------------------------------------------------------------------------
# ABI-correct advapi32 bindings (HANDLE is 8 bytes on x64 — never c_int)
# ---------------------------------------------------------------------------
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_advapi32.ImpersonateNamedPipeClient.argtypes = [ctypes.wintypes.HANDLE]
_advapi32.ImpersonateNamedPipeClient.restype = ctypes.wintypes.BOOL
_advapi32.RevertToSelf.argtypes = []
_advapi32.RevertToSelf.restype = ctypes.wintypes.BOOL

PIPE = r"\\.\pipe\selfconnect-loadtest"
ITERATIONS = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_sa_with_dacl() -> win32security.SECURITY_ATTRIBUTES:
    """Same DACL construction as named_pipe_identity.py — only owning user allowed."""
    me, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, me)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    sa.bInheritHandle = False
    return sa


@dataclass
class IterResult:
    iteration: int
    passed: bool = False
    sid: Optional[str] = None
    identity: Optional[str] = None
    revert_called: bool = False
    handle_closed: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-iteration server routine
# ---------------------------------------------------------------------------

def _server_once(result: IterResult, ready_event: threading.Event) -> None:
    h = None
    impersonated = False
    try:
        sa = _build_sa_with_dacl()
        h = win32pipe.CreateNamedPipe(
            PIPE,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            # max instances = 1 per iteration so reconnect is unambiguous
            1, 65536, 65536, 0, sa,
        )
        ready_event.set()  # signal client: pipe is up

        win32pipe.ConnectNamedPipe(h, None)
        win32file.ReadFile(h, 256)  # drain payload

        if _advapi32.ImpersonateNamedPipeClient(int(h)) == 0:
            raise OSError(
                f"ImpersonateNamedPipeClient failed: {ctypes.get_last_error()}"
            )
        impersonated = True

        try:
            tok = win32security.OpenThreadToken(
                win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True
            )
            sid = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
            name, dom, _ = win32security.LookupAccountSid("", sid)
            result.sid = win32security.ConvertSidToStringSid(sid)
            result.identity = f"{dom}\\{name}"
        finally:
            _advapi32.RevertToSelf()
            result.revert_called = True

    except Exception:  # noqa: BLE001
        result.error = traceback.format_exc().strip().splitlines()[-1]
        if impersonated and not result.revert_called:
            _advapi32.RevertToSelf()
            result.revert_called = True
    finally:
        if h is not None:
            try:
                win32file.CloseHandle(h)
                result.handle_closed = True
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Per-iteration client routine
# ---------------------------------------------------------------------------

def _client_once(ready_event: threading.Event) -> None:
    ready_event.wait(timeout=5.0)
    win32pipe.WaitNamedPipe(PIPE, 5000)
    h = win32file.CreateFile(
        PIPE,
        win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        0, None, win32con.OPEN_EXISTING, 0, None,
    )
    try:
        win32file.WriteFile(h, b"identity=I-AM-ROOT spoofed=true")
    finally:
        win32file.CloseHandle(h)


# ---------------------------------------------------------------------------
# Main load-test loop
# ---------------------------------------------------------------------------

def run_load_test() -> list[IterResult]:
    results: list[IterResult] = []

    for i in range(1, ITERATIONS + 1):
        res = IterResult(iteration=i)
        ready_event = threading.Event()

        srv = threading.Thread(target=_server_once, args=(res, ready_event), daemon=True)
        srv.start()

        client_error: Optional[str] = None
        try:
            _client_once(ready_event)
        except Exception:  # noqa: BLE001
            client_error = traceback.format_exc().strip().splitlines()[-1]

        srv.join(timeout=5)

        if client_error and not res.error:
            res.error = f"client: {client_error}"

        # Verdict for this iteration
        res.passed = (
            res.sid is not None
            and res.revert_called
            and res.handle_closed
            and res.error is None
        )
        results.append(res)

        # Small gap so Windows can fully release the pipe name before next instance
        time.sleep(0.05)

    return results


def main() -> int:
    print(f"Named pipe identity load test — {ITERATIONS} sequential connections\n")

    # Baseline: what SID should every connection resolve to?
    expected_sid = win32security.ConvertSidToStringSid(
        win32security.LookupAccountName("", win32api.GetUserName())[0]
    )
    print(f"Expected SID (owning user): {expected_sid}\n")

    results = run_load_test()

    passed = 0
    failed = 0
    sid_drift = False

    for r in results:
        status = "PASS" if r.passed else "FAIL"
        sid_match = "SID-OK" if r.sid == expected_sid else "SID-MISMATCH"
        revert = "REVERT-OK" if r.revert_called else "NO-REVERT"
        handle = "HANDLE-CLOSED" if r.handle_closed else "HANDLE-LEAK"
        detail = f"{r.identity} ({r.sid})" if r.sid else f"none — {r.error}"

        print(
            f"  [{r.iteration:02d}] {status:4s} | {sid_match} | {revert} | {handle} | {detail}"
        )

        if r.passed:
            passed += 1
        else:
            failed += 1

        if r.sid and r.sid != expected_sid:
            sid_drift = True

    print(f"\n{'='*60}")
    print(f"Total: {passed}/{ITERATIONS} passed, {failed} failed")

    if sid_drift:
        print("ANOMALY: SID drift detected — not all connections resolved to the expected SID")

    # Verify SID consistency across all passing iterations
    resolved_sids = {r.sid for r in results if r.sid is not None}
    if len(resolved_sids) > 1:
        print(f"ANOMALY: Multiple distinct SIDs resolved: {resolved_sids}")
        failed += 1  # count as an additional failure

    if failed == 0 and not sid_drift:
        print("OVERALL: PASS — all iterations consistent, no handle leaks, RevertToSelf always called")
        return 0
    else:
        print("OVERALL: FAIL")
        return 3


if __name__ == "__main__":
    sys.exit(main())
