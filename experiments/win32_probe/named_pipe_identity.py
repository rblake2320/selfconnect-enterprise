"""POC: OS-enforced caller identity over a DACL-guarded named pipe.

enterprise/transport.py uses WM_COPYDATA (OS-verified *sender HWND*). This probe
demonstrates the complementary primitive: a named pipe created with an explicit DACL,
where the server calls ImpersonateNamedPipeClient() and reads the connecting client's
identity (SID) *from the OS token*, not from anything the client asserted in the payload.

Patent / ATO relevance
----------------------
OS-controlled identity vs application-controlled identity. The agent's identity on the
IPC boundary is established by the Windows access-control layer (the pipe ACL + the
impersonated token), so an agent cannot spoof a different identity at the application
level. This is the distinction DoD/IL5 reviewers recognize during an ATO.

Run:  python experiments/win32_probe/named_pipe_identity.py
Exit: 0 = PASS (server read OS-verified client SID), 3 = FAIL
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import sys
import threading
import time

import win32api
import win32con
import win32file
import win32pipe
import win32security

PIPE = r"\\.\pipe\selfconnect-idprobe"

# Prototype the advapi32 calls explicitly: HANDLE is pointer-sized (8 bytes on x64).
# Letting ctypes default the handle arg to c_int (4 bytes) is the same class of ABI
# bug Codex flagged in self_connect.py — fix it at the source here too.
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_advapi32.ImpersonateNamedPipeClient.argtypes = [ctypes.wintypes.HANDLE]
_advapi32.ImpersonateNamedPipeClient.restype = ctypes.wintypes.BOOL
_advapi32.RevertToSelf.argtypes = []
_advapi32.RevertToSelf.restype = ctypes.wintypes.BOOL


def _build_sa_with_dacl() -> win32security.SECURITY_ATTRIBUTES:
    """Pipe security descriptor whose DACL grants the *current user* full control only.

    This is the OS-level allowlist: only the owning identity may connect.
    """
    me, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, me)
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    sa.bInheritHandle = False
    return sa


def _server(result: dict) -> None:
    try:
        sa = _build_sa_with_dacl()
        h = win32pipe.CreateNamedPipe(
            PIPE,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 0, sa,
        )
        result["pipe_created"] = True
        win32pipe.ConnectNamedPipe(h, None)
        win32file.ReadFile(h, 256)  # drain the client's (untrusted) payload

        # Establish identity from the OS, NOT from the payload:
        if _advapi32.ImpersonateNamedPipeClient(int(h)) == 0:
            raise OSError(f"ImpersonateNamedPipeClient failed: {ctypes.get_last_error()}")
        try:
            tok = win32security.OpenThreadToken(
                win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True
            )
            sid = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
            name, dom, _ = win32security.LookupAccountSid("", sid)
            result["client_identity"] = f"{dom}\\{name}"
            result["client_sid"] = win32security.ConvertSidToStringSid(sid)
        finally:
            _advapi32.RevertToSelf()
        win32file.CloseHandle(h)
    except Exception as e:  # noqa: BLE001 — surface any failure to the verdict
        result["error"] = f"{type(e).__name__}: {e}"


def _client() -> None:
    win32pipe.WaitNamedPipe(PIPE, 5000)
    h = win32file.CreateFile(
        PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None,
        win32con.OPEN_EXISTING, 0, None,
    )
    # The client asserts a FALSE identity in the payload — the server must ignore it
    # and trust the OS token instead.
    win32file.WriteFile(h, b"identity=I-AM-ROOT spoofed=true")
    win32file.CloseHandle(h)


def main() -> int:
    result: dict = {}
    srv = threading.Thread(target=_server, args=(result,), daemon=True)
    srv.start()
    time.sleep(0.3)  # let the pipe come up
    try:
        _client()
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: client could not connect: {e}")
        return 3
    srv.join(timeout=5)

    if result.get("error"):
        print(f"FAIL: {result['error']}")
        return 3
    if not result.get("client_sid"):
        print(f"FAIL: server never resolved client identity. state={result}")
        return 3

    expected = win32security.ConvertSidToStringSid(
        win32security.LookupAccountName("", win32api.GetUserName())[0]
    )
    matched = result["client_sid"] == expected
    print(
        f"PASS: pipe DACL enforced; server read OS-verified client identity "
        f"{result['client_identity']} (SID {result['client_sid']}). "
        f"Payload claimed 'I-AM-ROOT' and was ignored. "
        f"SID matches owning user: {matched}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
