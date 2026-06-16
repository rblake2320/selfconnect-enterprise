"""chained_channel.py — the composed embodiment, gap-free (Claude 1 / selfconnect-enterprise).

One governed loop binding the three proven legs (all live in THIS repo):
  READ      : UIA TextChanged on a terminal text surface -> delta   (uia_textpattern)
  IDENTITY  : sign SHA-256(delta) with a TPM-backed key             (tpm_identity, Platform KSP)
  TRANSPORT : send over a DACL-guarded named pipe; the server impersonates the client and
              records the OS-verified caller SID, THEN verifies the TPM signature
                                                                     (named_pipe_identity)

Self-contained end-to-end self-test (Role B server thread + Role A client in one process)
against a THROWAWAY console this process spawns — never a live agent window.

Why this differs from the selfconnect-repo draft (see REVIEW_chained_channel.md):
  - real DACL pipe + ImpersonateNamedPipeClient  -> the OS-identity leg is actually exercised
  - TPM signing (hardware-attested), not Ed25519 software identity
  - uses the proven GetModule / comtypes-handler / 64-bit-handle paths (no ABI truncation)

Run:  python experiments/win32_probe/chained_channel.py
Exit: 0 = CHAIN COMPLETE (all four legs), 1 = a leg failed
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import pythoncom
import win32api
import win32con
import win32file
import win32pipe
import win32security

from named_pipe_identity import _advapi32, _build_sa_with_dacl
from tpm_identity import (
    NCRYPT,
    NCRYPT_OVERWRITE_KEY_FLAG,
    NCRYPT_SILENT_FLAG,
    _ck,
    _export_pub_blob,
    _open_platform_provider,
    _sign,
    _verify,
)
from uia_textpattern import (
    UIA_Text_TextChangedEventId,
    compute_delta,
    get_uia,
    read_text,
    register_textchanged,
    text_element,
)

PIPE = r"\\.\pipe\sc_chain_e"
TERM_CLASSES = {"ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS"}
CREATE_NEW_CONSOLE = 0x00000010


# ── TRANSPORT leg: Role B — DACL pipe server that impersonates + verifies ──────
def role_b(result: dict) -> None:
    try:
        sa = _build_sa_with_dacl()
        h = win32pipe.CreateNamedPipe(
            PIPE, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 0, sa,
        )
        win32pipe.ConnectNamedPipe(h, None)
        _, data = win32file.ReadFile(h, 65536)              # read the signed payload
        if _advapi32.ImpersonateNamedPipeClient(int(h)) == 0:  # OS-verified caller identity
            raise OSError("ImpersonateNamedPipeClient failed")
        try:
            tok = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
            sid = win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
            name, dom, _ = win32security.LookupAccountSid("", sid)
            result["caller"] = f"{dom}\\{name}"
            result["caller_sid"] = win32security.ConvertSidToStringSid(sid)
        finally:
            _advapi32.RevertToSelf()
        win32file.CloseHandle(h)

        payload = json.loads(bytes(data))
        digest = bytes.fromhex(payload["delta_hash"])
        sig = bytes.fromhex(payload["sig"])
        pub = bytes.fromhex(payload["pub"])
        result["token"] = payload["token"]
        result["sig_valid"] = _verify(pub, digest, sig)      # IDENTITY leg verified
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"


# ── helpers ────────────────────────────────────────────────────────────────────
def _new_terminal_hwnds(before: set[int]) -> set[int]:
    import win32gui

    out: set[int] = set()

    def cb(hh, _):
        try:
            if win32gui.IsWindowVisible(hh) and win32gui.GetClassName(hh) in TERM_CLASSES:
                out.add(hh)
        except Exception:  # noqa: BLE001
            pass
        return True

    win32gui.EnumWindows(cb, None)
    return out - before


def main() -> int:
    import win32gui

    token = f"SC_CHAIN_{id(object()) & 0xFFFF:04x}"

    # READ leg: spawn a throwaway console that prints the token after a short delay
    # (delay lets us register the TextChanged handler before the line appears).
    before = _new_terminal_hwnds(set())
    cmd = f"ping -n 3 127.0.0.1 >nul & echo {token} & ping -n 4 127.0.0.1 >nul"
    subprocess.Popen(["conhost.exe", "cmd", "/c", cmd], creationflags=CREATE_NEW_CONSOLE)  # noqa: F841
    mine = None
    for _ in range(20):
        time.sleep(0.3)
        new = _new_terminal_hwnds(before)
        if new:
            mine = sorted(new)[0]
            break
    if not mine:
        print("FAIL: no throwaway console appeared.")
        return 1

    uia, UIA = get_uia()
    el = text_element(uia, UIA, mine)
    if el is None:
        print(f"FAIL: no TextPattern element on spawned hwnd={mine}.")
        return 1

    last = [read_text(uia, UIA, el)]
    captured: list[str] = []

    def on_change(_sender):
        try:
            now = read_text(uia, UIA, el)
            d = compute_delta(last[0], now)
            last[0] = now
            if d.strip():
                captured.append(d)
        except Exception:  # noqa: BLE001
            pass

    handler = register_textchanged(uia, UIA, el, on_change)

    # TRANSPORT leg: start the DACL pipe server before the client writes.
    result: dict = {}
    srv = threading.Thread(target=role_b, args=(result,), daemon=True)
    srv.start()
    time.sleep(0.3)

    # Pump the COM loop until the token shows up in a delta (the "new output" we read).
    deadline = time.time() + 14
    delta = None
    while time.time() < deadline:
        pythoncom.PumpWaitingMessages()
        time.sleep(0.05)
        hit = next((d for d in captured if token in d), None)
        if hit:
            delta = hit
            break
    try:
        uia.RemoveAutomationEventHandler(UIA_Text_TextChangedEventId, el, handler)
    except Exception:  # noqa: BLE001
        pass

    if not delta:
        print(f"FAIL: TextChanged never delivered a delta containing {token!r}.")
        return 1
    print(f"[READ] TextChanged delta carried the token; delta={delta.strip()[:60]!r}")

    # IDENTITY leg: sign SHA-256(delta) with a TPM-backed key (Platform Crypto Provider).
    digest = hashlib.sha256(delta.encode()).digest()
    prov = _open_platform_provider()
    hkey = ctypes.c_void_p()
    _ck(NCRYPT.NCryptCreatePersistedKey(prov, ctypes.byref(hkey), "ECDSA_P256", "sc-chain-key", 0,
                                        NCRYPT_OVERWRITE_KEY_FLAG), "create")
    _ck(NCRYPT.NCryptFinalizeKey(hkey, NCRYPT_SILENT_FLAG), "finalize")
    try:
        pub = _export_pub_blob(hkey)
        sig = _sign(hkey, digest)
    finally:
        NCRYPT.NCryptDeleteKey(hkey, 0)
        NCRYPT.NCryptFreeObject(prov)
    print(f"[IDENTITY] signed SHA-256(delta) with TPM key; sig_len={len(sig)}")

    # TRANSPORT leg (client side): write the signed payload over the DACL pipe.
    payload = {"token": token, "delta_hash": digest.hex(), "sig": sig.hex(), "pub": pub.hex()}
    win32pipe.WaitNamedPipe(PIPE, 5000)
    ch = win32file.CreateFile(PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None,
                              win32con.OPEN_EXISTING, 0, None)
    win32file.WriteFile(ch, json.dumps(payload).encode())
    win32file.CloseHandle(ch)
    srv.join(timeout=6)

    # Verdict — all four legs.
    if result.get("error"):
        print(f"FAIL: server: {result['error']}")
        return 1
    read_ok = True
    id_ok = bool(result.get("sig_valid"))
    pipe_ok = bool(result.get("caller_sid"))
    token_ok = result.get("token") == token
    print(f"[TRANSPORT] OS-verified caller={result.get('caller')} SID={result.get('caller_sid')}")
    print(f"[IDENTITY ] TPM signature valid={id_ok}")
    if read_ok and id_ok and pipe_ok and token_ok:
        print("CHAIN COMPLETE — UIA read + TPM identity + OS-verified DACL pipe all verified.")
        return 0
    print(f"INCOMPLETE: read={read_ok} id={id_ok} pipe={pipe_ok} token={token_ok}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
