"""chained_channel.py — a bounded local composition experiment.

One experimental loop binding three locally exercised legs:
  READ      : UIA TextChanged on a terminal text surface -> delta   (uia_textpattern)
  IDENTITY  : sign SHA-256(delta) with a Platform-KSP key when the
              hardware-property probe confirms the provider boundary
  TRANSPORT : send over a DACL-guarded named pipe; the server impersonates the client and
              records the OS-reported caller SID, THEN verifies the signature
                                                                     (named_pipe_identity)

Self-contained end-to-end self-test (Role B server thread + Role A client in one process)
against a THROWAWAY console this process spawns — never a live agent window.

Why this differs from the selfconnect-repo draft (see REVIEW_chained_channel.md):
  - real DACL pipe + ImpersonateNamedPipeClient  -> the OS-identity leg is actually exercised
  - Platform-KSP signing with a fail-closed hardware-property probe; this is
    not remote attestation or a production identity-binding protocol
  - uses the exercised GetModule / comtypes-handler / 64-bit-handle paths (no ABI truncation)

Run:  python experiments/win32_probe/chained_channel.py
Exit: 0 = CHAIN COMPLETE (all four legs), 1 = a leg failed
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
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

if __package__:
    from .named_pipe_identity import _advapi32, _build_sa_with_dacl
    from .tpm_identity import (
        NCRYPT,
        NCRYPT_OVERWRITE_KEY_FLAG,
        NCRYPT_SILENT_FLAG,
        _ck,
        _export_pub_blob,
        _open_platform_provider,
        _sign,
        _verify,
    )
    from .uia_textpattern import (
        UIA_Text_TextChangedEventId,
        compute_delta,
        get_uia,
        read_text,
        register_textchanged,
        text_element,
    )
else:  # Direct-script compatibility.
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


def _unique_pipe_name() -> str:
    """Return a session-unique pipe name with a 128-bit random suffix.

    A per-invocation random suffix prevents a same-user attacker from
    predicting the pipe name and racing to connect before the legitimate
    client (WR-003).  FILE_FLAG_FIRST_PIPE_INSTANCE in role_b adds a
    second layer: the OS rejects any second CreateNamedPipe call for the
    same name, so even a guessed name cannot be hijacked.
    """
    return r"\.\pipe\sc_chain_" + secrets.token_hex(16)

TERM_CLASSES = {"ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS"}
CREATE_NEW_CONSOLE = 0x00000010
# WR-005: avoid presenting a visible throwaway test window. SW_HIDE is not an
# access-control boundary and does not prevent same-session discovery by every
# process-inspection or accessibility path.
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0


# ── TRANSPORT leg: Role B — DACL pipe server that impersonates + verifies ──────
def role_b(result: dict, expected_pub: bytes, pipe: str) -> None:
    """WR-001: ``expected_pub`` is the TPM public key blob registered before this
    thread started.  Any payload whose ``pub`` field does not match byte-for-byte
    is rejected — this prevents self-signed substitution where an attacker supplies
    their own key blob alongside their own signature and ``_verify`` returns True.
    """
    try:
        sa = _build_sa_with_dacl()
        # WR-003: FILE_FLAG_FIRST_PIPE_INSTANCE ensures only this process can
        # create the server end -- a second caller with the same name receives
        # ERROR_ACCESS_DENIED even if it guesses the random suffix.
        h = win32pipe.CreateNamedPipe(
            pipe,
            win32pipe.PIPE_ACCESS_DUPLEX | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 0, sa,
        )
        win32pipe.ConnectNamedPipe(h, None)

        # WR-009 FIX: challenge-response — server generates a nonce and sends it to
        # the client BEFORE the client reads UIA or signs anything.  The client must
        # include this nonce in the signed material (sha256(delta + nonce)). This
        # establishes response freshness for the signed bytes, not that those bytes
        # necessarily originated from UIA; source attestation remains out of scope.
        challenge_nonce = secrets.token_bytes(32)
        win32file.WriteFile(h, challenge_nonce)              # send challenge to client

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
        # WR-009: digest is sha256(delta_bytes + challenge_nonce); we reconstruct it
        # from the server-generated nonce — the client cannot predict this value.
        delta_bytes = bytes.fromhex(payload["delta_bytes"])
        expected_digest = hashlib.sha256(delta_bytes + challenge_nonce).digest()
        client_digest = bytes.fromhex(payload["delta_hash"])
        if client_digest != expected_digest:
            raise ValueError("challenge-response digest mismatch — UIA leg not verified")
        sig = bytes.fromhex(payload["sig"])
        pub = bytes.fromhex(payload["pub"])

        # WR-001: reject any pub that does not match the pre-registered key.
        # An attacker cannot pass their own pub+sig pair and have _verify return
        # True — the server only accepts signatures made with the key it already holds.
        if pub != expected_pub:
            result["sig_valid"] = False
            result["token"] = payload.get("token")
            result["pub_mismatch"] = True
            return

        result["token"] = payload["token"]
        result["sig_valid"] = _verify(pub, expected_digest, sig)  # IDENTITY leg verified
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"


# ── helpers ────────────────────────────────────────────────────────────────────
def _new_terminal_hwnds(before: set[int]) -> set[int]:
    import win32gui

    out: set[int] = set()

    def cb(hh, _):
        try:
            # Do not filter by IsWindowVisible: this experiment itself must locate
            # the non-visible throwaway console. This also demonstrates that SW_HIDE
            # alone is not a discovery-prevention boundary.
            if win32gui.GetClassName(hh) in TERM_CLASSES:
                out.add(hh)
        except Exception:  # noqa: BLE001
            pass
        return True

    win32gui.EnumWindows(cb, None)
    return out - before


def main() -> int:
    import win32gui

    token = f"SC_CHAIN_{secrets.token_hex(16)}"

    # READ leg: spawn a throwaway console that prints the token after a short delay
    # (delay lets us register the TextChanged handler before the line appears).
    # Use SW_HIDE to avoid presenting a visible test console. Same-session UIA or
    # process-inspection confidentiality is not established by this setting.
    before = _new_terminal_hwnds(set())
    cmd = f"ping -n 3 127.0.0.1 >nul & echo {token} & ping -n 4 127.0.0.1 >nul"
    si = subprocess.STARTUPINFO()
    si.dwFlags |= STARTF_USESHOWWINDOW
    si.wShowWindow = SW_HIDE
    child = subprocess.Popen(
        ["conhost.exe", "cmd", "/c", cmd],
        creationflags=CREATE_NEW_CONSOLE,
        startupinfo=si,
    )
    child_pid = child.pid
    mine = None
    for _ in range(20):
        time.sleep(0.3)
        new = _new_terminal_hwnds(before)
        for hwnd in new:
            try:
                _, owner_pid = win32gui.GetWindowThreadProcessId(hwnd)
            except Exception:  # noqa: BLE001
                continue
            if owner_pid == child_pid:
                mine = hwnd
                break
        if mine:
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

    # WR-001: create and export the TPM key BEFORE the server thread starts so the
    # server has a pre-registered expected_pub it can pin against.  The key is kept
    # alive (hkey / prov not freed yet) so the same handle can be used to sign once
    # the challenge nonce is known; cleanup happens in the finally block below.
    prov = _open_platform_provider()
    hkey = ctypes.c_void_p()
    _ck(NCRYPT.NCryptCreatePersistedKey(prov, ctypes.byref(hkey), "ECDSA_P256", "sc-chain-key", 0,
                                        NCRYPT_OVERWRITE_KEY_FLAG), "create")
    _ck(NCRYPT.NCryptFinalizeKey(hkey, NCRYPT_SILENT_FLAG), "finalize")
    pub = _export_pub_blob(hkey)   # pre-register; server will reject any other key

    # WR-003: generate a session-unique pipe name so a same-user attacker cannot
    # predict it.  FILE_FLAG_FIRST_PIPE_INSTANCE in role_b adds the second layer.
    pipe = _unique_pipe_name()

    # TRANSPORT leg: start the DACL pipe server before the client writes.
    # Pass expected_pub so the server can reject self-signed substitution (WR-001).
    result: dict = {}
    srv = threading.Thread(target=role_b, args=(result, pub, pipe), daemon=True)
    srv.start()
    time.sleep(0.3)

    # Pump the COM loop until the token shows up in a delta (the "new output" we read).
    deadline = time.time() + 14
    delta = None
    while time.time() < deadline:
        pythoncom.PumpWaitingMessages()
        time.sleep(0.05)
        hit = next((d for d in captured if any(line.strip() == token for line in d.splitlines())), None)
        if hit:
            delta = hit
            break
    try:
        uia.RemoveAutomationEventHandler(UIA_Text_TextChangedEventId, el, handler)
    except Exception:  # noqa: BLE001
        pass

    if not delta:
        print(f"FAIL: TextChanged never delivered a delta containing {token!r}.")
        NCRYPT.NCryptDeleteKey(hkey, 0)
        NCRYPT.NCryptFreeObject(prov)
        return 1
    print(f"[READ] TextChanged delta carried the token; delta={delta.strip()[:60]!r}")

    # TRANSPORT leg (client side, step 1): open the pipe and receive the server challenge.
    # WR-009 FIX: The server sends a 32-byte nonce before the client signs anything.
    # The client reads it here, AFTER the UIA delta is captured, and folds it into
    # the signed digest — forcing both the UIA read and the pipe handshake to happen
    # in the same interaction.
    win32pipe.WaitNamedPipe(pipe, 5000)
    ch = win32file.CreateFile(pipe, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None,
                              win32con.OPEN_EXISTING, 0, None)
    win32file.SetNamedPipeHandleState(ch, win32pipe.PIPE_READMODE_MESSAGE, None, None)
    _, challenge_nonce_raw = win32file.ReadFile(ch, 32)     # receive server challenge
    challenge_nonce = bytes(challenge_nonce_raw)
    print(f"[TRANSPORT] received server challenge nonce ({len(challenge_nonce)} bytes)")

    # IDENTITY leg: sign SHA-256(delta_bytes + challenge_nonce) with the
    # hardware-confirmed Platform-KSP key created above. This is a local
    # proof-of-possession experiment, not ordinary AgentIdentity or remote
    # attestation.
    delta_bytes = delta.encode()
    digest = hashlib.sha256(delta_bytes + challenge_nonce).digest()
    try:
        sig = _sign(hkey, digest)
    finally:
        NCRYPT.NCryptDeleteKey(hkey, 0)
        NCRYPT.NCryptFreeObject(prov)
    print(f"[IDENTITY] signed SHA-256(delta+nonce) with Platform-KSP key; sig_len={len(sig)}")

    # TRANSPORT leg (client side, step 2): send the signed payload.
    # delta_bytes is included so the server can independently reconstruct the digest
    # as sha256(delta_bytes + server_nonce) and compare against delta_hash.
    payload = {
        "token": token,
        "delta_bytes": delta_bytes.hex(),
        "delta_hash": digest.hex(),
        "sig": sig.hex(),
        "pub": pub.hex(),
    }
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
    print(f"[IDENTITY ] Platform-KSP signature valid={id_ok}")
    if read_ok and id_ok and pipe_ok and token_ok:
        print("CHAIN COMPLETE — UIA read + Platform-KSP key proof + OS-verified DACL pipe verified.")
        return 0
    print(f"INCOMPLETE: read={read_ok} id={id_ok} pipe={pipe_ok} token={token_ok}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
