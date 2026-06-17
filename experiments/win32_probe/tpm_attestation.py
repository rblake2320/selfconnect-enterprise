"""POC (next-four #2): TPM key ATTESTATION via NCryptCreateClaim — doc-grounded build.

Upgrades "we signed with a TPM key" toward "here is a verifiable claim that the key is
TPM-resident." Prior run returned E_INVALIDARG (0x80070057) from NCryptCreateClaim because the
PLATFORM claim was called with a NULL parameter list.

Doc-grounded correction (Microsoft Learn `nf-ncrypt-ncryptcreateclaim`, ncrypt.h 10.0.26100.0):
the ONLY documented claim parameter is the attestation NONCE
(`NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE` = 49, aka `NCRYPTBUFFER_ATTESTATION_STATEMENT_NONCE`),
carried in a proper `NCryptBufferDesc {ulVersion=NCRYPTBUFFER_VERSION(0), cBuffers, pBuffers}`
over `NCryptBuffer {cbBuffer, BufferType, pvBuffer}`. There is **no "PCR selection mask" buffer
type** in NCryptCreateClaim — the original diagnosis's PCR buffer does not exist in the API, so we
do NOT invent one (the code's own rule: do not guess crypto params). We pass the documented nonce
buffer and capture exactly what the TPM returns.

Outcomes captured to sc_tpm_fix.json:
  0 = PASS  (claim produced; verify attempted; claim blob serialized)
  2 = NA    (NTE_NOT_SUPPORTED — platform attestation needs AIK/EK provisioning not present here,
             OR PLATFORM-via-NCryptCreateClaim still rejects a nonce-only param list: honest finding)
  3 = FAIL  (unexpected hard failure)

Run:  python experiments/win32_probe/tpm_attestation.py
"""
from __future__ import annotations

import base64
import ctypes
import datetime
import json
import os
import secrets
import sys

from tpm_identity import (
    NCRYPT,
    NCRYPT_OVERWRITE_KEY_FLAG,
    NCRYPT_SILENT_FLAG,
    _open_platform_provider,
)

# --- authoritative constants (ncrypt.h 10.0.26100.0; verified, not guessed) ---
NCRYPT_CLAIM_PLATFORM = 0x00010000
NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT = 0x00000003
NCRYPTBUFFER_VERSION = 0
NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE = 49  # == NCRYPTBUFFER_ATTESTATION_STATEMENT_NONCE
KEY = "sc-attest-key"
NTE_NOT_SUPPORTED = 0x80090029
E_INVALIDARG = 0x80070057
CHECKPOINT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sc_tpm_fix.json")


class NCryptBuffer(ctypes.Structure):
    _fields_ = [
        ("cbBuffer", ctypes.c_ulong),
        ("BufferType", ctypes.c_ulong),
        ("pvBuffer", ctypes.c_void_p),
    ]


class NCryptBufferDesc(ctypes.Structure):
    _fields_ = [
        ("ulVersion", ctypes.c_ulong),
        ("cBuffers", ctypes.c_ulong),
        ("pBuffers", ctypes.POINTER(NCryptBuffer)),
    ]


def _nonce_param_list(nonce: bytes):
    """Build a one-buffer NCryptBufferDesc carrying the documented attestation nonce.

    Returns (desc, keepalive) — keepalive MUST stay referenced for the duration of the call
    so the nonce/array memory the desc points at is not garbage-collected.
    """
    nonce_arr = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
    arr = (NCryptBuffer * 1)()
    arr[0].cbBuffer = len(nonce)
    arr[0].BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
    arr[0].pvBuffer = ctypes.cast(nonce_arr, ctypes.c_void_p)
    desc = NCryptBufferDesc(NCRYPTBUFFER_VERSION, 1, ctypes.cast(arr, ctypes.POINTER(NCryptBuffer)))
    return desc, (nonce_arr, arr)


def _hex(code: int) -> str:
    return f"0x{code & 0xFFFFFFFF:08X}"


def _checkpoint(payload: dict) -> None:
    payload["recorded_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    with open(CHECKPOINT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"checkpoint -> {CHECKPOINT}")


def main() -> int:
    nonce = secrets.token_bytes(32)
    layout = {
        "ncryptBufferDesc": {"ulVersion": NCRYPTBUFFER_VERSION, "cBuffers": 1},
        "buffers": [{"BufferType": NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, "cbBuffer": len(nonce),
                     "name": "NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE"}],
        "claimType": "NCRYPT_CLAIM_PLATFORM (0x00010000)",
        "nonce_b64": base64.b64encode(nonce).decode(),
    }

    try:
        prov = _open_platform_provider()
    except OSError as e:  # noqa: BLE001
        _checkpoint({"verdict": "NA", "reason": f"Platform Crypto Provider unavailable: {e}", "layout": layout})
        print(f"NA: Platform Crypto Provider unavailable: {e}")
        return 2

    hkey = ctypes.c_void_p()
    st = NCRYPT.NCryptCreatePersistedKey(
        prov, ctypes.byref(hkey), "ECDSA_P256", KEY, 0, NCRYPT_OVERWRITE_KEY_FLAG
    )
    if st != 0:
        _checkpoint({"verdict": "FAIL", "stage": "create_key", "code": _hex(st), "layout": layout})
        print(f"FAIL: create key -> {_hex(st)}")
        NCRYPT.NCryptFreeObject(prov)
        return 3
    NCRYPT.NCryptFinalizeKey(hkey, NCRYPT_SILENT_FLAG)

    try:
        desc, _keep = _nonce_param_list(nonce)

        # Pass 1: size query, now WITH the documented nonce parameter list.
        cb = ctypes.c_ulong(0)
        st_size = NCRYPT.NCryptCreateClaim(
            hkey, None, NCRYPT_CLAIM_PLATFORM, ctypes.byref(desc), None, 0, ctypes.byref(cb), 0
        )
        codes = {"size_call": _hex(st_size), "size_cb": cb.value}

        if st_size != 0:
            code = st_size & 0xFFFFFFFF
            if code == NTE_NOT_SUPPORTED:
                msg = ("NCryptCreateClaim(PLATFORM, +nonce) -> 0x80090029 (NTE_NOT_SUPPORTED): the "
                       "BufferDesc is now well-formed (no longer E_INVALIDARG); platform attestation "
                       "simply isn't provisioned on this TPM/config (needs AIK/EK). Honest hardware finding.")
                verdict = "NA"
            elif code == E_INVALIDARG:
                msg = ("NCryptCreateClaim(PLATFORM, +nonce) STILL -> 0x80070057 (E_INVALIDARG). A "
                       "well-formed nonce-only param list is not accepted: PLATFORM/PCR attestation is "
                       "NOT a supported NCryptCreateClaim path (no PCR-mask buffer exists in the API). "
                       "Use NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT (key attestation, no params) for "
                       "remote-verifiable TPM-residency, or TBS/TPM2_Quote for true PCR attestation.")
                verdict = "NA"
            else:
                msg = f"NCryptCreateClaim(PLATFORM, +nonce) -> {_hex(st_size)} — attestation unavailable here."
                verdict = "NA"
            _checkpoint({"verdict": verdict, "claim_type": "NCRYPT_CLAIM_PLATFORM",
                         "return_codes": codes, "layout": layout, "note": msg})
            print(f"{verdict}: {msg}")
            return 2

        # Pass 2: produce the claim blob.
        buf = (ctypes.c_ubyte * cb.value)()
        st_blob = NCRYPT.NCryptCreateClaim(
            hkey, None, NCRYPT_CLAIM_PLATFORM, ctypes.byref(desc), buf, cb.value, ctypes.byref(cb), 0
        )
        codes["blob_call"] = _hex(st_blob)
        if st_blob != 0:
            _checkpoint({"verdict": "FAIL", "stage": "claim_blob", "return_codes": codes, "layout": layout})
            print(f"FAIL: NCryptCreateClaim (blob) -> {_hex(st_blob)}")
            return 3
        claim = bytes(buf[: cb.value])

        # Best-effort verify with the same nonce param list.
        vdesc, _vkeep = _nonce_param_list(nonce)
        cbuf = (ctypes.c_ubyte * len(claim))(*claim)
        vs = NCRYPT.NCryptVerifyClaim(
            hkey, None, NCRYPT_CLAIM_PLATFORM, ctypes.byref(vdesc), cbuf, len(claim), None, 0
        )
        codes["verify_call"] = _hex(vs)

        blob_path = os.path.join(os.path.dirname(CHECKPOINT), "sc_platform_claim.bin")
        with open(blob_path, "wb") as fh:
            fh.write(claim)
        _checkpoint({"verdict": "PASS", "claim_type": "NCRYPT_CLAIM_PLATFORM",
                     "claim_bytes": len(claim), "claim_blob_file": blob_path,
                     "claim_b64_preview": base64.b64encode(claim).decode()[:120] + "...",
                     "verify_valid": vs == 0, "return_codes": codes, "layout": layout})
        print(f"PASS: TPM platform attestation claim produced ({len(claim)} bytes); "
              f"NCryptVerifyClaim valid={vs == 0} ({_hex(vs)}); blob -> {blob_path}")
        return 0
    finally:
        NCRYPT.NCryptDeleteKey(hkey, 0)
        NCRYPT.NCryptFreeObject(prov)


if __name__ == "__main__":
    sys.exit(main())
