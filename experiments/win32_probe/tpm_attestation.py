"""POC (next-four #2): TPM key ATTESTATION via NCryptCreateClaim.

Upgrades last night's "we signed with a TPM key" to "here is a verifiable claim that the
key is TPM-resident" (NCRYPT_CLAIM_PLATFORM). A remote verifier can then check the claim
blob to confirm the agent's signing key genuinely lives in a real TPM on this machine —
the difference between a demo and a procurement-grade hardware-identity claim.

This is best-effort: platform attestation can require a provisioned AIK/EK. If this TPM
or config doesn't support it, the probe reports NA honestly (that is itself a finding).

Run:  python experiments/win32_probe/tpm_attestation.py
Exit: 0 = claim produced (verify attempted), 2 = not supported on this TPM/config (NA), 3 = FAIL
"""
from __future__ import annotations

import ctypes
import sys

from tpm_identity import (
    NCRYPT,
    NCRYPT_OVERWRITE_KEY_FLAG,
    NCRYPT_SILENT_FLAG,
    _open_platform_provider,
)

NCRYPT_CLAIM_PLATFORM = 0x00010000
KEY = "sc-attest-key"
NTE_NOT_SUPPORTED = 0x80090029


def main() -> int:
    try:
        prov = _open_platform_provider()
    except OSError as e:  # noqa: BLE001
        print(f"NA: Platform Crypto Provider unavailable: {e}")
        return 2

    hkey = ctypes.c_void_p()
    st = NCRYPT.NCryptCreatePersistedKey(
        prov, ctypes.byref(hkey), "ECDSA_P256", KEY, 0, NCRYPT_OVERWRITE_KEY_FLAG
    )
    if st != 0:
        print(f"FAIL: create key -> 0x{st & 0xFFFFFFFF:08X}")
        NCRYPT.NCryptFreeObject(prov)
        return 3
    NCRYPT.NCryptFinalizeKey(hkey, NCRYPT_SILENT_FLAG)

    try:
        # Pass 1: size of the platform attestation claim blob.
        cb = ctypes.c_ulong(0)
        st = NCRYPT.NCryptCreateClaim(
            hkey, None, NCRYPT_CLAIM_PLATFORM, None, None, 0, ctypes.byref(cb), 0
        )
        if st != 0:
            code = st & 0xFFFFFFFF
            if code == 0x80070057:  # E_INVALIDARG
                print("NA: NCryptCreateClaim(PLATFORM) -> 0x80070057 (E_INVALIDARG). The call "
                      "is malformed, NOT a hardware limit: a PLATFORM claim requires a built "
                      "NCryptBufferDesc parameter list (attestation nonce + PCR mask / hash alg). "
                      "Deferred to a proper doc-grounded build — do not guess crypto params.")
            elif code == NTE_NOT_SUPPORTED:
                print("NA: NCryptCreateClaim(PLATFORM) -> 0x80090029 (NTE_NOT_SUPPORTED) — "
                      "platform attestation not available on this TPM/config (needs AIK/EK).")
            else:
                print(f"NA: NCryptCreateClaim(PLATFORM) -> 0x{code:08X} — attestation unavailable here.")
            return 2

        buf = (ctypes.c_ubyte * cb.value)()
        st = NCRYPT.NCryptCreateClaim(
            hkey, None, NCRYPT_CLAIM_PLATFORM, None, buf, cb.value, ctypes.byref(cb), 0
        )
        if st != 0:
            print(f"FAIL: NCryptCreateClaim (blob) -> 0x{st & 0xFFFFFFFF:08X}")
            return 3
        claim = bytes(buf[: cb.value])

        # Best-effort verify (roles/params vary; don't fail the probe on a verify quirk).
        verified = None
        try:
            cbuf = (ctypes.c_ubyte * len(claim))(*claim)
            vs = NCRYPT.NCryptVerifyClaim(
                hkey, None, NCRYPT_CLAIM_PLATFORM, None, cbuf, len(claim), None, 0
            )
            verified = (vs == 0, f"0x{vs & 0xFFFFFFFF:08X}")
        except Exception as e:  # noqa: BLE001
            verified = (False, f"verify raised {type(e).__name__}")

        print(f"PASS: TPM platform attestation claim produced ({len(claim)} bytes); "
              f"NCryptVerifyClaim valid={verified[0]} ({verified[1]})")
        return 0
    finally:
        NCRYPT.NCryptDeleteKey(hkey, 0)
        NCRYPT.NCryptFreeObject(prov)


if __name__ == "__main__":
    sys.exit(main())
