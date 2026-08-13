"""Enterprise POC for Platform Crypto Provider identity.

enterprise/crypto.py persists ECDSA P-384 keys in the *software* KSP
("Microsoft Software Key Storage Provider"). This probe swaps the provider to the
TPM-backed "Microsoft Platform Crypto Provider" and exercises a full
create -> sign -> verify cycle. A PASS is evidence that this provider reported a
hardware implementation for the ephemeral probe key in that run; it is not remote
attestation, payload-to-PCR binding, or proof that other SelfConnect keys use it.

Patent relevance
----------------
This probe is reduction-to-practice evidence for hardware-backed local signing.
The ephemeral probe key is not the ordinary AgentIdentity/CngIdentity key and the
probe does not establish remote attestation or deployed key custody.

Run:  python enterprise_experiments/win32_probe/tpm_identity.py
Exit: 0 = PASS (hardware-backed), 1 = key worked but NOT hardware-backed,
      2 = TPM/provider unavailable (NA), 3 = FAIL
"""
from __future__ import annotations

import ctypes
import hashlib
import sys

NCRYPT = ctypes.windll.ncrypt
BCRYPT = ctypes.windll.bcrypt

MS_PLATFORM = "Microsoft Platform Crypto Provider"  # TPM-backed KSP
SUCCESS = 0
NCRYPT_OVERWRITE_KEY_FLAG = 0x80
NCRYPT_SILENT_FLAG = 0x40
NCRYPT_IMPL_HARDWARE_FLAG = 0x1  # bit in NCRYPT_IMPL_TYPE_PROPERTY
KEY_NAME = "selfconnect-tpm-probe"

# (algorithm name, coord bytes, ECCPUBLICBLOB sign-magic) — TPMs usually do P-256;
# we try it first and fall back to P-384.
CURVES = (("ECDSA_P256", 32), ("ECDSA_P384", 48))


def _ck(st: int, op: str) -> None:
    if st != SUCCESS:
        raise OSError(f"{op} -> 0x{st & 0xFFFFFFFF:08X}")


def _open_platform_provider():
    h = ctypes.c_void_p()
    st = NCRYPT.NCryptOpenStorageProvider(ctypes.byref(h), MS_PLATFORM, 0)
    _ck(st, "NCryptOpenStorageProvider(Platform)")
    return h


def _impl_type(hkey) -> int:
    out = ctypes.c_ulong(0)
    cb = ctypes.c_ulong(0)
    st = NCRYPT.NCryptGetProperty(
        hkey, "Impl Type", ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(cb), 0
    )
    _ck(st, "NCryptGetProperty(Impl Type)")
    return out.value


def _export_pub_blob(hkey) -> bytes:
    cb = ctypes.c_ulong()
    st = NCRYPT.NCryptExportKey(hkey, None, "ECCPUBLICBLOB", None, None, 0, ctypes.byref(cb), 0)
    _ck(st, "NCryptExportKey(size)")
    buf = (ctypes.c_ubyte * cb.value)()
    st = NCRYPT.NCryptExportKey(hkey, None, "ECCPUBLICBLOB", None, buf, cb.value, ctypes.byref(cb), 0)
    _ck(st, "NCryptExportKey")
    return bytes(buf[: cb.value])


def _sign(hkey, digest: bytes) -> bytes:
    sig_buf = (ctypes.c_ubyte * 256)()
    cb = ctypes.c_ulong()
    st = NCRYPT.NCryptSignHash(
        hkey, None,
        (ctypes.c_ubyte * len(digest))(*digest), len(digest),
        sig_buf, 256, ctypes.byref(cb), 0,
    )
    _ck(st, "NCryptSignHash")
    return bytes(sig_buf[: cb.value])


def _verify(pub_blob: bytes, digest: bytes, sig: bytes) -> bool:
    h_algo = ctypes.c_void_p()
    if BCRYPT.BCryptOpenAlgorithmProvider(ctypes.byref(h_algo), "ECDSA", None, 0) != SUCCESS:
        # generic ECDSA provider may not accept the blob; try curve-specific below
        h_algo = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    blob = (ctypes.c_ubyte * len(pub_blob))(*pub_blob)
    st = BCRYPT.BCryptImportKeyPair(h_algo, None, "ECCPUBLICBLOB", ctypes.byref(h_key), blob, len(pub_blob), 0)
    if st != SUCCESS:
        return False
    hb = (ctypes.c_ubyte * len(digest))(*digest)
    sb = (ctypes.c_ubyte * len(sig))(*sig)
    st = BCRYPT.BCryptVerifySignature(h_key, None, hb, len(digest), sb, len(sig), 0)
    BCRYPT.BCryptDestroyKey(h_key)
    BCRYPT.BCryptCloseAlgorithmProvider(h_algo, 0)
    return st == SUCCESS


def main() -> int:
    try:
        prov = _open_platform_provider()
    except OSError as e:
        print(f"NA: Microsoft Platform Crypto Provider unavailable ({e}). No usable TPM KSP.")
        return 2

    payload = b"AGENT=SC-AGENT1 ACTION=read_text TS=2026-06-16"
    # P-256 -> SHA-256, P-384 -> SHA-384 (match digest size to curve)
    for algo, coord in CURVES:
        hkey = ctypes.c_void_p()
        st = NCRYPT.NCryptCreatePersistedKey(prov, ctypes.byref(hkey), algo, KEY_NAME, 0, NCRYPT_OVERWRITE_KEY_FLAG)
        if st != SUCCESS:
            print(f"  {algo}: create skipped (0x{st & 0xFFFFFFFF:08X})")
            continue
        if NCRYPT.NCryptFinalizeKey(hkey, NCRYPT_SILENT_FLAG) != SUCCESS:
            NCRYPT.NCryptFreeObject(hkey)
            print(f"  {algo}: finalize failed")
            continue
        try:
            # Impl-Type query is best-effort: some TPM providers return NTE_NOT_SUPPORTED.
            # Some provider versions do not return Impl Type. Do not infer a PASS
            # from the provider name alone when hardware status is unavailable.
            try:
                impl = _impl_type(hkey)
                hw = bool(impl & NCRYPT_IMPL_HARDWARE_FLAG)
                impl_str = f"0x{impl:X}"
            except OSError:
                impl_str = "n/a (NTE_NOT_SUPPORTED)"
                hw = False
            digest = (hashlib.sha256 if coord == 32 else hashlib.sha384)(payload).digest()
            sig = _sign(hkey, digest)
            pub = _export_pub_blob(hkey)
            ok = _verify(pub, digest, sig)
        finally:
            NCRYPT.NCryptDeleteKey(hkey, 0)  # frees handle + removes sealed key
        NCRYPT.NCryptFreeObject(prov)
        verdict = "PASS" if (ok and hw) else ("WORKS-but-SOFTWARE" if ok else "FAIL")
        print(
            f"{verdict}: algo={algo} hardware_backed={hw} impl_flags={impl_str} "
            f"sign_verify={'ok' if ok else 'FAILED'} sig_len={len(sig)}"
        )
        return 0 if (ok and hw) else (1 if ok else 3)

    NCRYPT.NCryptFreeObject(prov)
    print("FAIL: TPM present but could not create a P-256 or P-384 key.")
    return 3


if __name__ == "__main__":
    sys.exit(main())
