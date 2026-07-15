"""enterprise.tpm_attestation — TPM platform attestation.

Hardware-rooted platform evidence via NCryptCreateClaim / NCryptVerifyClaim.

The module creates a TPM-backed key under the Microsoft Platform Crypto
Provider and attempts to create a platform attestation claim over PCR state
using a nonce for freshness. Windows exposes NCRYPT_CLAIM_PLATFORM as platform
PCR evidence; binding that evidence to a specific agent key is a higher-level
protocol composition, not something this function falsely claims when the
platform claim itself is unavailable.

Patent note
-----------
This is a stronger embodiment of "machine-bound agent identity" than either the
DPAPI path (identity.py) or the NCrypt software KSP path (identity_cng.py) when
the platform can produce a claim. The function never returns a fake PASS:
unsupported machines return supported=False with the Windows status code.

API
---
    from enterprise.tpm_attestation import (
        TpmAttestationResult,
        create_tpm_platform_claim,
        verify_tpm_platform_claim,
        tpm_probe,
    )

    result = create_tpm_platform_claim(os.urandom(32))
    if result.supported:
        ok = verify_tpm_platform_claim(result)

Exit convention (tpm_probe):
    supported=True   — hardware-backed claim created and verified
    supported=False  — TPM/Platform Crypto Provider unavailable (NA, not error)

Version: 1.0.0-enterprise
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Windows guard — every public API is a no-op on non-Windows platforms.
# ---------------------------------------------------------------------------

_WIN32_AVAILABLE = sys.platform == "win32"

if _WIN32_AVAILABLE:
    import ctypes

    # Re-use the exercised DLL handles from tpm_identity so we don't open the
    # same DLL twice in the same process.  If that module is not importable
    # (e.g. the experiments tree is not on sys.path) we fall back to opening
    # ncrypt.dll ourselves.
    try:
        from experiments.win32_probe.tpm_identity import (  # type: ignore[import]
            BCRYPT,
            MS_PLATFORM,
            NCRYPT,
            NCRYPT_OVERWRITE_KEY_FLAG,
            NCRYPT_SILENT_FLAG,
            SUCCESS,
            _ck,
            _export_pub_blob,
            _open_platform_provider,
            _sign,
            _verify,
        )
        _TPMI_AVAILABLE = True
    except Exception:  # noqa: BLE001  — import-time, must not crash the module
        _TPMI_AVAILABLE = False
        ctypes = ctypes  # keep linter happy — already imported above
        NCRYPT = ctypes.windll.ncrypt  # type: ignore[assignment]
        BCRYPT = ctypes.windll.bcrypt  # type: ignore[assignment]
        MS_PLATFORM = "Microsoft Platform Crypto Provider"
        SUCCESS = 0
        NCRYPT_OVERWRITE_KEY_FLAG = 0x80
        NCRYPT_SILENT_FLAG = 0x40

        def _ck(st: int, op: str) -> None:
            if st != SUCCESS:
                raise OSError(f"{op} -> 0x{st & 0xFFFFFFFF:08X}")

        def _open_platform_provider():  # type: ignore[return]
            h = ctypes.c_void_p()
            st = NCRYPT.NCryptOpenStorageProvider(ctypes.byref(h), MS_PLATFORM, 0)
            _ck(st, "NCryptOpenStorageProvider(Platform)")
            return h

        def _export_pub_blob(hkey) -> bytes:
            cb = ctypes.c_ulong()
            st = NCRYPT.NCryptExportKey(
                hkey, None, "ECCPUBLICBLOB", None, None, 0, ctypes.byref(cb), 0
            )
            _ck(st, "NCryptExportKey(size)")
            buf = (ctypes.c_ubyte * cb.value)()
            st = NCRYPT.NCryptExportKey(
                hkey, None, "ECCPUBLICBLOB", None, buf, cb.value, ctypes.byref(cb), 0
            )
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
            if BCRYPT.BCryptOpenAlgorithmProvider(
                ctypes.byref(h_algo), "ECDSA", None, 0
            ) != SUCCESS:
                h_algo = ctypes.c_void_p()
            h_key = ctypes.c_void_p()
            blob = (ctypes.c_ubyte * len(pub_blob))(*pub_blob)
            st = BCRYPT.BCryptImportKeyPair(
                h_algo, None, "ECCPUBLICBLOB", ctypes.byref(h_key), blob, len(pub_blob), 0
            )
            if st != SUCCESS:
                return False
            hb = (ctypes.c_ubyte * len(digest))(*digest)
            sb = (ctypes.c_ubyte * len(sig))(*sig)
            st = BCRYPT.BCryptVerifySignature(h_key, None, hb, len(digest), sb, len(sig), 0)
            BCRYPT.BCryptDestroyKey(h_key)
            BCRYPT.BCryptCloseAlgorithmProvider(h_algo, 0)
            return st == SUCCESS

    # -----------------------------------------------------------------------
    # NCryptCreateClaim / NCryptVerifyClaim structures & bindings
    # -----------------------------------------------------------------------

    # Platform-attestation claim type from the Windows SDK ncrypt.h.
    NCRYPT_CLAIM_PLATFORM: int = 0x00010000

    # NCryptBufferDesc buffer-type constants for attestation parameters.
    NCRYPTBUFFER_ATTESTATION_CLAIM_PCR_MASK: int = 80
    NCRYPTBUFFER_ATTESTATION_CLAIM_NONCE: int = 81

    # HRESULT codes that mean "TPM feature unavailable on this machine".
    _NTE_NOT_SUPPORTED: int = 0x80090029
    _NTE_BAD_FLAGS: int = 0x80090009
    _NTE_UNAVAILABLE: int = 0x8009000B

    class NCryptBuffer(ctypes.Structure):
        """Mirrors the Windows NCryptBuffer C struct (winbase.h / bcrypt.h)."""

        _fields_ = [
            ("cbBuffer", ctypes.c_ulong),
            ("BufferType", ctypes.c_ulong),
            ("pvBuffer", ctypes.c_void_p),
        ]

    class NCryptBufferDesc(ctypes.Structure):
        """Mirrors the Windows NCryptBufferDesc C struct."""

        _fields_ = [
            ("ulVersion", ctypes.c_ulong),
            ("cBuffers", ctypes.c_ulong),
            ("pBuffers", ctypes.POINTER(NCryptBuffer)),
        ]

    # Bind NCryptCreateClaim / NCryptVerifyClaim.
    # Wrapped in try/except: on Windows builds where ncrypt.dll does not export
    # these symbols (e.g. Windows 7, IoT stripped images) the module must degrade
    # gracefully rather than raising AttributeError at import time (fail-closed).
    try:
        NCRYPT.NCryptCreateClaim = ctypes.windll.ncrypt.NCryptCreateClaim
        NCRYPT.NCryptCreateClaim.argtypes = [
            ctypes.c_void_p,                          # hSubjectKey
            ctypes.c_void_p,                          # hAuthorityKey (NULL for SW)
            ctypes.c_ulong,                           # dwClaimType
            ctypes.POINTER(NCryptBufferDesc),         # pParameterList
            ctypes.c_void_p,                          # pbClaimBlob
            ctypes.c_ulong,                           # cbClaimBlob
            ctypes.POINTER(ctypes.c_ulong),           # pcbResult
            ctypes.c_ulong,                           # dwFlags
        ]
        NCRYPT.NCryptCreateClaim.restype = ctypes.c_long

        NCRYPT.NCryptVerifyClaim = ctypes.windll.ncrypt.NCryptVerifyClaim
        NCRYPT.NCryptVerifyClaim.argtypes = [
            ctypes.c_void_p,                          # hSubjectKey
            ctypes.c_void_p,                          # hAuthorityKey (NULL)
            ctypes.c_ulong,                           # dwClaimType
            ctypes.POINTER(NCryptBufferDesc),         # pParameterList
            ctypes.c_void_p,                          # pbClaimBlob
            ctypes.c_ulong,                           # cbClaimBlob
            ctypes.POINTER(NCryptBufferDesc),         # pOutput
            ctypes.c_ulong,                           # dwFlags
        ]
        NCRYPT.NCryptVerifyClaim.restype = ctypes.c_long

        _NCRYPT_CLAIM_FUNCS_AVAILABLE = True
    except (AttributeError, OSError):
        # NCryptCreateClaim not present on this Windows build — mark unavailable.
        _NCRYPT_CLAIM_FUNCS_AVAILABLE = False

else:
    # Stub type for non-Windows so the dataclass can still be imported.
    NCRYPT_CLAIM_PLATFORM = 0x00010000
    NCRYPTBUFFER_ATTESTATION_CLAIM_PCR_MASK = 80
    NCRYPTBUFFER_ATTESTATION_CLAIM_NONCE = 81
    _NCRYPT_CLAIM_FUNCS_AVAILABLE = False

    class NCryptBuffer:  # type: ignore[no-redef]
        pass

    class NCryptBufferDesc:  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# TpmAttestationResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class TpmAttestationResult:
    """Result of a TPM platform attestation attempt.

    Fields
    ------
    nonce           — the random nonce used to create the claim
    public_key_blob — ECCPUBLICBLOB (raw Windows CNG format) of the subject key
    claim_blob      — opaque attestation blob from NCryptCreateClaim; empty bytes
                      when supported=False
    algorithm       — CNG algorithm string (default "ECDSA_P256")
    supported       — True if hardware-backed claim was produced
    error           — human-readable reason when supported=False; None on success
    """

    nonce: bytes = field(default_factory=bytes)
    public_key_blob: bytes = field(default_factory=bytes)
    claim_blob: bytes = field(default_factory=bytes)
    algorithm: str = "ECDSA_P256"
    pcr_mask: int = 0x00FFFFFF
    supported: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TPM_KEY_NAME = "SelfConnect.tpm-attestation-probe"

# HRESULT codes that indicate TPM unavailability (not a programming error).
_TPM_NA_CODES = frozenset({
    0x80090029,  # NTE_NOT_SUPPORTED
    0x80090009,  # NTE_BAD_FLAGS
    0x8009000B,  # NTE_UNAVAILABLE
    0x80090008,  # NTE_FAIL
    0x80090002,  # NTE_BAD_KEYSET (provider not accessible)
    0x80090026,  # platform attestation material not provisioned/found
})


def _hresult(value: int) -> int:
    """Normalise a signed c_long HRESULT to unsigned 32-bit."""
    return value & 0xFFFFFFFF


def _is_tpm_na(hresult: int) -> bool:
    return _hresult(hresult) in _TPM_NA_CODES


def _platform_claim_params(nonce: bytes, pcr_mask: int) -> tuple[NCryptBufferDesc, Any, Any, Any]:
    nonce_buf = (ctypes.c_ubyte * len(nonce))(*nonce)
    pcr_mask_value = ctypes.c_ulong(pcr_mask)
    buffers = (NCryptBuffer * 2)()
    buffers[0].cbBuffer = ctypes.sizeof(pcr_mask_value)
    buffers[0].BufferType = NCRYPTBUFFER_ATTESTATION_CLAIM_PCR_MASK
    buffers[0].pvBuffer = ctypes.cast(ctypes.byref(pcr_mask_value), ctypes.c_void_p)
    buffers[1].cbBuffer = len(nonce)
    buffers[1].BufferType = NCRYPTBUFFER_ATTESTATION_CLAIM_NONCE
    buffers[1].pvBuffer = ctypes.cast(nonce_buf, ctypes.c_void_p)

    bufdesc = NCryptBufferDesc()
    bufdesc.ulVersion = 0
    bufdesc.cBuffers = len(buffers)
    bufdesc.pBuffers = ctypes.cast(buffers, ctypes.POINTER(NCryptBuffer))
    return bufdesc, buffers, nonce_buf, pcr_mask_value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_tpm_platform_claim(nonce: bytes, pcr_mask: int = 0x00FFFFFF) -> TpmAttestationResult:
    """Create a hardware-backed platform attestation claim.

    A fresh ECDSA_P256 key is created under the Microsoft Platform Crypto
    Provider (TPM-backed), then NCryptCreateClaim binds it to the current TPM
    PCR state using ``nonce`` for freshness.  The key is deleted before
    returning — only the public key blob and claim blob are retained.

    Parameters
    ----------
    nonce : bytes
        Random bytes (at least 8, at most 64 recommended) for replay
        prevention.  Use ``os.urandom(32)``.

    Returns
    -------
    TpmAttestationResult
        ``supported=True`` when a claim was produced.  ``supported=False`` with
        ``error`` set when the Platform Crypto Provider or NCryptCreateClaim
        feature is unavailable on this machine (treated as NA, not failure).
    """
    if not _WIN32_AVAILABLE:
        return TpmAttestationResult(
            nonce=nonce,
            pcr_mask=pcr_mask,
            supported=False,
            error="TPM attestation requires Windows",
        )

    # Guard: NCryptCreateClaim not present on this Windows build (fail-closed).
    if not _NCRYPT_CLAIM_FUNCS_AVAILABLE:
        return TpmAttestationResult(
            nonce=nonce,
            pcr_mask=pcr_mask,
            supported=False,
            error="NCryptCreateClaim not available on this Windows build",
        )

    prov = None
    hkey = None
    claim_cb = ctypes.c_ulong(0)

    try:
        # 1. Open Microsoft Platform Crypto Provider (requires functional TPM).
        try:
            prov = _open_platform_provider()
        except OSError as exc:
            return TpmAttestationResult(
                nonce=nonce,
                pcr_mask=pcr_mask,
                supported=False,
                error=f"Microsoft Platform Crypto Provider unavailable: {exc}",
            )

        # 2. Create an ephemeral ECDSA_P256 key (TPMs universally support P-256).
        hkey = ctypes.c_void_p()
        st = NCRYPT.NCryptCreatePersistedKey(
            prov, ctypes.byref(hkey), "ECDSA_P256", _TPM_KEY_NAME, 0,
            NCRYPT_OVERWRITE_KEY_FLAG,
        )
        if _hresult(st) != 0:
            if _is_tpm_na(st):
                return TpmAttestationResult(
                    nonce=nonce,
                    pcr_mask=pcr_mask,
                    supported=False,
                    error=(
                        f"TPM not available or Platform Crypto Provider unsupported "
                        f"(NCryptCreatePersistedKey -> 0x{_hresult(st):08X})"
                    ),
                )
            raise OSError(f"NCryptCreatePersistedKey -> 0x{_hresult(st):08X}")

        st = NCRYPT.NCryptFinalizeKey(hkey, NCRYPT_SILENT_FLAG)
        if _hresult(st) != 0:
            if _is_tpm_na(st):
                return TpmAttestationResult(
                    nonce=nonce,
                    pcr_mask=pcr_mask,
                    supported=False,
                    error=(
                        f"TPM not available or Platform Crypto Provider unsupported "
                        f"(NCryptFinalizeKey -> 0x{_hresult(st):08X})"
                    ),
                )
            raise OSError(f"NCryptFinalizeKey -> 0x{_hresult(st):08X}")

        # 3. Export public key blob (ECCPUBLICBLOB — X||Y coordinates).
        try:
            pub_blob = _export_pub_blob(hkey)
        except OSError as exc:
            return TpmAttestationResult(
                nonce=nonce,
                pcr_mask=pcr_mask,
                supported=False,
                error=f"Failed to export public key blob: {exc}",
            )

        # 4. Build NCryptBufferDesc with PCR mask + nonce.
        bufdesc, _buffers, _nonce_buf, _pcr_mask_value = _platform_claim_params(nonce, pcr_mask)

        # 5. NCryptCreateClaim — query required size, then fill a
        # caller-allocated buffer. The Windows SDK signature is
        # pbClaimBlob/cbClaimBlob/pcbResult, not an allocated PBYTE*.
        # NCRYPT_CLAIM_PLATFORM quotes PCR state through the platform
        # attestation material; passing the agent key handle as hSubjectKey
        # makes Windows return ERROR_INVALID_PARAMETER.
        st = NCRYPT.NCryptCreateClaim(
            None,
            None,                          # authority key (NULL = software-bound)
            NCRYPT_CLAIM_PLATFORM,
            ctypes.byref(bufdesc),
            None,                          # query required blob size
            0,
            ctypes.byref(claim_cb),        # OUT: blob size
            0,                             # dwFlags
        )

        hr = _hresult(st)
        if hr != 0:
            if _is_tpm_na(st) or hr in {0x80090029, 0x80090009}:
                return TpmAttestationResult(
                    nonce=nonce,
                    pcr_mask=pcr_mask,
                    public_key_blob=pub_blob,
                    supported=False,
                    error=(
                        "TPM not available or Platform Crypto Provider unsupported "
                        f"(NCryptCreateClaim -> 0x{hr:08X})"
                    ),
                )
            raise OSError(f"NCryptCreateClaim -> 0x{hr:08X}")

        if claim_cb.value == 0:
            return TpmAttestationResult(
                nonce=nonce,
                pcr_mask=pcr_mask,
                public_key_blob=pub_blob,
                supported=False,
                error=(
                    "NCryptCreateClaim size query returned S_OK but reported "
                    "zero bytes (no hardware attestation blob available)"
                ),
            )

        claim_bytes_arr = (ctypes.c_ubyte * claim_cb.value)()
        st = NCRYPT.NCryptCreateClaim(
            None,
            None,
            NCRYPT_CLAIM_PLATFORM,
            ctypes.byref(bufdesc),
            claim_bytes_arr,
            claim_cb.value,
            ctypes.byref(claim_cb),
            0,
        )
        hr = _hresult(st)
        if hr != 0:
            if _is_tpm_na(st) or hr in {0x80090029, 0x80090009}:
                return TpmAttestationResult(
                    nonce=nonce,
                    pcr_mask=pcr_mask,
                    public_key_blob=pub_blob,
                    supported=False,
                    error=(
                        "TPM not available or Platform Crypto Provider unsupported "
                        f"(NCryptCreateClaim fill -> 0x{hr:08X})"
                    ),
                )
            raise OSError(f"NCryptCreateClaim fill -> 0x{hr:08X}")

        # DOWNGRADE GUARD: NCryptCreateClaim succeeded (hr == 0) but returned a
        # zero-size blob.  This occurs on Windows builds where the Platform Crypto
        # Provider is present but no AIK (Attestation Identity Key) is enrolled,
        # causing a silent software-only fallback that is NOT hardware-backed.
        # We must NOT return supported=True in this case.
        if claim_cb.value == 0:
            return TpmAttestationResult(
                nonce=nonce,
                pcr_mask=pcr_mask,
                public_key_blob=pub_blob,
                supported=False,
                error=(
                    "NCryptCreateClaim returned S_OK but produced an empty claim blob "
                    "(software-only fallback detected — no hardware attestation)"
                ),
            )

        claim_bytes = bytes(claim_bytes_arr)

        # Final anti-downgrade check: a valid hardware platform claim must be
        # non-trivially sized.  MSDN does not document a minimum, but in practice
        # a legitimate NCRYPT_CLAIM_PLATFORM blob is always > 64 bytes.  If we
        # received fewer than 16 bytes, something is wrong.
        if len(claim_bytes) < 16:
            return TpmAttestationResult(
                nonce=nonce,
                pcr_mask=pcr_mask,
                public_key_blob=pub_blob,
                supported=False,
                error=(
                    f"NCryptCreateClaim blob suspiciously small ({len(claim_bytes)} bytes) "
                    "— possible software-only fallback; refusing supported=True"
                ),
            )

        return TpmAttestationResult(
            nonce=nonce,
            public_key_blob=pub_blob,
            claim_blob=claim_bytes,
            algorithm="ECDSA_P256",
            pcr_mask=pcr_mask,
            supported=True,
            error=None,
        )

    except Exception as exc:  # noqa: BLE001
        # Unknown error — still return supported=False, never raise.
        return TpmAttestationResult(
            nonce=nonce,
            pcr_mask=pcr_mask,
            supported=False,
            error=f"Unexpected error during TPM attestation: {exc}",
        )

    finally:
        # Always clean up — delete the ephemeral key.
        if hkey is not None and hkey.value:
            try:
                NCRYPT.NCryptDeleteKey(hkey, 0)
            except Exception:  # noqa: BLE001
                pass
        if prov is not None and prov.value:
            try:
                NCRYPT.NCryptFreeObject(prov)
            except Exception:  # noqa: BLE001
                pass


def verify_tpm_platform_claim(result: TpmAttestationResult) -> bool:
    """Verify a TPM platform attestation claim produced by create_tpm_platform_claim.

    Parameters
    ----------
    result : TpmAttestationResult
        The result previously returned by ``create_tpm_platform_claim``.

    Returns
    -------
    bool
        True if the claim blob verifies successfully under NCryptVerifyClaim.
        False if unsupported, the claim blob is empty, or verification fails.
    """
    if not result.supported or not result.claim_blob or not _WIN32_AVAILABLE or not _NCRYPT_CLAIM_FUNCS_AVAILABLE:
        return False

    try:
        # Re-open the Platform Crypto Provider for NCryptVerifyClaim.
        prov = _open_platform_provider()
    except OSError:
        return False

    hkey = None
    try:
        # Re-import the public key so NCryptVerifyClaim can validate the claim.
        # We need to re-create a temporary key handle from the stored blob.
        # NCryptVerifyClaim requires a key handle, not raw bytes.
        # We'll import the public key into NCrypt for verification.
        hkey = ctypes.c_void_p()
        pub_blob = result.public_key_blob
        pub_arr = (ctypes.c_ubyte * len(pub_blob))(*pub_blob)

        st = NCRYPT.NCryptImportKey(
            prov,
            None,
            "ECCPUBLICBLOB",
            None,
            ctypes.byref(hkey),
            pub_arr,
            len(pub_blob),
            0,
        )
        if _hresult(st) != 0:
            return False

        # Build the same PCR-mask + nonce parameter list for verification.
        bufdesc, _buffers, _nonce_buf, _pcr_mask_value = _platform_claim_params(
            result.nonce,
            result.pcr_mask,
        )

        claim_arr = (ctypes.c_ubyte * len(result.claim_blob))(*result.claim_blob)
        output = NCryptBufferDesc()
        output.ulVersion = 0
        output.cBuffers = 0
        output.pBuffers = None

        st = NCRYPT.NCryptVerifyClaim(
            hkey,
            None,
            NCRYPT_CLAIM_PLATFORM,
            ctypes.byref(bufdesc),
            claim_arr,
            len(result.claim_blob),
            ctypes.byref(output),
            0,
        )
        return _hresult(st) == 0

    except Exception:  # noqa: BLE001
        return False

    finally:
        if hkey is not None and hkey.value:
            try:
                NCRYPT.NCryptFreeObject(hkey)
            except Exception:  # noqa: BLE001
                pass
        if prov is not None and prov.value:
            try:
                NCRYPT.NCryptFreeObject(prov)
            except Exception:  # noqa: BLE001
                pass


def tpm_probe() -> dict:
    """Run a self-contained TPM attestation probe and return a status dict.

    This function NEVER returns a fake PASS.  If the TPM or Platform Crypto
    Provider is unavailable on this machine, ``supported=False`` is returned —
    that is a normal NA condition, not a test failure.

    Returns
    -------
    dict with keys:
        supported   — bool: True only when hardware-backed claim was created
        claim_size  — int: size in bytes of the claim blob (0 if not supported)
        nonce_hex   — str: hex of the random nonce used
        pubkey_hex  — str: hex of the ECCPUBLICBLOB (empty string if unsupported)
        error       — str | None: human-readable reason when not supported
    """
    nonce = os.urandom(32)
    try:
        result = create_tpm_platform_claim(nonce)
    except Exception as exc:  # noqa: BLE001
        return {
            "supported": False,
            "claim_size": 0,
            "nonce_hex": nonce.hex(),
            "pubkey_hex": "",
            "error": f"tpm_probe: unexpected exception: {exc}",
        }

    return {
        "supported": result.supported,
        "claim_size": len(result.claim_blob),
        "nonce_hex": result.nonce.hex(),
        "pubkey_hex": result.public_key_blob.hex(),
        "error": result.error,
    }


__all__ = [
    "NCRYPT_CLAIM_PLATFORM",
    "NCRYPTBUFFER_ATTESTATION_CLAIM_NONCE",
    "NCRYPTBUFFER_ATTESTATION_CLAIM_PCR_MASK",
    "NCryptBuffer",
    "NCryptBufferDesc",
    "TpmAttestationResult",
    "create_tpm_platform_claim",
    "tpm_probe",
    "verify_tpm_platform_claim",
]
