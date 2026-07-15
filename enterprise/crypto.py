"""enterprise/crypto.py — ECDSA P-384/SHA-384 primitives via Windows CNG

Replaces the Python 'cryptography' library with direct Windows CNG (BCrypt/NCrypt)
can use Windows CNG cryptographic operations. Whether a deployment uses a
currently validated module depends on the exact OS build, mode, module, and
operating environment. All key material is
stored in the NCrypt Software Key Storage Provider — never in a Python object or
DPAPI blob.

Algorithm selection (used by CNSA guidance, but not a compliance claim):
    Signature: ECDSA P-384 (BCRYPT_ECDSA_P384_ALGORITHM)
    Digest:    SHA-384 (BCRYPT_SHA384_ALGORITHM)
    Key store: Microsoft Software Key Storage Provider (NCrypt software KSP)

Crypto-agility design:
    ALGO_SIGN_W and ALGO_HASH_W are the only algorithm identifiers in this file.
    A future post-quantum migration requires a separately reviewed provider,
    key/signature encoding, identity migration, and verifier-compatibility
    design. Changing two constants is not sufficient evidence of migration.
    ALGO_ID is stored in identity files so old signatures remain verifiable
    after a migration.

Validation status:
    Calling Windows CNG does not itself establish FIPS validation. The exact
    module, certificate status, tested operating environment, OS build,
    configuration, and policy mode must be verified for the deployment. The
    portable test backend is never validation evidence.

Public key format:
    Raw concatenated X || Y coordinates from BCRYPT_ECCPUBLIC_BLOB (header
    stripped).  For ECDSA P-384 this is always 96 bytes.  Peers store this
    alongside the ALGO_ID string so they can reconstruct the correct key type
    for verification even after an algorithm migration.

Usage:
    # First boot — generate and persist key
    signer = CngSigner.create("selfconnect-agent-e")
    pub_bytes = signer.public_key_bytes  # 96-byte raw X||Y

    # Every subsequent boot — load existing key
    signer = CngSigner.load("selfconnect-agent-e")

    # Sign
    sig = signer.sign(b"action payload")  # 96-byte IEEE P1363 signature

    # Verify (any caller, no key handle required)
    ok = cng_verify(b"action payload", sig, pub_bytes)

    # Hash
    digest = cng_sha384(b"entry bytes")  # 48-byte SHA-384 digest

    # Cleanup
    signer.close()  # or use as context manager

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes

# ── Windows CNG DLL handles ────────────────────────────────────────────────────
# On non-Windows platforms ctypes.windll is stubbed by conftest.py so this
# module imports cleanly.  CNG functions will raise at call-time on non-Windows.
# Tests that call CNG must be marked:
#   @pytest.mark.skipif(sys.platform != 'win32', reason='Windows CNG only')

import sys as _sys
import os as _os
# TEST-ONLY backend selection. Windows production path is unchanged; off-Windows
# (or with SELFCONNECT_CRYPTO_BACKEND=portable) the public API is served by a
# cryptography-backed implementation at the end of this module so the CNG suite
# runs cross-platform. The portable backend is NOT FIPS-validated.
_USE_PORTABLE_CRYPTO = _sys.platform != 'win32' or _os.environ.get('SELFCONNECT_CRYPTO_BACKEND') == 'portable'
CRYPTO_BACKEND_ID = "portable-test" if _USE_PORTABLE_CRYPTO else "windows-cng"
# True when a usable ECDSA-P384/SHA-384 signing backend is present:
# Windows CNG natively, or the cryptography-backed portable backend off-Windows.
# CNG crypto tests gate on this instead of sys.platform so they run cross-platform.
CNG_BACKEND_AVAILABLE = True
if _USE_PORTABLE_CRYPTO:
    _bcrypt = None  # type: ignore[assignment]
    _ncrypt = None  # type: ignore[assignment]
else:
    _bcrypt = ctypes.windll.bcrypt  # type: ignore[attr-defined]
    _ncrypt = ctypes.windll.ncrypt  # type: ignore[attr-defined]

# ── Algorithm identifiers ──────────────────────────────────────────────────────
# TO MIGRATE: update only these constants (plus coord/sig byte sizes below).

ALGO_SIGN_W = "ECDSA_P384"           # BCRYPT_ECDSA_P384_ALGORITHM
ALGO_HASH_W = "SHA384"               # BCRYPT_SHA384_ALGORITHM
ALGO_ID     = "ECDSA_P384_SHA384"    # stored in identity files for crypto-agility

# ── Key / signature size constants for ECDSA P-384 ────────────────────────────

P384_COORD_BYTES = 48   # bytes per curve coordinate (384 / 8)
P384_SIG_BYTES   = 96   # IEEE P1363 signature: r || s, each 48 bytes
SHA384_BYTES     = 48   # SHA-384 digest output

# ── Return code sentinels ──────────────────────────────────────────────────────

_STATUS_SUCCESS = 0x00000000   # BCrypt NTSTATUS
_SEC_SUCCESS    = 0x00000000   # NCrypt SECURITY_STATUS (same value, same meaning)

# ── Key storage provider name ─────────────────────────────────────────────────

_MS_KSP = "Microsoft Software Key Storage Provider"

# ── NCrypt key flags ──────────────────────────────────────────────────────────

_NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
_NCRYPT_SILENT_FLAG        = 0x00000040

# ── BCRYPT_ECCPUBLIC_BLOB magic value for P-384 ───────────────────────────────

_BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345  # b"ECS3" little-endian
_BCRYPT_ECCKEY_BLOB_HEADER_SIZE = 8           # dwMagic (4) + cbKey (4)


class _BCRYPT_ECCKEY_BLOB(ctypes.Structure):
    """Header of a BCRYPT_ECCKEY_BLOB (BCrypt public key import/export)."""
    _fields_ = [
        ("dwMagic", ctypes.c_ulong),
        ("cbKey",   ctypes.c_ulong),  # byte length of each coordinate
    ]


# ── Error helpers ──────────────────────────────────────────────────────────────

def _ck_bcrypt(status: int, op: str) -> None:
    """Raise OSError if BCrypt returned a non-success NTSTATUS."""
    if status != _STATUS_SUCCESS:
        # Cast to int so format spec works even if status is a MagicMock (non-Windows CI)
        raise OSError(f"BCrypt {op} failed: 0x{int(status) & 0xFFFFFFFF:08X}")


def _ck_ncrypt(status: int, op: str) -> None:
    """Raise OSError if NCrypt returned a non-success SECURITY_STATUS."""
    if status != _SEC_SUCCESS:
        # Cast to int so format spec works even if status is a MagicMock (non-Windows CI)
        raise OSError(f"NCrypt {op} failed: 0x{int(status) & 0xFFFFFFFF:08X}")


# ── SHA-384 hashing ────────────────────────────────────────────────────────────

def cng_sha384(data: bytes) -> bytes:
    """Hash data with SHA-384 via Windows BCrypt.  Returns 48-byte digest.

    Uses the Windows CNG bcrypt.dll path. No validation status is implied by
    calling this function alone.
    """
    h_algo = ctypes.c_void_p()
    st = _bcrypt.BCryptOpenAlgorithmProvider(
        ctypes.byref(h_algo), ALGO_HASH_W, None, 0
    )
    _ck_bcrypt(st, "BCryptOpenAlgorithmProvider(SHA384)")

    h_hash = ctypes.c_void_p()
    st = _bcrypt.BCryptCreateHash(
        h_algo,
        ctypes.byref(h_hash),
        None, 0,   # CNG manages hash object memory
        None, 0,   # no HMAC secret
        0,
    )
    _ck_bcrypt(st, "BCryptCreateHash")

    data_buf = (ctypes.c_ubyte * len(data))(*data) if data else (ctypes.c_ubyte * 1)(0)
    st = _bcrypt.BCryptHashData(h_hash, data_buf, len(data), 0)
    _ck_bcrypt(st, "BCryptHashData")

    digest = (ctypes.c_ubyte * SHA384_BYTES)()
    st = _bcrypt.BCryptFinishHash(h_hash, digest, SHA384_BYTES, 0)
    _ck_bcrypt(st, "BCryptFinishHash")

    _bcrypt.BCryptDestroyHash(h_hash)
    _bcrypt.BCryptCloseAlgorithmProvider(h_algo, 0)
    return bytes(digest)


# ── NCrypt private helpers ─────────────────────────────────────────────────────

def _ncrypt_open_provider():
    """Open the NCrypt software KSP.  Returns an opaque provider handle."""
    h_prov = ctypes.c_void_p()
    st = _ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(h_prov), _MS_KSP, 0
    )
    _ck_ncrypt(st, "NCryptOpenStorageProvider")
    return h_prov


def _ncrypt_export_public(h_key) -> bytes:
    """Export ECDSA P-384 public key as raw X || Y bytes (96 bytes, no header)."""
    blob_type = "ECCPUBLICBLOB"

    # Two-pass: first get required buffer size
    cb_out = ctypes.c_ulong()
    st = _ncrypt.NCryptExportKey(
        h_key, None, blob_type, None, None, 0, ctypes.byref(cb_out), 0
    )
    _ck_ncrypt(st, "NCryptExportKey (size query)")

    buf = (ctypes.c_ubyte * cb_out.value)()
    st = _ncrypt.NCryptExportKey(
        h_key, None, blob_type, None, buf, cb_out.value, ctypes.byref(cb_out), 0
    )
    _ck_ncrypt(st, "NCryptExportKey")

    # Strip the 8-byte BCRYPT_ECCKEY_BLOB header; return raw X || Y
    raw = bytes(buf)
    return raw[_BCRYPT_ECCKEY_BLOB_HEADER_SIZE:]


def _ncrypt_sign_hash(h_key, digest: bytes) -> bytes:
    """Sign a pre-computed hash with ECDSA P-384.  Returns 96-byte P1363 sig."""
    hash_buf = (ctypes.c_ubyte * len(digest))(*digest)
    sig_buf  = (ctypes.c_ubyte * P384_SIG_BYTES)()
    cb_result = ctypes.c_ulong()

    st = _ncrypt.NCryptSignHash(
        h_key,
        None,              # pPaddingInfo — NULL for ECDSA
        hash_buf,
        len(digest),
        sig_buf,
        P384_SIG_BYTES,
        ctypes.byref(cb_result),
        0,                 # dwFlags
    )
    _ck_ncrypt(st, "NCryptSignHash")
    return bytes(sig_buf[: cb_result.value])


# ── CngSigner ─────────────────────────────────────────────────────────────────

class CngSigner:
    """ECDSA P-384 signer backed by the Windows NCrypt software KSP.

    Holds open NCrypt handles for the lifetime of the instance — one
    StorageProvider handle and one key handle — to avoid per-sign KSP open cost.

    Call close() or use as a context manager.  The key material never leaves
    the NCrypt software KSP in plaintext; only the public key is exported.

    Key names are scoped to the Windows user profile.  Two agents with the same
    key name on the same machine are the same agent (same key material).
    Use agent_name strings that are globally unique within your deployment,
    e.g. "selfconnect-agent-e-orchestrator".
    """

    def __init__(
        self,
        key_name: str,
        _h_prov: ctypes.c_void_p,
        _h_key:  ctypes.c_void_p,
        _pub_raw: bytes,
    ) -> None:
        self._key_name = key_name
        self._h_prov   = _h_prov
        self._h_key    = _h_key
        self._pub_raw  = _pub_raw

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def create(cls, key_name: str, overwrite: bool = False) -> "CngSigner":
        """Generate a new ECDSA P-384 key and persist it in NCrypt software KSP.

        Args:
            key_name:  Unique name for this key (scoped to current Windows user).
            overwrite: If True, replace an existing key with the same name.

        Raises:
            OSError: If NCrypt key generation fails or key already exists
                     (when overwrite=False).
        """
        h_prov = _ncrypt_open_provider()
        h_key  = ctypes.c_void_p()
        flags  = _NCRYPT_OVERWRITE_KEY_FLAG if overwrite else 0

        st = _ncrypt.NCryptCreatePersistedKey(
            h_prov,
            ctypes.byref(h_key),
            ALGO_SIGN_W,   # algorithm
            key_name,      # persistent key name
            0,             # dwLegacyKeySpec = AT_NONE
            flags,
        )
        _ck_ncrypt(st, "NCryptCreatePersistedKey")

        st = _ncrypt.NCryptFinalizeKey(h_key, _NCRYPT_SILENT_FLAG)
        _ck_ncrypt(st, "NCryptFinalizeKey")

        pub_raw = _ncrypt_export_public(h_key)
        return cls(key_name, h_prov, h_key, pub_raw)

    @classmethod
    def load(cls, key_name: str) -> "CngSigner":
        """Load an existing ECDSA P-384 key from NCrypt software KSP.

        Raises:
            FileNotFoundError: If no key named key_name exists for this user.
            OSError: If NCrypt reports another error.
        """
        h_prov = _ncrypt_open_provider()
        h_key  = ctypes.c_void_p()

        st = _ncrypt.NCryptOpenKey(
            h_prov,
            ctypes.byref(h_key),
            key_name,
            0,   # dwLegacyKeySpec = AT_NONE
            0,   # dwFlags
        )
        if st != _SEC_SUCCESS:
            _ncrypt.NCryptFreeObject(h_prov)
            # NTE_BAD_KEYSET = 0x80090016 — key not found
            if st == ctypes.c_long(0x80090016).value:
                raise FileNotFoundError(
                    f"No NCrypt key found for {key_name!r}. "
                    "Call CngSigner.create() on first boot."
                )
            raise OSError(f"NCryptOpenKey failed: 0x{int(st) & 0xFFFFFFFF:08X}")

        pub_raw = _ncrypt_export_public(h_key)
        return cls(key_name, h_prov, h_key, pub_raw)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def key_name(self) -> str:
        """NCrypt key name this signer was created/loaded under."""
        return self._key_name

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 96-byte ECDSA P-384 public key (X || Y, no header).

        Share with peers for signature verification.  Store alongside ALGO_ID
        so peers can reconstruct the correct key type after a migration.
        """
        return self._pub_raw

    @property
    def algo_id(self) -> str:
        """Algorithm identifier string — embed in identity files for crypto-agility."""
        return ALGO_ID

    # ── Cryptographic operations ──────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """Hash data with SHA-384 then sign with ECDSA P-384.

        Returns a 96-byte IEEE P1363 signature (r || s).
        """
        digest = cng_sha384(data)
        return _ncrypt_sign_hash(self._h_key, digest)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Release NCrypt handles.  Safe to call multiple times."""
        h_key, h_prov = self._h_key, self._h_prov
        self._h_key  = None  # type: ignore[assignment]
        self._h_prov = None  # type: ignore[assignment]
        if h_key:
            _ncrypt.NCryptFreeObject(h_key)
        if h_prov:
            _ncrypt.NCryptFreeObject(h_prov)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "CngSigner":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"CngSigner(key_name={self._key_name!r}, algo={ALGO_ID!r})"


# ── Module-level helpers ───────────────────────────────────────────────────────

def cng_verify(data: bytes, signature: bytes, public_key_raw: bytes) -> bool:
    """Verify an ECDSA P-384/SHA-384 signature against a raw public key.

    Args:
        data:           The original signed bytes.
        signature:      96-byte IEEE P1363 ECDSA P-384 signature.
        public_key_raw: 96-byte raw X || Y public key (from CngSigner.public_key_bytes).

    Returns:
        True if signature is valid; False for any failure (never raises).
    """
    try:
        digest = cng_sha384(data)

        # Reconstruct BCRYPT_ECCPUBLIC_BLOB: 8-byte header + X || Y
        if len(public_key_raw) != P384_COORD_BYTES * 2:
            return False
        header = _BCRYPT_ECCKEY_BLOB()
        header.dwMagic = _BCRYPT_ECDSA_PUBLIC_P384_MAGIC
        header.cbKey   = P384_COORD_BYTES

        blob_size = _BCRYPT_ECCKEY_BLOB_HEADER_SIZE + len(public_key_raw)
        blob = (ctypes.c_ubyte * blob_size)()
        ctypes.memmove(blob, ctypes.byref(header), _BCRYPT_ECCKEY_BLOB_HEADER_SIZE)
        pub_buf = (ctypes.c_ubyte * len(public_key_raw))(*public_key_raw)
        ctypes.memmove(
            ctypes.addressof(blob) + _BCRYPT_ECCKEY_BLOB_HEADER_SIZE,
            pub_buf,
            len(public_key_raw),
        )

        # Open ECDSA P-384 algorithm provider (BCrypt — no key store needed for verify)
        h_algo = ctypes.c_void_p()
        st = _bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(h_algo), ALGO_SIGN_W, None, 0
        )
        if st != _STATUS_SUCCESS:
            return False

        # Import the public key
        h_key = ctypes.c_void_p()
        st = _bcrypt.BCryptImportKeyPair(
            h_algo,
            None,           # hImportKey (unused for public key import)
            "ECCPUBLICBLOB",
            ctypes.byref(h_key),
            blob,
            blob_size,
            0,
        )
        if st != _STATUS_SUCCESS:
            _bcrypt.BCryptCloseAlgorithmProvider(h_algo, 0)
            return False

        # Verify the signature
        hash_buf = (ctypes.c_ubyte * SHA384_BYTES)(*digest)
        sig_buf  = (ctypes.c_ubyte * len(signature))(*signature)
        st = _bcrypt.BCryptVerifySignature(
            h_key,
            None,               # pPaddingInfo — NULL for ECDSA
            hash_buf,
            SHA384_BYTES,
            sig_buf,
            len(signature),
            0,
        )

        _bcrypt.BCryptDestroyKey(h_key)
        _bcrypt.BCryptCloseAlgorithmProvider(h_algo, 0)
        return st == _STATUS_SUCCESS

    except Exception:
        return False


def cng_key_exists(key_name: str) -> bool:
    """Return True if a persisted NCrypt key with key_name exists for this user."""
    try:
        h_prov = _ncrypt_open_provider()
    except OSError:
        return False
    h_key = ctypes.c_void_p()
    st = _ncrypt.NCryptOpenKey(h_prov, ctypes.byref(h_key), key_name, 0, 0)
    if st == _SEC_SUCCESS:
        _ncrypt.NCryptFreeObject(h_key)
    _ncrypt.NCryptFreeObject(h_prov)
    return st == _SEC_SUCCESS


def cng_delete_key(key_name: str) -> bool:
    """Delete a persisted NCrypt key.  Returns True if deleted, False if not found."""
    try:
        h_prov = _ncrypt_open_provider()
    except OSError:
        return False
    h_key = ctypes.c_void_p()
    st = _ncrypt.NCryptOpenKey(h_prov, ctypes.byref(h_key), key_name, 0, 0)
    if st != _SEC_SUCCESS:
        _ncrypt.NCryptFreeObject(h_prov)
        return False
    # NCryptDeleteKey frees h_key internally — do NOT call NCryptFreeObject(h_key) after
    st = _ncrypt.NCryptDeleteKey(h_key, 0)
    _ncrypt.NCryptFreeObject(h_prov)
    return st == _SEC_SUCCESS


# ── Public API ─────────────────────────────────────────────────────────────────

__all__ = [
    # Class API
    "CngSigner",
    # Hash
    "cng_sha384",
    # Module-level helpers
    "cng_verify",
    "cng_key_exists",
    "cng_delete_key",
    # Constants (for callers who need to store algo metadata)
    "ALGO_ID",
    "ALGO_SIGN_W",
    "ALGO_HASH_W",
    "P384_SIG_BYTES",
    "P384_COORD_BYTES",
    "SHA384_BYTES",
    "CNG_BACKEND_AVAILABLE",
    "CRYPTO_BACKEND_ID",
]


# ── TEST-ONLY portable backend override (non-Windows) ─────────────────────────
# Production Windows CNG path above is unchanged. When the portable backend is
# selected, replace the public API with the cryptography-backed implementation.
if _USE_PORTABLE_CRYPTO:
    from enterprise._portable_crypto import (  # noqa: E402
        CngSigner,
        cng_sha384,
        cng_verify,
        cng_key_exists,
        cng_delete_key,
    )
