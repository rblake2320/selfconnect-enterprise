"""enterprise/_portable_crypto.py — TEST-ONLY portable CNG-equivalent backend.

Provides a drop-in implementation of the enterprise.crypto public API
(CngSigner, cng_sha384, cng_verify, cng_key_exists, cng_delete_key) using the
pure-Python `cryptography` library, so the CNG test suite runs on non-Windows
platforms.

NOT FIPS-validated. Windows CNG (bcrypt.dll / ncrypt.dll) remains the production
crypto path. This module is selected only when sys.platform != 'win32' or when
SELFCONNECT_CRYPTO_BACKEND=portable is set.

Wire compatibility with the CNG path:
  - public_key_bytes: 96-byte raw X || Y (P-384, big-endian, 48 bytes each)
  - signatures:       96-byte IEEE P1363 (r || s, 48 bytes each)
  - digests:          48-byte SHA-384
  - keys persisted by name in a software keystore (emulating the NCrypt KSP
    name-scoped persistence) so create()/load()/delete() behave identically.
"""
from __future__ import annotations

import base64
import hashlib
import os
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

# Mirror the constants the CNG module exposes (kept in sync with enterprise.crypto).
ALGO_ID = "ECDSA_P384_SHA384"
P384_COORD_BYTES = 48
P384_SIG_BYTES = 96
SHA384_BYTES = 48
_CURVE = ec.SECP384R1()


def _keystore_dir() -> pathlib.Path:
    raw = os.environ.get(
        "SELFCONNECT_PORTABLE_KSP",
        str(pathlib.Path.home() / ".selfconnect" / "portable_ksp"),
    )
    d = pathlib.Path(raw).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    return d


def _key_path(key_name: str) -> pathlib.Path:
    # URL-safe-encode the name so KSP-style names ("SelfConnect.agent") are
    # filesystem-safe and collision-free.
    enc = base64.urlsafe_b64encode(key_name.encode("utf-8")).decode("ascii")
    return _keystore_dir() / f"{enc}.pem"


def cng_sha384(data: bytes) -> bytes:
    """SHA-384 digest (48 bytes)."""
    return hashlib.sha384(data).digest()


def _pub_raw(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    nums = private_key.public_key().public_numbers()
    return nums.x.to_bytes(P384_COORD_BYTES, "big") + nums.y.to_bytes(P384_COORD_BYTES, "big")


class CngSigner:
    """Portable ECDSA P-384 signer mirroring the CNG NCrypt signer API."""

    def __init__(self, key_name: str, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._key_name = key_name
        self._private_key: ec.EllipticCurvePrivateKey | None = private_key
        self._pub_raw = _pub_raw(private_key)
        # CNG-handle compatibility: the Windows signer exposes _h_key/_h_prov and
        # nulls them on close(). Mirror that contract so handle-lifecycle tests pass.
        self._h_key: object | None = object()
        self._h_prov: object | None = object()

    @classmethod
    def create(cls, key_name: str, overwrite: bool = False) -> "CngSigner":
        path = _key_path(key_name)
        if path.exists() and not overwrite:
            raise OSError(f"portable KSP: key {key_name!r} already exists")
        private_key = ec.generate_private_key(_CURVE)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        return cls(key_name, private_key)

    @classmethod
    def load(cls, key_name: str) -> "CngSigner":
        path = _key_path(key_name)
        if not path.exists():
            raise FileNotFoundError(
                f"No portable KSP key found for {key_name!r}. "
                "Call CngSigner.create() on first boot."
            )
        private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        return cls(key_name, private_key)  # type: ignore[arg-type]

    @property
    def key_name(self) -> str:
        return self._key_name

    @property
    def public_key_bytes(self) -> bytes:
        return self._pub_raw

    @property
    def algo_id(self) -> str:
        return ALGO_ID

    def sign(self, data: bytes) -> bytes:
        if self._private_key is None:
            raise OSError("portable KSP: signer is closed")
        digest = cng_sha384(data)
        der = self._private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA384())))
        r, s = decode_dss_signature(der)
        return r.to_bytes(P384_COORD_BYTES, "big") + s.to_bytes(P384_COORD_BYTES, "big")

    def close(self) -> None:
        self._private_key = None
        self._h_key = None
        self._h_prov = None

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


def cng_verify(data: bytes, signature: bytes, public_key_raw: bytes) -> bool:
    """Verify an ECDSA P-384/SHA-384 P1363 signature. Never raises."""
    try:
        if len(signature) != P384_SIG_BYTES or len(public_key_raw) != P384_COORD_BYTES * 2:
            return False
        x = int.from_bytes(public_key_raw[:P384_COORD_BYTES], "big")
        y = int.from_bytes(public_key_raw[P384_COORD_BYTES:], "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, _CURVE).public_key()
        r = int.from_bytes(signature[:P384_COORD_BYTES], "big")
        s = int.from_bytes(signature[P384_COORD_BYTES:], "big")
        der = encode_dss_signature(r, s)
        digest = cng_sha384(data)
        pub.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA384())))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def cng_key_exists(key_name: str) -> bool:
    return _key_path(key_name).exists()


def cng_delete_key(key_name: str) -> bool:
    path = _key_path(key_name)
    if path.exists():
        path.unlink()
        return True
    return False
