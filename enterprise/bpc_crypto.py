"""enterprise/bpc_crypto.py — Python port of BPC cryptographic operations.

Implements the same operations as @bpc/core (TypeScript) using the `cryptography`
library that is already a dependency of the enterprise layer.

Canonical payload format matches canonical.ts exactly:
  - JSON.stringify with alphabetically sorted keys, no spaces.
  - Same forbidden keys enforced.

HMAC/HKDF operations match hmac.ts exactly:
  - hashSecret: HKDF-SHA-256 with fixed salt + info strings.
  - hmacDerive: HMAC-SHA-256 over base64url-decoded key material.

Signature matches crypto.ts exactly:
  - ECDSA P-256 / SHA-256 over UTF-8-encoded canonical JSON.
  - Base64url output (no padding).

Version: 1.0.0  BPC+TSK integration
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── BPC forbidden keys (mirrors canonical.ts) ─────────────────────────────────
_FORBIDDEN_KEYS: frozenset[str] = frozenset([
    "__proto__", "constructor", "prototype",
    "__defineGetter__", "__defineSetter__",
    "__lookupGetter__", "__lookupSetter__",
])

# ── HKDF constants (mirrors hmac.ts) ─────────────────────────────────────────
_HKDF_INFO = b"bpc-v1-hmac-key"
_HKDF_SALT = b"bpc-protocol-hmac-salt-v1"

# ── P-256 key derivation info ─────────────────────────────────────────────────
_P256_DERIVE_INFO = b"bpc-p256-derive"


# ── Base64url helpers ─────────────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    """Encode bytes to base64url (no padding). Matches BPC encoding.ts b64url()."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode base64url string (handles missing padding)."""
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


# ── Canonical payload ─────────────────────────────────────────────────────────

def canonicalize(obj: dict[str, Any]) -> str:
    """Produce a deterministic JSON string matching BPC canonical.ts canonicalize().

    - Keys sorted alphabetically (matches Object.keys().sort()).
    - No spaces in separators (matches JSON.stringify default for primitives).
    - Only scalar values allowed (str, int, float, bool, None).
    - Forbidden keys rejected.
    """
    if not isinstance(obj, dict):
        raise TypeError("BPC canonicalize: input must be a plain dict")
    sorted_obj: dict[str, Any] = {}
    for key in sorted(obj.keys()):
        if key in _FORBIDDEN_KEYS:
            raise TypeError(f"BPC canonicalize: forbidden key '{key}' in payload")
        val = obj[key]
        if isinstance(val, dict) or isinstance(val, list):
            raise TypeError(f"BPC canonicalize: nested object at key '{key}' not allowed")
        sorted_obj[key] = val
    return json.dumps(sorted_obj, separators=(",", ":"), ensure_ascii=False)


# ── Key derivation ────────────────────────────────────────────────────────────

def derive_p256_from_ed25519(
    ed25519_private_key: Any,
    agent_id: str,
) -> ec.EllipticCurvePrivateKey:
    """Derive a deterministic ECDSA P-256 private key from an ed25519 private key.

    The ed25519 key is the DPAPI-protected root of trust. The P-256 key is derived
    deterministically via HKDF-SHA-256 so the same identity always produces the same
    BPC keypair. No additional secret storage needed.

    Args:
        ed25519_private_key: Ed25519PrivateKey (from AgentIdentity).
        agent_id: Agent ID string used as HKDF salt (e.g. "SC-A7F3B2E1").
    """
    raw = ed25519_private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=agent_id.encode("utf-8"),
        info=_P256_DERIVE_INFO,
    )
    key_bytes = hkdf.derive(raw)
    # Create P-256 private key from 32-byte scalar
    scalar = int.from_bytes(key_bytes, "big")
    # P-256 order — scalar must be in [1, n-1]
    _P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    scalar = (scalar % (_P256_ORDER - 1)) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def p256_public_key_to_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """Export P-256 public key as JWK dict (for registration with Ultra Server)."""
    pub = private_key.public_key()
    # Use OpenSSL uncompressed point encoding: 0x04 | x (32 bytes) | y (32 bytes)
    pub_bytes = pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    x_bytes = pub_bytes[1:33]
    y_bytes = pub_bytes[33:65]
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(x_bytes),
        "y": b64url(y_bytes),
        "key_ops": ["verify"],
        "ext": True,
    }


def compute_fingerprint(jwk: dict[str, Any]) -> str:
    """Compute BPC fingerprint: base64url(SHA-256(JSON(jwk)))[:20].

    Matches computeFingerprint() in crypto.ts.
    """
    data = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(data).digest()
    return b64url(digest)[:20]


# ── Signing / verification ────────────────────────────────────────────────────

def sign_payload(private_key: ec.EllipticCurvePrivateKey, payload: dict[str, Any]) -> str:
    """ECDSA P-256 / SHA-256 signature over canonical JSON.

    Returns base64url-encoded raw (r||s) signature — 64 bytes, matching the
    WebCrypto ECDSA output format used by signPayload() in crypto.ts.
    """
    canonical = canonicalize(payload).encode("utf-8")
    # DER-encoded signature from cryptography library
    der_sig = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    # Convert DER → raw r||s (WebCrypto format: 32 bytes each)
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64url(raw_sig)


def verify_payload_with_jwk(jwk: dict[str, Any], payload: dict[str, Any], signature: str) -> bool:
    """Verify an ECDSA P-256 / SHA-256 signature using a JWK public key.

    Args:
        jwk: Public key JWK dict with kty="EC", crv="P-256", x, y fields.
        payload: The canonical payload dict (will be canonicalized internally).
        signature: Base64url-encoded raw (r||s) signature.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        pub_key = pub_numbers.public_key()
        canonical = canonicalize(payload).encode("utf-8")
        sig_bytes = b64url_decode(signature)
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der_sig = encode_dss_signature(r, s)
        pub_key.verify(der_sig, canonical, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ── HMAC / secret operations ──────────────────────────────────────────────────

def hash_secret(secret: str) -> str:
    """Derive a 256-bit HMAC key from a user secret using HKDF-SHA-256.

    Matches hashSecret() in hmac.ts. Uses fixed HKDF_SALT and HKDF_INFO.
    Returns base64url-encoded 32-byte derived key.
    """
    if not secret:
        raise ValueError("BPC hash_secret: secret must not be empty")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    derived = hkdf.derive(secret.encode("utf-8"))
    return b64url(derived)


def hmac_derive(key_material: str, data: str) -> str:
    """HMAC-SHA-256 over data using base64url-decoded key material.

    Matches hmacDerive() in hmac.ts.
    Returns base64url-encoded 32-byte HMAC tag.
    """
    if not key_material:
        raise ValueError("BPC hmac_derive: key_material must not be empty")
    key_bytes = b64url_decode(key_material)
    tag = _hmac.new(key_bytes, data.encode("utf-8"), hashlib.sha256).digest()
    return b64url(tag)


def body_hash(body: str) -> str:
    """SHA-256 hash of body text, base64url-encoded.

    Matches the body_hash field in BPCCanonicalPayload.
    """
    digest = hashlib.sha256(body.encode("utf-8")).digest()
    return b64url(digest)


def constant_time_equal(a: str, b: str) -> bool:
    """Constant-time string comparison. Safe against timing oracles."""
    a_bytes = a.encode("utf-8")
    b_bytes = b.encode("utf-8")
    return _hmac.compare_digest(a_bytes, b_bytes)


# ── Nonce generation ──────────────────────────────────────────────────────────

def generate_nonce() -> str:
    """Generate a UUID v4 nonce (matches BPC nonce.ts generateNonce())."""
    import uuid
    return str(uuid.uuid4())
