"""enterprise/bpc_crypto.py — BPC Cryptographic Primitives (Python port)

Python port of the critical BPC crypto operations for the latency-sensitive
per-injection path (~2-5ms local).  Uses the `cryptography` library which is
already a dependency for ed25519 and P-384 in the enterprise layer.

Operations provided:
  - ECDSA P-256 keypair generation (non-extractable equivalent via in-memory CryptoKey)
  - HKDF-SHA-256 derivation of P-256 private key from ed25519 seed material
  - ECDSA P-256 sign / verify (DER-encoded signature, base64url output)
  - HMAC-SHA-256 (secret HMAC derivation for BPC canonical payload)
  - SHA-256 body hash (BPC body_hash field)
  - Canonical payload construction and JSON serialization (alphabetically sorted)
  - Constant-time bytes comparison (timing-safe equal)

Key derivation chain (from integration plan):
  DPAPI (machine+user bound)
    └─ ed25519 private key (AgentIdentity)
         └─ HKDF-SHA-256(ed25519_priv_bytes, info=b"bpc-p256-derive", salt=agent_id_bytes)
              └─ ECDSA P-256 private key (BPC Layer 1)

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC as _CryptoHMAC


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    """URL-safe base64 encoding without padding (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decoding; adds padding as needed."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Timing-safe byte comparison (equivalent to Node.js crypto.timingSafeEqual)."""
    return _hmac.compare_digest(a, b)


# ── HKDF derivation ───────────────────────────────────────────────────────────

def derive_p256_private_key(
    ed25519_private_bytes: bytes,
    agent_id: str,
) -> ec.EllipticCurvePrivateKey:
    """Derive a deterministic ECDSA P-256 private key from an ed25519 seed.

    Uses HKDF-SHA-256 with:
      - ikm  = ed25519_private_bytes (32 bytes raw seed)
      - salt = agent_id encoded as UTF-8
      - info = b"bpc-p256-derive"

    The 32-byte output is used as the P-256 private key scalar (reduced mod n).
    This is the same derivation chain specified in the integration plan.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=agent_id.encode(),
        info=b"bpc-p256-derive",
    )
    key_bytes = hkdf.derive(ed25519_private_bytes)

    # Interpret as a big-endian integer and reduce mod P-256 order n.
    # P-256 order n (hex):
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    scalar = int.from_bytes(key_bytes, "big") % n
    if scalar == 0:
        # Astronomically unlikely, but handle it.
        scalar = 1

    # Reconstruct private key from scalar via raw bytes.
    scalar_bytes = scalar.to_bytes(32, "big")
    private_key = ec.derive_private_key(
        int.from_bytes(scalar_bytes, "big"),
        ec.SECP256R1(),
    )
    return private_key


# ── P-256 keypair ─────────────────────────────────────────────────────────────

@dataclass
class P256KeyPair:
    """Holds a P-256 keypair with serialization helpers."""
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey

    @classmethod
    def generate(cls) -> "P256KeyPair":
        """Generate a fresh random P-256 keypair."""
        priv = ec.generate_private_key(ec.SECP256R1())
        return cls(private_key=priv, public_key=priv.public_key())

    @classmethod
    def from_private_key(cls, private_key: ec.EllipticCurvePrivateKey) -> "P256KeyPair":
        return cls(private_key=private_key, public_key=private_key.public_key())

    def public_key_jwk(self) -> dict:
        """Export public key as JWK (matches BPC spec §5 fingerprint format)."""
        pub_numbers = self.public_key.public_numbers()
        x = _b64url_encode(pub_numbers.x.to_bytes(32, "big"))
        y = _b64url_encode(pub_numbers.y.to_bytes(32, "big"))
        return {"kty": "EC", "crv": "P-256", "x": x, "y": y}

    def public_key_fingerprint(self) -> str:
        """base64url(SHA-256(JSON.stringify(pubJwk))).substring(0, 20) — BPC spec §5."""
        jwk_json = json.dumps(self.public_key_jwk(), separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(jwk_json.encode()).digest()
        return _b64url_encode(digest)[:20]

    def private_key_raw_bytes(self) -> bytes:
        """Export private key as raw 32-byte big-endian scalar."""
        return self.private_key.private_numbers().private_value.to_bytes(32, "big")


# ── ECDSA P-256 sign / verify ─────────────────────────────────────────────────

def p256_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    """Sign message with ECDSA P-256 SHA-256.  Returns base64url DER signature."""
    sig_der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return _b64url_encode(sig_der)


def p256_verify(
    public_key: ec.EllipticCurvePublicKey,
    message: bytes,
    signature_b64url: str,
) -> bool:
    """Verify ECDSA P-256 SHA-256 signature.  Returns True if valid."""
    try:
        sig_der = _b64url_decode(signature_b64url)
        public_key.verify(sig_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def p256_public_key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Import a P-256 public key from JWK dict."""
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return pub_numbers.public_key()


# ── HMAC-SHA-256 ──────────────────────────────────────────────────────────────

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA-256 returning raw 32-byte digest."""
    h = _CryptoHMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def hmac_sha256_b64url(key: bytes, message: bytes) -> str:
    """HMAC-SHA-256 returning full 256-bit base64url output (43 chars, BPC §7 step 4)."""
    return _b64url_encode(hmac_sha256(key, message))


def derive_secret_hmac(secret: str, nonce: str, timestamp: int) -> str:
    """BPC §7 step 4: HMAC-SHA-256(secret, nonce + timestamp) → base64url (43 chars).

    The user's plaintext secret is the HMAC key.
    The concatenation of nonce and str(timestamp) is the message.
    Full 256-bit output used (not truncated).
    """
    key = secret.encode()
    msg = (nonce + str(timestamp)).encode()
    return hmac_sha256_b64url(key, msg)


# ── SHA-256 body hash ─────────────────────────────────────────────────────────

def body_hash(body: bytes) -> str:
    """BPC §7 step 3: "sha256:" + base64url(SHA-256(body)).substring(0, 32)."""
    digest = hashlib.sha256(body).digest()
    return "sha256:" + _b64url_encode(digest)[:32]


EMPTY_BODY_HASH: str = body_hash(b"")


# ── Canonical payload ─────────────────────────────────────────────────────────

@dataclass
class BPCCanonicalPayload:
    """BPC §9 canonical payload — all fields, alphabetically sorted on serialization."""
    body_hash: str
    method: str
    nonce: str
    pair_id: str
    path: str
    secret_hmac: str
    timestamp: int
    version: str = "1.0"

    def to_canonical_json(self) -> str:
        """Serialize as JSON with keys sorted alphabetically (BPC §7 step 6)."""
        d = {
            "body_hash":   self.body_hash,
            "method":      self.method,
            "nonce":       self.nonce,
            "pair_id":     self.pair_id,
            "path":        self.path,
            "secret_hmac": self.secret_hmac,
            "timestamp":   self.timestamp,
            "version":     self.version,
        }
        return json.dumps(d, separators=(",", ":"), sort_keys=True)

    def to_canonical_bytes(self) -> bytes:
        return self.to_canonical_json().encode()

    def to_signed_data_b64url(self) -> str:
        """base64url(UTF-8(canonical_json)) — X-BPC-Signed-Data header value."""
        return _b64url_encode(self.to_canonical_bytes())


def build_canonical_payload(
    pair_id: str,
    secret: str,
    method: str,
    path: str,
    body: bytes = b"",
) -> BPCCanonicalPayload:
    """Construct a fresh BPC canonical payload with new nonce and timestamp."""
    nonce = str(secrets.token_hex(16))  # 32-char hex UUID equivalent
    ts = int(time.time() * 1000)        # Unix milliseconds
    return BPCCanonicalPayload(
        body_hash=body_hash(body) if body else EMPTY_BODY_HASH,
        method=method.upper(),
        nonce=nonce,
        pair_id=pair_id,
        path=path,
        secret_hmac=derive_secret_hmac(secret, nonce, ts),
        timestamp=ts,
    )


# ── BPC request headers ───────────────────────────────────────────────────────

@dataclass
class BPCHeaders:
    """The four BPC HTTP headers (BPC §17)."""
    pair_id: str        # X-BPC-Pair-ID
    signature: str      # X-BPC-Signature
    signed_data: str    # X-BPC-Signed-Data
    version: str = "1.0"  # X-BPC-Version

    def as_dict(self) -> dict:
        return {
            "X-BPC-Pair-ID":    self.pair_id,
            "X-BPC-Signature":  self.signature,
            "X-BPC-Signed-Data": self.signed_data,
            "X-BPC-Version":    self.version,
        }


def sign_bpc_request(
    keypair: P256KeyPair,
    pair_id: str,
    secret: str,
    method: str,
    path: str,
    body: bytes = b"",
) -> tuple[BPCCanonicalPayload, BPCHeaders]:
    """Build and sign a BPC request.  Returns (payload, headers).

    BPC §7 steps 1-9:
      1. Generate nonce
      2. Capture timestamp
      3. Compute body hash
      4. Derive secret HMAC
      5. Build canonical payload
      6. Canonicalize (sort keys)
      7. Sign with ECDSA P-256
      8. Encode signed data as base64url
      9. Return headers
    """
    payload = build_canonical_payload(pair_id, secret, method, path, body)
    canonical_bytes = payload.to_canonical_bytes()
    signature = p256_sign(keypair.private_key, canonical_bytes)
    signed_data = payload.to_signed_data_b64url()
    headers = BPCHeaders(
        pair_id=pair_id,
        signature=signature,
        signed_data=signed_data,
    )
    return payload, headers


def verify_bpc_request_local(
    public_key: ec.EllipticCurvePublicKey,
    headers: BPCHeaders,
    method: str,
    path: str,
    body: bytes = b"",
    sig_window_ms: int = 60_000,
    seen_nonces: Optional[set] = None,
) -> tuple[bool, str]:
    """Local fast-path BPC verification (no server round-trip).

    Checks (BPC §8 steps 5-12, excluding rate limit and pair registry):
      - Signed data decodes and parses
      - Protocol version == "1.0"
      - Timestamp within sig_window_ms
      - Nonce not in seen_nonces (if provided)
      - Method and path match
      - Body hash matches
      - ECDSA signature valid

    Returns (ok: bool, error_code: str).
    """
    # Decode signed data
    try:
        canonical_json = _b64url_decode(headers.signed_data).decode()
        payload_dict = json.loads(canonical_json)
    except Exception:
        return False, "invalid_signed_data"

    # Version check
    if payload_dict.get("version") != "1.0":
        return False, "unsupported_version"

    # Timestamp window
    now_ms = int(time.time() * 1000)
    ts = payload_dict.get("timestamp", 0)
    if abs(now_ms - ts) > sig_window_ms:
        return False, "timestamp_expired"

    # Nonce uniqueness
    nonce = payload_dict.get("nonce", "")
    if seen_nonces is not None:
        if nonce in seen_nonces:
            return False, "replay_detected"
        seen_nonces.add(nonce)

    # Method and path match
    if payload_dict.get("method") != method.upper():
        return False, "method_path_mismatch"
    if payload_dict.get("path") != path:
        return False, "method_path_mismatch"

    # Body hash match
    expected_bh = body_hash(body) if body else EMPTY_BODY_HASH
    if payload_dict.get("body_hash") != expected_bh:
        return False, "body_hash_mismatch"

    # ECDSA signature
    canonical_bytes = canonical_json.encode()
    if not p256_verify(public_key, canonical_bytes, headers.signature):
        return False, "signature_invalid"

    return True, "ok"
