"""enterprise/policy_sign.py — Policy Bundle Signing

Supports two signing backends:

1. **CNG (Windows, production)** — ECDSA P-384 / SHA-384 via NCrypt software KSP.
   Used with CngIdentity / CngSigner.  Public key is 96 bytes (X || Y raw P-384).

2. **Ed25519 (cross-platform, CI/testing)** — Pure-Python ECDSA via the
   ``cryptography`` package.  Used with AgentIdentity.  Public key is 32 bytes.

``verify_policy_signature`` auto-detects the algorithm by public-key length:
  - 32 bytes  → Ed25519 (pure Python, no Windows required)
  - 96 bytes  → CNG P-384 (Windows NCrypt, production path)

Usage (admin — creates a signed bundle with CNG, Windows only):
    from enterprise.policy import make_bundle
    from enterprise.policy_sign import sign_policy
    from enterprise.identity_cng import CngIdentity

    with CngIdentity.load("smarteye-admin", data_dir=...) as admin:
        bundle = make_bundle("policy-2026-v1", agents={...})
        signed_dict = sign_policy(bundle.to_dict(), admin)
        PolicyBundle.from_dict(signed_dict).save(Path("policy.json"))

Usage (admin — creates a signed bundle with Ed25519, cross-platform):
    from enterprise.policy import make_bundle
    from enterprise.policy_sign import sign_policy
    from enterprise.identity import AgentIdentity

    with AgentIdentity.init("admin", data_dir=...) as admin:
        bundle = make_bundle("policy-2026-v1", agents={...})
        signed_dict = sign_policy(bundle.to_dict(), admin)

Usage (agent — verifies on load, works for both key types):
    from enterprise.policy import PolicyBundle, PolicyEnforcer

    bundle   = PolicyBundle.from_file(Path("policy.json"))
    enforcer = PolicyEnforcer(bundle, require_signature=True)
    # enforcer uses bundle.signed_by_pub for verification

Version: 1.1.0-enterprise  Session 17
"""
from __future__ import annotations

from enterprise.policy import PolicyBundle

# Ed25519 key length (raw bytes)
_ED25519_KEY_BYTES = 32
# CNG P-384 key length (X || Y raw bytes)
_P384_KEY_BYTES = 96


def sign_policy(bundle_dict: dict, signer) -> dict:  # type: ignore[type-arg]
    """Sign a policy bundle dict with any signer that has .sign() and .public_key_bytes.

    Adds 'sig' (hex signature) and 'signed_by_pub' (hex public key) to the bundle dict.
    The signature covers all fields except 'sig' and 'signed_by_pub' themselves
    (canonical sorted JSON, no whitespace).

    Compatible signers:
        - enterprise.crypto.CngSigner  (ECDSA P-384, Windows CNG)
        - enterprise.identity.AgentIdentity  (Ed25519, pure Python)

    Args:
        bundle_dict: Raw policy dict (from make_bundle().to_dict() or a loaded file).
        signer:      Any object with .sign(data: bytes) -> bytes and
                     .public_key_bytes -> bytes.

    Returns:
        A new dict with 'sig' and 'signed_by_pub' added/replaced.
    """
    # Build an unsigned bundle to get canonical signable bytes
    unsigned = {k: v for k, v in bundle_dict.items() if k not in ("sig", "signed_by_pub")}
    bundle   = PolicyBundle.from_dict(unsigned)
    sig      = signer.sign(bundle.to_signable_bytes())

    signed = dict(bundle_dict)
    signed["sig"]           = sig.hex()
    signed["signed_by_pub"] = signer.public_key_bytes.hex()
    return signed


def verify_policy_signature(bundle: PolicyBundle, pub_key_bytes: bytes) -> bool:
    """Verify the signature on a PolicyBundle.

    Auto-detects the signing algorithm by public key length:
      - 32 bytes → Ed25519 (pure Python via ``cryptography``)
      - 96 bytes → CNG ECDSA P-384 (Windows NCrypt)

    Args:
        bundle:        The PolicyBundle to verify.
        pub_key_bytes: Raw public key bytes from the signer.

    Returns:
        True if the signature is present and valid; False otherwise (never raises).
    """
    if not bundle.sig:
        return False
    try:
        sig_bytes = bytes.fromhex(bundle.sig)
    except ValueError:
        return False

    data = bundle.to_signable_bytes()

    if len(pub_key_bytes) == _ED25519_KEY_BYTES:
        return _verify_ed25519(data, sig_bytes, pub_key_bytes)
    elif len(pub_key_bytes) == _P384_KEY_BYTES:
        return _verify_cng_p384(data, sig_bytes, pub_key_bytes)
    else:
        # Unknown key size — reject
        return False


def _verify_ed25519(data: bytes, signature: bytes, public_key_raw: bytes) -> bool:
    """Verify an Ed25519 signature using the pure-Python ``cryptography`` library."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub = Ed25519PublicKey.from_public_bytes(public_key_raw)
        pub.verify(signature, data)
        return True
    except Exception:
        return False


def _verify_cng_p384(data: bytes, signature: bytes, public_key_raw: bytes) -> bool:
    """Verify a CNG ECDSA P-384 signature.  Windows only — returns False on non-Windows."""
    try:
        from enterprise.crypto import cng_verify
        return cng_verify(data, signature, public_key_raw)
    except Exception:
        return False


__all__ = ["sign_policy", "verify_policy_signature"]
