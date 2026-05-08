"""enterprise/policy_sign.py — Policy Bundle Signing via CNG

Admins sign policy bundles with their CngIdentity (ECDSA P-384 / SHA-384).
Agents verify on load.  The signing key's public key is embedded in the bundle
so any peer with the raw pubkey bytes can verify — no PKI required.

Usage (admin — creates a signed bundle):
    from enterprise.policy import make_bundle
    from enterprise.policy_sign import sign_policy
    from enterprise.identity_cng import CngIdentity

    with CngIdentity.load("smarteye-admin", data_dir=...) as admin:
        bundle = make_bundle("policy-2026-v1", agents={...})
        signed_dict = sign_policy(bundle.to_dict(), admin)
        PolicyBundle.from_dict(signed_dict).save(Path("policy.json"))

Usage (agent — verifies on load):
    from enterprise.policy import PolicyBundle, PolicyEnforcer

    bundle   = PolicyBundle.from_file(Path("policy.json"))
    enforcer = PolicyEnforcer(bundle, require_signature=True)
    # enforcer uses bundle.signed_by_pub for verification

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

from enterprise.crypto import CngSigner, cng_verify
from enterprise.policy import PolicyBundle


def sign_policy(bundle_dict: dict, signer: CngSigner) -> dict:
    """Sign a policy bundle dict.

    Adds 'sig' (hex ECDSA P-384 signature) and 'signed_by_pub' (hex public key)
    to the bundle dict.  The signature covers all fields except 'sig' and
    'signed_by_pub' themselves (canonical sorted JSON, no whitespace).

    Args:
        bundle_dict: Raw policy dict (from make_bundle().to_dict() or a loaded file).
        signer:      Open CngSigner holding the signing key.

    Returns:
        A new dict with 'sig' and 'signed_by_pub' added/replaced.
    """
    # Build an unsigned bundle to get canonical signable bytes
    unsigned = {k: v for k, v in bundle_dict.items() if k not in ("sig", "signed_by_pub")}
    bundle   = PolicyBundle.from_dict(unsigned)
    sig      = signer.sign(bundle.to_signable_bytes())

    signed = dict(bundle_dict)
    signed["sig"]          = sig.hex()
    signed["signed_by_pub"] = signer.public_key_bytes.hex()
    return signed


def verify_policy_signature(bundle: PolicyBundle, pub_key_bytes: bytes) -> bool:
    """Verify the CNG signature on a PolicyBundle.

    Args:
        bundle:        The PolicyBundle to verify.
        pub_key_bytes: 96-byte ECDSA P-384 public key of the expected signer.

    Returns:
        True if the signature is present and valid; False otherwise (never raises).
    """
    if not bundle.sig:
        return False
    try:
        sig_bytes = bytes.fromhex(bundle.sig)
    except ValueError:
        return False
    return cng_verify(bundle.to_signable_bytes(), sig_bytes, pub_key_bytes)


__all__ = ["sign_policy", "verify_policy_signature"]
