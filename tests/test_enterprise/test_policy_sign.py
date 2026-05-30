"""tests/test_enterprise/test_policy_sign.py — Integration tests for policy signing

Calls real Windows CNG NCrypt for key operations.  Keys are unique per test
and deleted in teardown.
"""
from __future__ import annotations

import time
import uuid

import pytest
from enterprise.crypto import CNG_BACKEND_AVAILABLE

from enterprise.crypto import cng_delete_key
from enterprise.identity_cng import CngIdentity
from enterprise.policy import PolicyEnforcer, make_bundle
from enterprise.policy_sign import sign_policy, verify_policy_signature


pytestmark = pytest.mark.skipif(
    not CNG_BACKEND_AVAILABLE,
    reason='No ECDSA-P384 signing backend available (CNG or portable)'
)


AGENT_A = "SC-AAAA0001"
AGENT_B = "SC-BBBB0002"
ADMIN_PREFIX = "sc-test-admin-"


@pytest.fixture
def admin_name():
    name = f"{ADMIN_PREFIX}{uuid.uuid4().hex[:10]}"
    yield name
    cng_delete_key(f"SelfConnect.{name}")


@pytest.fixture
def admin(tmp_path, admin_name):
    with CngIdentity.init(admin_name, data_dir=tmp_path) as ident:
        yield ident


def _unsigned_bundle() -> dict:
    return make_bundle(
        "policy-sign-test-v1",
        agents={
            AGENT_A: {
                "role": "orchestrator",
                "clearance": "SECRET",
                "allowed_targets": [AGENT_B],
                "allowed_apps": [],
                "blocked_apps": [],
                "allowed_actions": ["assign_task", "read_text"],
                "requires_operator_approval": [],
                "max_classification": "SECRET",
                "revoked": False,
            }
        },
        valid_from=time.time() - 10,
    ).to_dict()


# ── sign_policy ────────────────────────────────────────────────────────────────

class TestSignPolicy:
    def test_sign_adds_sig_field(self, admin):
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        assert "sig" in signed
        assert len(signed["sig"]) == 192  # 96 bytes = 192 hex chars

    def test_sign_adds_signed_by_pub(self, admin):
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        assert "signed_by_pub" in signed
        assert len(bytes.fromhex(signed["signed_by_pub"])) == 96

    def test_signing_does_not_modify_other_fields(self, admin):
        unsigned = _unsigned_bundle()
        signed   = sign_policy(unsigned, admin._signer)
        for key in unsigned:
            if key not in ("sig", "signed_by_pub"):
                assert signed[key] == unsigned[key]

    def test_sign_twice_produces_different_sigs(self, admin):
        """ECDSA uses a random nonce — each signature is unique."""
        b = _unsigned_bundle()
        s1 = sign_policy(b, admin._signer)["sig"]
        s2 = sign_policy(b, admin._signer)["sig"]
        assert s1 != s2


# ── verify_policy_signature ────────────────────────────────────────────────────

class TestVerifyPolicySignature:
    def test_valid_signature_verifies(self, admin):
        from enterprise.policy import PolicyBundle
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        bundle = PolicyBundle.from_dict(signed)
        assert verify_policy_signature(bundle, admin.public_key_bytes) is True

    def test_tampered_policy_fails_verify(self, admin):
        from enterprise.policy import PolicyBundle
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        signed["agents"][AGENT_A]["allowed_actions"].append("TAMPERED")
        bundle = PolicyBundle.from_dict(signed)
        assert verify_policy_signature(bundle, admin.public_key_bytes) is False

    def test_wrong_public_key_fails_verify(self, tmp_path, admin):
        from enterprise.policy import PolicyBundle
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        bundle = PolicyBundle.from_dict(signed)

        other_name = f"{ADMIN_PREFIX}{uuid.uuid4().hex[:10]}"
        try:
            with CngIdentity.init(other_name, data_dir=tmp_path) as other_admin:
                assert verify_policy_signature(bundle, other_admin.public_key_bytes) is False
        finally:
            cng_delete_key(f"SelfConnect.{other_name}")

    def test_empty_sig_fails_verify(self, admin):
        from enterprise.policy import PolicyBundle
        unsigned = _unsigned_bundle()
        bundle   = PolicyBundle.from_dict(unsigned)
        assert verify_policy_signature(bundle, admin.public_key_bytes) is False

    def test_invalid_hex_sig_fails_verify(self, admin):
        from enterprise.policy import PolicyBundle
        d = dict(_unsigned_bundle())
        d["sig"] = "not-valid-hex!!"
        bundle   = PolicyBundle.from_dict(d)
        assert verify_policy_signature(bundle, admin.public_key_bytes) is False


# ── End-to-end: sign → load → enforce ─────────────────────────────────────────

class TestSignedPolicyEnforcement:
    def test_signed_policy_allows_action(self, admin):
        from enterprise.policy import PolicyBundle
        signed  = sign_policy(_unsigned_bundle(), admin._signer)
        bundle  = PolicyBundle.from_dict(signed)
        enforcer = PolicyEnforcer(
            bundle,
            trust_root_pub=admin.public_key_bytes,
            require_signature=True,
        )
        d = enforcer.check(AGENT_A, "assign_task")
        assert d.allowed is True

    def test_tampered_policy_is_denied_by_enforcer(self, admin):
        from enterprise.policy import PolicyBundle
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        # Tamper: add an action post-signing
        signed["agents"][AGENT_A]["allowed_actions"].append("INJECT_EVIL")
        bundle   = PolicyBundle.from_dict(signed)
        enforcer = PolicyEnforcer(
            bundle,
            trust_root_pub=admin.public_key_bytes,
            require_signature=True,
        )
        # Sig cached as invalid → all checks return signature invalid
        d = enforcer.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert "signature" in d.reason

    def test_signed_policy_saved_and_loaded(self, tmp_path, admin):
        from enterprise.policy import PolicyBundle
        signed = sign_policy(_unsigned_bundle(), admin._signer)
        p      = tmp_path / "policy.json"
        PolicyBundle.from_dict(signed).save(p)

        loaded   = PolicyBundle.from_file(p)
        enforcer = PolicyEnforcer(
            loaded,
            trust_root_pub=admin.public_key_bytes,
            require_signature=True,
        )
        d = enforcer.check(AGENT_A, "read_text", target_agent=AGENT_B)
        assert d.allowed is True
        assert d.policy_id == "policy-sign-test-v1"
