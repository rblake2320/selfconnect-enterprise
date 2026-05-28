"""tests/test_enterprise/test_e2e_chain.py — End-to-end pipeline chain test

GAP-4: The most critical missing test. Chains ALL layers:
    CngIdentity → PolicyBundle sign → PolicyEnforcer → CngLedger → LedgerObserver

This test uses REAL Windows CNG crypto (no mocking). Keys are created with
unique names and deleted in teardown.
"""
from __future__ import annotations

import time
import uuid

import pytest
from enterprise.crypto import CNG_BACKEND_AVAILABLE

from enterprise.crypto import (
    CngSigner,
    cng_delete_key,
)
from enterprise.identity_cng import CngIdentity, CngLedger
from enterprise.observer import LedgerObserver, ObserverFilter
from enterprise.policy import PolicyBundle, PolicyEnforcer, make_bundle
from enterprise.policy_sign import sign_policy
import sys


pytestmark = pytest.mark.skipif(
    not CNG_BACKEND_AVAILABLE,
    reason='No ECDSA-P384 signing backend available (CNG or portable)'
)


AGENT_NAME_PREFIX = "sc-e2e-"


@pytest.fixture
def e2e_names():
    """Generate unique names for agent and signer keys."""
    suffix = uuid.uuid4().hex[:8]
    return {
        "agent": f"{AGENT_NAME_PREFIX}agent-{suffix}",
        "signer": f"{AGENT_NAME_PREFIX}signer-{suffix}",
    }


class TestEndToEndChain:
    """Full pipeline: identity → signed policy → enforce → ledger → observer.

    This is a single test that validates every layer interacts correctly
    with real CNG crypto on a real Windows machine. No mocks.
    """

    def test_full_chain(self, tmp_path, e2e_names):
        agent_name = e2e_names["agent"]
        signer_name = e2e_names["signer"]

        try:
            # ── Step 1: Create CngIdentity (real NCrypt key) ─────────────
            identity = CngIdentity.init(agent_name, data_dir=tmp_path)
            assert identity.agent_id.startswith("SC-")
            assert len(identity.public_key_bytes) == 96

            # ── Step 2: Create a signing key and sign a PolicyBundle ──────
            signer = CngSigner.create(f"SelfConnect.{signer_name}")
            signer_pub = signer.public_key_bytes

            agent_policy = {
                identity.agent_id: {
                    "role": "worker",
                    "clearance": "SECRET",
                    "allowed_targets": [],
                    "allowed_apps": ["python.exe"],
                    "blocked_apps": [],
                    "allowed_actions": ["read_text", "assign_task"],
                    "requires_operator_approval": [],
                    "max_classification": "SECRET",
                    "revoked": False,
                }
            }

            bundle = make_bundle(
                policy_id="e2e-test-policy-v1",
                agents=agent_policy,
                valid_from=time.time() - 60,
            )

            # Sign the bundle
            signed_dict = sign_policy(bundle.to_dict(), signer)
            signed_bundle = PolicyBundle.from_dict(signed_dict)

            assert signed_bundle.sig, "Bundle must have a signature"
            assert signed_bundle.signed_by_pub, "Bundle must have signer public key"

            # ── Step 3: Build PolicyEnforcer with real signed bundle ──────
            enforcer = PolicyEnforcer(
                policy=signed_bundle,
                trust_root_pub=signer_pub,
                require_signature=True,
            )

            # ── Step 4: Check an ALLOWED action ──────────────────────────
            allow_decision = enforcer.check(
                agent_id=identity.agent_id,
                action="read_text",
                classification="UNCLASSIFIED",
            )
            assert allow_decision.allowed is True, \
                f"Expected allow, got deny: {allow_decision.reason}"

            # ── Step 5: Check a DENIED action ────────────────────────────
            deny_decision = enforcer.check(
                agent_id=identity.agent_id,
                action="delete_system_files",  # not in allowed_actions
                classification="UNCLASSIFIED",
            )
            assert deny_decision.allowed is False, \
                "Expected deny for unlisted action"

            # ── Step 6: Log both decisions to CngLedger ──────────────────
            ledger_path = tmp_path / "e2e_ledger.jsonl"
            ledger = CngLedger(identity, log_path=ledger_path)

            entry_allow = ledger.log(
                action="read_text",
                result="success",
                metadata=allow_decision.to_ledger_metadata(),
            )
            assert entry_allow["seq"] == 1
            assert entry_allow["decision"] == "allow"

            entry_deny = ledger.log(
                action="delete_system_files",
                result="blocked",
                metadata=deny_decision.to_ledger_metadata(),
            )
            assert entry_deny["seq"] == 2
            assert entry_deny["decision"] == "deny"

            # ── Step 7: Verify ledger hash chain is intact ───────────────
            valid, count, msg = ledger.verify()
            assert valid is True, f"Hash chain verification failed: {msg}"
            assert count == 2, f"Expected 2 entries, got {count}"

            # ── Step 8: Run LedgerObserver — only allow appears ──────────
            # Pass the verified ledger as verifier (production path).
            observer = LedgerObserver(
                ledger_path=ledger_path,
                observer_filter=ObserverFilter(
                    allowed_decisions=["allow"],
                ),
                verifier=ledger,
            )
            records = observer.extract()

            assert len(records) == 1, \
                f"Observer should extract exactly 1 allow record, got {len(records)}"
            assert records[0].action == "read_text"
            assert records[0].decision == "allow"

            # Verify the deny entry is NOT in training data
            deny_records = [r for r in records if r.action == "delete_system_files"]
            assert len(deny_records) == 0, \
                "SECURITY VIOLATION: denied action appeared in training data"

            # ── Step 9: Verify observer Alpaca output is well-formed ─────
            alpaca = records[0].to_alpaca()
            assert "instruction" in alpaca
            assert "input" in alpaca
            assert "output" in alpaca
            assert identity.agent_id in alpaca["instruction"]

        finally:
            # ── Cleanup: delete NCrypt keys ──────────────────────────────
            cng_delete_key(f"SelfConnect.{agent_name}")
            cng_delete_key(f"SelfConnect.{signer_name}")

    def test_chain_with_tampered_policy_fails(self, tmp_path, e2e_names):
        """Sign a policy, then tamper with it. Enforcer must reject."""
        agent_name = e2e_names["agent"]
        signer_name = e2e_names["signer"]

        try:
            identity = CngIdentity.init(agent_name, data_dir=tmp_path)
            signer = CngSigner.create(f"SelfConnect.{signer_name}")

            bundle = make_bundle(
                policy_id="tamper-test-v1",
                agents={
                    identity.agent_id: {
                        "role": "worker",
                        "clearance": "SECRET",
                        "allowed_actions": ["read_text"],
                        "max_classification": "SECRET",
                    }
                },
                valid_from=time.time() - 60,
            )

            signed_dict = sign_policy(bundle.to_dict(), signer)
            # Tamper: change allowed_actions after signing
            signed_dict["agents"][identity.agent_id]["allowed_actions"] = [
                "read_text", "delete_system_files", "exfiltrate_data"
            ]
            tampered_bundle = PolicyBundle.from_dict(signed_dict)

            enforcer = PolicyEnforcer(
                policy=tampered_bundle,
                trust_root_pub=signer.public_key_bytes,
                require_signature=True,
            )

            # The enforcer should detect invalid signature and deny
            decision = enforcer.check(
                agent_id=identity.agent_id,
                action="delete_system_files",
                classification="UNCLASSIFIED",
            )
            assert decision.allowed is False, \
                "SECURITY VIOLATION: tampered policy was accepted"

        finally:
            cng_delete_key(f"SelfConnect.{agent_name}")
            cng_delete_key(f"SelfConnect.{signer_name}")

    def test_chain_classification_ceiling(self, tmp_path, e2e_names):
        """Agent with SECRET clearance cannot process TOP_SECRET data."""
        agent_name = e2e_names["agent"]
        signer_name = e2e_names["signer"]

        try:
            identity = CngIdentity.init(agent_name, data_dir=tmp_path)
            signer = CngSigner.create(f"SelfConnect.{signer_name}")

            bundle = make_bundle(
                policy_id="ceiling-test-v1",
                agents={
                    identity.agent_id: {
                        "role": "worker",
                        "clearance": "SECRET",
                        "allowed_actions": ["read_text"],
                        "max_classification": "SECRET",
                    }
                },
                valid_from=time.time() - 60,
            )

            signed_dict = sign_policy(bundle.to_dict(), signer)
            signed_bundle = PolicyBundle.from_dict(signed_dict)

            enforcer = PolicyEnforcer(
                policy=signed_bundle,
                trust_root_pub=signer.public_key_bytes,
                require_signature=True,
            )

            # SECRET data with SECRET clearance: allowed
            decision_ok = enforcer.check(
                agent_id=identity.agent_id,
                action="read_text",
                classification="SECRET",
            )
            assert decision_ok.allowed is True

            # TOP_SECRET data with SECRET clearance: denied
            decision_ts = enforcer.check(
                agent_id=identity.agent_id,
                action="read_text",
                classification="TOP_SECRET",
            )
            assert decision_ts.allowed is False, \
                "SECURITY VIOLATION: TOP_SECRET data processed by SECRET agent"

        finally:
            cng_delete_key(f"SelfConnect.{agent_name}")
            cng_delete_key(f"SelfConnect.{signer_name}")

    def test_chain_revoked_agent_denied(self, tmp_path, e2e_names):
        """A revoked agent must be denied even for normally-allowed actions."""
        agent_name = e2e_names["agent"]
        signer_name = e2e_names["signer"]

        try:
            identity = CngIdentity.init(agent_name, data_dir=tmp_path)
            signer = CngSigner.create(f"SelfConnect.{signer_name}")

            bundle = make_bundle(
                policy_id="revoke-test-v1",
                agents={
                    identity.agent_id: {
                        "role": "worker",
                        "clearance": "SECRET",
                        "allowed_actions": ["read_text"],
                        "max_classification": "SECRET",
                        "revoked": True,
                    }
                },
                valid_from=time.time() - 60,
            )

            signed_dict = sign_policy(bundle.to_dict(), signer)
            signed_bundle = PolicyBundle.from_dict(signed_dict)

            enforcer = PolicyEnforcer(
                policy=signed_bundle,
                trust_root_pub=signer.public_key_bytes,
                require_signature=True,
            )

            decision = enforcer.check(
                agent_id=identity.agent_id,
                action="read_text",
                classification="UNCLASSIFIED",
            )
            assert decision.allowed is False, \
                "SECURITY VIOLATION: revoked agent was allowed to act"

        finally:
            cng_delete_key(f"SelfConnect.{agent_name}")
            cng_delete_key(f"SelfConnect.{signer_name}")
