"""Adversarial tests for owner-authorized, agent-authored action proofs."""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from enterprise.delegation import (
    AgentActionProof,
    DelegationGrant,
    issue_delegation_grant,
    sign_delegated_action,
    verify_delegated_action,
)
from enterprise.identity import AgentIdentity


def _identity(tmp_path, name: str) -> AgentIdentity:
    with (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda value: value[4:]),
    ):
        return AgentIdentity.init(name, data_dir=tmp_path)


class _P384Signer:
    """Ephemeral signer using the P1363 format expected by CNG verification."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP384R1())
        numbers = self._key.public_key().public_numbers()
        self.public_key_bytes = numbers.x.to_bytes(48, "big") + numbers.y.to_bytes(48, "big")

    def sign(self, data: bytes) -> bytes:
        der = self._key.sign(data, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")


@pytest.fixture
def proof_chain(tmp_path):
    owner = _identity(tmp_path, "owner")
    agent = _identity(tmp_path, "agent")
    grant = issue_delegation_grant(
        signer=owner,
        issuer_principal="OWNER:RON",
        subject_public_key=agent.public_key_bytes,
        allowed_actions=("sc_inject_text", "sc_read_output"),
        target_constraints={"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 42},
        governance_mode="enterprise",
        classification_ceiling="UNCLASSIFIED",
        issued_at=1_000.0,
        not_before=1_000.0,
        expires_at=2_000.0,
        revocation_epoch=7,
        nonce="grant-nonce-001",
    )
    proof = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id="action-001",
        action="sc_inject_text",
        target={
            "exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "hwnd": 42,
            "pid": 1234,
        },
        payload=b"Get-Date",
        governance_mode="enterprise",
        classification="UNCLASSIFIED",
        occurred_at=1_500.0,
    )
    return owner, agent, grant, proof


def test_valid_dual_signature_chain_verifies(proof_chain):
    owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(
        grant,
        proof,
        now=1_600.0,
        payload=b"Get-Date",
        trusted_issuer_public_key=owner.public_key_bytes,
        minimum_revocation_epoch=7,
    )
    assert result.ok is True
    assert result.reason == "ok"
    assert result.grant_id == grant.grant_id
    assert result.proof_id == proof.proof_id


def test_p384_authority_and_ed25519_agent_chain_verifies(tmp_path):
    owner = _P384Signer()
    agent = _identity(tmp_path, "p384-grant-agent")
    grant = issue_delegation_grant(
        signer=owner,
        issuer_principal="ENTERPRISE:AUTHORITY",
        subject_public_key=agent.public_key_bytes,
        allowed_actions=("sc_read_output",),
        target_constraints={"hwnd": 42},
        governance_mode="enterprise",
        classification_ceiling="UNCLASSIFIED",
        issued_at=1_000.0,
        not_before=1_000.0,
        expires_at=2_000.0,
        revocation_epoch=3,
        nonce="p384-grant",
    )
    proof = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id="p384-action",
        action="sc_read_output",
        target={"hwnd": 42, "pid": 100},
        payload=b"",
        governance_mode="enterprise",
        classification="UNCLASSIFIED",
        occurred_at=1_500.0,
    )
    result = verify_delegated_action(
        grant,
        proof,
        now=1_600.0,
        payload=b"",
        trusted_issuer_public_key=owner.public_key_bytes,
    )
    assert result.ok is True


def test_round_trip_preserves_grant_and_proof_ids(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    restored_grant = DelegationGrant.from_dict(grant.to_dict())
    restored_proof = AgentActionProof.from_dict(proof.to_dict())
    assert restored_grant == grant
    assert restored_proof == proof
    assert restored_grant.grant_id == grant.grant_id
    assert restored_proof.proof_id == proof.proof_id


def test_wrong_owner_trust_root_is_rejected(tmp_path, proof_chain):
    _owner, _agent, grant, proof = proof_chain
    stranger = _identity(tmp_path, "stranger-owner")
    result = verify_delegated_action(
        grant, proof, now=1_600.0, trusted_issuer_public_key=stranger.public_key_bytes
    )
    assert result.ok is False
    assert "trusted authority" in result.reason


def test_tampered_owner_scope_invalidates_authority_signature(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    tampered = replace(grant, allowed_actions=(*grant.allowed_actions, "sc_admin"))
    result = verify_delegated_action(tampered, proof, now=1_600.0)
    assert result.ok is False
    assert "authority signature" in result.reason


def test_agent_cannot_expand_scope_by_resigning_action(proof_chain):
    _owner, agent, grant, _proof = proof_chain
    expanded = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id="action-admin",
        action="sc_admin",
        target={"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 42},
        payload=b"admin",
        governance_mode="enterprise",
        classification="UNCLASSIFIED",
        occurred_at=1_500.0,
    )
    result = verify_delegated_action(grant, expanded, now=1_600.0)
    assert result.ok is False
    assert "delegated scope" in result.reason


def test_different_agent_cannot_use_grant(tmp_path, proof_chain):
    _owner, _agent, grant, _proof = proof_chain
    other_agent = _identity(tmp_path, "other-agent")
    substituted = sign_delegated_action(
        grant=grant,
        agent_identity=other_agent,
        action_id="action-other",
        action="sc_inject_text",
        target={"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 42},
        payload=b"Get-Date",
        governance_mode="enterprise",
        classification="UNCLASSIFIED",
        occurred_at=1_500.0,
    )
    result = verify_delegated_action(grant, substituted, now=1_600.0)
    assert result.ok is False
    assert "delegated subject" in result.reason


def test_tampered_agent_action_invalidates_agent_signature(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    tampered = replace(proof, action="sc_read_output")
    result = verify_delegated_action(grant, tampered, now=1_600.0)
    assert result.ok is False
    assert "agent action signature" in result.reason


def test_payload_substitution_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(grant, proof, now=1_600.0, payload=b"Remove-Item")
    assert result.ok is False
    assert "payload digest" in result.reason


@pytest.mark.parametrize(
    ("target", "missing_key"),
    [
        ({"exe": "C:/Temp/powershell.exe", "hwnd": 42}, "exe"),
        ({"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 99}, "hwnd"),
    ],
)
def test_target_substitution_is_rejected(proof_chain, target, missing_key):
    _owner, agent, grant, _proof = proof_chain
    substituted = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id=f"target-{missing_key}",
        action="sc_inject_text",
        target=target,
        payload=b"Get-Date",
        governance_mode="enterprise",
        classification="UNCLASSIFIED",
        occurred_at=1_500.0,
    )
    result = verify_delegated_action(grant, substituted, now=1_600.0)
    assert result.ok is False
    assert missing_key in result.reason


def test_expired_grant_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(grant, proof, now=2_001.0)
    assert result.ok is False
    assert "expired" in result.reason


def test_not_yet_valid_grant_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(grant, proof, now=999.0)
    assert result.ok is False
    assert "not yet valid" in result.reason


def test_future_action_timestamp_is_rejected(proof_chain):
    _owner, agent, grant, _proof = proof_chain
    future = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id="future-action",
        action="sc_inject_text",
        target={"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 42},
        payload=b"Get-Date",
        governance_mode="enterprise",
        classification="UNCLASSIFIED",
        occurred_at=1_700.0,
    )
    result = verify_delegated_action(grant, future, now=1_600.0)
    assert result.ok is False
    assert "verification window" in result.reason


def test_revoked_grant_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(
        grant, proof, now=1_600.0, revoked_grant_ids={grant.grant_id}
    )
    assert result.ok is False
    assert "grant is revoked" in result.reason


def test_revoked_agent_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(
        grant, proof, now=1_600.0, revoked_agent_ids={proof.agent_id}
    )
    assert result.ok is False
    assert "agent is revoked" in result.reason


def test_stale_revocation_checkpoint_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(
        grant, proof, now=1_600.0, minimum_revocation_epoch=8
    )
    assert result.ok is False
    assert "checkpoint is stale" in result.reason


def test_replayed_action_id_is_rejected(proof_chain):
    _owner, _agent, grant, proof = proof_chain
    result = verify_delegated_action(
        grant, proof, now=1_600.0, seen_action_ids={proof.action_id}
    )
    assert result.ok is False
    assert "already been consumed" in result.reason


def test_governance_mode_substitution_is_rejected(proof_chain):
    _owner, agent, grant, _proof = proof_chain
    downgraded = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id="mode-downgrade",
        action="sc_inject_text",
        target={"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 42},
        payload=b"Get-Date",
        governance_mode="normal",
        classification="UNCLASSIFIED",
        occurred_at=1_500.0,
    )
    result = verify_delegated_action(grant, downgraded, now=1_600.0)
    assert result.ok is False
    assert "governance mode" in result.reason


def test_classification_substitution_is_rejected(proof_chain):
    _owner, agent, grant, _proof = proof_chain
    relabeled = sign_delegated_action(
        grant=grant,
        agent_identity=agent,
        action_id="classification-change",
        action="sc_inject_text",
        target={"exe": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "hwnd": 42},
        payload=b"Get-Date",
        governance_mode="enterprise",
        classification="SECRET",
        occurred_at=1_500.0,
    )
    result = verify_delegated_action(grant, relabeled, now=1_600.0)
    assert result.ok is False
    assert "classification" in result.reason


def test_serialized_grant_id_tampering_is_rejected(proof_chain):
    _owner, _agent, grant, _proof = proof_chain
    value = grant.to_dict()
    value["grant_id"] = "0" * 64
    with pytest.raises(ValueError, match="grant_id"):
        DelegationGrant.from_dict(value)


def test_duplicate_allowed_actions_are_rejected(proof_chain):
    _owner, _agent, grant, _proof = proof_chain
    with pytest.raises(ValueError, match="duplicates"):
        replace(grant, allowed_actions=("sc_inject_text", "sc_inject_text"))
