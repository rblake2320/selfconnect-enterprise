from __future__ import annotations

import json

from enterprise.identity import AgentIdentity
from enterprise.policy import PolicyBundle
from enterprise.policy_sign import verify_policy_signature
from tools.create_conformance_fixture import create_fixture


def test_fixture_uses_separate_persistent_actor_and_policy_authority(tmp_path):
    manifest = create_fixture(
        tmp_path,
        agent_name="fixture-actor",
        allowed_app="WindowsTerminal.exe",
        classification="UNCLASSIFIED",
        require_approval=True,
    )
    policy = PolicyBundle.from_file(tmp_path / "policy.json")
    trust_root = bytes.fromhex((tmp_path / "policy-authority-public.hex").read_text().strip())
    actor = AgentIdentity.load("fixture-actor", data_dir=tmp_path / "identities")
    authority = AgentIdentity.load(
        "fixture-actor-policy-authority", data_dir=tmp_path / "identities"
    )

    assert manifest["agent_id"] == actor.agent_id
    assert authority.agent_id != actor.agent_id
    assert json.loads((tmp_path / "policy.json").read_text())["signed_by_pub"] == trust_root.hex()
    assert verify_policy_signature(policy, trust_root)
    agent_policy = policy.get_agent(actor.agent_id)
    assert agent_policy is not None
    assert agent_policy.requires_operator_approval == frozenset({"sc_inject_text"})
    assert not (tmp_path / "action-ledger.jsonl").exists()
