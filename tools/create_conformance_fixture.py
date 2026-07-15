"""Create a bounded, real-cryptography fixture for live conformance runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from enterprise.identity import AgentIdentity
from enterprise.policy import make_bundle
from enterprise.policy_sign import sign_policy


def create_fixture(
    output_dir: Path,
    *,
    agent_name: str,
    allowed_app: str,
    classification: str,
    require_approval: bool,
) -> dict[str, str]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    identity_dir = output_dir / "identities"
    actor = (
        AgentIdentity.load(agent_name, data_dir=identity_dir)
        if AgentIdentity.exists(agent_name, data_dir=identity_dir)
        else AgentIdentity.init(agent_name, data_dir=identity_dir)
    )
    authority_name = f"{agent_name}-policy-authority"
    authority = (
        AgentIdentity.load(authority_name, data_dir=identity_dir)
        if AgentIdentity.exists(authority_name, data_dir=identity_dir)
        else AgentIdentity.init(authority_name, data_dir=identity_dir)
    )
    policy_id = f"conformance-{actor.agent_id.lower()}-v1"
    actions = ["sc_inject_text", "sc_read_output"]
    bundle = make_bundle(
        policy_id,
        agents={
            actor.agent_id: {
                "role": "conformance-actor",
                "clearance": classification,
                "allowed_targets": [],
                "allowed_apps": [allowed_app],
                "blocked_apps": [],
                "allowed_actions": actions,
                "requires_operator_approval": ["sc_inject_text"] if require_approval else [],
                "max_classification": classification,
                "revoked": False,
            }
        },
        signed_by=authority.agent_id,
    )
    policy_path = output_dir / "policy.json"
    trust_root_path = output_dir / "policy-authority-public.hex"
    ledger_path = output_dir / "action-ledger.jsonl"
    policy_path.write_text(json.dumps(sign_policy(bundle.to_dict(), authority), indent=2), encoding="utf-8")
    trust_root_path.write_text(authority.public_key_bytes.hex() + "\n", encoding="ascii")
    manifest = {
        "agent_id": actor.agent_id,
        "agent_name": agent_name,
        "policy_id": policy_id,
        "allowed_app": allowed_app,
        "classification": classification,
        "requires_approval": str(require_approval).lower(),
        "identity_dir": str(identity_dir),
        "policy": str(policy_path),
        "trust_root": str(trust_root_path),
        "ledger": str(ledger_path),
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--agent-name", default="live-conformance-actor")
    parser.add_argument("--allowed-app", default="WindowsTerminal.exe")
    parser.add_argument("--classification", choices=("UNCLASSIFIED", "CUI"), default="UNCLASSIFIED")
    parser.add_argument("--require-approval", action="store_true")
    args = parser.parse_args()
    manifest = create_fixture(
        args.output_dir,
        agent_name=args.agent_name,
        allowed_app=args.allowed_app,
        classification=args.classification,
        require_approval=args.require_approval,
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
