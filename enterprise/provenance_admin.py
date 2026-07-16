"""Administrator-only enrollment management for the provenance service."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from enterprise.provenance_ipc import AgentEnrollment, EnrollmentRegistry
from enterprise.provenance_service import ProvenanceServicePaths


def _load_document(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "agents": []}
    registry = EnrollmentRegistry.load(path)
    agents = []
    for item in registry.all_enrollments:
        agents.append({
            "agent_id": item.agent_id,
            "algorithm": item.algorithm,
            "enabled": item.enabled,
            "public_key_hex": item.public_key.hex(),
            "sid": item.sid,
            "supervisor": item.supervisor,
        })
    return {"version": 1, "agents": agents}


def _write_atomic(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    descriptor, raw = tempfile.mkstemp(prefix=".enrollments-", suffix=".tmp", dir=path.parent)
    temp = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _agent_dict(args) -> dict:
    value = {
        "agent_id": args.agent_id,
        "algorithm": args.algorithm,
        "enabled": not args.disabled,
        "public_key_hex": args.public_key_hex,
        "sid": args.sid,
        "supervisor": args.supervisor,
    }
    enrollment = AgentEnrollment.from_dict(value)
    return {
        "agent_id": enrollment.agent_id,
        "algorithm": enrollment.algorithm,
        "enabled": enrollment.enabled,
        "public_key_hex": enrollment.public_key.hex(),
        "sid": enrollment.sid,
        "supervisor": enrollment.supervisor,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        type=Path,
        default=ProvenanceServicePaths.from_env().enrollment_file,
        help="enrollment JSON path",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll")
    enroll.add_argument("--agent-id", required=True)
    enroll.add_argument("--algorithm", choices=["ed25519", "ecdsa-p384-cng"], required=True)
    enroll.add_argument("--public-key-hex", required=True)
    enroll.add_argument("--sid", required=True)
    enroll.add_argument("--supervisor", action="store_true")
    enroll.add_argument("--disabled", action="store_true")
    remove = commands.add_parser("remove")
    remove.add_argument("--agent-id", required=True)
    commands.add_parser("list")
    args = parser.parse_args(argv)

    document = _load_document(args.file)
    if args.command == "list":
        for item in document["agents"]:
            print(json.dumps({
                "agent_id": item["agent_id"],
                "algorithm": item["algorithm"],
                "enabled": item["enabled"],
                "sid": item["sid"],
                "supervisor": item["supervisor"],
            }, sort_keys=True))
        return 0

    agents = [item for item in document["agents"] if item.get("agent_id") != args.agent_id]
    if args.command == "enroll":
        candidate = _agent_dict(args)
        if candidate["supervisor"]:
            agents = [{**item, "supervisor": False} for item in agents]
        agents.append(candidate)
    elif len(agents) == len(document["agents"]):
        parser.error(f"agent {args.agent_id!r} is not enrolled")
    output = {"version": 1, "agents": sorted(agents, key=lambda item: item["agent_id"])}
    # Validate the complete result, not only the changed row.
    EnrollmentRegistry([AgentEnrollment.from_dict(item) for item in output["agents"]])
    _write_atomic(args.file, output)
    print(f"updated {args.file}; restart {os.environ.get('SC_PROVENANCE_SERVICE_NAME', 'SelfConnectProvenance')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
