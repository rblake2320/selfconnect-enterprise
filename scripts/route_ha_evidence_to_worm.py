#!/usr/bin/env python3
"""scripts/route_ha_evidence_to_worm.py — Route the named HA acceptance and
incident evidence artifacts into the configured immutable WORM sink.

Fail-closed CLI: exits non-zero and prints the exact reason on any missing
artifact, sink misconfiguration, or failed live retention verification.
Never reports success on a partially routed set.

Required environment (see docs/ato/WORM_EVIDENCE_ROUTING_OWNER_CHECKLIST.md):
    SCENT_WORM_SINK=s3 (or r2)
    SCENT_WORM_BUCKET=<dedicated bucket with Object Lock enabled at creation>
    SCENT_WORM_REGION, SCENT_WORM_PREFIX, SCENT_WORM_MIN_RETENTION_DAYS
    AWS credentials resolvable by boto3 (env vars, profile, or role).

Usage:
    python scripts/route_ha_evidence_to_worm.py [--session-id ID] [--verify-only]
"""
from __future__ import annotations

import argparse
import json
import sys

from enterprise.audit_config import AuditConfig
from enterprise.evidence_worm_router import (
    DEFAULT_EVIDENCE_ARTIFACTS,
    EvidenceRoutingError,
    route_evidence_artifacts,
    verify_immutable_sink,
)
from enterprise.provenance import ReplicationError
from enterprise.worm_service import WormServiceError, make_replication_sink


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session-id",
        default="ha-evidence-worm-routing",
        help="WORM session id evidence artifacts are grouped under.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify the sink's live immutable-retention configuration; do not push.",
    )
    args = parser.parse_args(argv)

    config = AuditConfig.from_env()
    try:
        sink = make_replication_sink(config)
    except WormServiceError as exc:
        print(f"FAIL: sink configuration error: {exc}", file=sys.stderr)
        return 2
    if sink is None:
        print(
            "FAIL: SCENT_WORM_SINK=none (or unset); set SCENT_WORM_SINK=s3 or r2 "
            "and SCENT_WORM_BUCKET before routing evidence.",
            file=sys.stderr,
        )
        return 2

    try:
        retention_evidence = verify_immutable_sink(sink)
    except EvidenceRoutingError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    result: dict = {"retention_configuration": retention_evidence}

    if not args.verify_only:
        try:
            receipts = route_evidence_artifacts(
                sink,
                DEFAULT_EVIDENCE_ARTIFACTS,
                session_id=args.session_id,
            )
        except (EvidenceRoutingError, ReplicationError) as exc:
            print(f"FAIL: evidence routing stopped: {exc}", file=sys.stderr)
            return 2
        result["session_id"] = args.session_id
        result["artifacts_routed"] = len(receipts)
        result["receipts"] = [r.to_dict() for r in receipts]

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
