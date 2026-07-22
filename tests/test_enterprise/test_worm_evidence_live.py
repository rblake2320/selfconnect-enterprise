"""tests/test_enterprise/test_worm_evidence_live.py — Live drill: route the
exact HA acceptance/incident evidence artifacts into a real immutable WORM
sink and prove retention, fork-detection, and deletion-denial against the
live provider.

This is intentionally NOT run by default. It requires a dedicated bucket
created with S3 Object Lock enabled (or an R2 bucket-lock rule), real
credentials, and network access — see
docs/ato/WORM_EVIDENCE_ROUTING_OWNER_CHECKLIST.md for the exact owner inputs.

Behavior mirrors the existing tests/test_e2e_ultra_gate.py convention:
  - Not explicitly requested (SCENT_REQUIRE_WORM_LIVE unset/!= "1"): skip with
    a fixed, reviewed reason if the live sink isn't configured.
  - Explicitly requested (SCENT_REQUIRE_WORM_LIVE=1) but the live sink is NOT
    configured: raise at collection time. This is a hard failure, not a skip
    — the whole point of an explicit request is that "credentials are
    missing" must never be reported as passing or as an ordinary skip.
"""
from __future__ import annotations

import os

import pytest

from enterprise.audit_config import AuditConfig, WormSinkType
from enterprise.evidence_worm_router import (
    DEFAULT_EVIDENCE_ARTIFACTS,
    route_evidence_artifacts,
    verify_deletion_denied,
    verify_immutable_sink,
)
from enterprise.worm_service import make_replication_sink


def _live_worm_config() -> AuditConfig | None:
    config = AuditConfig.from_env()
    if config.worm_sink not in (WormSinkType.S3, WormSinkType.R2):
        return None
    if not config.worm_bucket:
        return None
    return config


_LIVE_CONFIG = _live_worm_config()

if os.environ.get("SCENT_REQUIRE_WORM_LIVE") == "1" and _LIVE_CONFIG is None:
    raise RuntimeError(
        "SCENT_REQUIRE_WORM_LIVE=1 but no live WORM sink is configured. Set "
        "SCENT_WORM_SINK=s3 (or r2), SCENT_WORM_BUCKET=<dedicated bucket with "
        "Object Lock enabled at creation>, SCENT_WORM_REGION, and provide "
        "AWS/R2 credentials resolvable by boto3. See "
        "docs/ato/WORM_EVIDENCE_ROUTING_OWNER_CHECKLIST.md."
    )

pytestmark = pytest.mark.skipif(
    _LIVE_CONFIG is None,
    reason="live WORM evidence sink not configured (set SCENT_WORM_SINK/SCENT_WORM_BUCKET)",
)


@pytest.fixture(scope="module")
def live_sink():
    assert _LIVE_CONFIG is not None
    sink = make_replication_sink(_LIVE_CONFIG)
    assert sink is not None
    return sink


def test_live_sink_has_provider_enforced_retention(live_sink):
    evidence = verify_immutable_sink(live_sink)
    assert evidence["backend"] in ("s3", "r2")
    assert evidence["bucket"] == _LIVE_CONFIG.worm_bucket


def test_live_routing_covers_every_named_evidence_artifact(live_sink):
    session_id = f"ha-evidence-worm-routing-live-{os.getpid()}"
    receipts = route_evidence_artifacts(live_sink, DEFAULT_EVIDENCE_ARTIFACTS, session_id=session_id)
    assert len(receipts) == len(DEFAULT_EVIDENCE_ARTIFACTS)
    for artifact, receipt in zip(DEFAULT_EVIDENCE_ARTIFACTS, receipts):
        assert receipt.relative_path == artifact
        assert receipt.receipt

    # Idempotent re-route of unchanged content must not raise fork_detected.
    reroute = route_evidence_artifacts(live_sink, DEFAULT_EVIDENCE_ARTIFACTS, session_id=session_id)
    assert [r.sha256 for r in reroute] == [r.sha256 for r in receipts]


def test_live_deletion_of_routed_evidence_is_denied(live_sink):
    session_id = f"ha-evidence-worm-deletion-denial-{os.getpid()}"
    receipts = route_evidence_artifacts(
        live_sink, DEFAULT_EVIDENCE_ARTIFACTS[:1], session_id=session_id
    )
    result = verify_deletion_denied(live_sink, receipts[0].receipt)
    assert result["delete_denied"] is True
