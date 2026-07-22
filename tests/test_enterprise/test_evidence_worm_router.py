"""tests/test_enterprise/test_evidence_worm_router.py — Unit tests for
enterprise.evidence_worm_router.

All tests run without network access, AWS credentials, or boto3 actually
touching a remote service: S3 calls are mocked with MagicMock, exactly like
tests/test_enterprise/test_worm_service.py. No test in this file requires
secrets.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from enterprise.evidence_worm_router import (
    DEFAULT_EVIDENCE_ARTIFACTS,
    EvidenceRoutingError,
    build_evidence_record,
    route_evidence_artifacts,
    verify_deletion_denied,
    verify_immutable_sink,
)
from enterprise.provenance import (
    InMemoryWitnessSink,
    ReplicationError,
    S3ObjectLockSink,
)


class FakeNotFound(Exception):
    response = {"Error": {"Code": "404"}}


class FakeAccessDenied(Exception):
    response = {"Error": {"Code": "AccessDenied"}}


def locked_head(*, root: str = "", etag: str = "locked-etag") -> dict:
    metadata = {"root": root} if root else {}
    return {
        "ETag": f'"{etag}"',
        "Metadata": metadata,
        "ObjectLockMode": "COMPLIANCE",
        "ObjectLockRetainUntilDate": datetime.now(timezone.utc) + timedelta(days=365),
    }


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestDefaultArtifactsExistOnDisk:
    def test_every_named_artifact_exists(self):
        """Regression guard: the router must never silently drop a file that
        moved or was renamed — a rename must fail loudly, not skip."""
        missing = [
            rel for rel in DEFAULT_EVIDENCE_ARTIFACTS if not (REPO_ROOT / rel).is_file()
        ]
        assert missing == []

    def test_list_is_non_empty_and_deduplicated(self):
        assert len(DEFAULT_EVIDENCE_ARTIFACTS) > 0
        assert len(DEFAULT_EVIDENCE_ARTIFACTS) == len(set(DEFAULT_EVIDENCE_ARTIFACTS))


class TestBuildEvidenceRecord:
    def test_computes_sha256_and_shape(self, tmp_path):
        f = tmp_path / "evidence.json"
        f.write_text('{"a": 1}', encoding="utf-8")
        record = build_evidence_record(f, "evidence.json", seq=3)
        assert record["seq"] == 3
        assert record["payload"]["type"] == "ha_evidence_artifact"
        assert record["payload"]["relative_path"] == "evidence.json"
        assert record["payload"]["size_bytes"] == len('{"a": 1}')
        assert len(record["payload"]["sha256"]) == 64
        assert record["payload"]["merkle_root"] == record["payload"]["sha256"]

    def test_raises_on_missing_file(self, tmp_path):
        missing = tmp_path / "does-not-exist.md"
        with pytest.raises(EvidenceRoutingError, match="missing from disk"):
            build_evidence_record(missing, "does-not-exist.md", seq=0)


class TestRouteEvidenceArtifactsInMemory:
    def test_routes_every_artifact_once(self, tmp_path):
        a = tmp_path / "a.md"
        b = tmp_path / "b.json"
        a.write_text("alpha", encoding="utf-8")
        b.write_text("beta", encoding="utf-8")
        sink = InMemoryWitnessSink()

        receipts = route_evidence_artifacts(
            sink, ["a.md", "b.json"], session_id="test-session", repo_root=tmp_path
        )

        assert [r.relative_path for r in receipts] == ["a.md", "b.json"]
        assert all(r.receipt for r in receipts)
        assert receipts[0].sha256 != receipts[1].sha256

    def test_stops_on_first_missing_artifact(self, tmp_path):
        a = tmp_path / "a.md"
        a.write_text("alpha", encoding="utf-8")
        sink = InMemoryWitnessSink()

        with pytest.raises(EvidenceRoutingError, match="missing.md"):
            route_evidence_artifacts(
                sink, ["a.md", "missing.md"], session_id="test-session", repo_root=tmp_path
            )

    def test_idempotent_reroute_of_unchanged_content(self, tmp_path):
        a = tmp_path / "a.md"
        a.write_text("alpha", encoding="utf-8")
        sink = InMemoryWitnessSink()

        first = route_evidence_artifacts(
            sink, ["a.md"], session_id="test-session", repo_root=tmp_path
        )
        second = route_evidence_artifacts(
            sink, ["a.md"], session_id="test-session", repo_root=tmp_path
        )
        assert first[0].sha256 == second[0].sha256

    def test_tampered_content_at_same_segment_is_rejected(self, tmp_path):
        """A rewritten evidence artifact must be caught as fork_detected, not
        silently accepted as an overwrite of previously routed evidence."""
        a = tmp_path / "a.md"
        a.write_text("alpha", encoding="utf-8")
        sink = InMemoryWitnessSink()
        route_evidence_artifacts(sink, ["a.md"], session_id="fork-session", repo_root=tmp_path)

        a.write_text("tampered", encoding="utf-8")
        with pytest.raises(ReplicationError, match="fork_detected"):
            route_evidence_artifacts(sink, ["a.md"], session_id="fork-session", repo_root=tmp_path)


class TestRouteEvidenceArtifactsS3:
    def test_routes_through_mocked_s3_object_lock_sink(self, tmp_path):
        a = tmp_path / "a.md"
        a.write_text("alpha", encoding="utf-8")
        digest = hashlib.sha256(b"alpha").hexdigest()

        mock_client = MagicMock()
        # Sequence for one seal-shaped record (payload has merkle_root) under
        # ObjectLockMode: (1) seal-index head miss -> put -> readback confirm,
        # (2) record head miss -> put -> readback confirm.
        mock_client.head_object.side_effect = [
            FakeNotFound(),
            locked_head(root=digest, etag="index-etag"),
            FakeNotFound(),
            locked_head(etag="record-etag"),
        ]
        mock_client.put_object.return_value = {"ETag": '"etag-1"'}
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = S3ObjectLockSink(bucket="ha-evidence-bucket", prefix="scent/audit/")

        receipts = route_evidence_artifacts(
            sink, ["a.md"], session_id="ha-evidence-worm-routing", repo_root=tmp_path
        )
        assert receipts[0].receipt.startswith("s3://ha-evidence-bucket/scent/audit/")

    def test_fork_detected_from_remote_seal_index_with_fresh_sink_instance(self, tmp_path):
        """Mirrors docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md: a second sink
        instance (e.g. a new process) must reject a conflicting root for the
        same (session_id, segment_no) using remote seal-index state, not just
        in-process memory."""
        a = tmp_path / "a.md"
        a.write_text("alpha", encoding="utf-8")
        first_root = hashlib.sha256(b"alpha").hexdigest()

        mock_client = MagicMock()
        mock_client.head_object.side_effect = [
            FakeNotFound(),
            locked_head(root=first_root, etag="index-etag"),
            FakeNotFound(),
            locked_head(etag="record-etag"),
        ]
        mock_client.put_object.return_value = {"ETag": '"etag-1"'}
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink_a = S3ObjectLockSink(bucket="ha-evidence-bucket", prefix="scent/audit/")

        route_evidence_artifacts(
            sink_a, ["a.md"], session_id="ha-evidence-worm-routing", repo_root=tmp_path
        )
        assert sink_a._seal_store[("ha-evidence-worm-routing", 0)] == first_root

        a.write_text("tampered", encoding="utf-8")
        # Fresh sink instance: no in-process seal_store state, so the fork
        # must be caught via the remote seal-index head, not local memory.
        mock_client.head_object.side_effect = [locked_head(root=first_root)]
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink_b = S3ObjectLockSink(bucket="ha-evidence-bucket", prefix="scent/audit/")

        with pytest.raises(ReplicationError, match="fork_detected"):
            route_evidence_artifacts(
                sink_b, ["a.md"], session_id="ha-evidence-worm-routing", repo_root=tmp_path
            )


class TestVerifyImmutableSink:
    def test_rejects_in_memory_sink(self):
        with pytest.raises(EvidenceRoutingError, match="InMemoryWitnessSink"):
            verify_immutable_sink(InMemoryWitnessSink())

    def test_accepts_s3_sink_with_live_object_lock_enabled(self):
        mock_client = MagicMock()
        mock_client.get_object_lock_configuration.return_value = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = S3ObjectLockSink(bucket="ha-evidence-bucket")

        result = verify_immutable_sink(sink)
        assert result["bucket"] == "ha-evidence-bucket"
        assert result["object_lock_enabled"] is True

    def test_raises_when_bucket_lacks_object_lock(self):
        mock_client = MagicMock()
        mock_client.get_object_lock_configuration.side_effect = Exception(
            "ObjectLockConfigurationNotFoundError"
        )
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = S3ObjectLockSink(bucket="ha-evidence-bucket")

        with pytest.raises(EvidenceRoutingError, match="live immutable-retention verification"):
            verify_immutable_sink(sink)


class TestVerifyDeletionDenied:
    def test_denial_is_reported_when_provider_rejects_delete(self):
        mock_client = MagicMock()
        mock_client.delete_object.side_effect = FakeAccessDenied("Access Denied")
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = S3ObjectLockSink(bucket="ha-evidence-bucket")

        result = verify_deletion_denied(sink, "s3://ha-evidence-bucket/scent/audit/a.md.json#etag")
        assert result["delete_denied"] is True
        mock_client.delete_object.assert_called_once_with(
            Bucket="ha-evidence-bucket", Key="scent/audit/a.md.json"
        )

    def test_raises_if_delete_actually_succeeds(self):
        """If a delete is NOT denied, immutability is not enforced — this must
        surface as a hard failure, never as a silent pass."""
        mock_client = MagicMock()
        mock_client.delete_object.return_value = {}
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = S3ObjectLockSink(bucket="ha-evidence-bucket")

        with pytest.raises(EvidenceRoutingError, match="was NOT denied"):
            verify_deletion_denied(sink, "s3://ha-evidence-bucket/scent/audit/a.md.json#etag")

    def test_rejects_malformed_receipt(self):
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = S3ObjectLockSink(bucket="ha-evidence-bucket")
        with pytest.raises(EvidenceRoutingError, match="not an S3-shaped receipt"):
            verify_deletion_denied(sink, "file:not-s3:0")
