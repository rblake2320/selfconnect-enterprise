"""tests/test_enterprise/test_worm_service.py — Unit tests for enterprise.worm_service."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock
import pytest

from enterprise.audit_config import AuditConfig, AuditMode, WormSinkType
from enterprise.provenance import InMemoryWitnessSink, ProvenanceRecorder
from enterprise.worm_service import (
    FileReplicationSink,
    WormServiceError,
    build_provenance_recorder,
    make_replication_sink,
)


# ---------------------------------------------------------------------------
# make_replication_sink
# ---------------------------------------------------------------------------

class TestMakeReplicationSinkMemory:
    def test_returns_in_memory_witness_sink(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        sink = make_replication_sink(cfg)
        assert isinstance(sink, InMemoryWitnessSink)

    def test_memory_sink_is_fresh_instance(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        s1 = make_replication_sink(cfg)
        s2 = make_replication_sink(cfg)
        assert s1 is not s2


class TestMakeReplicationSinkNone:
    def test_returns_none_for_none_sink(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.NONE)
        sink = make_replication_sink(cfg)
        assert sink is None


class TestMakeReplicationSinkFile:
    def test_returns_file_sink(self, tmp_path):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.FILE,
            worm_file_dir=str(tmp_path),
        )
        sink = make_replication_sink(cfg)
        assert isinstance(sink, FileReplicationSink)

    def test_raises_if_file_dir_empty(self):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.FILE,
            worm_file_dir="",
        )
        with pytest.raises(WormServiceError, match="SCENT_WORM_FILE_DIR"):
            make_replication_sink(cfg)


class TestMakeReplicationSinkS3:
    def test_raises_if_boto3_absent(self):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.S3,
            worm_bucket="my-bucket",
        )
        with patch.dict("sys.modules", {"boto3": None}):
            with pytest.raises(WormServiceError, match="boto3"):
                make_replication_sink(cfg)

    def test_raises_if_bucket_empty_even_with_boto3(self):
        """Even if boto3 is present, missing bucket should raise."""
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.S3,
            worm_bucket="",
        )
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            with pytest.raises(WormServiceError, match="SCENT_WORM_BUCKET"):
                make_replication_sink(cfg)

    def test_returns_s3_sink_when_boto3_available(self):
        from enterprise.provenance import S3ObjectLockSink
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.S3,
            worm_bucket="audit-bucket",
            worm_prefix="test/",
        )
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = make_replication_sink(cfg)
        assert isinstance(sink, S3ObjectLockSink)
        assert sink.bucket == "audit-bucket"
        assert sink.prefix == "test/"


class TestMakeReplicationSinkR2:
    def test_raises_if_boto3_absent(self):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.R2,
            worm_bucket="r2-bucket",
        )
        with patch.dict("sys.modules", {"boto3": None}):
            with pytest.raises(WormServiceError, match="boto3"):
                make_replication_sink(cfg)

    def test_raises_if_bucket_empty_even_with_boto3(self):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.R2,
            worm_bucket="",
        )
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            with pytest.raises(WormServiceError, match="SCENT_WORM_BUCKET"):
                make_replication_sink(cfg)

    def test_returns_r2_sink_when_boto3_available(self):
        from enterprise.provenance import CloudflareR2Sink
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.R2,
            worm_bucket="r2-audit",
            worm_prefix="r2/",
        )
        mock_boto3 = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            sink = make_replication_sink(cfg)
        assert isinstance(sink, CloudflareR2Sink)
        assert sink.bucket == "r2-audit"


# ---------------------------------------------------------------------------
# build_provenance_recorder
# ---------------------------------------------------------------------------

class TestBuildProvenanceRecorder:
    def test_returns_provenance_recorder_for_memory(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-001")
        assert isinstance(recorder, ProvenanceRecorder)
        assert recorder.session_id == "test-session-001"

    def test_recorder_has_memory_sink(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-002")
        assert isinstance(recorder._replication_sink, InMemoryWitnessSink)

    def test_recorder_none_sink_has_no_replication(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.NONE)
        recorder = build_provenance_recorder(cfg, "test-session-003")
        assert recorder._replication_sink is None

    def test_raises_worm_service_error_government_with_none_sink(self):
        cfg = AuditConfig(audit_mode=AuditMode.GOVERNMENT, worm_sink=WormSinkType.NONE)
        with pytest.raises(WormServiceError, match="government"):
            build_provenance_recorder(cfg, "test-session-004")

    def test_enterprise_memory_sink_logs_warning(self, caplog):
        import logging
        cfg = AuditConfig(audit_mode=AuditMode.ENTERPRISE, worm_sink=WormSinkType.MEMORY)
        with caplog.at_level(logging.WARNING, logger="enterprise.worm_service"):
            recorder = build_provenance_recorder(cfg, "test-session-005")
        assert any("AU-9" in r.message for r in caplog.records)
        assert isinstance(recorder, ProvenanceRecorder)

    def test_government_mode_with_memory_sink_succeeds(self):
        """Government + memory sink should succeed (memory is a valid sink, not NONE)."""
        cfg = AuditConfig(audit_mode=AuditMode.GOVERNMENT, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-006")
        assert isinstance(recorder, ProvenanceRecorder)
        assert isinstance(recorder._replication_sink, InMemoryWitnessSink)

    def test_recorder_agent_id_set(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-007")
        assert recorder._agent_id == "scent-service"

    def test_recorder_audit_mode_consumer_mapped(self):
        from enterprise.provenance import AuditMode as PAuditMode
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-008")
        assert recorder._audit_mode == PAuditMode.CONSUMER

    def test_recorder_audit_mode_enterprise_mapped(self):
        from enterprise.provenance import AuditMode as PAuditMode
        cfg = AuditConfig(audit_mode=AuditMode.ENTERPRISE, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-009")
        assert recorder._audit_mode == PAuditMode.ENTERPRISE

    def test_recorder_audit_mode_government_mapped_to_military(self):
        from enterprise.provenance import AuditMode as PAuditMode
        cfg = AuditConfig(audit_mode=AuditMode.GOVERNMENT, worm_sink=WormSinkType.MEMORY)
        recorder = build_provenance_recorder(cfg, "test-session-010")
        assert recorder._audit_mode == PAuditMode.MILITARY


# ---------------------------------------------------------------------------
# FileReplicationSink
# ---------------------------------------------------------------------------

class TestFileReplicationSink:
    def test_creates_directory_if_not_exists(self, tmp_path):
        new_dir = tmp_path / "audit" / "sub"
        FileReplicationSink(str(new_dir))
        assert new_dir.exists()

    def test_push_creates_file(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        record = {
            "seq": 1,
            "session_id": "sess-abc",
            "event_type": "tool_call",
            "payload": {"tool": "bash"},
            "prev_hash": "0" * 96,
            "ts": "2026-01-01T00:00:00+00:00",
            "agent_id": "forge",
        }
        sink.push("sess-abc", 0, record)
        session_file = tmp_path / "sess-abc.ndjson"
        assert session_file.exists()

    def test_push_returns_receipt_string(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        record = {
            "seq": 5,
            "session_id": "sess-xyz",
            "event_type": "tool_call",
            "payload": {},
            "prev_hash": "0" * 96,
            "ts": "2026-01-01T00:00:00+00:00",
            "agent_id": "forge",
        }
        receipt = sink.push("sess-xyz", 0, record)
        assert receipt.startswith("file:sess-xyz:5")

    def test_push_writes_valid_json_line(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        record = {
            "seq": 1,
            "session_id": "sess-json",
            "event_type": "tool_call",
            "payload": {"key": "value"},
            "prev_hash": "0" * 96,
            "ts": "2026-01-01T00:00:00+00:00",
            "agent_id": "forge",
        }
        sink.push("sess-json", 0, record)
        session_file = tmp_path / "sess-json.ndjson"
        lines = session_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["event_type"] == "tool_call"
        assert parsed["seq"] == 1

    def test_push_multiple_events_appends_lines(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        for i in range(5):
            record = {
                "seq": i + 1,
                "session_id": "sess-multi",
                "event_type": "tool_call",
                "payload": {},
                "prev_hash": "0" * 96,
                "ts": "2026-01-01T00:00:00+00:00",
                "agent_id": "forge",
            }
            sink.push("sess-multi", 0, record)
        session_file = tmp_path / "sess-multi.ndjson"
        lines = [ln for ln in session_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 5

    def test_push_seal_record_creates_segment_file(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        seal_record = {
            "seq": 100,
            "session_id": "sess-seal",
            "event_type": "merkle_seal",
            "payload": {"merkle_root": "abc123", "sealed_events": 100, "segment_no": 1},
            "prev_hash": "0" * 96,
            "ts": "2026-01-01T00:00:00+00:00",
            "agent_id": "forge",
        }
        sink.push("sess-seal", 1, seal_record)
        seg_file = tmp_path / "sess-seal.seg000001.ndjson"
        assert seg_file.exists()

    def test_each_event_line_is_valid_json(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        records = [
            {
                "seq": i,
                "session_id": "sess-valid",
                "event_type": "shell_exec",
                "payload": {"cmd": f"echo {i}"},
                "prev_hash": "0" * 96,
                "ts": "2026-01-01T00:00:00+00:00",
                "agent_id": "forge",
            }
            for i in range(1, 4)
        ]
        for r in records:
            sink.push("sess-valid", 0, r)
        session_file = tmp_path / "sess-valid.ndjson"
        for line in session_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                parsed = json.loads(line)
                assert "event_type" in parsed

    def test_close_does_not_raise(self, tmp_path):
        sink = FileReplicationSink(str(tmp_path))
        sink.close()  # Should not raise


# ---------------------------------------------------------------------------
# WRAITH security regression — _write_merkle_seal fail-closed (HIGH)
# ---------------------------------------------------------------------------

class TestMerkleSealFailClosed:
    """Regression: _write_merkle_seal must not silently swallow OSError in
    enterprise/military modes (WRAITH finding — error swallowing)."""

    def test_merkle_seal_oserror_raises_in_enterprise_mode(self, tmp_path):
        """Enterprise mode: OSError reading the log for Merkle computation must
        propagate as ProvenanceRecorderError, not silently return."""
        from enterprise.provenance import (
            AuditMode as PAuditMode,
            ProvenanceRecorder,
            ProvenanceRecorderError,
        )

        recorder = ProvenanceRecorder(
            session_id="seal-test-ent",
            agent_id="wraith",
            audit_mode=PAuditMode.ENTERPRISE,
            log_dir=tmp_path,
            seal_interval=1000,  # suppress automatic seal
        )
        recorder.start()
        # Force the log path to a non-existent location so the open() inside
        # _write_merkle_seal raises OSError.
        recorder._log_path = tmp_path / "nonexistent_dir" / "nofile.jsonl"

        with pytest.raises(ProvenanceRecorderError, match="Merkle seal failed"):
            recorder._write_merkle_seal(final=False)

    def test_merkle_seal_oserror_raises_in_military_mode(self, tmp_path):
        """Military mode: same fail-closed behaviour."""
        from enterprise.provenance import (
            AuditMode as PAuditMode,
            InMemoryWitnessSink,
            ProvenanceRecorder,
            ProvenanceRecorderError,
        )

        recorder = ProvenanceRecorder(
            session_id="seal-test-mil",
            agent_id="wraith",
            audit_mode=PAuditMode.MILITARY,
            log_dir=tmp_path,
            seal_interval=1000,
            replication_sink=InMemoryWitnessSink(),
        )
        recorder.start()
        recorder._log_path = tmp_path / "nonexistent_dir" / "nofile.jsonl"

        with pytest.raises(ProvenanceRecorderError, match="Merkle seal failed"):
            recorder._write_merkle_seal(final=False)

    def test_merkle_seal_oserror_returns_silently_in_consumer_mode(self, tmp_path):
        """Consumer mode: OSError from _write_merkle_seal should NOT raise —
        best-effort only."""
        from enterprise.provenance import AuditMode as PAuditMode, ProvenanceRecorder

        recorder = ProvenanceRecorder(
            session_id="seal-test-consumer",
            agent_id="wraith",
            audit_mode=PAuditMode.CONSUMER,
            log_dir=tmp_path,
            seal_interval=1000,
        )
        recorder.start()
        recorder._log_path = tmp_path / "nonexistent_dir" / "nofile.jsonl"

        # Should not raise in consumer mode
        recorder._write_merkle_seal(final=False)
