"""enterprise/worm_service.py — Factory for WORM replication sinks and ProvenanceRecorder.

Maps AuditConfig (enterprise/audit_config.py) to the correct ReplicationSink
implementation and wires it into a ProvenanceRecorder.

AuditMode mapping to provenance.AuditMode:
    audit_config.CONSUMER    → provenance.AuditMode.CONSUMER
    audit_config.ENTERPRISE  → provenance.AuditMode.ENTERPRISE
    audit_config.GOVERNMENT  → provenance.AuditMode.MILITARY  (fail-closed)
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Optional

from enterprise.audit_config import AuditConfig, AuditMode, WormSinkType
from enterprise.provenance import (
    CloudflareR2Sink,
    InMemoryWitnessSink,
    ProvenanceRecorder,
    ReplicationSink,
    S3ObjectLockSink,
)
from enterprise.provenance import AuditMode as ProvenanceAuditMode

logger = logging.getLogger(__name__)


class WormServiceError(RuntimeError):
    """Raised when the WORM service cannot satisfy the configured audit mode."""


# ---------------------------------------------------------------------------
# AuditMode mapping
# ---------------------------------------------------------------------------

_MODE_MAP: dict[AuditMode, ProvenanceAuditMode] = {
    AuditMode.CONSUMER: ProvenanceAuditMode.CONSUMER,
    AuditMode.ENTERPRISE: ProvenanceAuditMode.ENTERPRISE,
    AuditMode.GOVERNMENT: ProvenanceAuditMode.MILITARY,
}


def _to_provenance_mode(audit_mode: AuditMode) -> ProvenanceAuditMode:
    return _MODE_MAP.get(audit_mode, ProvenanceAuditMode.CONSUMER)


# ---------------------------------------------------------------------------
# FileReplicationSink — simple NDJSON append sink (no cloud dependency)
# ---------------------------------------------------------------------------

class FileReplicationSink(ReplicationSink):
    """Append-only NDJSON file sink for WORM replication.

    Writes one JSON line per event to a .ndjson file under *file_dir*.
    Uses write-to-temp + atomic rename-on-segment-close semantics: individual
    event records are flushed immediately (append mode); the rename-on-close
    path is reserved for segment seal records to produce an immutable segment
    file.

    Thread safety: protected by an internal RLock.
    """

    def __init__(self, file_dir: str) -> None:
        self._dir = Path(file_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._active_path: Optional[Path] = None

    def _session_path(self, session_id: str) -> Path:
        return self._dir / f"{session_id}.ndjson"

    def push(self, session_id: str, segment_no: int, record: dict) -> str:
        """Append *record* as a JSON line to the session NDJSON file.

        Returns a receipt string of the form ``file:<session_id>:<seq>``.
        """
        with self._lock:
            target = self._session_path(session_id)
            line = json.dumps(record, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
            # Use a temp file in the same directory for atomic write, then
            # rename if this is a seal record to produce an immutable segment.
            payload = record.get("payload", {})
            is_seal = "merkle_root" in payload

            if is_seal:
                # Segment seal: write to a named segment file via atomic rename.
                seg_path = self._dir / f"{session_id}.seg{segment_no:06d}.ndjson"
                tmp_fd, tmp_name = tempfile.mkstemp(dir=self._dir, suffix=".tmp")
                try:
                    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                    os.replace(tmp_name, seg_path)
                except Exception:
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
            else:
                # Regular event: append directly to the session file.
                with open(target, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()

            seq = record.get("seq", "?")
            return f"file:{session_id}:{seq}"

    def close(self) -> None:
        pass  # No persistent handles to close


# ---------------------------------------------------------------------------
# make_replication_sink
# ---------------------------------------------------------------------------

def make_replication_sink(config: AuditConfig) -> Optional[ReplicationSink]:
    """Return the correct ReplicationSink for *config*, or None for NONE sink.

    Raises WormServiceError if:
    - S3/R2 sink is requested but boto3 is not installed.
    - FILE sink is requested but worm_file_dir is empty/invalid.
    """
    sink_type = config.worm_sink

    if sink_type == WormSinkType.NONE:
        return None

    if sink_type == WormSinkType.MEMORY:
        return InMemoryWitnessSink()

    if sink_type == WormSinkType.FILE:
        file_dir = config.worm_file_dir
        if not file_dir:
            raise WormServiceError(
                "FILE sink requires SCENT_WORM_FILE_DIR to be set."
            )
        return FileReplicationSink(file_dir)

    if sink_type == WormSinkType.S3:
        try:
            import boto3  # noqa: F401
        except ImportError:
            raise WormServiceError(
                "S3 WORM sink requires boto3. Install with: pip install boto3"
            )
        if not config.worm_bucket:
            raise WormServiceError(
                "S3 sink requires SCENT_WORM_BUCKET to be set."
            )
        return S3ObjectLockSink(
            bucket=config.worm_bucket,
            prefix=config.worm_prefix,
            region_name=config.worm_region,
        )

    if sink_type == WormSinkType.R2:
        try:
            import boto3  # noqa: F401
        except ImportError:
            raise WormServiceError(
                "R2 WORM sink requires boto3 (S3-compatible). Install with: pip install boto3"
            )
        if not config.worm_bucket:
            raise WormServiceError(
                "R2 sink requires SCENT_WORM_BUCKET to be set."
            )
        return CloudflareR2Sink(
            bucket=config.worm_bucket,
            prefix=config.worm_prefix,
            endpoint_url=config.worm_endpoint,
            region_name=config.worm_region,
        )

    # Unknown sink type — should not happen given enum validation in AuditConfig.
    raise WormServiceError(f"Unknown WORM sink type: {sink_type!r}")


# ---------------------------------------------------------------------------
# build_provenance_recorder
# ---------------------------------------------------------------------------

def build_provenance_recorder(config: AuditConfig, session_id: str) -> ProvenanceRecorder:
    """Build a ProvenanceRecorder wired with the correct ReplicationSink.

    Raises WormServiceError if:
    - config.fail_closed_without_worm() is True and no real sink is available.
    - The configured sink cannot be instantiated (e.g., missing boto3).
    """
    sink: Optional[ReplicationSink]

    try:
        sink = make_replication_sink(config)
    except WormServiceError:
        if config.fail_closed_without_worm():
            raise
        logger.warning(
            "WORM sink creation failed in %s mode; falling back to no replication.",
            config.audit_mode.value,
        )
        sink = None

    # Government mode: refuse to start without a real sink (fail-closed).
    if config.fail_closed_without_worm() and sink is None:
        raise WormServiceError(
            "government audit mode requires a WORM replication sink. "
            "Configure SCENT_WORM_SINK to one of: memory, file, s3, r2."
        )

    # Enterprise mode with only memory sink: AU-9 compliance warning.
    if (
        config.audit_mode == AuditMode.ENTERPRISE
        and isinstance(sink, InMemoryWitnessSink)
    ):
        logger.warning(
            "AU-9 compliance warning: enterprise mode is using InMemoryWitnessSink. "
            "Off-host WORM replication (file, s3, r2) is required for AU-9."
        )

    provenance_mode = _to_provenance_mode(config.audit_mode)

    return ProvenanceRecorder(
        session_id=session_id,
        agent_id="scent-service",
        audit_mode=provenance_mode,
        replication_sink=sink,
    )
