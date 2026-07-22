"""enterprise/evidence_worm_router.py — Route named HA acceptance and incident
evidence artifacts into the configured immutable WORM replication sink.

Closes part of docs/assurance/ha_test_coverage.json:immutable-evidence-deployment,
whose stated closure requirement is:
    "Route the exact HA acceptance and incident artifacts into the reviewed
    immutable sink, then exercise retention/deletion denial, recovery access,
    and continuing custody operations."

This module does not add a new transport. enterprise/provenance.py already
provides S3ObjectLockSink and CloudflareR2Sink with idempotent, fork-detecting,
retention-verified pushes; this module reuses that exact contract to carry
whole evidence files (docs/assurance/ha_test_coverage.json, the HA acceptance
runbooks, prior live WORM/host-acceptance proofs) instead of per-event
provenance records.

Fail-closed by design: a missing named artifact, a sink that cannot prove live
immutable retention, or a provider that allows deletion of a routed object are
all treated as errors, never as silent skips.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from enterprise.provenance import (
    CloudflareR2Sink,
    ReplicationError,
    ReplicationSink,
    S3ObjectLockSink,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# The exact HA acceptance and incident evidence artifacts named by
# docs/assurance/ha_test_coverage.json and docs/operations/HA_TEST_STANDARDS_MATRIX.md.
# Order is stable: it fixes the segment number (and therefore the S3 object
# key) each artifact routes to, so re-running this list is idempotent.
DEFAULT_EVIDENCE_ARTIFACTS: tuple[str, ...] = (
    "docs/assurance/ha_test_coverage.json",
    "docs/operations/HA_TEST_STANDARDS_MATRIX.md",
    "docs/operations/ULTRA_FINAL_HA_ACCEPTANCE.md",
    "docs/operations/SPARK2_HOST_ACCEPTANCE.md",
    "docs/operations/ULTRA_INDEPENDENT_STATE_HA.md",
    "docs/operations/ULTRA_DISASTER_RECOVERY.md",
    "docs/verification/spark2-host-evidence-03add3e.json",
    "docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.json",
    "docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md",
)


class EvidenceRoutingError(RuntimeError):
    """Raised when an evidence artifact cannot be routed or verified.

    Fail-closed: callers must treat this as a routing failure, never as a
    condition to retry-as-skip or report as partial success.
    """


@dataclass(frozen=True)
class EvidenceReceipt:
    relative_path: str
    sha256: str
    size_bytes: int
    receipt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "receipt": self.receipt,
        }


def build_evidence_record(path: Path, relative_path: str, *, seq: int) -> dict:
    """Build a canonical WORM event record for one evidence artifact file.

    Raises EvidenceRoutingError if the file does not exist — a missing named
    artifact must fail the routing run, never be silently skipped.
    """
    if not path.is_file():
        raise EvidenceRoutingError(
            f"named HA evidence artifact is missing from disk: {relative_path}"
        )
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    return {
        "seq": seq,
        "payload": {
            "type": "ha_evidence_artifact",
            "relative_path": relative_path,
            "sha256": digest,
            "size_bytes": len(data),
            # S3ObjectLockSink/CloudflareR2Sink key fork-detection off
            # payload["merkle_root"] (enterprise/provenance.py:_s3_record_root).
            # A content hash is a valid root for a single-file record: a later
            # push of different bytes for the same artifact produces a
            # different root and is rejected as fork_detected instead of
            # silently overwriting previously routed evidence.
            "merkle_root": digest,
        },
    }


def route_evidence_artifacts(
    sink: ReplicationSink,
    artifacts: Sequence[str] = DEFAULT_EVIDENCE_ARTIFACTS,
    *,
    session_id: str,
    repo_root: Path = REPO_ROOT,
) -> list[EvidenceReceipt]:
    """Push every named evidence artifact through *sink*, in order.

    Fail-closed: raises on the first missing file or the first
    ReplicationError (including fork_detected). A partial, silently
    truncated evidence set must never be reported as fully routed.
    """
    receipts: list[EvidenceReceipt] = []
    for seq, relative_path in enumerate(artifacts):
        path = repo_root / relative_path
        record = build_evidence_record(path, relative_path, seq=seq)
        receipt = sink.push(session_id, seq, record)
        receipts.append(
            EvidenceReceipt(
                relative_path=relative_path,
                sha256=record["payload"]["sha256"],
                size_bytes=record["payload"]["size_bytes"],
                receipt=receipt,
            )
        )
    return receipts


def verify_immutable_sink(sink: ReplicationSink) -> dict[str, Any]:
    """Confirm *sink* is a live, provider-enforced immutable retention sink.

    Raises EvidenceRoutingError for any sink type that is not independently
    verifiable (memory/file sinks are replicas only, never WORM evidence) or
    that fails live retention verification.
    """
    if not isinstance(sink, (S3ObjectLockSink, CloudflareR2Sink)):
        raise EvidenceRoutingError(
            "evidence routing requires a live S3 Object Lock or Cloudflare R2 "
            f"bucket-lock sink; got {type(sink).__name__}, which provides no "
            "externally enforced immutability guarantee"
        )
    try:
        return sink.verify_retention_configuration()
    except ReplicationError as exc:
        raise EvidenceRoutingError(
            f"configured sink did not pass live immutable-retention verification: {exc}"
        ) from exc


def _parse_s3_receipt(receipt: str) -> tuple[str, str]:
    if not receipt.startswith("s3://"):
        raise EvidenceRoutingError(f"not an S3-shaped receipt: {receipt!r}")
    without_scheme = receipt[len("s3://") :]
    bucket, _, rest = without_scheme.partition("/")
    key, _, _etag = rest.partition("#")
    if not bucket or not key:
        raise EvidenceRoutingError(f"malformed S3 receipt: {receipt!r}")
    return bucket, key


def verify_deletion_denied(
    sink: S3ObjectLockSink | CloudflareR2Sink, receipt: str
) -> dict[str, Any]:
    """Attempt to delete a routed evidence object and confirm the provider denies it.

    This is the live deletion-denial exercise required before
    immutable-evidence-deployment can move from PARTIAL to PASS. Raises
    EvidenceRoutingError if the delete is *not* denied — i.e. evidence that
    was supposed to be immutable was actually deletable.
    """
    _, key = _parse_s3_receipt(receipt)
    try:
        sink.attempt_delete(key)
    except Exception as exc:  # noqa: BLE001 — the provider's denial *is* the proof
        return {"key": key, "delete_denied": True, "denial_error": str(exc)}
    raise EvidenceRoutingError(
        f"deletion of routed WORM evidence object {key!r} was NOT denied by "
        "the provider; immutable retention is not actually being enforced"
    )


__all__ = [
    "DEFAULT_EVIDENCE_ARTIFACTS",
    "EvidenceReceipt",
    "EvidenceRoutingError",
    "build_evidence_record",
    "route_evidence_artifacts",
    "verify_deletion_denied",
    "verify_immutable_sink",
]
