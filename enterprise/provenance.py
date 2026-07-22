"""enterprise.provenance — Tamper-evident session provenance for SelfConnect agents.

SECURITY DESIGN
---------------
This module implements the evidence foundation for SelfConnect agent sessions.
The core principle: the audited process is NOT the auditor.

Agents submit events via ProvenanceRecorder.record(). They never hold a direct
file handle to the ledger. A hardened deployment must run the recorder under a
separate Windows service identity and enforce filesystem/service ACLs. The
in-process implementation exercises record signing and chain verification; it
does not establish that process-isolation boundary.

THREAT MODEL — 13 adversarial fixes implemented
-------------------------------------------------
Fix 1:  Session states (OPEN/SEALED/INTERRUPTED/RECONSTRUCTED) + signed heartbeat.
        Missing SESSION_CLOSE alone does not mean tampering — it may mean crash.
        Explicit states + high-water marks distinguish crash from truncation.

Fix 2:  Manifest signed + compared against remote witness receipts.
        Local manifest rollback is detectable only via external anchor.

Fix 3:  Remote witness rejects forked segment roots for same (session_id, seg_no).
        Prevents maintaining two valid histories for the same session.

Fix 4:  Canonical serialization: ensure_ascii=True, sort_keys, no floats.
        Prevents encoding-ambiguity signature bypass.

Fix 5:  Named pipe: strict DACL + per-session random name + challenge-response.
        Client uses SECURITY_IDENTIFICATION to prevent token theft.
        (Documented in sc_shell.py; enforced in Phase 2 Windows service.)

Fix 6:  Per-event signature verification — unsigned events from registered agents
        are rejected by the recorder.

Fix 7:  close() requires orchestrator token — agent cannot close its own audit.

Fix 8:  Event-type-to-identity binding — privileged events (APPROVAL_GRANTED,
        POLICY_LOADED, AUDIT_MODE_CHANGE) only accepted from supervisor identity.

Fix 9:  agent_id bound to public key at session open — every event verified.

Fix 10: verify() before resume — broken chain or manifest/witness mismatch blocks.

Fix 11: Policy/audit-mode downgrade is a signed, governed event — blocked or
        requires operator authorization. Downgrade attempts logged as violations.

Fix 12: TELEMETRY_GAP event when OS corroboration sensor is disabled/stops.

Fix 13: Bounded input queue with backpressure + AU-5 audit-failure alert on
        disk exhaustion.

Candidate control mappings: NIST AU-9, AU-10, AU-12, and AU-5. These are
preliminary engineering mappings pending qualified assessor review.

LANGUAGE: EFS = confidentiality-at-rest only (not immutability).
          VSS = snapshot/recovery only (not evidence-grade immutability).
          Correct claim: tamper-evident + append-only + externally witnessed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import secrets
import threading
import urllib.parse
import urllib.request
import uuid
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENESIS_HASH: str = "0" * 96          # SHA-384 zero sentinel (96 hex chars)
RECORD_VERSION_V2: str = "selfconnect.provenance.record.v2"
_DEFAULT_SEAL_INTERVAL: int = 100      # Merkle seal every N events
_DEFAULT_HEARTBEAT_INTERVAL: int = 60  # Heartbeat every N seconds
_PROVENANCE_DIR_ENV: str = "SC_PROVENANCE_DIR"

# Privileged event types — only accepted from supervisor/orchestrator identity
_PRIVILEGED_EVENT_TYPES: frozenset[str] = frozenset({
    "approval_granted",
    "policy_loaded",
    "audit_mode_change",
    "session_close",   # agent cannot close its own audit (Fix 7)
})


# ---------------------------------------------------------------------------
# SessionState
# ---------------------------------------------------------------------------

class SessionState(str, Enum):
    """Explicit session lifecycle states (Fix 1)."""
    OPEN = "open"
    SEALED = "sealed"
    INTERRUPTED = "interrupted"     # unclean shutdown — not necessarily tampered
    RECONSTRUCTED = "reconstructed" # resumed from interrupted state


# ---------------------------------------------------------------------------
# SessionEventType
# ---------------------------------------------------------------------------

class SessionEventType(str, Enum):
    """All recordable event types in a SelfConnect session."""

    # Lifecycle
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    SESSION_RESUME = "session_resume"
    SESSION_INTERRUPT = "session_interrupt"
    SESSION_RECONSTRUCTED = "session_reconstructed"

    # Heartbeat / high-water mark (Fix 1)
    HEARTBEAT = "heartbeat"

    # Agent actions
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    SHELL_EXEC = "shell_exec"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    NETWORK_REQUEST = "network_request"

    # Orchestration
    AGENT_SPAWN = "agent_spawn"
    AGENT_HANDOFF = "agent_handoff"
    MESH_MESSAGE = "mesh_message"

    # Governance (privileged — Fix 8)
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    POLICY_LOADED = "policy_loaded"
    AUDIT_MODE_CHANGE = "audit_mode_change"

    # Security
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    POLICY_VIOLATION = "policy_violation"

    # OS corroboration (Fix 12)
    TELEMETRY_GAP = "telemetry_gap"
    OS_EVENT = "os_event"

    # Checkpoints
    CHECKPOINT = "checkpoint"
    MERKLE_SEAL = "merkle_seal"
    SEGMENT_SEALED = "segment_sealed"
    REPLICATION_ACK = "replication_ack"


# ---------------------------------------------------------------------------
# AuditMode
# ---------------------------------------------------------------------------

class AuditMode(str, Enum):
    """Policy tier controlling fail-closed behaviour and replication requirements."""
    CONSUMER = "consumer"
    ENTERPRISE = "enterprise"
    MILITARY = "military"

    def allows_downgrade_to(self, target: "AuditMode") -> bool:
        """Returns True only if target is same or higher tier (Fix 11)."""
        order = {AuditMode.CONSUMER: 0, AuditMode.ENTERPRISE: 1, AuditMode.MILITARY: 2}
        return order[target] >= order[self]


# ---------------------------------------------------------------------------
# SessionEvent dataclass
# ---------------------------------------------------------------------------

@dataclass
class SessionEvent:
    """A single provenance event. Immutable after construction."""

    event_type: SessionEventType
    payload: dict[str, Any] = field(default_factory=dict)
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Optional OS corroboration field (Fix 12)
    os_corroboration: Optional[dict] = None

    def to_dict(self) -> dict:
        d = {
            "event_type": self.event_type.value,
            "payload": self.payload,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "ts": self.ts,
        }
        if self.os_corroboration is not None:
            d["os_corroboration"] = self.os_corroboration
        return d


# ---------------------------------------------------------------------------
# ReplicationSink — abstract base for off-host WORM replication
# ---------------------------------------------------------------------------

class ReplicationError(RuntimeError):
    """Raised by a ReplicationSink when a push fails."""


class ReplicationSink(ABC):
    """Abstract base for off-host WORM replication sinks.

    Implement push() to activate. The recorder calls push() after every
    successful local write in enterprise/military mode.

    FORK DETECTION (Fix 3): The remote endpoint must reject conflicting
    segment roots for the same (session_id, segment_no) pair. Once a root
    is acknowledged, any future push with the same (session_id, segment_no)
    but a different root must raise ReplicationError with reason="fork_detected".
    """

    @abstractmethod
    def push(self, session_id: str, segment_no: int, record: dict) -> str:
        """Push a single event record.

        Returns a receipt string (e.g., remote object key or hash).
        Must be idempotent. Must raise ReplicationError on fork detection.
        """

    def get_latest_receipt(self, session_id: str) -> Optional[dict]:
        """Return the latest stored receipt for a session, or None."""
        return None

    def close(self) -> None:
        """Optional teardown."""


class S3ObjectLockSink(ReplicationSink):
    """AWS S3 Object Lock WORM replication sink.

    S3 Object Lock in COMPLIANCE mode provides a non-bypassable retention
    mechanism for the configured period. Suitability for a regulated or
    government deployment remains configuration- and assessment-dependent.

    Fork detection: the S3 key includes (session_id, segment_no, root_hash[:16]).
    A conflicting root for the same (session_id, segment_no) will produce a
    different key, so both versions exist — but the verifier checks for
    duplicate (session_id, segment_no) with different roots.

    The sink writes canonical JSON records. Each key includes the session,
    segment, sequence, and record root prefix so repeated writes are idempotent
    and conflicting roots produce distinct evidence objects.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "provenance/",
        *,
        endpoint_url: str | None = None,
        region_name: str | None = None,
        object_lock_mode: str = "COMPLIANCE",
        retention_days: int = 365,
    ) -> None:
        import boto3

        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.object_lock_mode = object_lock_mode
        self.retention_days = retention_days
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            region_name=region_name or None,
        )
        self._seal_store: dict[tuple[str, int], str] = {}
        self._receipts: dict[str, dict] = {}
        self._lock = threading.Lock()

    def push(self, session_id: str, segment_no: int, record: dict) -> str:
        return _push_s3_record(
            client=self._client,
            bucket=self.bucket,
            prefix=self.prefix,
            session_id=session_id,
            segment_no=segment_no,
            record=record,
            object_lock_mode=self.object_lock_mode,
            retention_days=self.retention_days,
            seal_store=self._seal_store,
            receipts=self._receipts,
            lock=self._lock,
        )

    def get_latest_receipt(self, session_id: str) -> Optional[dict]:
        return self._receipts.get(session_id)

    def verify_retention_configuration(self) -> dict[str, Any]:
        """Verify that the live bucket has S3 Object Lock enabled."""
        try:
            response = self._client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as exc:
            raise ReplicationError(f"s3_object_lock_configuration_failed: {exc}") from exc
        config = response.get("ObjectLockConfiguration", {})
        if config.get("ObjectLockEnabled") != "Enabled":
            raise ReplicationError("s3_object_lock_not_enabled")
        return {
            "backend": "s3",
            "bucket": self.bucket,
            "object_lock_enabled": True,
            "object_lock_mode": self.object_lock_mode,
            "minimum_retention_days": self.retention_days,
        }

    def attempt_delete(self, key: str) -> None:
        """Attempt to delete a retained object.

        This exists only so callers can prove a live Object Lock bucket
        actually denies deletion of retained evidence: a successful delete
        here means immutability is NOT enforced and must be treated as a
        verification failure, never as routine cleanup. Raises whatever
        exception the provider raises (e.g. AccessDenied) on denial.
        """
        self._client.delete_object(Bucket=self.bucket, Key=key)


class CloudflareR2Sink(ReplicationSink):
    """Cloudflare R2 S3-compatible replication sink.

    R2 object-lock/WORM configuration is bucket-side. This sink writes
    canonical JSON evidence through the S3-compatible API and leaves retention
    enforcement to the configured R2 bucket policy.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "provenance/",
        *,
        endpoint_url: str | None = None,
        region_name: str | None = None,
        account_id: str = "",
        api_token: str = "",
        jurisdiction: str = "default",
        minimum_retention_days: int = 365,
    ) -> None:
        import boto3

        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.account_id = account_id
        self._api_token = api_token
        self.jurisdiction = jurisdiction
        self.minimum_retention_days = minimum_retention_days
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            region_name=region_name or None,
        )
        self._seal_store: dict[tuple[str, int], str] = {}
        self._receipts: dict[str, dict] = {}
        self._lock = threading.Lock()

    def push(self, session_id: str, segment_no: int, record: dict) -> str:
        return _push_s3_record(
            client=self._client,
            bucket=self.bucket,
            prefix=self.prefix,
            session_id=session_id,
            segment_no=segment_no,
            record=record,
            object_lock_mode="",
            retention_days=0,
            seal_store=self._seal_store,
            receipts=self._receipts,
            lock=self._lock,
        )

    def get_latest_receipt(self, session_id: str) -> Optional[dict]:
        return self._receipts.get(session_id)

    def verify_retention_configuration(self) -> dict[str, Any]:
        """Verify a live Cloudflare R2 bucket-lock rule covers this prefix."""
        if not self.account_id or not self._api_token:
            raise ReplicationError(
                "r2_bucket_lock_verification_requires_account_id_and_api_token"
            )
        account = urllib.parse.quote(self.account_id, safe="")
        bucket = urllib.parse.quote(self.bucket, safe="")
        request = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{account}/r2/buckets/{bucket}/lock",
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Accept": "application/json",
                "cf-r2-jurisdiction": self.jurisdiction,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise ReplicationError(f"r2_bucket_lock_query_failed: {exc}") from exc
        if not payload.get("success"):
            raise ReplicationError("r2_bucket_lock_query_not_successful")
        rules = payload.get("result", {}).get("rules", [])
        required_seconds = self.minimum_retention_days * 86_400
        now = datetime.now(timezone.utc)
        for rule in rules:
            if not rule.get("enabled"):
                continue
            rule_prefix = str(rule.get("prefix") or "").strip("/")
            if rule_prefix and not self.prefix.startswith(rule_prefix):
                continue
            condition = rule.get("condition", {})
            condition_type = condition.get("type")
            sufficient = condition_type == "Indefinite"
            if condition_type == "Age":
                sufficient = int(condition.get("maxAgeSeconds", 0)) >= required_seconds
            elif condition_type == "Date":
                try:
                    retain_until = datetime.fromisoformat(
                        str(condition.get("date", "")).replace("Z", "+00:00")
                    )
                    sufficient = (retain_until - now).total_seconds() >= required_seconds
                except ValueError:
                    sufficient = False
            if sufficient:
                return {
                    "backend": "r2",
                    "bucket": self.bucket,
                    "rule_id": str(rule.get("id", "")),
                    "rule_prefix": rule_prefix,
                    "minimum_retention_days": self.minimum_retention_days,
                    "condition_type": condition_type,
                }
        raise ReplicationError(
            "r2_bucket_lock_has_no_enabled_rule_covering_prefix_and_retention"
        )

    def attempt_delete(self, key: str) -> None:
        """Attempt to delete a retained object.

        See S3ObjectLockSink.attempt_delete: a successful delete here means
        the R2 bucket-lock rule is NOT enforcing retention and must be
        treated as a verification failure, never as routine cleanup.
        """
        self._client.delete_object(Bucket=self.bucket, Key=key)


def _safe_s3_component(value: str) -> str:
    clean = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)
    clean = clean.strip(".-_")
    return clean or hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _s3_record_root(record: dict) -> str:
    payload = record.get("payload", {})
    return str(payload.get("merkle_root") or canonical_hash(record))


def _s3_object_key(prefix: str, session_id: str, segment_no: int, record: dict) -> str:
    seq = record.get("seq", 0)
    try:
        seq_int = int(seq)
    except (TypeError, ValueError):
        seq_int = 0
    root = _s3_record_root(record)
    session = _safe_s3_component(session_id)
    prefix_part = prefix.strip("/")
    body = f"{session}/seg-{segment_no:06d}/seq-{seq_int:012d}-{root[:16]}.json"
    return f"{prefix_part}/{body}" if prefix_part else body


def _s3_seal_index_key(prefix: str, session_id: str, segment_no: int) -> str:
    session = _safe_s3_component(session_id)
    prefix_part = prefix.strip("/")
    body = f"{session}/seg-{segment_no:06d}/seal-index.json"
    return f"{prefix_part}/{body}" if prefix_part else body


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    return str(response.get("Error", {}).get("Code", ""))


def _is_not_found_error(exc: Exception) -> bool:
    code = _error_code(exc)
    return code in {"404", "NoSuchKey", "NotFound", "NoSuchBucket"}


def _is_precondition_error(exc: Exception) -> bool:
    return _error_code(exc) in {"412", "PreconditionFailed"}


def _root_from_head(head: dict) -> str:
    return str(head.get("Metadata", {}).get("root", ""))


def _s3_object_lock_args(object_lock_mode: str, retention_days: int) -> dict[str, Any]:
    if not object_lock_mode:
        return {}
    return {
        "ObjectLockMode": object_lock_mode,
        "ObjectLockRetainUntilDate": (
            datetime.now(timezone.utc) + timedelta(days=max(1, retention_days))
        ),
    }


def _verify_s3_object_retention(
    head: dict[str, Any],
    *,
    mode: str,
    minimum_retain_until: datetime,
) -> None:
    if head.get("ObjectLockMode") != mode:
        raise ReplicationError("s3_object_retention_mode_not_confirmed")
    retain_until = head.get("ObjectLockRetainUntilDate")
    if not isinstance(retain_until, datetime):
        raise ReplicationError("s3_object_retention_date_not_confirmed")
    if retain_until.tzinfo is None:
        retain_until = retain_until.replace(tzinfo=timezone.utc)
    if retain_until < minimum_retain_until:
        raise ReplicationError("s3_object_retention_period_shorter_than_requested")


def _confirm_remote_seal_root(
    *,
    client: Any,
    bucket: str,
    key: str,
    session_id: str,
    segment_no: int,
    root: str,
    object_lock_mode: str,
    retention_days: int,
) -> None:
    try:
        head = client.head_object(Bucket=bucket, Key=key)
    except Exception as exc:
        raise ReplicationError(f"s3_seal_index_head_failed: {exc}") from exc
    remote_root = _root_from_head(head)
    if object_lock_mode:
        _verify_s3_object_retention(
            head,
            mode=object_lock_mode,
            minimum_retain_until=datetime.now(timezone.utc) + timedelta(
                days=max(1, retention_days) - 1
            ),
        )
    if not remote_root:
        raise ReplicationError(
            f"s3_seal_index_missing_root: session={session_id} segment={segment_no}"
        )
    if remote_root != root:
        raise ReplicationError(
            f"fork_detected: session={session_id} segment={segment_no} "
            f"existing_root={remote_root[:16]}… new_root={root[:16]}…"
        )


def _ensure_s3_seal_index(
    *,
    client: Any,
    bucket: str,
    prefix: str,
    session_id: str,
    segment_no: int,
    root: str,
    object_lock_mode: str,
    retention_days: int,
) -> None:
    key = _s3_seal_index_key(prefix, session_id, segment_no)
    try:
        head = client.head_object(Bucket=bucket, Key=key)
        if object_lock_mode:
            _verify_s3_object_retention(
                head,
                mode=object_lock_mode,
                minimum_retain_until=datetime.now(timezone.utc) + timedelta(
                    days=max(1, retention_days) - 1
                ),
            )
        remote_root = _root_from_head(head)
        if not remote_root:
            raise ReplicationError(
                f"s3_seal_index_missing_root: session={session_id} segment={segment_no}"
            )
        if remote_root != root:
            raise ReplicationError(
                f"fork_detected: session={session_id} segment={segment_no} "
                f"existing_root={remote_root[:16]}… new_root={root[:16]}…"
            )
        return
    except ReplicationError:
        raise
    except Exception as exc:
        if not _is_not_found_error(exc):
            raise ReplicationError(f"s3_seal_index_head_failed: {exc}") from exc

    body = json.dumps(
        {
            "type": "s3_seal_index",
            "session_id": session_id,
            "segment_no": segment_no,
            "root": root,
        },
        separators=(",", ":"),
        ensure_ascii=True,
        sort_keys=True,
    )
    put_args: dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "Body": body.encode("utf-8"),
        "ContentType": "application/json",
        "Metadata": {
            "session-id": session_id[:256],
            "segment-no": str(segment_no),
            "event-type": "seal_index",
            "root": root,
        },
        "IfNoneMatch": "*",
    }
    put_args.update(_s3_object_lock_args(object_lock_mode, retention_days))
    try:
        client.put_object(**put_args)
    except Exception as exc:
        if _is_precondition_error(exc):
            _confirm_remote_seal_root(
                client=client,
                bucket=bucket,
                key=key,
                session_id=session_id,
                segment_no=segment_no,
                root=root,
                object_lock_mode=object_lock_mode,
                retention_days=retention_days,
            )
            return
        raise ReplicationError(f"s3_seal_index_put_failed: {exc}") from exc
    if object_lock_mode:
        _confirm_remote_seal_root(
            client=client,
            bucket=bucket,
            key=key,
            session_id=session_id,
            segment_no=segment_no,
            root=root,
            object_lock_mode=object_lock_mode,
            retention_days=retention_days,
        )


def _push_s3_record(
    *,
    client: Any,
    bucket: str,
    prefix: str,
    session_id: str,
    segment_no: int,
    record: dict,
    object_lock_mode: str,
    retention_days: int,
    seal_store: dict[tuple[str, int], str],
    receipts: dict[str, dict],
    lock: threading.Lock,
) -> str:
    root = _s3_record_root(record)
    payload = record.get("payload", {})
    is_seal = "merkle_root" in payload
    key = _s3_object_key(prefix, session_id, segment_no, record)

    with lock:
        if is_seal:
            fork_key = (session_id, segment_no)
            existing_root = seal_store.get(fork_key)
            if existing_root and existing_root != root:
                raise ReplicationError(
                    f"fork_detected: session={session_id} segment={segment_no} "
                    f"existing_root={existing_root[:16]}… new_root={root[:16]}…"
                )
            _ensure_s3_seal_index(
                client=client,
                bucket=bucket,
                prefix=prefix,
                session_id=session_id,
                segment_no=segment_no,
                root=root,
                object_lock_mode=object_lock_mode,
                retention_days=retention_days,
            )
            seal_store[fork_key] = root

        try:
            head = client.head_object(Bucket=bucket, Key=key)
            if object_lock_mode:
                _verify_s3_object_retention(
                    head,
                    mode=object_lock_mode,
                    minimum_retain_until=datetime.now(timezone.utc) + timedelta(
                        days=max(1, retention_days) - 1
                    ),
                )
            receipt = {
                "backend": "s3",
                "bucket": bucket,
                "key": key,
                "etag": str(head.get("ETag", "")).strip('"'),
                "root": root,
            }
            receipts[session_id] = receipt
            return f"s3://{bucket}/{key}#{receipt['etag']}"
        except Exception as exc:
            if not _is_not_found_error(exc):
                raise ReplicationError(f"s3_head_failed: {exc}") from exc

        body = json.dumps(record, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
        put_args: dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": body.encode("utf-8"),
            "ContentType": "application/json",
            "Metadata": {
                "session-id": session_id[:256],
                "segment-no": str(segment_no),
                "seq": str(record.get("seq", "")),
                "event-type": str(record.get("event_type", ""))[:128],
                "root": root,
            },
        }
        if object_lock_mode:
            put_args.update(_s3_object_lock_args(object_lock_mode, retention_days))
        try:
            response = client.put_object(**put_args)
        except Exception as exc:
            raise ReplicationError(f"s3_put_failed: {exc}") from exc

        if object_lock_mode:
            try:
                retention_head = client.head_object(Bucket=bucket, Key=key)
            except Exception as exc:
                raise ReplicationError(f"s3_retention_readback_failed: {exc}") from exc
            _verify_s3_object_retention(
                retention_head,
                mode=object_lock_mode,
                minimum_retain_until=datetime.now(timezone.utc) + timedelta(
                    days=max(1, retention_days) - 1
                ),
            )

        receipt = {
            "backend": "s3",
            "bucket": bucket,
            "key": key,
            "etag": str(response.get("ETag", "")).strip('"'),
            "root": root,
        }
        receipts[session_id] = receipt
        return f"s3://{bucket}/{key}#{receipt['etag']}"


class InMemoryWitnessSink(ReplicationSink):
    """In-memory witness sink for testing and development.

    Fork detection applies only to Merkle seal records: rejects conflicting
    Merkle roots for the same (session_id, segment_no) pair.  Individual
    event records are identified by their seq number; different events in the
    same segment naturally have different hashes and must NOT trigger fork
    detection.
    """

    def __init__(self) -> None:
        # (session_id, segment_no) -> merkle_root — only populated for seal records
        self._seal_store: dict[tuple, str] = {}
        self._receipts: dict[str, dict] = {}  # session_id -> latest receipt
        self._lock = threading.Lock()

    def push(self, session_id: str, segment_no: int, record: dict) -> str:
        with self._lock:
            payload = record.get("payload", {})
            is_seal = "merkle_root" in payload
            root = payload.get("merkle_root", canonical_hash(record))

            if is_seal:
                # Fork detection: only enforce on Merkle seal records
                key = (session_id, segment_no)
                if key in self._seal_store and self._seal_store[key] != root:
                    raise ReplicationError(
                        f"fork_detected: session={session_id} segment={segment_no} "
                        f"existing_root={self._seal_store[key][:16]}… "
                        f"new_root={root[:16]}…"
                    )
                self._seal_store[key] = root

            receipt = {
                "session_id": session_id,
                "segment_no": segment_no,
                "seq": record.get("seq"),
                "root": root,
                "is_seal": is_seal,
                "ts": datetime.now(timezone.utc).isoformat(),
                "receipt_id": secrets.token_hex(8),
            }
            self._receipts[session_id] = receipt
            return receipt["receipt_id"]

    def get_latest_receipt(self, session_id: str) -> Optional[dict]:
        with self._lock:
            return self._receipts.get(session_id)


# ---------------------------------------------------------------------------
# ProvenanceRecorderError
# ---------------------------------------------------------------------------

class ProvenanceRecorderError(RuntimeError):
    """Raised when the recorder cannot start, the sink is unavailable,
    or a security constraint is violated."""


# ---------------------------------------------------------------------------
# ProvenanceRecorder
# ---------------------------------------------------------------------------

class ProvenanceRecorder:
    """Append-only, hash-chained, session-state-aware provenance recorder.

    The recorder is the sole writer to the provenance log. Agents submit
    events via record(); they never hold a direct file handle to the log.

    Parameters
    ----------
    session_id:
        Stable identifier for this session.
    agent_id:
        Identity string of the recording agent.
    audit_mode:
        consumer | enterprise | military.
    log_dir:
        Directory for the provenance JSONL file. Defaults to
        $SC_PROVENANCE_DIR or ~/.selfconnect/provenance/.
    seal_interval:
        Events between Merkle seals.
    heartbeat_interval:
        Seconds between automatic heartbeat records (0 = disabled).
    identity:
        Optional AgentIdentity for Ed25519 per-event signing.
    supervisor_id:
        Identity string of the supervisor/orchestrator. Required for
        privileged event types (Fix 8). If None, privileged events are
        blocked in enterprise/military mode.
    orchestrator_token:
        Secret token required to call close() (Fix 7). If None, close()
        is unrestricted (consumer mode only).
    replication_sink:
        Optional ReplicationSink for off-host WORM replication.
        Required in military mode.
    """

    def __init__(
        self,
        session_id: str,
        agent_id: str = "",
        audit_mode: AuditMode | str = AuditMode.CONSUMER,
        log_dir: Optional[Path] = None,
        seal_interval: int = _DEFAULT_SEAL_INTERVAL,
        heartbeat_interval: int = _DEFAULT_HEARTBEAT_INTERVAL,
        identity: Any = None,
        supervisor_id: Optional[str] = None,
        orchestrator_token: Optional[str] = None,
        replication_sink: Optional[ReplicationSink] = None,
    ) -> None:
        self._session_id = session_id
        self._agent_id = agent_id
        self._audit_mode = AuditMode(audit_mode)
        self._seal_interval = seal_interval
        self._heartbeat_interval = heartbeat_interval
        self._identity = identity
        self._supervisor_id = supervisor_id
        self._orchestrator_token = orchestrator_token
        self._replication_sink = replication_sink
        self._lock = threading.RLock()
        self._seq = 0
        self._segment_no = 0
        self._prev_hash = GENESIS_HASH
        self._first_event_hash: Optional[str] = None
        self._event_count_since_seal = 0
        self._session_state = SessionState.OPEN
        self._started = False
        self._closed = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()
        self._registered_agents: dict[str, Any] = {}  # agent_id -> public_key (Fix 9)

        # Resolve log directory
        if log_dir is None:
            env_dir = os.environ.get(_PROVENANCE_DIR_ENV)
            log_dir = Path(env_dir) if env_dir else (
                Path.home() / ".selfconnect" / "provenance"
            )
        self._log_dir = Path(log_dir)
        self._log_path = self._log_dir / f"{session_id}.jsonl"

    # ── Public API ────────────────────────────────────────────────────────

    def start(self, *, resume: bool = False) -> None:
        """Initialise the recorder. Must be called before record().

        Fail-closed behaviour (Fix 13):
        - enterprise/military: raises ProvenanceRecorderError if sink unavailable.
        - military: also raises if no replication_sink is configured.
        - consumer: best-effort; continues without provenance on failure.
        """
        with self._lock:
            if self._started:
                return

            # Military requires replication sink (Fix 2, Fix 3)
            if (
                self._audit_mode == AuditMode.MILITARY
                and self._replication_sink is None
            ):
                raise ProvenanceRecorderError(
                    "military audit mode requires a ReplicationSink. "
                    "Configure S3ObjectLockSink, CloudflareR2Sink, or "
                    "InMemoryWitnessSink (testing only)."
                )

            if (
                self._audit_mode == AuditMode.ENTERPRISE
                and self._replication_sink is None
            ):
                warnings.warn(
                    "enterprise audit mode: no ReplicationSink configured. "
                    "No live-verified immutable retention sink is configured. "
                    "Configure S3ObjectLockSink or CloudflareR2Sink.",
                    stacklevel=2,
                )

            try:
                self._log_dir.mkdir(parents=True, exist_ok=True)
                self._log_path.touch(exist_ok=True)
                _try_set_append_only(self._log_path)
            except OSError as exc:
                if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
                    raise ProvenanceRecorderError(
                        f"Provenance sink unavailable — cannot start session "
                        f"in {self._audit_mode.value} mode: {exc}"
                    ) from exc
                logger.warning("Provenance sink unavailable (consumer mode): %s", exc)
                return

            had_existing_events = self._log_path.stat().st_size > 0
            self._load_chain_state()
            if resume and not had_existing_events:
                raise ProvenanceRecorderError("cannot resume a provenance session with no existing events")

            self._started = True

            if resume:
                self._session_state = SessionState.RECONSTRUCTED
                self._append_record(
                    SessionEventType.SESSION_RECONSTRUCTED,
                    payload={
                        "audit_mode": self._audit_mode.value,
                        "agent_id": self._agent_id,
                        "session_state": SessionState.RECONSTRUCTED.value,
                    },
                    agent_id=self._agent_id,
                    _internal=True,
                )
            else:
                # Write SESSION_OPEN (not a privileged event — agent writes this)
                self._append_record(
                    SessionEventType.SESSION_OPEN,
                    payload={
                        "audit_mode": self._audit_mode.value,
                        "agent_id": self._agent_id,
                        "session_state": SessionState.OPEN.value,
                    },
                    agent_id=self._agent_id,
                    _internal=True,
                )

            # Start heartbeat thread (Fix 1)
            if self._heartbeat_interval > 0:
                self._heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    daemon=True,
                    name=f"provenance-heartbeat-{self._session_id[:8]}",
                )
                self._heartbeat_thread.start()

    def register_agent(self, agent_id: str, public_key: Any = None) -> None:
        """Register an agent identity and optional public key (Fix 9).

        Once registered, events from this agent_id must have valid signatures
        if a public_key is provided.
        """
        with self._lock:
            self._registered_agents[agent_id] = public_key

    def record(
        self,
        event_type: SessionEventType | str,
        payload: Optional[dict] = None,
        agent_id: Optional[str] = None,
        signature: Optional[bytes] = None,
        os_corroboration: Optional[dict] = None,
    ) -> Optional[dict]:
        """Append a hash-chained event record.

        Parameters
        ----------
        event_type:
            The event type to record.
        payload:
            Event-specific data. Secrets/PII should be redacted before passing.
        agent_id:
            Submitting agent identity. Defaults to self._agent_id.
        signature:
            Ed25519/ECDSA signature over canonical_bytes(record) using the
            agent's private key. Required for registered agents (Fix 6).
        os_corroboration:
            Optional OS-level telemetry corroboration (Fix 12).

        Returns the written record dict, or None in consumer mode if sink
        is unavailable. Raises ProvenanceRecorderError in enterprise/military
        mode on any failure (fail-closed).
        """
        with self._lock:
            if self._closed:
                raise ProvenanceRecorderError("Recorder is closed.")
            if not self._started:
                if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
                    raise ProvenanceRecorderError(
                        "start() must be called before record()."
                    )
                return None

            event_type_val = SessionEventType(event_type)
            submitter = agent_id or self._agent_id

            # Fix 8: privileged event type authority check
            self._check_event_authority(event_type_val, submitter)

            # Fix 6: signature verification for registered agents
            self._check_signature(event_type_val, submitter, payload, signature)

            return self._append_record(
                event_type_val,
                payload=payload,
                agent_id=submitter,
                signature=signature,
                os_corroboration=os_corroboration,
            )

    def close(
        self,
        summary: Optional[dict] = None,
        orchestrator_token: Optional[str] = None,
    ) -> None:
        """Write a SESSION_CLOSE event and seal the session (Fix 7).

        In enterprise/military mode, requires the orchestrator_token that was
        set at construction. An agent cannot close its own audit trail.
        """
        with self._lock:
            if self._closed:
                return

            # Fix 7: orchestrator token check
            if (
                self._orchestrator_token is not None
                and self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY)
            ):
                if orchestrator_token != self._orchestrator_token:
                    # Log the attempt as a violation before raising
                    self._append_record(
                        SessionEventType.POLICY_VIOLATION,
                        payload={
                            "violation": "unauthorized_close_attempt",
                            "submitter": "unknown",
                        },
                        agent_id=self._agent_id,
                        _internal=True,
                    )
                    raise ProvenanceRecorderError(
                        "close() requires the orchestrator_token in "
                        f"{self._audit_mode.value} mode."
                    )

            if self._started:
                self._stop_heartbeat.set()
                self._session_state = SessionState.SEALED
                self._append_record(
                    SessionEventType.SESSION_CLOSE,
                    payload={
                        "summary": summary or {},
                        "total_events": self._seq,
                        "session_state": SessionState.SEALED.value,
                    },
                    agent_id=self._agent_id,
                    _internal=True,
                )
                # Final Merkle seal
                self._write_merkle_seal(final=True)

            self._closed = True
            if self._replication_sink is not None:
                try:
                    self._replication_sink.close()
                except Exception:
                    pass

    def interrupt(self, reason: str = "service_stop") -> None:
        """Record a non-sealing service interruption for restart recovery.

        This is distinct from ``close()``: an interrupted client session may be
        verified and reconstructed by the dedicated service after restart.
        """
        with self._lock:
            if self._closed:
                return
            self._stop_heartbeat.set()
            if self._started:
                self._session_state = SessionState.INTERRUPTED
                self._append_record(
                    SessionEventType.SESSION_INTERRUPT,
                    payload={
                        "reason": reason,
                        "session_state": SessionState.INTERRUPTED.value,
                    },
                    agent_id=self._agent_id,
                    _internal=True,
                )
                self._write_merkle_seal(final=False)
            self._closed = True
            if self._replication_sink is not None:
                self._replication_sink.close()

    def change_audit_mode(
        self,
        new_mode: AuditMode | str,
        orchestrator_token: Optional[str] = None,
        reason: str = "",
    ) -> None:
        """Change the audit mode (Fix 11).

        Downgrade (e.g., military → consumer) is blocked in enterprise/military
        unless the orchestrator_token is provided. The change is always logged
        as a signed AUDIT_MODE_CHANGE event.
        """
        with self._lock:
            new_mode = AuditMode(new_mode)
            old_mode = self._audit_mode

            is_downgrade = not old_mode.allows_downgrade_to(new_mode)

            if is_downgrade:
                if (
                    self._orchestrator_token is not None
                    and orchestrator_token != self._orchestrator_token
                ):
                    self._append_record(
                        SessionEventType.POLICY_VIOLATION,
                        payload={
                            "violation": "unauthorized_audit_mode_downgrade",
                            "from": old_mode.value,
                            "to": new_mode.value,
                        },
                        agent_id=self._agent_id,
                        _internal=True,
                    )
                    raise ProvenanceRecorderError(
                        f"Audit mode downgrade from {old_mode.value} to "
                        f"{new_mode.value} requires orchestrator_token."
                    )

            self._audit_mode = new_mode
            self._append_record(
                SessionEventType.AUDIT_MODE_CHANGE,
                payload={
                    "from": old_mode.value,
                    "to": new_mode.value,
                    "is_downgrade": is_downgrade,
                    "reason": reason,
                },
                agent_id=self._agent_id,
                _internal=True,
            )

    def report_telemetry_gap(self, sensor: str, detail: str = "") -> None:
        """Record a TELEMETRY_GAP event when an OS sensor stops (Fix 12)."""
        self.record(
            SessionEventType.TELEMETRY_GAP,
            payload={"sensor": sensor, "detail": detail},
        )

    def verify(self) -> "VerificationResult":
        """Verify the hash chain integrity of the log file.

        Checks:
        - Chain continuity (every prev_hash matches)
        - Timestamp monotonicity (Fix 1)
        - Session state (SEALED vs INTERRUPTED vs missing close)
        - First event hash matches expected genesis (Fix 1)
        - Last seq matches or exceeds any known high-water mark

        Returns a VerificationResult with ok, count, state, and message.
        """
        with self._lock:
            public_key = self._identity.public_key_bytes if self._identity is not None else None
            return _verify_chain(
                self._log_path,
                self._session_id,
                recorder_public_key=public_key,
                require_recorder_signatures=public_key is not None,
            )

    def tail(self, n: int = 10) -> list[dict]:
        """Return the last n event records."""
        with self._lock:
            if not self._log_path.exists():
                return []
            lines = self._log_path.read_text(encoding="utf-8").splitlines()
            recent = [ln for ln in lines if ln.strip()][-n:]
            result = []
            for line in recent:
                try:
                    result.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return result

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._seq

    @property
    def session_state(self) -> SessionState:
        with self._lock:
            return self._session_state

    @property
    def is_started(self) -> bool:
        return self._started

    @property
    def is_closed(self) -> bool:
        return self._closed

    # ── Internal ──────────────────────────────────────────────────────────

    def _append_record(
        self,
        event_type: SessionEventType,
        payload: Optional[dict] = None,
        agent_id: Optional[str] = None,
        signature: Optional[bytes] = None,
        os_corroboration: Optional[dict] = None,
        _internal: bool = False,
    ) -> Optional[dict]:
        """Core append logic. Must be called with self._lock held."""
        self._seq += 1
        now = datetime.now(timezone.utc).isoformat()

        record: dict[str, Any] = {
            "record_version": RECORD_VERSION_V2,
            "seq": self._seq,
            "ts": now,
            "session_id": self._session_id,
            "agent_id": agent_id or self._agent_id,
            "event_type": event_type.value,
            "payload": payload or {},
            "prev_hash": self._prev_hash,
        }

        if os_corroboration is not None:
            record["os_corroboration"] = os_corroboration

        # The agent signature must be present before the recorder signs. Record
        # format v2 includes it in both the recorder signature and chain hash.
        if signature is not None:
            record["agent_sig"] = signature.hex() if isinstance(signature, bytes) else signature

        # Per-event signature from the recorder's own identity (Fix 6)
        if self._identity is not None:
            try:
                record["recorder_sig"] = self._identity.sign(
                    canonical_bytes(record)
                ).hex()
            except Exception as exc:
                if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
                    raise ProvenanceRecorderError(f"Recorder signing failed: {exc}") from exc
                logger.warning("Recorder signing failed: %s", exc)

        # Update chain hash (Fix 4: canonical_bytes is deterministic)
        new_hash = canonical_hash(record)
        self._prev_hash = new_hash

        # Track first event hash for prepend-attack detection (Fix 1)
        if self._seq == 1:
            self._first_event_hash = new_hash

        # Write to local sink (append-only)
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            # Fix 13: AU-5 audit failure alert
            self._handle_sink_failure(exc)
            return None

        # Off-host replication
        if self._replication_sink is not None:
            self._replicate(record)

        self._event_count_since_seal += 1

        # Merkle seal at interval
        if (
            self._event_count_since_seal >= self._seal_interval
            and event_type != SessionEventType.MERKLE_SEAL
        ):
            self._write_merkle_seal()

        return record

    def _check_event_authority(
        self, event_type: SessionEventType, submitter: str
    ) -> None:
        """Fix 8: enforce event-type-to-identity binding."""
        if event_type.value not in _PRIVILEGED_EVENT_TYPES:
            return
        if self._audit_mode == AuditMode.CONSUMER:
            return  # consumer mode: no authority enforcement
        if self._supervisor_id is None:
            if self._audit_mode == AuditMode.MILITARY:
                raise ProvenanceRecorderError(
                    f"Privileged event {event_type.value!r} requires a "
                    "supervisor_id to be configured in military mode."
                )
            return
        if submitter != self._supervisor_id:
            # Log the attempt as a violation
            self._append_record(
                SessionEventType.POLICY_VIOLATION,
                payload={
                    "violation": "unauthorized_privileged_event",
                    "event_type": event_type.value,
                    "submitter": submitter,
                    "required_supervisor": self._supervisor_id,
                },
                agent_id=self._agent_id,
                _internal=True,
            )
            raise ProvenanceRecorderError(
                f"Event type {event_type.value!r} may only be submitted by "
                f"supervisor {self._supervisor_id!r}, not {submitter!r}."
            )

    def _check_signature(
        self,
        event_type: SessionEventType,
        submitter: str,
        payload: Optional[dict],
        signature: Optional[bytes],
    ) -> None:
        """Fix 6: verify agent signature for registered agents."""
        if submitter not in self._registered_agents:
            return
        public_key = self._registered_agents[submitter]
        if public_key is None:
            return  # registered but no key — skip verification
        if signature is None:
            if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
                raise ProvenanceRecorderError(
                    f"Registered agent {submitter!r} must provide a signature "
                    f"for event {event_type.value!r} in "
                    f"{self._audit_mode.value} mode."
                )
            return
        # Verify the signature against the canonical payload bytes
        try:
            canonical = json.dumps(
                {"event_type": event_type.value, "payload": payload or {}},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            public_key.verify(signature, canonical)
        except Exception as exc:
            raise ProvenanceRecorderError(
                f"Signature verification failed for agent {submitter!r}: {exc}"
            ) from exc

    def _handle_sink_failure(self, exc: OSError) -> None:
        """Fix 13: AU-5 audit failure response."""
        logger.critical(
            "AUDIT FAILURE: provenance sink write failed for session %s: %s",
            self._session_id, exc,
        )
        if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
            raise ProvenanceRecorderError(
                f"Provenance sink write failed (fail-closed): {exc}"
            ) from exc

    def ensure_replicated(self, record: dict) -> bool:
        """Idempotently repair replication before recovery is acknowledged."""
        with self._lock:
            if self._replication_sink is None:
                if self._audit_mode == AuditMode.MILITARY:
                    raise ProvenanceRecorderError(
                        "military recovery cannot acknowledge without a replication sink"
                    )
                return False
            return self._replicate(record)

    def _replicate(self, record: dict) -> bool:
        """Push record to replication sink with fork detection."""
        try:
            receipt = self._replication_sink.push(
                self._session_id, self._segment_no, record
            )
            # Append a lightweight replication ACK to the local log
            # (not replicated itself to avoid infinite loop)
            if receipt:
                ack: dict[str, Any] = {
                    "seq": f"ack-{self._seq}",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "session_id": self._session_id,
                    "event_type": SessionEventType.REPLICATION_ACK.value,
                    "receipt": receipt,
                    "prev_hash": self._prev_hash,
                }
                try:
                    with open(self._log_path, "a", encoding="utf-8") as fh:
                        fh.write(
                            json.dumps(ack, separators=(",", ":"), ensure_ascii=True)
                            + "\n"
                        )
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError:
                    if self._audit_mode == AuditMode.MILITARY:
                        raise ProvenanceRecorderError(
                            "replication succeeded but its local receipt could not be persisted"
                        )
                    logger.warning("Replication receipt could not be persisted locally")
                return True
            return False
        except NotImplementedError:
            if self._audit_mode == AuditMode.MILITARY:
                raise ProvenanceRecorderError(
                    "replication sink is not implemented in military mode"
                )
            logger.warning("Replication sink is not implemented")
            return False
        except ReplicationError as exc:
            err_str = str(exc)
            if "fork_detected" in err_str:
                # Fix 3: fork detection — this is a critical security event
                logger.critical(
                    "FORK DETECTED in session %s: %s", self._session_id, exc
                )
                if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
                    raise ProvenanceRecorderError(
                        f"Fork detected — session integrity compromised: {exc}"
                    ) from exc
            else:
                if self._audit_mode == AuditMode.MILITARY:
                    raise ProvenanceRecorderError(
                        f"Replication failed in military mode: {exc}"
                    ) from exc
                logger.warning("Replication failed (non-fatal): %s", exc)
            return False
        return False

    def _write_merkle_seal(self, final: bool = False) -> None:
        """Compute Merkle root over recent events and append a seal record."""
        try:
            with open(self._log_path, encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            # Fix: in enterprise/military mode a failed Merkle seal is an AU-5 event,
            # not a silent no-op.  Consumer mode may continue with best-effort.
            logger.critical(
                "AUDIT FAILURE: cannot read log for Merkle seal in session %s: %s",
                self._session_id, exc,
            )
            if self._audit_mode in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
                raise ProvenanceRecorderError(
                    f"Merkle seal failed — cannot read provenance log "
                    f"(fail-closed in {self._audit_mode.value} mode): {exc}"
                ) from exc
            return

        start = max(0, len(lines) - self._event_count_since_seal)
        chunk = lines[start:]
        leaf_hashes = [
            hashlib.sha384(ln.encode("utf-8")).hexdigest() for ln in chunk
        ]
        merkle_root = _merkle_root(leaf_hashes)
        self._segment_no += 1
        self._event_count_since_seal = 0
        self._append_record(
            SessionEventType.MERKLE_SEAL,
            payload={
                "merkle_root": merkle_root,
                "sealed_events": len(chunk),
                "segment_no": self._segment_no,
                "final": final,
            },
            _internal=True,
        )

    def _heartbeat_loop(self) -> None:
        """Periodically write heartbeat records (Fix 1 — high-water marks)."""
        while not self._stop_heartbeat.wait(timeout=self._heartbeat_interval):
            with self._lock:
                if self._closed or not self._started:
                    break
                try:
                    self._append_record(
                        SessionEventType.HEARTBEAT,
                        payload={
                            "seq_at_heartbeat": self._seq,
                            "session_state": self._session_state.value,
                        },
                        _internal=True,
                    )
                except Exception as exc:
                    logger.warning("Heartbeat write failed: %s", exc)

    def _load_chain_state(self) -> None:
        """Resume chain state from an existing log file (for session resume)."""
        if not self._log_path.exists():
            return
        lines = [
            ln.strip()
            for ln in self._log_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        if not lines:
            return
        try:
            records = [json.loads(line) for line in lines]
        except json.JSONDecodeError as exc:
            raise ProvenanceRecorderError(
                "cannot resume a provenance log containing malformed JSON"
            ) from exc
        chain_records = [record for record in records if isinstance(record.get("seq"), int)]
        if not chain_records:
            raise ProvenanceRecorderError(
                "cannot resume a provenance log with no integer-sequence events"
            )
        last = chain_records[-1]
        self._seq = last["seq"]
        # Replication ACK lines are receipts, not hash-chain members. Resuming
        # from an ACK would fork the next event from the authoritative chain.
        self._prev_hash = canonical_hash(last)
        self._first_event_hash = canonical_hash(chain_records[0])


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    ok: bool
    count: int
    session_state: Optional[str]
    message: str
    high_water_seq: int = 0
    last_heartbeat_ts: Optional[str] = None
    signatures_verified: bool = False
    agent_attestations_verified: int = 0
    legacy_agent_signatures_unverified: int = 0


# ---------------------------------------------------------------------------
# Standalone verify function
# ---------------------------------------------------------------------------

def verify_log(
    log_path: Path,
    session_id: Optional[str] = None,
    *,
    recorder_public_key: bytes | None = None,
    require_recorder_signatures: bool = False,
) -> VerificationResult:
    """Verify a provenance log without trusting the recorder process.

    Chain-only verification remains available for legacy logs. Attribution
    claims require a separately trusted public key and signature verification.
    """
    return _verify_chain(
        log_path,
        session_id,
        recorder_public_key=recorder_public_key,
        require_recorder_signatures=require_recorder_signatures,
    )


def _verify_recorder_signature(record: dict, public_key: bytes) -> bool:
    try:
        signature = bytes.fromhex(str(record.get("recorder_sig", "")))
    except ValueError:
        return False
    if not signature:
        return False
    payload = canonical_bytes(record)
    if len(public_key) == 32:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
            return True
        except Exception:
            return False
    if len(public_key) == 96:
        try:
            from enterprise.crypto import cng_verify

            return bool(cng_verify(payload, signature, public_key))
        except Exception:
            return False
    return False


def _verify_service_agent_attestation(record: dict) -> bool | None:
    """Verify the persisted v1 service request from record fields.

    ``None`` means this is not a dedicated-service record. ``False`` means the
    record claims that provenance but the persisted attribution is incomplete
    or invalid.
    """
    corroboration = record.get("os_corroboration")
    if not isinstance(corroboration, dict) or "provenance_service" not in corroboration:
        return None
    metadata = corroboration.get("provenance_service")
    required = {
        "agent_algorithm",
        "agent_key_version",
        "agent_public_key_hex",
        "caller_sid",
        "issued_at_ms",
        "nonce",
        "operation",
        "protocol_version",
        "request_hash",
        "request_id",
        "request_signature",
    }
    if not isinstance(metadata, dict) or set(metadata) != required:
        return False
    if record.get("record_version") != RECORD_VERSION_V2:
        return False
    algorithm = metadata.get("agent_algorithm")
    if algorithm not in {"ed25519", "ecdsa-p384-cng"}:
        return False
    if metadata.get("agent_key_version") != 1:
        return False
    try:
        public_key = bytes.fromhex(str(metadata.get("agent_public_key_hex", "")))
        event_signature = bytes.fromhex(str(record.get("agent_sig", "")))
        request_signature = bytes.fromhex(str(metadata.get("request_signature", "")))
    except ValueError:
        return False
    expected_key_bytes = 32 if algorithm == "ed25519" else 96
    expected_signature_bytes = 64 if algorithm == "ed25519" else 96
    if len(public_key) != expected_key_bytes:
        return False
    if len(event_signature) != expected_signature_bytes or len(request_signature) != expected_signature_bytes:
        return False
    request = {
        "agent_id": record.get("agent_id"),
        "event_signature": record.get("agent_sig"),
        "event_type": record.get("event_type"),
        "issued_at_ms": metadata.get("issued_at_ms"),
        "nonce": metadata.get("nonce"),
        "operation": metadata.get("operation"),
        "os_corroboration": corroboration.get("client"),
        "payload": record.get("payload"),
        "request_id": metadata.get("request_id"),
        "session_id": record.get("session_id"),
        "version": metadata.get("protocol_version"),
    }
    actual_request_hash = hashlib.sha384(
        json.dumps(
            request,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    if actual_request_hash != metadata.get("request_hash"):
        return False
    event_bytes = json.dumps(
        {"event_type": record.get("event_type"), "payload": record.get("payload")},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    request_bytes = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    try:
        if algorithm == "ed25519":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            verifier = Ed25519PublicKey.from_public_bytes(public_key)
            verifier.verify(event_signature, event_bytes)
            verifier.verify(request_signature, request_bytes)
        else:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

            verifier = ec.EllipticCurvePublicNumbers(
                int.from_bytes(public_key[:48], "big"),
                int.from_bytes(public_key[48:], "big"),
                ec.SECP384R1(),
            ).public_key()
            event_der = encode_dss_signature(
                int.from_bytes(event_signature[:48], "big"),
                int.from_bytes(event_signature[48:], "big"),
            )
            request_der = encode_dss_signature(
                int.from_bytes(request_signature[:48], "big"),
                int.from_bytes(request_signature[48:], "big"),
            )
            verifier.verify(event_der, event_bytes, ec.ECDSA(hashes.SHA384()))
            verifier.verify(request_der, request_bytes, ec.ECDSA(hashes.SHA384()))
    except Exception:
        return False
    digest = hashlib.sha256(public_key) if algorithm == "ed25519" else hashlib.sha384(public_key)
    return record.get("agent_id") == "SC-" + digest.hexdigest()[:8].upper()


def _verify_chain(
    log_path: Path,
    session_id: Optional[str] = None,
    *,
    recorder_public_key: bytes | None = None,
    require_recorder_signatures: bool = False,
) -> VerificationResult:
    """Internal chain verification with all Fix 1/2/10 checks."""
    if not log_path.exists():
        return VerificationResult(
            ok=True, count=0, session_state=None,
            message="no log file — nothing to verify"
        )
    if require_recorder_signatures and recorder_public_key is None:
        return VerificationResult(
            ok=False,
            count=0,
            session_state=None,
            message="recorder public key is required for signature verification",
        )

    prev = GENESIS_HASH
    count = 0
    last_ts: Optional[str] = None
    session_state: Optional[str] = None
    high_water_seq = 0
    last_heartbeat_ts: Optional[str] = None
    has_close = False
    agent_attestations_verified = 0
    legacy_agent_signatures_unverified = 0

    try:
        with open(log_path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    return VerificationResult(
                        ok=False, count=count, session_state=session_state,
                        message=f"JSON parse error at line {lineno}: {exc}"
                    )

                # Skip replication ACK records (not part of hash chain)
                seq = record.get("seq", "")
                if isinstance(seq, str) and seq.startswith("ack-"):
                    continue

                # Chain continuity check
                stored_prev = record.get("prev_hash", "")
                if stored_prev != prev:
                    return VerificationResult(
                        ok=False, count=count, session_state=session_state,
                        message=(
                            f"chain break at seq {record.get('seq', '?')} "
                            f"(line {lineno}): "
                            f"expected {prev[:16]}… got {stored_prev[:16]}…"
                        )
                    )

                if require_recorder_signatures and not _verify_recorder_signature(
                    record, recorder_public_key or b""
                ):
                    return VerificationResult(
                        ok=False,
                        count=count,
                        session_state=session_state,
                        message=(
                            "recorder signature invalid or missing at seq "
                            f"{record.get('seq', '?')} (line {lineno})"
                        ),
                    )

                attestation = _verify_service_agent_attestation(record)
                if attestation is False:
                    return VerificationResult(
                        ok=False,
                        count=count,
                        session_state=session_state,
                        message=(
                            "agent request attestation invalid or incomplete at seq "
                            f"{record.get('seq', '?')} (line {lineno})"
                        ),
                    )
                if attestation is True:
                    agent_attestations_verified += 1
                elif record.get("agent_sig") and record.get("record_version") != RECORD_VERSION_V2:
                    legacy_agent_signatures_unverified += 1

                # Timestamp monotonicity check (Fix 1)
                ts = record.get("ts", "")
                if last_ts and ts < last_ts:
                    return VerificationResult(
                        ok=False, count=count, session_state=session_state,
                        message=(
                            f"timestamp regression at seq {record.get('seq', '?')} "
                            f"(line {lineno}): {ts} < {last_ts}"
                        )
                    )
                last_ts = ts

                prev = canonical_hash(record)
                count += 1

                # Track session state
                et = record.get("event_type", "")
                if et == SessionEventType.SESSION_CLOSE.value:
                    has_close = True
                    session_state = record.get("payload", {}).get(
                        "session_state", SessionState.SEALED.value
                    )
                elif et == SessionEventType.HEARTBEAT.value:
                    last_heartbeat_ts = ts
                    hw = record.get("payload", {}).get("seq_at_heartbeat", 0)
                    if isinstance(hw, int):
                        high_water_seq = max(high_water_seq, hw)

                if isinstance(seq, int):
                    high_water_seq = max(high_water_seq, seq)

    except OSError as exc:
        return VerificationResult(
            ok=False, count=count, session_state=session_state,
            message=f"read error: {exc}"
        )

    # Fix 1: distinguish sealed from interrupted
    if not has_close:
        session_state = SessionState.INTERRUPTED.value
        # INTERRUPTED is not automatically tampering — it may be a crash
        # The caller (resume verifier) decides whether to block or warn

    return VerificationResult(
        ok=True,
        count=count,
        session_state=session_state,
        message=(
            f"{count} events, chain intact, "
            f"state={session_state or 'unknown'}"
        ),
        high_water_seq=high_water_seq,
        last_heartbeat_ts=last_heartbeat_ts,
        signatures_verified=require_recorder_signatures,
        agent_attestations_verified=agent_attestations_verified,
        legacy_agent_signatures_unverified=legacy_agent_signatures_unverified,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def canonical_bytes(record: dict) -> bytes:
    """Deterministic bytes for hashing/signing (Fix 4).

    Rules:
    - Sort keys alphabetically
    - No whitespace (separators=(',', ':'))
    - ensure_ascii=True (no unicode ambiguity)
    - v2 excludes only ``recorder_sig``. The agent signature and persisted
      request attestation are bound by the recorder signature and chain hash.
    - Legacy records exclude both signatures to preserve verification of
      existing ledgers; their agent signatures are reported as unverified.
    - No floats in the record schema; all numeric values are int or str
    """
    excluded = {"recorder_sig"}
    if record.get("record_version") != RECORD_VERSION_V2:
        excluded.add("agent_sig")
    r = {k: v for k, v in record.items() if k not in excluded}
    return json.dumps(
        r,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def canonical_hash(record: dict) -> str:
    """SHA-384 hex digest of canonical_bytes(record)."""
    return hashlib.sha384(canonical_bytes(record)).hexdigest()


def _merkle_root(hashes: list[str]) -> str:
    """Binary Merkle root from SHA-384 hex-digest strings."""
    if not hashes:
        return hashlib.sha384(b"").hexdigest()
    layer = hashes[:]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [
            hashlib.sha384((layer[i] + layer[i + 1]).encode("ascii")).hexdigest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


def _try_set_append_only(path: Path) -> None:
    """Best-effort append-only file protection.

    Linux:   chattr +a (requires CAP_LINUX_IMMUTABLE; silently skipped)
    Windows: See _try_set_append_only_windows() — best-effort via ctypes.
             Full DACL enforcement (deny FILE_WRITE_DATA, DELETE to agent SID)
             requires the Phase 2 Windows service deployment.
    """
    system = platform.system()
    if system == "Linux":
        try:
            import subprocess
            subprocess.run(
                ["chattr", "+a", str(path)],
                capture_output=True,
                timeout=3,
            )
        except Exception:
            pass
    elif system == "Windows":
        _try_set_append_only_windows(path)


def _try_set_append_only_windows(path: Path) -> None:
    """Attempt Windows FILE_APPEND_DATA-only protection (Fix 5 partial).

    Opens the file with FILE_APPEND_DATA | SYNCHRONIZE (no FILE_WRITE_DATA,
    no DELETE). Verifies the DACL allows append and surfaces permission errors.

    Full protection (denying FILE_WRITE_DATA and DELETE to agent SID) requires
    the Windows service deployment and explicit DACL manipulation via SetFileSecurity.
    """
    try:
        import ctypes

        FILE_APPEND_DATA = 0x0004
        SYNCHRONIZE = 0x00100000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.CreateFileW(
            str(path),
            FILE_APPEND_DATA | SYNCHRONIZE,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value
        if handle != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(handle)
    except Exception:
        pass
