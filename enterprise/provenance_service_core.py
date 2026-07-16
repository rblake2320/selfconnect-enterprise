"""Restart-safe authorization and commit core for the provenance service."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

from enterprise.provenance import (
    AuditMode,
    ProvenanceRecorder,
    SessionEventType,
    canonical_hash,
)
from enterprise.provenance_ipc import (
    DEFAULT_FRESHNESS_MS,
    PROTOCOL_VERSION,
    SERVICE_METADATA_KEY,
    EnrollmentRegistry,
    ProvenanceProtocolError,
    VerifiedRecordRequest,
    sign_service_response,
    verify_record_request,
)

_AGENT_EVENTS = frozenset({
    SessionEventType.TOOL_CALL,
    SessionEventType.TOOL_RESULT,
    SessionEventType.SHELL_EXEC,
    SessionEventType.FILE_WRITE,
    SessionEventType.FILE_READ,
    SessionEventType.NETWORK_REQUEST,
    SessionEventType.AGENT_SPAWN,
    SessionEventType.AGENT_HANDOFF,
    SessionEventType.MESH_MESSAGE,
    SessionEventType.APPROVAL_REQUEST,
})

_SUPERVISOR_EVENTS = frozenset({
    SessionEventType.APPROVAL_GRANTED,
    SessionEventType.APPROVAL_DENIED,
    SessionEventType.POLICY_LOADED,
    SessionEventType.AUDIT_MODE_CHANGE,
    SessionEventType.TELEMETRY_GAP,
    SessionEventType.OS_EVENT,
})


class ProvenanceServiceUnavailable(RuntimeError):
    """The service cannot establish an authoritative commit result."""


class ProvenanceRequestStore:
    """SQLite replay/idempotency state owned by the service identity."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.execute("PRAGMA trusted_schema=OFF")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        result = self._connection.execute("PRAGMA quick_check").fetchone()
        if not result or result[0] != "ok":
            raise ProvenanceServiceUnavailable("provenance request database failed integrity check")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS provenance_nonces (
                agent_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                PRIMARY KEY (agent_id, nonce)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS provenance_receipts (
                request_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                committed_at_ms INTEGER NOT NULL
            ) STRICT;
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def transaction(self):
        return _RequestTransaction(self)

    def receipt(self, request_id: str) -> tuple[str, dict[str, Any]] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT request_hash, response_json FROM provenance_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            response = json.loads(row[1])
        except json.JSONDecodeError as exc:
            raise ProvenanceServiceUnavailable("stored provenance receipt is corrupt") from exc
        if not isinstance(response, dict):
            raise ProvenanceServiceUnavailable("stored provenance receipt has invalid shape")
        return str(row[0]), response


class _RequestTransaction:
    def __init__(self, store: ProvenanceRequestStore) -> None:
        self.store = store
        self.connection = store._connection

    def __enter__(self) -> "_RequestTransaction":
        self.store._lock.acquire()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except Exception:
            self.store._lock.release()
            raise
        return self

    def __exit__(self, exc_type, _exc, _tb) -> None:
        try:
            self.connection.execute("COMMIT" if exc_type is None else "ROLLBACK")
        finally:
            self.store._lock.release()

    def prune(self, now_ms: int) -> None:
        self.connection.execute(
            "DELETE FROM provenance_nonces WHERE expires_at_ms < ?",
            (now_ms,),
        )

    def receipt(self, request_id: str) -> tuple[str, dict[str, Any]] | None:
        row = self.connection.execute(
            "SELECT request_hash, response_json FROM provenance_receipts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        response = json.loads(row[1])
        if not isinstance(response, dict):
            raise ProvenanceServiceUnavailable("stored provenance receipt has invalid shape")
        return str(row[0]), response

    def consume_nonce(self, agent_id: str, nonce: str, expires_at_ms: int) -> bool:
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO provenance_nonces(agent_id, nonce, expires_at_ms) VALUES (?, ?, ?)",
            (agent_id, nonce, expires_at_ms),
        )
        return cursor.rowcount == 1

    def save_receipt(
        self,
        request_id: str,
        request_digest: str,
        response: dict[str, Any],
        committed_at_ms: int,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO provenance_receipts(request_id, request_hash, response_json, committed_at_ms)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(request_id) DO NOTHING
            """,
            (
                request_id,
                request_digest,
                json.dumps(response, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                committed_at_ms,
            ),
        )


class ProvenanceServiceCore:
    """Single authoritative write door shared by all pipe worker threads."""

    def __init__(
        self,
        *,
        registry: EnrollmentRegistry,
        request_store: ProvenanceRequestStore,
        recorder_factory: Callable[[str, str | None], ProvenanceRecorder],
        service_identity: Any,
        on_commit: Callable[[ProvenanceRecorder], None] | None = None,
        freshness_ms: int = DEFAULT_FRESHNESS_MS,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        if freshness_ms < 1:
            raise ValueError("freshness_ms must be positive")
        self.registry = registry
        self.request_store = request_store
        self.recorder_factory = recorder_factory
        self.service_identity = service_identity
        self.on_commit = on_commit
        self.freshness_ms = freshness_ms
        self.now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._recorders: dict[str, ProvenanceRecorder] = {}
        self._lock = threading.RLock()

    def _recorder(self, session_id: str) -> ProvenanceRecorder:
        recorder = self._recorders.get(session_id)
        if recorder is not None:
            return recorder
        recorder = self.recorder_factory(session_id, self.registry.supervisor_id)
        if recorder._audit_mode not in (AuditMode.ENTERPRISE, AuditMode.MILITARY):
            raise ProvenanceServiceUnavailable("dedicated service requires enterprise or military audit mode")
        if not recorder.is_started:
            recorder.start()
        for enrollment in self.registry.enrollments:
            recorder.register_agent(enrollment.agent_id, enrollment.recorder_public_key())
        self._recorders[session_id] = recorder
        return recorder

    @staticmethod
    def _stored_receipt(
        stored: tuple[str, dict[str, Any]] | None,
        verified: VerifiedRecordRequest,
    ) -> dict[str, Any] | None:
        if stored is None:
            return None
        digest, response = stored
        if digest != verified.request_hash:
            raise ProvenanceProtocolError(
                "idempotency_conflict",
                "request_id is already bound to different signed content",
            )
        replay = dict(response)
        replay["status"] = "already_committed"
        return replay

    @staticmethod
    def _receipt_from_record(record: dict[str, Any], request_id: str, now_ms: int) -> dict[str, Any]:
        return {
            "ok": True,
            "receipt": {
                "event_type": record.get("event_type"),
                "record_hash": canonical_hash(record),
                "seq": record.get("seq"),
                "session_id": record.get("session_id"),
            },
            "request_id": request_id,
            "server_ts_ms": now_ms,
            "status": "committed",
            "version": PROTOCOL_VERSION,
        }

    @staticmethod
    def _recover_record(recorder: ProvenanceRecorder, verified: VerifiedRecordRequest) -> dict[str, Any] | None:
        verification = recorder.verify()
        if not verification.ok:
            raise ProvenanceServiceUnavailable("cannot reconcile against an invalid provenance chain")
        try:
            lines = recorder.log_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ProvenanceServiceUnavailable("cannot read provenance chain for reconciliation") from exc
        found: dict[str, Any] | None = None
        for line in lines:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProvenanceServiceUnavailable("provenance chain contains malformed JSON") from exc
            metadata = record.get("os_corroboration", {}).get(SERVICE_METADATA_KEY, {})
            if metadata.get("request_id") != verified.request_id:
                continue
            if metadata.get("request_hash") != verified.request_hash:
                raise ProvenanceProtocolError(
                    "idempotency_conflict",
                    "ledger request_id is bound to different signed content",
                )
            if found is not None:
                raise ProvenanceServiceUnavailable("duplicate request_id exists in authoritative ledger")
            found = record
        return found

    def handle_record(self, request: dict[str, Any], caller_sid: str) -> dict[str, Any]:
        now = self.now_ms()
        verified = verify_record_request(
            request,
            self.registry,
            caller_sid,
            now_ms=now,
            freshness_ms=self.freshness_ms,
            allow_stale_receipt_lookup=True,
        )
        stored = self._stored_receipt(self.request_store.receipt(verified.request_id), verified)
        if stored is not None:
            return sign_service_response(self.service_identity, stored)
        if verified.stale:
            raise ProvenanceProtocolError("stale_request", "uncommitted request is outside freshness window")
        if verified.event_type not in _AGENT_EVENTS | _SUPERVISOR_EVENTS:
            raise ProvenanceProtocolError(
                "service_internal_event",
                "lifecycle, authentication, integrity, and replication events are service-generated only",
            )
        if verified.event_type in _SUPERVISOR_EVENTS and not verified.enrollment.supervisor:
            raise ProvenanceProtocolError(
                "supervisor_required",
                "privileged provenance event requires the enrolled supervisor identity",
            )

        with self._lock:
            recorder = self._recorder(verified.session_id)
            with self.request_store.transaction() as transaction:
                transaction.prune(now)
                stored = self._stored_receipt(transaction.receipt(verified.request_id), verified)
                if stored is not None:
                    return sign_service_response(self.service_identity, stored)
                recovered = self._recover_record(recorder, verified)
                if recovered is not None:
                    recorder.ensure_replicated(recovered)
                    if self.on_commit is not None:
                        self.on_commit(recorder)
                    response = self._receipt_from_record(recovered, verified.request_id, now)
                    transaction.save_receipt(
                        verified.request_id, verified.request_hash, response, now
                    )
                    response["status"] = "already_committed"
                    return sign_service_response(self.service_identity, response)
                if not transaction.consume_nonce(
                    verified.enrollment.agent_id,
                    verified.nonce,
                    verified.issued_at_ms + self.freshness_ms,
                ):
                    raise ProvenanceProtocolError("replayed_nonce", "nonce was already consumed")
                os_corroboration = {
                    SERVICE_METADATA_KEY: {
                        "agent_algorithm": verified.enrollment.algorithm,
                        "agent_key_version": 1,
                        "agent_public_key_hex": verified.enrollment.public_key.hex(),
                        "caller_sid": caller_sid,
                        "issued_at_ms": verified.issued_at_ms,
                        "nonce": verified.nonce,
                        "operation": "record",
                        "protocol_version": PROTOCOL_VERSION,
                        "request_hash": verified.request_hash,
                        "request_id": verified.request_id,
                        "request_signature": verified.request_signature.hex(),
                    },
                }
                if verified.os_corroboration is not None:
                    os_corroboration["client"] = verified.os_corroboration
                record = recorder.record(
                    verified.event_type,
                    payload=verified.payload,
                    agent_id=verified.enrollment.agent_id,
                    signature=verified.event_signature,
                    os_corroboration=os_corroboration,
                )
                if record is None:
                    raise ProvenanceServiceUnavailable("recorder did not return a committed record")
                if self.on_commit is not None:
                    self.on_commit(recorder)
                response = self._receipt_from_record(record, verified.request_id, now)
                transaction.save_receipt(
                    verified.request_id, verified.request_hash, response, now
                )
            return sign_service_response(self.service_identity, response)

    def close(self) -> None:
        with self._lock:
            for recorder in self._recorders.values():
                if recorder.is_started and not recorder.is_closed:
                    # A service interruption is not represented as a clean
                    # client-controlled session close. The recorder's existing
                    # heartbeat/high-water evidence remains available on restart.
                    recorder._stop_heartbeat.set()
            self.request_store.close()


def fsync_directory(path: Path) -> None:
    """Best-effort directory metadata durability for non-Windows test hosts."""
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
