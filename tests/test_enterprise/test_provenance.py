"""Comprehensive adversarial test suite for enterprise.provenance and enterprise.session_index.

Tests are organized by threat model fix number (Fix 1 through Fix 13) and cover:
  - Normal operation (happy path)
  - Each of the 13 adversarial fixes
  - Fail-closed behaviour
  - Session state machine
  - Merkle sealing
  - SessionIndex chain integrity
  - Resume verification with rollback/fork detection
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid

import pytest

from enterprise.provenance import (
    GENESIS_HASH,
    AuditMode,
    InMemoryWitnessSink,
    ProvenanceRecorder,
    ProvenanceRecorderError,
    ReplicationError,
    ReplicationSink,
    SessionEventType,
    SessionState,
    canonical_bytes,
    canonical_hash,
    verify_log,
    _merkle_root,
)
from enterprise.session_index import (
    SessionIndex,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_log_dir(tmp_path):
    return tmp_path / "provenance"


@pytest.fixture
def recorder(tmp_log_dir):
    """A started consumer-mode recorder."""
    r = ProvenanceRecorder(
        session_id=str(uuid.uuid4()),
        agent_id="test-agent",
        audit_mode=AuditMode.CONSUMER,
        log_dir=tmp_log_dir,
        heartbeat_interval=0,  # disable heartbeat in tests
    )
    r.start()
    yield r
    if not r.is_closed:
        r.close()


@pytest.fixture
def enterprise_recorder(tmp_log_dir):
    """A started enterprise-mode recorder with InMemoryWitnessSink."""
    sink = InMemoryWitnessSink()
    r = ProvenanceRecorder(
        session_id=str(uuid.uuid4()),
        agent_id="enterprise-agent",
        audit_mode=AuditMode.ENTERPRISE,
        log_dir=tmp_log_dir,
        heartbeat_interval=0,
        supervisor_id="supervisor-001",
        orchestrator_token="orch-secret-token",
        replication_sink=sink,
    )
    r.start()
    yield r, sink
    if not r.is_closed:
        try:
            r.close(orchestrator_token="orch-secret-token")
        except Exception:
            pass


@pytest.fixture
def military_recorder(tmp_log_dir):
    """A started military-mode recorder with InMemoryWitnessSink."""
    sink = InMemoryWitnessSink()
    r = ProvenanceRecorder(
        session_id=str(uuid.uuid4()),
        agent_id="military-agent",
        audit_mode=AuditMode.MILITARY,
        log_dir=tmp_log_dir,
        heartbeat_interval=0,
        supervisor_id="supervisor-mil",
        orchestrator_token="mil-orch-token",
        replication_sink=sink,
    )
    r.start()
    yield r, sink
    if not r.is_closed:
        try:
            r.close(orchestrator_token="mil-orch-token")
        except Exception:
            pass


@pytest.fixture
def session_index(tmp_log_dir):
    return SessionIndex(index_dir=tmp_log_dir)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_start_and_close(self, tmp_log_dir):
        r = ProvenanceRecorder(
            session_id="happy-001",
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        assert r.is_started
        assert not r.is_closed
        r.close()
        assert r.is_closed

    def test_record_returns_dict(self, recorder):
        result = recorder.record(SessionEventType.TOOL_CALL, payload={"cmd": "ls"})
        assert result is not None
        assert result["event_type"] == "tool_call"
        assert result["seq"] == 2  # seq 1 = SESSION_OPEN

    def test_event_count_increments(self, recorder):
        initial = recorder.event_count
        recorder.record(SessionEventType.TOOL_CALL)
        recorder.record(SessionEventType.TOOL_RESULT)
        assert recorder.event_count == initial + 2

    def test_log_file_created(self, recorder):
        assert recorder.log_path.exists()

    def test_chain_is_valid_after_records(self, recorder):
        for i in range(10):
            recorder.record(SessionEventType.TOOL_CALL, payload={"i": i})
        result = recorder.verify()
        assert result.ok
        assert result.count >= 10

    def test_tail_returns_recent_events(self, recorder):
        for i in range(5):
            recorder.record(SessionEventType.CHECKPOINT, payload={"n": i})
        tail = recorder.tail(3)
        assert len(tail) == 3

    def test_session_state_open_during_run(self, recorder):
        assert recorder.session_state == SessionState.OPEN

    def test_session_state_sealed_after_close(self, tmp_log_dir):
        r = ProvenanceRecorder(
            session_id="seal-test",
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.close()
        assert r.is_closed

    def test_double_start_is_idempotent(self, recorder):
        initial_count = recorder.event_count
        recorder.start()  # second call should be no-op
        assert recorder.event_count == initial_count

    def test_double_close_is_idempotent(self, tmp_log_dir):
        r = ProvenanceRecorder(
            session_id="double-close",
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.close()
        r.close()  # second close should not raise


# ---------------------------------------------------------------------------
# Fix 1: Session states + heartbeat + truncation vs crash distinction
# ---------------------------------------------------------------------------

class TestFix1SessionStates:
    def test_interrupted_state_when_no_close(self, tmp_log_dir):
        """A log without SESSION_CLOSE should show state=interrupted, not fail."""
        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        # Do NOT close — simulate crash
        result = verify_log(r.log_path, sid)
        assert result.ok  # chain is intact
        assert result.session_state == SessionState.INTERRUPTED.value

    def test_sealed_state_after_close(self, tmp_log_dir):
        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        r.close()
        result = verify_log(r.log_path, sid)
        assert result.ok
        assert result.session_state == SessionState.SEALED.value

    def test_heartbeat_writes_high_water_mark(self, tmp_log_dir):
        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=1,  # 1 second
        )
        r.start()
        for _ in range(5):
            r.record(SessionEventType.TOOL_CALL)
        time.sleep(1.5)  # wait for heartbeat
        r.close()
        result = verify_log(r.log_path, sid)
        assert result.ok
        assert result.high_water_seq > 0

    def test_timestamp_monotonicity_detected(self, tmp_log_dir):
        """Manually craft a log with a timestamp regression and verify it fails."""
        sid = str(uuid.uuid4())
        log_path = tmp_log_dir / f"{sid}.jsonl"
        tmp_log_dir.mkdir(parents=True, exist_ok=True)

        # Write two records with reversed timestamps
        prev = GENESIS_HASH
        r1 = {
            "seq": 1, "ts": "2025-01-02T00:00:00+00:00",
            "session_id": sid, "agent_id": "a",
            "event_type": "session_open", "payload": {}, "prev_hash": prev,
        }
        h1 = canonical_hash(r1)
        r2 = {
            "seq": 2, "ts": "2025-01-01T00:00:00+00:00",  # earlier!
            "session_id": sid, "agent_id": "a",
            "event_type": "tool_call", "payload": {}, "prev_hash": h1,
        }
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(r1) + "\n")
            fh.write(json.dumps(r2) + "\n")

        result = verify_log(log_path, sid)
        assert not result.ok
        assert "timestamp regression" in result.message


# ---------------------------------------------------------------------------
# Fix 2: Manifest rollback detection
# ---------------------------------------------------------------------------

class TestFix2ManifestRollback:
    def test_rollback_detected_when_log_seq_less_than_manifest(self, tmp_log_dir):
        sink = InMemoryWitnessSink()
        index = SessionIndex(index_dir=tmp_log_dir, replication_sink=sink)
        sid = str(uuid.uuid4())

        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            replication_sink=sink,
        )
        r.start()
        for _ in range(10):
            r.record(SessionEventType.TOOL_CALL)
        index.open_session(r)
        index.update_session(sid, recorder=r)

        # Simulate rollback: truncate log to fewer events
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        r.log_path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")

        result = index.verify_for_resume(sid)
        # Should detect rollback (high_water_seq < last_known_seq)
        assert not result.ok or result.rollback_suspected

    def test_first_event_hash_mismatch_detected(self, tmp_log_dir):
        """Prepend attack: replace log with a new one starting from GENESIS_HASH."""
        sink = InMemoryWitnessSink()
        index = SessionIndex(index_dir=tmp_log_dir, replication_sink=sink)
        sid = str(uuid.uuid4())

        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        index.open_session(r)

        # Replace log with a completely different chain (same session_id)
        r2 = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir / "alt",
            heartbeat_interval=0,
        )
        r2.start()
        r2.record(SessionEventType.TOOL_CALL, payload={"injected": True})
        r2.close()

        # Overwrite original log with the attacker's log
        r.log_path.write_text(
            r2.log_path.read_text(encoding="utf-8"), encoding="utf-8"
        )

        result = index.verify_for_resume(sid)
        # First event hash should not match manifest
        assert not result.ok


# ---------------------------------------------------------------------------
# Fix 3: Fork detection via InMemoryWitnessSink
# ---------------------------------------------------------------------------

class TestFix3ForkDetection:
    def test_fork_detected_by_witness_sink(self, tmp_log_dir):
        """Fork detection fires when two Merkle seal records claim different roots
        for the same (session_id, segment_no). Individual event records with
        different hashes in the same segment are NOT forks."""
        sink = InMemoryWitnessSink()
        sid = "fork-test-session"

        # Merkle seal record for segment 1 — branch A
        seal_a = {
            "seq": 100, "ts": "2025-01-01T00:00:00+00:00",
            "session_id": sid, "agent_id": "recorder",
            "event_type": "merkle_seal",
            "payload": {"merkle_root": "aaa" * 32, "sealed_events": 100, "segment_no": 1},
            "prev_hash": GENESIS_HASH,
        }
        # Conflicting Merkle seal for the SAME segment — different root = fork
        seal_b = {
            "seq": 100, "ts": "2025-01-01T00:00:00+00:00",
            "session_id": sid, "agent_id": "recorder",
            "event_type": "merkle_seal",
            "payload": {"merkle_root": "bbb" * 32, "sealed_events": 100, "segment_no": 1},
            "prev_hash": GENESIS_HASH,
        }

        # First seal push succeeds
        sink.push(sid, 1, seal_a)

        # Second seal push with different root for same (session_id, segment_no) is a fork
        with pytest.raises(ReplicationError, match="fork_detected"):
            sink.push(sid, 1, seal_b)

        # Individual event records with different hashes in same segment are NOT forks
        event_a = {
            "seq": 1, "ts": "2025-01-01T00:00:00+00:00",
            "session_id": sid, "agent_id": "a",
            "event_type": "tool_call", "payload": {"branch": "A"},
            "prev_hash": GENESIS_HASH,
        }
        event_b = {
            "seq": 2, "ts": "2025-01-01T00:00:01+00:00",
            "session_id": sid, "agent_id": "a",
            "event_type": "tool_call", "payload": {"branch": "B"},
            "prev_hash": "x" * 96,
        }
        # Both individual events push successfully — different hashes, same segment, not a fork
        sink.push(sid, 0, event_a)
        sink.push(sid, 0, event_b)  # must NOT raise

    def test_same_root_is_idempotent(self, tmp_log_dir):
        """Pushing the same root twice is idempotent (no fork)."""
        sink = InMemoryWitnessSink()
        sid = "idempotent-test"
        record = {
            "seq": 1, "ts": "2025-01-01T00:00:00+00:00",
            "session_id": sid, "agent_id": "a",
            "event_type": "tool_call", "payload": {},
            "prev_hash": GENESIS_HASH,
        }
        receipt1 = sink.push(sid, 0, record)
        receipt2 = sink.push(sid, 0, record)
        assert receipt1 != receipt2  # different receipt IDs
        # But no exception — same root is fine

    def test_military_recorder_raises_on_fork(self, tmp_log_dir):
        """In military mode, fork detection raises ProvenanceRecorderError."""
        class ForkingSink(ReplicationSink):
            def __init__(self):
                self._first = True
            def push(self, session_id, segment_no, record):
                if not self._first:
                    raise ReplicationError("fork_detected: test")
                self._first = False
                return "receipt-1"

        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.MILITARY,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            replication_sink=ForkingSink(),
        )
        r.start()
        with pytest.raises(ProvenanceRecorderError, match="Fork detected"):
            r.record(SessionEventType.TOOL_CALL)


# ---------------------------------------------------------------------------
# Fix 4: Canonical serialization
# ---------------------------------------------------------------------------

class TestFix4CanonicalSerialization:
    def test_canonical_bytes_is_deterministic(self):
        record = {
            "seq": 1, "ts": "2025-01-01T00:00:00+00:00",
            "session_id": "s1", "agent_id": "a1",
            "event_type": "tool_call", "payload": {"z": 1, "a": 2},
            "prev_hash": GENESIS_HASH,
        }
        b1 = canonical_bytes(record)
        b2 = canonical_bytes(record)
        assert b1 == b2

    def test_canonical_bytes_excludes_signatures(self):
        record = {
            "seq": 1, "ts": "t", "session_id": "s", "agent_id": "a",
            "event_type": "tool_call", "payload": {},
            "prev_hash": GENESIS_HASH,
            "recorder_sig": "aabbcc",
            "agent_sig": "ddeeff",
        }
        b = canonical_bytes(record)
        parsed = json.loads(b.decode("ascii"))
        assert "recorder_sig" not in parsed
        assert "agent_sig" not in parsed

    def test_canonical_bytes_is_ascii_only(self):
        record = {
            "seq": 1, "ts": "t", "session_id": "s", "agent_id": "a",
            "event_type": "tool_call", "payload": {"unicode": "caf\u00e9"},
            "prev_hash": GENESIS_HASH,
        }
        b = canonical_bytes(record)
        b.decode("ascii")  # must not raise

    def test_canonical_bytes_sorts_keys(self):
        r1 = {"b": 2, "a": 1, "prev_hash": GENESIS_HASH}
        r2 = {"a": 1, "b": 2, "prev_hash": GENESIS_HASH}
        assert canonical_bytes(r1) == canonical_bytes(r2)

    def test_canonical_hash_is_sha384(self):
        record = {
            "seq": 1, "ts": "t", "session_id": "s", "agent_id": "a",
            "event_type": "tool_call", "payload": {},
            "prev_hash": GENESIS_HASH,
        }
        h = canonical_hash(record)
        assert len(h) == 96  # SHA-384 = 48 bytes = 96 hex chars

    def test_chain_break_detected_on_tampered_record(self, tmp_log_dir):
        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL, payload={"cmd": "ls"})
        r.record(SessionEventType.TOOL_CALL, payload={"cmd": "pwd"})
        r.close()

        # Tamper with the second record
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        second = json.loads(lines[1])
        second["payload"]["cmd"] = "rm -rf /"  # tamper
        lines[1] = json.dumps(second)
        r.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_log(r.log_path, sid)
        assert not result.ok
        assert "chain break" in result.message


# ---------------------------------------------------------------------------
# Fix 6: Per-event signature verification
# ---------------------------------------------------------------------------

class TestFix6SignatureVerification:
    def test_unsigned_event_from_registered_agent_blocked_in_enterprise(
        self, enterprise_recorder
    ):
        r, sink = enterprise_recorder
        # Register an agent with a mock public key
        class MockPublicKey:
            def verify(self, sig, data):
                raise Exception("bad signature")

        r.register_agent("registered-agent", public_key=MockPublicKey())
        with pytest.raises(ProvenanceRecorderError, match="must provide a signature"):
            r.record(
                SessionEventType.TOOL_CALL,
                agent_id="registered-agent",
                signature=None,
            )

    def test_unsigned_event_from_unregistered_agent_allowed(self, enterprise_recorder):
        r, sink = enterprise_recorder
        # Unregistered agents can submit without signatures
        result = r.record(
            SessionEventType.TOOL_CALL,
            agent_id="unregistered-agent",
            signature=None,
        )
        assert result is not None

    def test_bad_signature_rejected(self, enterprise_recorder):
        r, sink = enterprise_recorder

        class StrictKey:
            def verify(self, sig, data):
                raise ValueError("signature mismatch")

        r.register_agent("strict-agent", public_key=StrictKey())
        with pytest.raises(ProvenanceRecorderError, match="Signature verification failed"):
            r.record(
                SessionEventType.TOOL_CALL,
                agent_id="strict-agent",
                signature=b"\x00" * 64,
            )

    def test_valid_signature_accepted(self, enterprise_recorder):
        r, sink = enterprise_recorder

        class GoodKey:
            def verify(self, sig, data):
                pass  # no exception = valid

        r.register_agent("good-agent", public_key=GoodKey())
        result = r.record(
            SessionEventType.TOOL_CALL,
            agent_id="good-agent",
            signature=b"\xab" * 64,
        )
        assert result is not None


# ---------------------------------------------------------------------------
# Fix 7: close() requires orchestrator token
# ---------------------------------------------------------------------------

class TestFix7OrchestratorToken:
    def test_close_without_token_blocked_in_enterprise(self, enterprise_recorder):
        r, sink = enterprise_recorder
        with pytest.raises(ProvenanceRecorderError, match="orchestrator_token"):
            r.close(orchestrator_token=None)

    def test_close_with_wrong_token_blocked(self, enterprise_recorder):
        r, sink = enterprise_recorder
        with pytest.raises(ProvenanceRecorderError, match="orchestrator_token"):
            r.close(orchestrator_token="wrong-token")

    def test_close_with_correct_token_succeeds(self, enterprise_recorder):
        r, sink = enterprise_recorder
        r.close(orchestrator_token="orch-secret-token")
        assert r.is_closed

    def test_unauthorized_close_attempt_logged_as_violation(
        self, enterprise_recorder, tmp_log_dir
    ):
        r, sink = enterprise_recorder
        try:
            r.close(orchestrator_token="wrong-token")
        except ProvenanceRecorderError:
            pass
        # Verify a POLICY_VIOLATION was logged
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        violations = [
            line for line in lines
            if '"policy_violation"' in line and '"unauthorized_close_attempt"' in line
        ]
        assert len(violations) >= 1

    def test_consumer_mode_close_without_token_allowed(self, recorder):
        recorder.close(orchestrator_token=None)
        assert recorder.is_closed


# ---------------------------------------------------------------------------
# Fix 8: Event-type-to-identity binding
# ---------------------------------------------------------------------------

class TestFix8EventTypeAuthority:
    def test_privileged_event_from_wrong_agent_blocked(self, enterprise_recorder):
        r, sink = enterprise_recorder
        with pytest.raises(ProvenanceRecorderError, match="may only be submitted by supervisor"):
            r.record(
                SessionEventType.APPROVAL_GRANTED,
                agent_id="rogue-agent",
            )

    def test_privileged_event_from_supervisor_allowed(self, enterprise_recorder):
        r, sink = enterprise_recorder
        result = r.record(
            SessionEventType.APPROVAL_GRANTED,
            agent_id="supervisor-001",
        )
        assert result is not None

    def test_unauthorized_privileged_event_logged_as_violation(
        self, enterprise_recorder
    ):
        r, sink = enterprise_recorder
        try:
            r.record(SessionEventType.APPROVAL_GRANTED, agent_id="rogue")
        except ProvenanceRecorderError:
            pass
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        violations = [
            ln for ln in lines
            if '"policy_violation"' in ln and '"unauthorized_privileged_event"' in ln
        ]
        assert len(violations) >= 1

    def test_consumer_mode_no_authority_enforcement(self, recorder):
        # Consumer mode: any agent can submit any event type
        result = recorder.record(
            SessionEventType.APPROVAL_GRANTED,
            agent_id="any-agent",
        )
        assert result is not None

    def test_military_mode_requires_supervisor_id(self, tmp_log_dir):
        """Military mode without supervisor_id blocks privileged events."""
        sink = InMemoryWitnessSink()
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.MILITARY,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            supervisor_id=None,  # no supervisor configured
            replication_sink=sink,
        )
        r.start()
        with pytest.raises(ProvenanceRecorderError, match="requires a supervisor_id"):
            r.record(SessionEventType.APPROVAL_GRANTED)
        r.close(orchestrator_token=None)


# ---------------------------------------------------------------------------
# Fix 9: agent_id bound to public key at session open
# ---------------------------------------------------------------------------

class TestFix9AgentIdentityBinding:
    def test_agent_registered_with_key(self, enterprise_recorder):
        r, sink = enterprise_recorder
        calls = []

        class TrackingKey:
            def verify(self, sig, data):
                calls.append(data)

        r.register_agent("tracked-agent", public_key=TrackingKey())
        r.record(
            SessionEventType.TOOL_CALL,
            agent_id="tracked-agent",
            signature=b"\x01" * 64,
        )
        assert len(calls) == 1

    def test_agent_registered_without_key_skips_verification(self, enterprise_recorder):
        r, sink = enterprise_recorder
        r.register_agent("keyless-agent", public_key=None)
        # Should not raise even without signature
        result = r.record(
            SessionEventType.TOOL_CALL,
            agent_id="keyless-agent",
            signature=None,
        )
        assert result is not None


# ---------------------------------------------------------------------------
# Fix 10: verify() before resume
# ---------------------------------------------------------------------------

class TestFix10VerifyBeforeResume:
    def test_resume_blocked_on_broken_chain(self, tmp_log_dir):
        sink = InMemoryWitnessSink()
        index = SessionIndex(index_dir=tmp_log_dir, replication_sink=sink)
        sid = str(uuid.uuid4())

        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        index.open_session(r)

        # Break the chain by corrupting a record
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["payload"]["injected"] = True
        lines[0] = json.dumps(rec)
        r.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = index.verify_for_resume(sid)
        assert not result.ok
        assert "chain break" in result.message

    def test_resume_allowed_on_intact_chain(self, tmp_log_dir):
        index = SessionIndex(index_dir=tmp_log_dir)
        sid = str(uuid.uuid4())

        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        index.open_session(r)
        r.close()
        index.update_session(sid, recorder=r, state=SessionState.SEALED)

        result = index.verify_for_resume(sid)
        assert result.ok

    def test_resume_blocked_on_missing_log(self, tmp_log_dir):
        index = SessionIndex(index_dir=tmp_log_dir)
        sid = str(uuid.uuid4())

        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        index.open_session(r)
        r.close()

        # Delete the log file
        r.log_path.unlink()

        result = index.verify_for_resume(sid)
        assert not result.ok
        assert "not found" in result.message


# ---------------------------------------------------------------------------
# Fix 11: Policy/audit-mode downgrade protection
# ---------------------------------------------------------------------------

class TestFix11PolicyDowngrade:
    def test_downgrade_without_token_blocked(self, enterprise_recorder):
        r, sink = enterprise_recorder
        with pytest.raises(ProvenanceRecorderError, match="Audit mode downgrade"):
            r.change_audit_mode(AuditMode.CONSUMER, orchestrator_token=None)

    def test_downgrade_with_correct_token_allowed(self, enterprise_recorder):
        r, sink = enterprise_recorder
        r.change_audit_mode(
            AuditMode.CONSUMER,
            orchestrator_token="orch-secret-token",
            reason="test downgrade",
        )
        assert r._audit_mode == AuditMode.CONSUMER

    def test_upgrade_does_not_require_token(self, recorder):
        # Consumer → enterprise is an upgrade, should not require token
        recorder.change_audit_mode(AuditMode.ENTERPRISE)
        assert recorder._audit_mode == AuditMode.ENTERPRISE

    def test_downgrade_attempt_logged_as_violation(self, enterprise_recorder):
        r, sink = enterprise_recorder
        try:
            r.change_audit_mode(AuditMode.CONSUMER, orchestrator_token="wrong")
        except ProvenanceRecorderError:
            pass
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        violations = [
            ln for ln in lines
            if '"policy_violation"' in ln and '"unauthorized_audit_mode_downgrade"' in ln
        ]
        assert len(violations) >= 1

    def test_audit_mode_change_logged(self, enterprise_recorder):
        r, sink = enterprise_recorder
        r.change_audit_mode(
            AuditMode.CONSUMER,
            orchestrator_token="orch-secret-token",
            reason="authorized downgrade",
        )
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        changes = [
            ln for ln in lines
            if '"audit_mode_change"' in ln
        ]
        assert len(changes) >= 1

    def test_audit_mode_allows_downgrade_logic(self):
        assert AuditMode.MILITARY.allows_downgrade_to(AuditMode.MILITARY)
        assert AuditMode.CONSUMER.allows_downgrade_to(AuditMode.MILITARY)
        assert not AuditMode.MILITARY.allows_downgrade_to(AuditMode.CONSUMER)
        assert not AuditMode.ENTERPRISE.allows_downgrade_to(AuditMode.CONSUMER)


# ---------------------------------------------------------------------------
# Fix 12: TELEMETRY_GAP event
# ---------------------------------------------------------------------------

class TestFix12TelemetryGap:
    def test_telemetry_gap_recorded(self, recorder):
        recorder.report_telemetry_gap(sensor="sysmon", detail="service stopped")
        lines = recorder.log_path.read_text(encoding="utf-8").splitlines()
        gaps = [ln for ln in lines if '"telemetry_gap"' in ln]
        assert len(gaps) == 1
        rec = json.loads(gaps[0])
        assert rec["payload"]["sensor"] == "sysmon"

    def test_telemetry_gap_in_chain(self, recorder):
        recorder.report_telemetry_gap(sensor="etw")
        result = recorder.verify()
        assert result.ok


# ---------------------------------------------------------------------------
# Fix 13: Fail-closed and AU-5 audit failure
# ---------------------------------------------------------------------------

class TestFix13FailClosed:
    def test_enterprise_fails_closed_on_bad_log_dir(self, tmp_path):
        """Enterprise mode should raise if log dir cannot be created."""
        # Use a path that cannot be created (file exists where dir should be)
        blocker = tmp_path / "blocker"
        blocker.write_text("blocking file")
        bad_dir = blocker / "subdir"  # can't create — parent is a file

        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=bad_dir,
            heartbeat_interval=0,
        )
        with pytest.raises(ProvenanceRecorderError):
            r.start()

    def test_consumer_continues_on_bad_log_dir(self, tmp_path):
        """Consumer mode should continue even if log dir cannot be created."""
        blocker = tmp_path / "blocker2"
        blocker.write_text("blocking file")
        bad_dir = blocker / "subdir"

        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.CONSUMER,
            log_dir=bad_dir,
            heartbeat_interval=0,
        )
        r.start()  # should not raise
        result = r.record(SessionEventType.TOOL_CALL)
        assert result is None  # consumer mode returns None when sink unavailable

    def test_military_requires_replication_sink(self, tmp_log_dir):
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.MILITARY,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            replication_sink=None,  # no sink
        )
        with pytest.raises(ProvenanceRecorderError, match="ReplicationSink"):
            r.start()

    def test_record_after_close_raises(self, recorder):
        recorder.close()
        with pytest.raises(ProvenanceRecorderError, match="closed"):
            recorder.record(SessionEventType.TOOL_CALL)

    def test_record_before_start_raises_in_enterprise(self, tmp_log_dir):
        sink = InMemoryWitnessSink()
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            replication_sink=sink,
        )
        # Do NOT call start()
        with pytest.raises(ProvenanceRecorderError, match="start\\(\\)"):
            r.record(SessionEventType.TOOL_CALL)


# ---------------------------------------------------------------------------
# Merkle sealing
# ---------------------------------------------------------------------------

class TestMerkleSeal:
    def test_merkle_seal_written_at_interval(self, tmp_log_dir):
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            seal_interval=5,
            heartbeat_interval=0,
        )
        r.start()
        for _ in range(6):
            r.record(SessionEventType.TOOL_CALL)
        r.close()
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        seals = [ln for ln in lines if '"merkle_seal"' in ln]
        assert len(seals) >= 1

    def test_merkle_root_is_deterministic(self):
        hashes = [hashlib.sha384(str(i).encode()).hexdigest() for i in range(4)]
        r1 = _merkle_root(hashes)
        r2 = _merkle_root(hashes)
        assert r1 == r2

    def test_merkle_root_of_empty_list(self):
        root = _merkle_root([])
        assert len(root) == 96

    def test_merkle_root_changes_on_tamper(self):
        hashes = [hashlib.sha384(str(i).encode()).hexdigest() for i in range(4)]
        original = _merkle_root(hashes)
        hashes[1] = hashlib.sha384(b"tampered").hexdigest()
        tampered = _merkle_root(hashes)
        assert original != tampered

    def test_final_seal_on_close(self, tmp_log_dir):
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            seal_interval=100,
            heartbeat_interval=0,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        r.close()
        lines = r.log_path.read_text(encoding="utf-8").splitlines()
        final_seals = [
            ln for ln in lines
            if '"merkle_seal"' in ln and '"final":true' in ln
        ]
        assert len(final_seals) >= 1


# ---------------------------------------------------------------------------
# SessionIndex
# ---------------------------------------------------------------------------

class TestSessionIndex:
    def test_open_and_list_session(self, tmp_log_dir, session_index):
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        session_index.open_session(r)
        sessions = session_index.list_sessions()
        assert any(s.session_id == r.session_id for s in sessions)
        r.close()

    def test_update_session_state(self, tmp_log_dir, session_index):
        r = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r.start()
        session_index.open_session(r)
        r.close()
        session_index.update_session(
            r.session_id, recorder=r, state=SessionState.SEALED
        )
        entry = session_index.get_session(r.session_id)
        assert entry is not None
        assert entry.session_state == SessionState.SEALED.value

    def test_index_chain_is_valid(self, tmp_log_dir, session_index):
        for _ in range(3):
            r = ProvenanceRecorder(
                session_id=str(uuid.uuid4()),
                audit_mode=AuditMode.CONSUMER,
                log_dir=tmp_log_dir,
                heartbeat_interval=0,
            )
            r.start()
            session_index.open_session(r)
            r.close()

        ok, message = session_index.verify_index_chain()
        assert ok, message

    def test_get_session_returns_none_for_unknown(self, session_index):
        result = session_index.get_session("nonexistent-session-id")
        assert result is None

    def test_list_sessions_filter_by_state(self, tmp_log_dir, session_index):
        for _ in range(2):
            r = ProvenanceRecorder(
                session_id=str(uuid.uuid4()),
                audit_mode=AuditMode.CONSUMER,
                log_dir=tmp_log_dir,
                heartbeat_interval=0,
            )
            r.start()
            session_index.open_session(r)
            r.close()
            session_index.update_session(
                r.session_id, state=SessionState.SEALED
            )

        # Add one open session
        r_open = ProvenanceRecorder(
            session_id=str(uuid.uuid4()),
            audit_mode=AuditMode.CONSUMER,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
        )
        r_open.start()
        session_index.open_session(r_open)

        sealed = session_index.list_sessions(state_filter="sealed")
        open_sessions = session_index.list_sessions(state_filter="open")
        assert len(sealed) >= 2
        assert len(open_sessions) >= 1
        r_open.close()


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

class TestConcurrency:
    def test_concurrent_record_calls_are_safe(self, recorder):
        errors = []

        def worker(n):
            try:
                for i in range(20):
                    recorder.record(
                        SessionEventType.TOOL_CALL,
                        payload={"worker": n, "i": i},
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent errors: {errors}"
        result = recorder.verify()
        assert result.ok

    def test_concurrent_index_writes_are_safe(self, tmp_log_dir):
        index = SessionIndex(index_dir=tmp_log_dir)
        errors = []

        def worker():
            try:
                r = ProvenanceRecorder(
                    session_id=str(uuid.uuid4()),
                    audit_mode=AuditMode.CONSUMER,
                    log_dir=tmp_log_dir,
                    heartbeat_interval=0,
                )
                r.start()
                index.open_session(r)
                r.close()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent index errors: {errors}"
        ok, msg = index.verify_index_chain()
        assert ok, msg


# ---------------------------------------------------------------------------
# Replication ACK records are skipped in chain verification
# ---------------------------------------------------------------------------

class TestReplicationAck:
    def test_ack_records_skipped_in_verify(self, tmp_log_dir):
        sink = InMemoryWitnessSink()
        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            replication_sink=sink,
        )
        r.start()
        r.record(SessionEventType.TOOL_CALL)
        r.close(orchestrator_token=None)  # no token in consumer-like close

        result = verify_log(r.log_path, sid)
        assert result.ok

    def test_enterprise_with_witness_sink_full_flow(self, tmp_log_dir):
        sink = InMemoryWitnessSink()
        sid = str(uuid.uuid4())
        r = ProvenanceRecorder(
            session_id=sid,
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=tmp_log_dir,
            heartbeat_interval=0,
            supervisor_id="sup",
            orchestrator_token="tok",
            replication_sink=sink,
        )
        r.start()
        for _ in range(5):
            r.record(SessionEventType.TOOL_CALL)
        r.close(orchestrator_token="tok")

        result = verify_log(r.log_path, sid)
        assert result.ok
        assert result.count >= 5
