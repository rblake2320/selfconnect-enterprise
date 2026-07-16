from __future__ import annotations

import hashlib
import json
import threading
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.provenance import (
    AuditMode,
    InMemoryWitnessSink,
    ProvenanceRecorder,
    ProvenanceRecorderError,
    ReplicationError,
    ReplicationSink,
    SessionEventType,
    verify_log,
)
from enterprise.provenance_ipc import (
    AgentEnrollment,
    EnrollmentRegistry,
    ProvenanceProtocolError,
    build_record_request,
    verify_service_response,
)
from enterprise.provenance_service_core import (
    ProvenanceRequestStore,
    ProvenanceServiceCore,
    ProvenanceServiceUnavailable,
    _RequestTransaction,
)

NOW = 1_750_000_000_000
SID = "S-1-5-21-1-2-3-1001"


class FakeIdentity:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.agent_id = "SC-" + hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def enrolled(identity: FakeIdentity, *, supervisor: bool = False) -> AgentEnrollment:
    return AgentEnrollment.from_dict({
        "agent_id": identity.agent_id,
        "algorithm": "ed25519",
        "public_key_hex": identity.public_key_bytes.hex(),
        "sid": SID,
        "supervisor": supervisor,
    })


class RecorderFactory:
    def __init__(self, directory) -> None:
        self.directory = directory
        self.recorders = {}

    def __call__(self, session_id, supervisor_id):
        recorder = ProvenanceRecorder(
            session_id,
            agent_id="provenance-service",
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=self.directory,
            heartbeat_interval=0,
            supervisor_id=supervisor_id,
            replication_sink=InMemoryWitnessSink(),
        )
        self.recorders[session_id] = recorder
        return recorder


def make_core(tmp_path, agent, *, supervisor=False):
    service = FakeIdentity()
    factory = RecorderFactory(tmp_path / "logs")
    store = ProvenanceRequestStore(tmp_path / "state" / "requests.sqlite3")
    core = ProvenanceServiceCore(
        registry=EnrollmentRegistry([enrolled(agent, supervisor=supervisor)]),
        request_store=store,
        recorder_factory=factory,
        service_identity=service,
        freshness_ms=60_000,
        now_ms=lambda: NOW,
    )
    return core, factory, service


def signed_request(agent, *, session_id=None, request_id=None, nonce="A" * 32, event_type=None):
    return build_record_request(
        agent,
        session_id=session_id or str(uuid.uuid4()),
        request_id=request_id or str(uuid.uuid4()),
        nonce=nonce,
        issued_at_ms=NOW,
        event_type=event_type or SessionEventType.TOOL_CALL,
        payload={"action": "diagnose", "result": "bounded"},
    )


def assert_service_signature(response, service):
    assert verify_service_response(
        response,
        algorithm="ed25519",
        public_key=service.public_key_bytes,
        expected_agent_id=service.agent_id,
    )


def client_records(recorder):
    return [
        json.loads(line)
        for line in recorder.log_path.read_text(encoding="utf-8").splitlines()
        if line and json.loads(line).get("event_type") == SessionEventType.TOOL_CALL.value
    ]


def test_commit_replay_and_stale_retry_return_one_signed_receipt(tmp_path):
    agent = FakeIdentity()
    core, factory, service = make_core(tmp_path, agent)
    value = signed_request(agent)
    first = core.handle_record(value, SID)
    assert first["status"] == "committed"
    assert_service_signature(first, service)
    core.now_ms = lambda: NOW + 600_000
    replay = core.handle_record(value, SID)
    assert replay["status"] == "already_committed"
    assert replay["receipt"] == first["receipt"]
    assert_service_signature(replay, service)
    assert len(client_records(factory.recorders[value["session_id"]])) == 1


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("agent_sig", "00" * 64),
        ("request_signature", "00" * 64),
        ("request_hash", "00" * 32),
    ],
)
def test_service_record_offline_verification_rejects_agent_attribution_tamper(
    tmp_path,
    field,
    replacement,
):
    agent = FakeIdentity()
    core, factory, _service = make_core(tmp_path, agent)
    value = signed_request(agent)
    core.handle_record(value, SID)
    recorder = factory.recorders[value["session_id"]]
    records = [json.loads(line) for line in recorder.log_path.read_text(encoding="utf-8").splitlines()]
    target = next(item for item in records if item.get("event_type") == SessionEventType.TOOL_CALL.value)
    if field == "agent_sig":
        target[field] = replacement
    else:
        target["os_corroboration"]["provenance_service"][field] = replacement
    recorder.log_path.write_text(
        "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records),
        encoding="utf-8",
    )
    result = verify_log(recorder.log_path, recorder.session_id)
    assert result.ok is False
    assert "agent request attestation" in result.message


def test_service_record_offline_verifies_both_agent_signatures(tmp_path):
    agent = FakeIdentity()
    core, factory, _service = make_core(tmp_path, agent)
    value = signed_request(agent)
    core.handle_record(value, SID)
    recorder = factory.recorders[value["session_id"]]
    result = verify_log(recorder.log_path, recorder.session_id)
    assert result.ok
    assert result.agent_attestations_verified == 1
    assert result.legacy_agent_signatures_unverified == 0


def test_same_request_id_cannot_be_rebound(tmp_path):
    agent = FakeIdentity()
    core, _factory, _service = make_core(tmp_path, agent)
    request_id = str(uuid.uuid4())
    first = signed_request(agent, request_id=request_id)
    core.handle_record(first, SID)
    second = signed_request(agent, request_id=request_id, nonce="B" * 32)
    with pytest.raises(ProvenanceProtocolError) as caught:
        core.handle_record(second, SID)
    assert caught.value.code == "idempotency_conflict"


def test_nonce_replay_across_distinct_requests_is_denied(tmp_path):
    agent = FakeIdentity()
    core, _factory, _service = make_core(tmp_path, agent)
    session_id = str(uuid.uuid4())
    core.handle_record(signed_request(agent, session_id=session_id), SID)
    with pytest.raises(ProvenanceProtocolError) as caught:
        core.handle_record(signed_request(agent, session_id=session_id), SID)
    assert caught.value.code == "replayed_nonce"


def test_commit_db_failure_recovers_from_authoritative_ledger_without_duplicate(tmp_path, monkeypatch):
    agent = FakeIdentity()
    core, factory, service = make_core(tmp_path, agent)
    value = signed_request(agent)
    original = _RequestTransaction.save_receipt
    failed = False

    def fail_once(self, *args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise sqlite_failure
        return original(self, *args, **kwargs)

    sqlite_failure = RuntimeError("simulated receipt commit failure")
    monkeypatch.setattr(_RequestTransaction, "save_receipt", fail_once)
    with pytest.raises(RuntimeError, match="simulated receipt"):
        core.handle_record(value, SID)
    response = core.handle_record(value, SID)
    assert response["status"] == "already_committed"
    assert_service_signature(response, service)
    assert len(client_records(factory.recorders[value["session_id"]])) == 1


def test_military_recovery_repairs_remote_replication_before_acknowledging(tmp_path):
    class FailOnceSink(ReplicationSink):
        def __init__(self) -> None:
            self.attempts = 0
            self.tool_attempts = 0
            self.records = []

        def push(self, session_id, segment_no, record):
            self.attempts += 1
            if record.get("event_type") == SessionEventType.TOOL_CALL.value:
                self.tool_attempts += 1
                if self.tool_attempts == 1:
                    raise ReplicationError("simulated remote outage")
            self.records.append((session_id, segment_no, record))
            return f"receipt-{self.attempts}"

        def get_latest_receipt(self, session_id):
            if not self.records:
                return None
            return {"root": "repaired", "session_id": session_id}

    agent = FakeIdentity()
    service = FakeIdentity()
    sink = FailOnceSink()
    recorders = {}

    def recorder_factory(session_id, supervisor_id):
        recorder = ProvenanceRecorder(
            session_id,
            agent_id="provenance-service",
            audit_mode=AuditMode.MILITARY,
            log_dir=tmp_path / "logs",
            heartbeat_interval=0,
            supervisor_id=supervisor_id,
            replication_sink=sink,
        )
        recorders[session_id] = recorder
        return recorder

    core = ProvenanceServiceCore(
        registry=EnrollmentRegistry([enrolled(agent)]),
        request_store=ProvenanceRequestStore(tmp_path / "state" / "requests.sqlite3"),
        recorder_factory=recorder_factory,
        service_identity=service,
        freshness_ms=60_000,
        now_ms=lambda: NOW,
    )
    value = signed_request(agent)

    with pytest.raises(ProvenanceRecorderError, match="Replication failed"):
        core.handle_record(value, SID)

    recorder = recorders[value["session_id"]]
    assert len(client_records(recorder)) == 1
    assert core.request_store.receipt(value["request_id"]) is None

    recovered = core.handle_record(value, SID)
    assert recovered["status"] == "already_committed"
    assert_service_signature(recovered, service)
    assert sink.tool_attempts == 2
    assert sum(
        record.get("event_type") == SessionEventType.TOOL_CALL.value
        for _session_id, _segment_no, record in sink.records
    ) == 1
    assert len(client_records(recorder)) == 1
    assert core.request_store.receipt(value["request_id"]) is not None


def test_privileged_event_requires_the_single_enrolled_supervisor(tmp_path):
    agent = FakeIdentity()
    core, _factory, _service = make_core(tmp_path, agent)
    with pytest.raises(ProvenanceProtocolError) as caught:
        core.handle_record(
            signed_request(agent, event_type=SessionEventType.APPROVAL_GRANTED),
            SID,
        )
    assert caught.value.code == "supervisor_required"

    supervisor_core, factory, _service = make_core(tmp_path / "supervisor", agent, supervisor=True)
    value = signed_request(agent, event_type=SessionEventType.APPROVAL_GRANTED)
    response = supervisor_core.handle_record(value, SID)
    assert response["ok"] is True
    assert len(factory.recorders) == 1


@pytest.mark.parametrize(
    "event_type",
    [
        SessionEventType.SESSION_OPEN,
        SessionEventType.SESSION_RECONSTRUCTED,
        SessionEventType.HEARTBEAT,
        SessionEventType.AUTH_SUCCESS,
        SessionEventType.POLICY_VIOLATION,
        SessionEventType.MERKLE_SEAL,
        SessionEventType.SEGMENT_SEALED,
        SessionEventType.REPLICATION_ACK,
    ],
)
def test_even_supervisor_cannot_manufacture_service_internal_evidence(tmp_path, event_type):
    agent = FakeIdentity()
    core, factory, _service = make_core(tmp_path, agent, supervisor=True)
    with pytest.raises(ProvenanceProtocolError) as caught:
        core.handle_record(signed_request(agent, event_type=event_type), SID)
    assert caught.value.code == "service_internal_event"
    assert not factory.recorders


def test_concurrent_duplicate_has_one_ledger_commit(tmp_path):
    agent = FakeIdentity()
    core, factory, _service = make_core(tmp_path, agent)
    value = signed_request(agent)
    responses = []
    errors = []

    def worker():
        try:
            responses.append(core.handle_record(value, SID))
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(responses) == 20
    assert {item["receipt"]["record_hash"] for item in responses} == {
        responses[0]["receipt"]["record_hash"]
    }
    assert len(client_records(factory.recorders[value["session_id"]])) == 1


def test_recovery_refuses_an_invalid_chain(tmp_path, monkeypatch):
    agent = FakeIdentity()
    core, factory, _service = make_core(tmp_path, agent)
    value = signed_request(agent)
    original = _RequestTransaction.save_receipt
    monkeypatch.setattr(
        _RequestTransaction,
        "save_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("fail after record")),
    )
    with pytest.raises(RuntimeError):
        core.handle_record(value, SID)
    monkeypatch.setattr(_RequestTransaction, "save_receipt", original)
    recorder = factory.recorders[value["session_id"]]
    lines = recorder.log_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["payload"]["tampered"] = True
    lines[0] = json.dumps(first, separators=(",", ":"))
    recorder.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceServiceUnavailable, match="invalid provenance chain"):
        core.handle_record(value, SID)
