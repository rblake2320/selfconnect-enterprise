from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.provenance import AuditMode, InMemoryWitnessSink, ProvenanceRecorder, SessionEventType
from enterprise.provenance_ipc import (
    MAX_FRAME_BYTES,
    AgentEnrollment,
    EnrollmentRegistry,
    build_record_request,
    decode_frame,
)
from enterprise.provenance_pipe import (
    PIPE_CLIENT_ACCESS,
    FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA,
    FILE_READ_DATA,
    PIPE_INTEGRITY_POLICY,
    PIPE_INTEGRITY_SID,
    SYNCHRONIZE,
    ProvenancePipeClient,
    ProvenancePipeConfig,
    ProvenancePipeError,
    ProvenancePipeServer,
    build_pipe_security_attributes,
    resolve_account_sid,
)
from enterprise.provenance_service_core import ProvenanceRequestStore, ProvenanceServiceCore

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe contract")


class FakeIdentity:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.agent_id = "SC-" + hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def make_stack(tmp_path, pipe_name, *, instances=4, request_timeout_ms=5_000):
    import win32api

    sid = resolve_account_sid(win32api.GetUserNameEx(2))
    agent = FakeIdentity()
    service = FakeIdentity()
    registry = EnrollmentRegistry([AgentEnrollment.from_dict({
        "agent_id": agent.agent_id,
        "algorithm": "ed25519",
        "public_key_hex": agent.public_key_bytes.hex(),
        "sid": sid,
    })])

    def recorder_factory(session_id, supervisor_id):
        return ProvenanceRecorder(
            session_id,
            agent_id="provenance-service",
            audit_mode=AuditMode.ENTERPRISE,
            log_dir=tmp_path / "logs",
            heartbeat_interval=0,
            supervisor_id=supervisor_id,
            replication_sink=InMemoryWitnessSink(),
        )

    core = ProvenanceServiceCore(
        registry=registry,
        request_store=ProvenanceRequestStore(tmp_path / "requests.sqlite3"),
        recorder_factory=recorder_factory,
        service_identity=service,
    )
    server = ProvenancePipeServer(
        core,
        ProvenancePipeConfig(
            service_sid=sid,
            client_sids=registry.allowed_sids,
            pipe_name=pipe_name,
            instances=instances,
            request_timeout_ms=request_timeout_ms,
        ),
    )
    client = ProvenancePipeClient(
        expected_service_sid=sid,
        service_agent_id=service.agent_id,
        service_algorithm="ed25519",
        service_public_key=service.public_key_bytes,
        pipe_name=pipe_name,
    )
    return agent, service, server, client, sid


def test_real_pipe_round_trip_and_concurrent_idempotency(tmp_path):
    pipe_name = rf"\\.\pipe\SelfConnectProvenance.test.{uuid.uuid4()}"
    agent, _service, server, client, _sid = make_stack(tmp_path, pipe_name)
    value = build_record_request(
        agent,
        session_id=str(uuid.uuid4()),
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "safe-test"},
    )
    server.start()
    try:
        responses = []
        errors = []

        def submit():
            try:
                responses.append(client.submit(value))
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=submit) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not errors
        assert len(responses) == 12
        assert sum(item["status"] == "committed" for item in responses) == 1
        assert {item["receipt"]["record_hash"] for item in responses} == {
            responses[0]["receipt"]["record_hash"]
        }
    finally:
        server.stop()


def test_client_fails_closed_when_server_process_sid_is_not_pinned(tmp_path):
    pipe_name = rf"\\.\pipe\SelfConnectProvenance.test.{uuid.uuid4()}"
    agent, service, server, _client, _sid = make_stack(tmp_path, pipe_name)
    request = build_record_request(
        agent,
        session_id=str(uuid.uuid4()),
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "safe-test"},
    )
    wrong = ProvenancePipeClient(
        expected_service_sid="S-1-5-18",
        service_agent_id=service.agent_id,
        service_algorithm="ed25519",
        service_public_key=service.public_key_bytes,
        pipe_name=pipe_name,
    )
    server.start()
    try:
        with pytest.raises(ProvenancePipeError, match="server SID"):
            wrong.submit(request)
    finally:
        server.stop()


def test_client_pipe_ace_does_not_grant_server_instance_creation():
    import win32api
    import win32security

    service_sid = resolve_account_sid(win32api.GetUserNameEx(2))
    client_sid = "S-1-5-32-545"
    attributes = build_pipe_security_attributes(service_sid, frozenset({client_sid}))
    dacl = attributes.SECURITY_DESCRIPTOR.GetSecurityDescriptorDacl()
    client = win32security.ConvertStringSidToSid(client_sid)
    masks = [
        int(dacl.GetAce(index)[1])
        for index in range(dacl.GetAceCount())
        if dacl.GetAce(index)[2] == client
    ]
    assert masks == [PIPE_CLIENT_ACCESS]
    assert masks[0] == FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
    assert not masks[0] & 0x0004  # FILE_CREATE_PIPE_INSTANCE / FILE_APPEND_DATA


def test_pipe_descriptor_has_exact_medium_no_write_up_integrity_label():
    import win32api
    import win32security

    service_sid = resolve_account_sid(win32api.GetUserNameEx(2))
    attributes = build_pipe_security_attributes(service_sid, frozenset())
    sacl = attributes.SECURITY_DESCRIPTOR.GetSecurityDescriptorSacl()
    assert sacl is not None
    assert sacl.GetAceCount() == 1
    ace = sacl.GetAce(0)
    assert int(ace[0][0]) == 17  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
    assert int(ace[1]) == PIPE_INTEGRITY_POLICY
    assert win32security.ConvertSidToStringSid(ace[2]) == PIPE_INTEGRITY_SID


def test_oversized_raw_message_is_a_signed_bounded_denial(tmp_path):
    import win32con
    import win32file
    import win32pipe

    pipe_name = rf"\\.\pipe\SelfConnectProvenance.test.{uuid.uuid4()}"
    _agent, service, server, _client, _sid = make_stack(tmp_path, pipe_name)
    server.start()
    handle = None
    try:
        win32pipe.WaitNamedPipe(pipe_name, 5_000)
        handle = win32file.CreateFile(
            pipe_name,
            PIPE_CLIENT_ACCESS,
            0,
            None,
            win32con.OPEN_EXISTING,
            0,
            None,
        )
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, b"x" * (MAX_FRAME_BYTES + 1))
        _hr, data = win32file.ReadFile(handle, MAX_FRAME_BYTES + 1)
        response = decode_frame(bytes(data))
        assert response["error"] == "frame_too_large"
        assert response["ok"] is False
        assert response["service_agent_id"] == service.agent_id
        assert isinstance(response["service_signature"], str)
    finally:
        if handle is not None:
            win32file.CloseHandle(handle)
        server.stop()


def test_idle_client_deadline_releases_the_only_pipe_instance(tmp_path):
    import win32con
    import win32file
    import win32pipe

    pipe_name = rf"\\.\pipe\SelfConnectProvenance.test.{uuid.uuid4()}"
    agent, service, server, client, _sid = make_stack(
        tmp_path,
        pipe_name,
        instances=1,
        request_timeout_ms=100,
    )
    server.start()
    idle = None
    try:
        win32pipe.WaitNamedPipe(pipe_name, 5_000)
        idle = win32file.CreateFile(
            pipe_name,
            PIPE_CLIENT_ACCESS,
            0,
            None,
            win32con.OPEN_EXISTING,
            0,
            None,
        )
        win32pipe.SetNamedPipeHandleState(idle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        _hr, data = win32file.ReadFile(idle, MAX_FRAME_BYTES + 1)
        denial = decode_frame(bytes(data))
        assert denial["error"] == "internal_fail_closed"
        assert denial["service_agent_id"] == service.agent_id
        win32file.CloseHandle(idle)
        idle = None

        value = build_record_request(
            agent,
            session_id=str(uuid.uuid4()),
            event_type=SessionEventType.TOOL_CALL,
            payload={"action": "after-idle-timeout"},
        )
        assert client.submit(value)["status"] == "committed"
        assert server.healthy
    finally:
        if idle is not None:
            win32file.CloseHandle(idle)
        server.stop()


def test_pipe_health_fails_when_an_instance_worker_cannot_be_created(tmp_path, monkeypatch):
    pipe_name = rf"\\.\pipe\SelfConnectProvenance.test.{uuid.uuid4()}"
    _agent, _service, server, _client, _sid = make_stack(
        tmp_path,
        pipe_name,
        instances=2,
    )
    original = server._create_pipe

    def fail_after_first(*, first):
        if first:
            return original(first=True)
        raise OSError("simulated pipe instance failure")

    monkeypatch.setattr(server, "_create_pipe", fail_after_first)
    server.start()
    try:
        deadline = time.monotonic() + 5
        while server.healthy and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not server.healthy
    finally:
        server.stop()
