from __future__ import annotations

import hashlib
import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.provenance import AuditMode, InMemoryWitnessSink, ProvenanceRecorder, SessionEventType
from enterprise.provenance_ipc import (
    AgentEnrollment,
    EnrollmentRegistry,
    MAX_FRAME_BYTES,
    ProvenanceProtocolError,
    build_record_request,
    canonical_json_bytes,
    decode_frame,
    encode_frame,
    sign_service_response,
    verify_record_request,
    verify_service_response,
)


class FakeIdentity:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.agent_id = "SC-" + hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def enrollment(identity: FakeIdentity, *, sid: str = "S-1-5-21-1-2-3-1001", **flags) -> AgentEnrollment:
    return AgentEnrollment.from_dict({
        "agent_id": identity.agent_id,
        "algorithm": "ed25519",
        "public_key_hex": identity.public_key_bytes.hex(),
        "sid": sid,
        **flags,
    })


def request(identity: FakeIdentity, **overrides):
    values = {
        "session_id": str(uuid.uuid4()),
        "event_type": SessionEventType.TOOL_CALL,
        "payload": {"action": "read", "count": 3},
        "issued_at_ms": 1_750_000_000_000,
        "nonce": "A" * 32,
        "request_id": str(uuid.uuid4()),
    }
    values.update(overrides)
    return build_record_request(identity, **values)


def test_signed_request_round_trip_matches_recorder_signature_contract(tmp_path):
    identity = FakeIdentity()
    registry = EnrollmentRegistry([enrollment(identity)])
    raw = encode_frame(request(identity))
    decoded = decode_frame(raw)
    verified = verify_record_request(
        decoded,
        registry,
        "S-1-5-21-1-2-3-1001",
        now_ms=1_750_000_000_000,
    )
    recorder = ProvenanceRecorder(
        verified.session_id,
        audit_mode=AuditMode.ENTERPRISE,
        log_dir=tmp_path,
        heartbeat_interval=0,
        replication_sink=InMemoryWitnessSink(),
    )
    recorder.start()
    recorder.register_agent(identity.agent_id, identity.private.public_key())
    record = recorder.record(
        verified.event_type,
        payload=verified.payload,
        agent_id=identity.agent_id,
        signature=verified.event_signature,
    )
    assert record and record["agent_sig"] == verified.event_signature.hex()


def test_request_binds_os_sid_and_full_enrolled_key():
    identity = FakeIdentity()
    registry = EnrollmentRegistry([enrollment(identity)])
    with pytest.raises(ProvenanceProtocolError, match="OS caller SID") as caught:
        verify_record_request(
            request(identity), registry, "S-1-5-21-9-9-9-1002", now_ms=1_750_000_000_000
        )
    assert caught.value.code == "caller_sid_mismatch"


def test_payload_tamper_breaks_both_signature_contracts():
    identity = FakeIdentity()
    registry = EnrollmentRegistry([enrollment(identity)])
    value = request(identity)
    value["payload"]["action"] = "delete"
    with pytest.raises(ProvenanceProtocolError) as caught:
        verify_record_request(value, registry, next(iter(registry.allowed_sids)), now_ms=1_750_000_000_000)
    assert caught.value.code == "invalid_event_signature"


def test_stale_request_only_parses_for_existing_receipt_lookup():
    identity = FakeIdentity()
    registry = EnrollmentRegistry([enrollment(identity)])
    value = request(identity)
    with pytest.raises(ProvenanceProtocolError) as caught:
        verify_record_request(value, registry, next(iter(registry.allowed_sids)), now_ms=1_750_000_100_000)
    assert caught.value.code == "stale_request"
    verified = verify_record_request(
        value,
        registry,
        next(iter(registry.allowed_sids)),
        now_ms=1_750_000_100_000,
        allow_stale_receipt_lookup=True,
    )
    assert verified.stale is True


@pytest.mark.parametrize(
    "value,code",
    [
        ({"x": 1.5}, "float_not_allowed"),
        ({"x": 2**80}, "integer_out_of_range"),
        ({"x": {1: "bad"}}, "non_string_key"),
    ],
)
def test_canonical_json_rejects_ambiguous_values(value, code):
    with pytest.raises(ProvenanceProtocolError) as caught:
        canonical_json_bytes(value)
    assert caught.value.code == code


def test_decode_rejects_noncanonical_but_valid_json():
    with pytest.raises(ProvenanceProtocolError) as caught:
        decode_frame(b'{"b": 2, "a": 1}')
    assert caught.value.code == "noncanonical_frame"


def test_frame_size_is_bounded_before_transport():
    with pytest.raises(ProvenanceProtocolError) as caught:
        encode_frame({"payload": "x" * MAX_FRAME_BYTES})
    assert caught.value.code == "frame_too_large"


def test_enrollment_rejects_label_that_does_not_match_key():
    identity = FakeIdentity()
    with pytest.raises(ProvenanceProtocolError) as caught:
        AgentEnrollment.from_dict({
            "agent_id": "SC-00000000",
            "algorithm": "ed25519",
            "public_key_hex": identity.public_key_bytes.hex(),
            "sid": "S-1-5-21-1-2-3-1001",
        })
    assert caught.value.code == "agent_key_mismatch"


def test_registry_rejects_multiple_supervisors():
    first = FakeIdentity()
    second = FakeIdentity()
    with pytest.raises(ProvenanceProtocolError) as caught:
        EnrollmentRegistry([
            enrollment(first, supervisor=True),
            enrollment(second, sid="S-1-5-21-1-2-3-1002", supervisor=True),
        ])
    assert caught.value.code == "multiple_supervisors"


def test_disabled_enrollment_is_not_an_authorization():
    identity = FakeIdentity()
    registry = EnrollmentRegistry([enrollment(identity, enabled=False)])
    with pytest.raises(ProvenanceProtocolError) as caught:
        verify_record_request(
            request(identity), registry, "S-1-5-21-1-2-3-1001", now_ms=1_750_000_000_000
        )
    assert caught.value.code == "unknown_agent"


def test_service_response_is_signed_and_tamper_evident():
    service = FakeIdentity()
    response = sign_service_response(service, {
        "ok": True,
        "request_id": str(uuid.uuid4()),
        "status": "committed",
        "version": "selfconnect.provenance.v1",
    })
    assert verify_service_response(
        response,
        algorithm="ed25519",
        public_key=service.public_key_bytes,
        expected_agent_id=service.agent_id,
    )
    response["status"] = "failed"
    assert not verify_service_response(
        response,
        algorithm="ed25519",
        public_key=service.public_key_bytes,
        expected_agent_id=service.agent_id,
    )


def test_enrollment_file_shape_is_exact(tmp_path):
    identity = FakeIdentity()
    path = tmp_path / "agents.json"
    path.write_text(json.dumps({
        "version": 1,
        "agents": [{
            "agent_id": identity.agent_id,
            "algorithm": "ed25519",
            "public_key_hex": identity.public_key_bytes.hex(),
            "sid": "S-1-5-21-1-2-3-1001",
        }],
    }), encoding="utf-8")
    assert EnrollmentRegistry.load(path).get(identity.agent_id) is not None
    path.write_text(json.dumps({"version": 1, "agents": ["not-an-object"]}), encoding="utf-8")
    with pytest.raises(ProvenanceProtocolError):
        EnrollmentRegistry.load(path)
