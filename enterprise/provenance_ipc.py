"""Versioned, signed request protocol for the dedicated provenance service.

The named-pipe transport supplies an OS-authenticated caller SID.  This module
adds an enrolled cryptographic identity, freshness, replay nonce, and a second
event signature in the exact format consumed by :class:`ProvenanceRecorder`.
It is deliberately transport-independent so malformed input can be rejected
before the Windows service touches the authoritative ledger.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from enterprise.provenance import SessionEventType

PROTOCOL_VERSION = "selfconnect.provenance.v1"
MAX_FRAME_BYTES = 65_536
DEFAULT_FRESHNESS_MS = 60_000
SERVICE_METADATA_KEY = "provenance_service"

_AGENT_ID = re.compile(r"^SC-[0-9A-F]{8}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_SID = re.compile(r"^S-1-(?:\d+-){1,14}\d+$")
_ALGORITHMS = {"ed25519", "ecdsa-p384-cng"}
_REQUEST_FIELDS = {
    "agent_id",
    "event_signature",
    "event_type",
    "issued_at_ms",
    "nonce",
    "operation",
    "os_corroboration",
    "payload",
    "request_id",
    "request_signature",
    "session_id",
    "version",
}


class ProvenanceProtocolError(ValueError):
    """A deterministic, non-secret protocol rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise ProvenanceProtocolError(code, message)


def _validate_json(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        _reject("json_too_deep", "JSON nesting exceeds 32 levels")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**63) <= value < 2**63:
            _reject("integer_out_of_range", "JSON integer exceeds signed 64-bit range")
        return
    if isinstance(value, float):
        _reject("float_not_allowed", "floating-point values are not canonical")
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _reject("non_string_key", "JSON object keys must be strings")
            _validate_json(item, depth=depth + 1)
        return
    _reject("unsupported_json_type", f"unsupported JSON type: {type(value).__name__}")


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the single ASCII representation used for hashing and signing."""
    _validate_json(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ProvenanceProtocolError("invalid_json", "value is not canonical JSON") from exc


def event_signing_bytes(event_type: str, payload: Mapping[str, Any]) -> bytes:
    """Match ``ProvenanceRecorder._check_signature`` exactly."""
    return canonical_json_bytes({"event_type": event_type, "payload": dict(payload)})


def request_signing_bytes(request: Mapping[str, Any]) -> bytes:
    unsigned = dict(request)
    unsigned.pop("request_signature", None)
    return canonical_json_bytes(unsigned)


def request_hash(request: Mapping[str, Any]) -> str:
    return hashlib.sha384(request_signing_bytes(request)).hexdigest()


def response_signing_bytes(response: Mapping[str, Any]) -> bytes:
    unsigned = dict(response)
    unsigned.pop("service_signature", None)
    return canonical_json_bytes(unsigned)


def encode_frame(value: Mapping[str, Any]) -> bytes:
    data = canonical_json_bytes(value)
    if len(data) > MAX_FRAME_BYTES:
        _reject("frame_too_large", f"frame exceeds {MAX_FRAME_BYTES} bytes")
    return data


def decode_frame(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_FRAME_BYTES:
        _reject("invalid_frame_size", "frame is empty or oversized")
    try:
        text = data.decode("ascii", errors="strict")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvenanceProtocolError("invalid_json", "frame is not strict ASCII JSON") from exc
    if not isinstance(value, dict):
        _reject("invalid_frame_shape", "frame root must be an object")
    # Reject alternate encodings and duplicate-whitespace representations.
    if canonical_json_bytes(value) != data:
        _reject("noncanonical_frame", "frame does not use canonical serialization")
    return value


def _parse_uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        _reject(f"invalid_{name}", f"{name} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProvenanceProtocolError(f"invalid_{name}", f"{name} must be a UUID") from exc
    canonical = str(parsed)
    if value != canonical:
        _reject(f"invalid_{name}", f"{name} must use canonical lowercase UUID form")
    return canonical


def _signature_bytes(value: Any, algorithm: str, field: str) -> bytes:
    expected = 64 if algorithm == "ed25519" else 96
    if not isinstance(value, str) or len(value) != expected * 2:
        _reject(f"invalid_{field}", f"{field} has the wrong encoded length")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ProvenanceProtocolError(f"invalid_{field}", f"{field} is not hexadecimal") from exc
    if len(raw) != expected:
        _reject(f"invalid_{field}", f"{field} has the wrong decoded length")
    return raw


@dataclass(frozen=True)
class AgentEnrollment:
    agent_id: str
    algorithm: str
    public_key: bytes
    sid: str
    supervisor: bool = False
    enabled: bool = True

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentEnrollment":
        allowed = {"agent_id", "algorithm", "public_key_hex", "sid", "supervisor", "enabled"}
        if set(value) - allowed:
            _reject("unexpected_enrollment_field", "enrollment contains an unknown field")
        agent_id = value.get("agent_id")
        algorithm = value.get("algorithm")
        sid = value.get("sid")
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            _reject("invalid_agent_id", "agent_id must be SC- plus eight uppercase hex digits")
        if algorithm not in _ALGORITHMS:
            _reject("invalid_algorithm", "unsupported enrollment algorithm")
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            _reject("invalid_sid", "enrollment SID is not canonical")
        key_hex = value.get("public_key_hex")
        expected = 32 if algorithm == "ed25519" else 96
        if not isinstance(key_hex, str) or len(key_hex) != expected * 2:
            _reject("invalid_public_key", "public key has the wrong encoded length")
        try:
            public_key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise ProvenanceProtocolError("invalid_public_key", "public key is not hexadecimal") from exc
        digest = hashlib.sha256(public_key) if algorithm == "ed25519" else hashlib.sha384(public_key)
        derived = "SC-" + digest.hexdigest()[:8].upper()
        if derived != agent_id:
            _reject("agent_key_mismatch", "agent_id does not match the enrolled public key")
        supervisor = value.get("supervisor", False)
        enabled = value.get("enabled", True)
        if not isinstance(supervisor, bool) or not isinstance(enabled, bool):
            _reject("invalid_enrollment_flag", "supervisor and enabled must be booleans")
        return cls(agent_id, algorithm, public_key, sid, supervisor, enabled)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            if self.algorithm == "ed25519":
                Ed25519PublicKey.from_public_bytes(self.public_key).verify(signature, data)
                return True
            from enterprise.identity_cng import cng_verify
            return bool(cng_verify(data, signature, self.public_key))
        except Exception:
            return False

    def recorder_public_key(self) -> Any:
        if self.algorithm == "ed25519":
            return Ed25519PublicKey.from_public_bytes(self.public_key)
        enrollment = self

        class _CngVerifier:
            @staticmethod
            def verify(signature: bytes, data: bytes) -> None:
                if not enrollment.verify(data, signature):
                    raise InvalidSignature("CNG signature invalid")

        return _CngVerifier()


class EnrollmentRegistry:
    def __init__(self, enrollments: list[AgentEnrollment]) -> None:
        by_id: dict[str, AgentEnrollment] = {}
        for enrollment in enrollments:
            if enrollment.agent_id in by_id:
                _reject("duplicate_agent", "agent_id appears more than once")
            by_id[enrollment.agent_id] = enrollment
        supervisors = [item.agent_id for item in enrollments if item.enabled and item.supervisor]
        if len(supervisors) > 1:
            _reject("multiple_supervisors", "only one enabled supervisor is permitted per service")
        self._by_id = by_id
        self.supervisor_id = supervisors[0] if supervisors else None

    @classmethod
    def load(cls, path: Path) -> "EnrollmentRegistry":
        raw = path.read_bytes()
        if len(raw) > 1_048_576:
            _reject("enrollment_file_too_large", "enrollment file exceeds 1 MiB")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProvenanceProtocolError("invalid_enrollment_file", "enrollment file is invalid JSON") from exc
        if not isinstance(value, dict) or set(value) != {"agents", "version"} or value.get("version") != 1:
            _reject("invalid_enrollment_file", "enrollment file must contain version 1 and agents")
        agents = value.get("agents")
        if not isinstance(agents, list):
            _reject("invalid_enrollment_file", "agents must be a list")
        if any(not isinstance(item, dict) for item in agents):
            _reject("invalid_enrollment_file", "every agents item must be an object")
        return cls([AgentEnrollment.from_dict(item) for item in agents])

    def get(self, agent_id: str) -> AgentEnrollment | None:
        value = self._by_id.get(agent_id)
        return value if value and value.enabled else None

    @property
    def allowed_sids(self) -> frozenset[str]:
        return frozenset(item.sid for item in self._by_id.values() if item.enabled)

    @property
    def enrollments(self) -> tuple[AgentEnrollment, ...]:
        return tuple(item for item in self._by_id.values() if item.enabled)

    @property
    def all_enrollments(self) -> tuple[AgentEnrollment, ...]:
        return tuple(self._by_id.values())


def build_record_request(
    identity: Any,
    *,
    session_id: str,
    event_type: SessionEventType | str,
    payload: Mapping[str, Any] | None = None,
    os_corroboration: Mapping[str, Any] | None = None,
    issued_at_ms: int | None = None,
    nonce: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    event_name = SessionEventType(event_type).value
    body = dict(payload or {})
    _validate_json(body)
    request: dict[str, Any] = {
        "agent_id": identity.agent_id,
        "event_type": event_name,
        "issued_at_ms": int(time.time() * 1000) if issued_at_ms is None else issued_at_ms,
        "nonce": nonce or base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("="),
        "operation": "record",
        "os_corroboration": dict(os_corroboration) if os_corroboration is not None else None,
        "payload": body,
        "request_id": request_id or str(uuid.uuid4()),
        "session_id": session_id,
        "version": PROTOCOL_VERSION,
    }
    request["event_signature"] = identity.sign(event_signing_bytes(event_name, body)).hex()
    request["request_signature"] = identity.sign(request_signing_bytes(request)).hex()
    encode_frame(request)
    return request


@dataclass(frozen=True)
class VerifiedRecordRequest:
    enrollment: AgentEnrollment
    event_signature: bytes
    event_type: SessionEventType
    issued_at_ms: int
    nonce: str
    os_corroboration: dict[str, Any] | None
    payload: dict[str, Any]
    request_hash: str
    request_id: str
    request_signature: bytes
    session_id: str
    stale: bool


def verify_record_request(
    request: Mapping[str, Any],
    registry: EnrollmentRegistry,
    caller_sid: str,
    *,
    now_ms: int | None = None,
    freshness_ms: int = DEFAULT_FRESHNESS_MS,
    allow_stale_receipt_lookup: bool = False,
) -> VerifiedRecordRequest:
    if set(request) != _REQUEST_FIELDS:
        _reject("invalid_request_fields", "request field set is not exact")
    encode_frame(request)
    if request.get("version") != PROTOCOL_VERSION or request.get("operation") != "record":
        _reject("unsupported_protocol", "unsupported version or operation")
    agent_id = request.get("agent_id")
    if not isinstance(agent_id, str):
        _reject("invalid_agent_id", "agent_id is required")
    enrollment = registry.get(agent_id)
    if enrollment is None:
        _reject("unknown_agent", "agent identity is not enrolled and enabled")
    if caller_sid != enrollment.sid:
        _reject("caller_sid_mismatch", "OS caller SID does not match the enrolled identity")
    session_id = _parse_uuid(request.get("session_id"), "session_id")
    request_id = _parse_uuid(request.get("request_id"), "request_id")
    nonce = request.get("nonce")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        _reject("invalid_nonce", "nonce must be unpadded base64url")
    issued_at_ms = request.get("issued_at_ms")
    if not isinstance(issued_at_ms, int) or isinstance(issued_at_ms, bool):
        _reject("invalid_timestamp", "issued_at_ms must be an integer")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    stale = abs(now - issued_at_ms) > freshness_ms
    if stale and not allow_stale_receipt_lookup:
        _reject("stale_request", "request timestamp is outside the freshness window")
    try:
        event_type = SessionEventType(request.get("event_type"))
    except (ValueError, TypeError) as exc:
        raise ProvenanceProtocolError("invalid_event_type", "event_type is not supported") from exc
    payload = request.get("payload")
    if not isinstance(payload, dict):
        _reject("invalid_payload", "payload must be an object")
    os_data = request.get("os_corroboration")
    if os_data is not None and not isinstance(os_data, dict):
        _reject("invalid_os_corroboration", "os_corroboration must be an object or null")
    event_signature = _signature_bytes(request.get("event_signature"), enrollment.algorithm, "event_signature")
    request_signature = _signature_bytes(
        request.get("request_signature"), enrollment.algorithm, "request_signature"
    )
    if not enrollment.verify(event_signing_bytes(event_type.value, payload), event_signature):
        _reject("invalid_event_signature", "event signature verification failed")
    if not enrollment.verify(request_signing_bytes(request), request_signature):
        _reject("invalid_request_signature", "request signature verification failed")
    return VerifiedRecordRequest(
        enrollment=enrollment,
        event_signature=event_signature,
        event_type=event_type,
        issued_at_ms=issued_at_ms,
        nonce=nonce,
        os_corroboration=dict(os_data) if os_data is not None else None,
        payload=dict(payload),
        request_hash=request_hash(request),
        request_id=request_id,
        request_signature=request_signature,
        session_id=session_id,
        stale=stale,
    )


def sign_service_response(identity: Any, response: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(response)
    result["service_agent_id"] = identity.agent_id
    result["service_signature"] = identity.sign(response_signing_bytes(result)).hex()
    encode_frame(result)
    return result


def verify_service_response(
    response: Mapping[str, Any],
    *,
    algorithm: str,
    public_key: bytes,
    expected_agent_id: str,
) -> bool:
    try:
        enrollment = AgentEnrollment(
            agent_id=expected_agent_id,
            algorithm=algorithm,
            public_key=public_key,
            sid="S-1-5-18",
        )
        signature = _signature_bytes(response.get("service_signature"), algorithm, "service_signature")
        return response.get("service_agent_id") == expected_agent_id and enrollment.verify(
            response_signing_bytes(response), signature
        )
    except ProvenanceProtocolError:
        return False
