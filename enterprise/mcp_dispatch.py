"""Runtime dispatcher for the SelfConnect Enterprise MCP tool roster.

``enterprise.mcp_tools`` defines the public tool schemas.  This module is the
matching execution layer: it validates arguments against those schemas, applies
lease gates for actuating calls, delegates routing to the governed channel
router, and records bounded audit events.

The dispatcher is intentionally small and in-process.  It gives MCP hosts and
the ``scent`` CLI a real call surface without turning the Windows service into a
network server.  A future MCP server can call ``MCPDispatcher.call_tool()``
directly.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, replace
from types import MappingProxyType
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.control import ControlPlane
from enterprise.delegation import (
    AgentActionProof,
    DelegatedActionReceipt,
    DelegationGrant,
    canonical_bytes,
    payload_digest,
    sign_delegated_receipt,
    verify_delegated_action,
    verify_delegated_receipt,
    verify_historical_delegated_action,
)
from enterprise.identity import AgentIdentity
from enterprise.logical_targets import LogicalTargetResolver
from enterprise.mcp_tools import get_tool, get_tool_registry
from enterprise.operator import DurableOperatorQueue, OperatorQueue
from enterprise.protected_tools import PROTECTED_DELEGATED_TOOLS
from enterprise.runtime_lifetime import RuntimeLifetime, governed_operation

try:
    from enterprise_experiments.win32_probe.channel_router import (
        ChannelRouter,
        ChannelRoutingError,
        TargetBinding,
    )
except Exception:  # noqa: BLE001
    ChannelRouter = None  # type: ignore[assignment]
    ChannelRoutingError = RuntimeError  # type: ignore[assignment]
    TargetBinding = None  # type: ignore[assignment,misc]

try:
    from enterprise.tpm_attestation import (
        create_tpm_platform_claim,
        tpm_probe,
        verify_tpm_platform_claim,
    )
    _TPM_ATTESTATION_AVAILABLE = True
except Exception:  # noqa: BLE001
    _TPM_ATTESTATION_AVAILABLE = False
    create_tpm_platform_claim = None  # type: ignore[assignment]
    tpm_probe = None  # type: ignore[assignment]
    verify_tpm_platform_claim = None  # type: ignore[assignment]


_AUDIT_LIMIT = 2_000
_MAX_ERROR_LEN = 512
_MAX_READ_CHARS = 65_536
_DEFAULT_DELIVERY_TIMEOUT_MS = 3_000
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_VALID_PROFILES = frozenset({"normal", "enterprise", "government"})
_VALID_LEASE_ROLES = frozenset({"sender", "receiver", "observer"})
_LEASE_TOOL_ROLES = MappingProxyType(
    {
        "sc_inject_text": frozenset({"sender"}),
        # Sender reads are part of the existing request/response flow. Receiver
        # and observer leases are explicitly read-only at this boundary.
        "sc_read_output": frozenset({"sender", "receiver", "observer"}),
    }
)
class MCPDispatchError(RuntimeError):
    """Raised internally for validation or execution failures."""


class MCPValidationError(MCPDispatchError):
    """Tool arguments did not match the registered schema."""


@dataclass(frozen=True)
class DelegationBoundary:
    issuer_resolver: Callable[[str], bytes | None]
    revocation_provider: Callable[[], Any]
    replay_store: Any

    def __post_init__(self) -> None:
        if not callable(self.issuer_resolver) or not callable(self.revocation_provider):
            raise ValueError("delegation trust and revocation providers must be callable")
        required = ("claim", "begin", "finish", "get")
        if any(not callable(getattr(self.replay_store, name, None)) for name in required):
            raise ValueError(
                "delegation replay store must provide claim(), begin(), finish(), and get()"
            )


@dataclass(frozen=True)
class _VerifiedDelegatedCall:
    grant: DelegationGrant
    proof: AgentActionProof
    payload: bytes
    session_id: str


@dataclass(frozen=True)
class RuntimeLease:
    lease_id: str
    agent_id: str
    hwnd: int
    role: str
    issued_at: float
    expires_at: float
    revoked: bool = False
    target_pid: int = 0
    target_exe: str = ""
    target_exe_path: str = ""
    target_class: str = ""
    target_title_hash: str = ""
    logical_target_id: str = ""

    @property
    def ttl_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def is_active(self, now: float | None = None) -> bool:
        ts = time.time() if now is None else now
        return not self.revoked and ts < self.expires_at

    def to_dict(self, now: float | None = None) -> dict[str, Any]:
        data = asdict(self)
        ts = time.time() if now is None else now
        data["ttl_seconds"] = max(0.0, self.expires_at - ts)
        data["active"] = self.is_active(ts)
        return data


@dataclass(frozen=True)
class _LeaseAuthority:
    """Signed snapshot of every issuance-time RuntimeLease authority field."""

    lease: RuntimeLease
    signature: bytes


class _LeaseAuthorityError(RuntimeError):
    def __init__(self, reason: str, *, issued_role: str = "missing") -> None:
        super().__init__(reason)
        self.issued_role = issued_role


class _LeaseAuthorityStore:
    """Own signed authority records and revocation state for one dispatcher.

    This boundary protects against replacement or deserialization of runtime
    lease/authority records. It is not a sandbox against arbitrary Python code
    execution or hostile reflection inside this process.
    """

    __slots__ = ("__private_key", "__public_key", "__records", "__revoked")

    def __init__(self) -> None:
        self.__private_key = Ed25519PrivateKey.generate()
        self.__public_key = self.__private_key.public_key()
        self.__records: dict[str, _LeaseAuthority] = {}
        self.__revoked: set[str] = set()

    def issue(self, lease: RuntimeLease) -> None:
        if lease.lease_id in self.__records or lease.lease_id in self.__revoked:
            raise MCPDispatchError("lease authority already exists")
        self.__records[lease.lease_id] = _LeaseAuthority(
            lease=lease,
            signature=self.__private_key.sign(_lease_authority_payload(lease)),
        )

    def revoke(self, lease: RuntimeLease) -> None:
        if lease.lease_id not in self.__records:
            raise MCPDispatchError("lease issuance authority is missing")
        revoked = replace(lease, revoked=True)
        self.__records[lease.lease_id] = _LeaseAuthority(
            lease=revoked,
            signature=self.__private_key.sign(_lease_authority_payload(revoked)),
        )
        self.__revoked.add(lease.lease_id)

    def verify(
        self,
        requested_lease_id: str,
        lease: RuntimeLease,
        *,
        allow_revoked: bool = False,
    ) -> RuntimeLease:
        if lease.lease_id != requested_lease_id:
            raise _LeaseAuthorityError(
                "lease storage key does not match the embedded signed lease id",
                issued_role=lease.role,
            )
        authority = self.__records.get(requested_lease_id)
        if authority is None:
            raise _LeaseAuthorityError("lease issuance authority is missing")
        issued_role = authority.lease.role
        try:
            self.__public_key.verify(
                authority.signature,
                _lease_authority_payload(authority.lease),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise _LeaseAuthorityError(
                "lease issuance authority signature is invalid",
                issued_role=issued_role,
            ) from exc
        if lease != authority.lease:
            raise _LeaseAuthorityError(
                "lease no longer matches its signed issuance authority",
                issued_role=issued_role,
            )
        if requested_lease_id in self.__revoked and not allow_revoked:
            raise _LeaseAuthorityError(
                "lease issuance authority is revoked",
                issued_role=issued_role,
            )
        return authority.lease


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: float
    event_type: str
    agent_id: str
    tool: str
    ok: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now() -> float:
    return time.time()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _lease_authority_payload(lease: RuntimeLease) -> bytes:
    return json.dumps(
        {
            **asdict(lease),
            "schema": "selfconnect.lease-authority.v1",
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _bound_error(value: str) -> str:
    return value[:_MAX_ERROR_LEN]


def _normalise_terminal_text(value: str) -> str:
    """Normalize only representation differences that UIA may introduce."""
    return _ANSI_ESCAPE_RE.sub("", value).replace("\r\n", "\n").replace("\r", "\n")


def _delivery_probe(value: str) -> str:
    """Return visible text while rejecting terminal state-control characters."""
    if any(character not in "\r\n" and not character.isprintable() for character in value):
        raise MCPDispatchError("text must contain only printable characters or newlines")
    probe = _normalise_terminal_text(value).strip("\n")
    if not probe.strip():
        raise MCPDispatchError("text must contain a visible non-whitespace character")
    return probe


def _normalise_b64(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    return base64.b64decode(padded.encode("ascii"), validate=False)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "__dict__"):
        return {
            key: _jsonable(val)
            for key, val in vars(value).items()
            if not key.startswith("_")
        }
    if isinstance(value, dict):
        return {str(key): _jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


class SchemaValidator:
    """Minimal JSON-schema validator for the tool schemas used here.

    The project does not depend on ``jsonschema`` at runtime.  The MCP schemas
    only need a constrained subset: required fields, additionalProperties,
    primitive type checks, min/max, maxLength, enum, and regex pattern.
    """

    def validate(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(args, dict):
            raise MCPValidationError("arguments must be a JSON object")
        schema = get_tool(tool_name)["inputSchema"]
        props = schema.get("properties", {})
        required = schema.get("required", [])

        for field in required:
            if field not in args:
                raise MCPValidationError(f"missing required field: {field}")

        if schema.get("additionalProperties") is False:
            extra = sorted(set(args) - set(props))
            if extra:
                raise MCPValidationError(f"unknown field(s): {', '.join(extra)}")

        validated = dict(args)
        for field, value in args.items():
            definition = props.get(field)
            if definition is None:
                continue
            self._validate_property(tool_name, field, value, definition)
        return validated

    def _validate_property(
        self,
        tool_name: str,
        field: str,
        value: Any,
        definition: dict[str, Any],
    ) -> None:
        typ = definition.get("type")
        if typ == "string" and not isinstance(value, str):
            raise MCPValidationError(f"{field} must be string")
        if typ == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise MCPValidationError(f"{field} must be integer")
        if typ == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise MCPValidationError(f"{field} must be number")
        if typ == "boolean" and not isinstance(value, bool):
            raise MCPValidationError(f"{field} must be boolean")
        if typ == "array" and not isinstance(value, list):
            raise MCPValidationError(f"{field} must be array")
        if typ == "object" and not isinstance(value, dict):
            raise MCPValidationError(f"{field} must be object")

        if isinstance(value, str):
            min_len = definition.get("minLength")
            if min_len is not None and len(value) < int(min_len):
                raise MCPValidationError(f"{field} below minLength {min_len}")
            max_len = definition.get("maxLength")
            if max_len is not None and len(value) > int(max_len):
                raise MCPValidationError(f"{field} exceeds maxLength {max_len}")
            pattern = definition.get("pattern")
            if pattern is not None and re.fullmatch(pattern, value) is None:
                raise MCPValidationError(f"{field} does not match required pattern")

        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in definition and value < int(definition["minimum"]):
                raise MCPValidationError(f"{field} below minimum {definition['minimum']}")
            if "maximum" in definition and value > int(definition["maximum"]):
                raise MCPValidationError(f"{field} above maximum {definition['maximum']}")

        if "enum" in definition and value not in definition["enum"]:
            raise MCPValidationError(
                f"{tool_name}.{field} must be one of {definition['enum']}"
            )


class MCPDispatcher:
    """Execute SelfConnect Enterprise MCP tools after schema validation."""

    def __init__(
        self,
        *,
        profile: str = "enterprise",
        router: Any | None = None,
        control_plane: ControlPlane | None = None,
        ledger: Any | None = None,
        policy_enforcer: Any | None = None,
        operator_queue: OperatorQueue | None = None,
        target_verifier: Callable[..., dict[str, Any]] | None = None,
        output_reader: Callable[[int], str] | None = None,
        identity_type: str = "software",
        now: Callable[[], float] = _now,
        runtime_lifetime: RuntimeLifetime | None = None,
        logical_target_resolver: LogicalTargetResolver | None = None,
        agt_policy_adapter: Any | None = None,
        delegation_identity: AgentIdentity | None = None,
        delegation_boundary: DelegationBoundary | None = None,
    ) -> None:
        if profile not in _VALID_PROFILES:
            raise ValueError(f"profile must be one of {sorted(_VALID_PROFILES)}, got {profile!r}")
        if profile == "enterprise" and type(operator_queue) is not DurableOperatorQueue:
            raise ValueError(
                "enterprise profile requires the exact durable operator queue"
            )
        binding_verifier = (
            getattr(operator_queue, "verify_consumed_binding", None)
            if operator_queue is not None
            else None
        )
        if profile == "enterprise" and not callable(binding_verifier):
            raise ValueError(
                "enterprise profile requires a durable approval binding verifier"
            )
        self.profile = profile
        self._runtime_lifetime = runtime_lifetime
        self._validator = SchemaValidator()
        self._target_verifier = target_verifier or self._load_target_verifier()
        self._logical_target_resolver = logical_target_resolver
        if agt_policy_adapter is not None and not callable(
            getattr(agt_policy_adapter, "run_tool_sync", None)
        ):
            raise ValueError("agt_policy_adapter must provide run_tool_sync()")
        self._agt_policy_adapter = agt_policy_adapter
        self._router = router if router is not None else (
            ChannelRouter(target_verifier=self._target_verifier) if ChannelRouter else None
        )
        self._operator_queue = operator_queue
        self._approval_binding_verifier = binding_verifier
        self._control = control_plane or ControlPlane(
            ledger=ledger,
            operator_queue=operator_queue,
        )
        self._ledger = ledger
        self._policy_enforcer = policy_enforcer
        self._output_reader = output_reader or self._load_output_reader()
        self._identity_type = identity_type
        self._now = now
        self._delegation_identity = delegation_identity
        self.__delegation_boundary = delegation_boundary
        self._leases: dict[str, RuntimeLease] = {}
        self.__lease_authority_store = _LeaseAuthorityStore()
        self._audit: list[AuditEvent] = []
        self._read_snapshots: dict[str, str] = {}
        self._injected_text: dict[str, str] = {}
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        self.__handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "sc_inject_text": self._sc_inject_text,
            "sc_read_output": self._sc_read_output,
            "sc_verify_target": self._sc_verify_target,
            "sc_request_lease": self._sc_request_lease,
            "sc_request_target_lease": self._sc_request_target_lease,
            "sc_revoke_lease": self._sc_revoke_lease,
            "sc_list_leases": self._sc_list_leases,
            "sc_get_lease_info": self._sc_get_lease_info,
            "sc_audit_tail": self._sc_audit_tail,
            "sc_audit_search": self._sc_audit_search,
            "sc_mesh_peers": self._sc_mesh_peers,
            "sc_channel_status": self._sc_channel_status,
            "sc_target_guard_check": self._sc_target_guard_check,
            "sc_identity_sign": self._sc_identity_sign,
            "sc_identity_verify": self._sc_identity_verify,
            "sc_session_stamp": self._sc_session_stamp,
            "sc_channel_route": self._sc_channel_route,
            "sc_echo_filter": self._sc_echo_filter,
            "sc_pipe_ping": self._sc_pipe_ping,
            "sc_policy_check": self._sc_policy_check,
            "sc_receipt_verify": self._sc_receipt_verify,
        }

        registered = {tool["name"] for tool in get_tool_registry()}
        missing = registered - set(self.__handlers)
        if missing:
            raise RuntimeError(f"MCP dispatcher missing handler(s): {sorted(missing)}")

    @governed_operation
    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate and execute a registered MCP tool.

        Returns an MCP-friendly dict.  Validation and execution failures are
        reported as ``{"ok": False, "error": ...}`` rather than escaping to the
        caller.  Unknown tools still fail closed with the same envelope.
        """
        return self.__execute_tool(name, arguments)

    def __execute_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        *,
        authorization: _VerifiedDelegatedCall | None = None,
    ) -> dict[str, Any]:
        args = {} if arguments is None else arguments
        try:
            if (
                self.profile in {"enterprise", "government"}
                and name in PROTECTED_DELEGATED_TOOLS
                and authorization is None
            ):
                raise MCPDispatchError(
                    "final actuation requires an owner-signed delegation grant and agent-signed action proof"
                )
            if name not in self.__handlers:
                get_tool(name)  # raises useful KeyError text if not registered
            validated = self._validator.validate(name, args)
            if self._agt_policy_adapter is None:
                if name in PROTECTED_DELEGATED_TOOLS:
                    result = self.__handlers[name](validated, authorization=authorization)
                else:
                    result = self.__handlers[name](validated)
            else:
                if name in PROTECTED_DELEGATED_TOOLS:
                    def handler(effective):
                        return self.__handlers[name](
                            effective, authorization=authorization
                        )
                else:
                    handler = self.__handlers[name]
                agt_outcome = self._agt_policy_adapter.run_tool_sync(
                    name,
                    validated,
                    handler,
                    snapshot={"selfconnect": {"profile": self.profile}},
                )
                result = agt_outcome.value
                validated = agt_outcome.effective_arguments
            result.setdefault("profile", self.profile)
            self._record_audit(name, True, validated, result)
            return {"ok": True, "tool": name, "result": result}
        except Exception as exc:  # noqa: BLE001
            error = _bound_error(str(exc))
            self._record_audit(name, False, args if isinstance(args, dict) else {}, {"error": error})
            return {"ok": False, "tool": name, "error": error}

    @governed_operation
    def call_delegated_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        grant: DelegationGrant,
        proof: AgentActionProof,
        payload: bytes,
        session_id: str,
    ) -> dict[str, Any]:
        """Verify, consume, actuate, and sign at the final MCP boundary."""
        if self.__delegation_boundary is None or self._delegation_identity is None:
            raise MCPDispatchError("delegation boundary is not configured")
        try:
            signed_call = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPDispatchError("delegated call payload is not canonical JSON") from exc
        if canonical_bytes(signed_call) != payload:
            raise MCPDispatchError("delegated call payload is not canonical JSON")
        if not isinstance(signed_call, dict) or signed_call.get("tool") != name:
            raise MCPDispatchError("delegated payload does not bind the requested MCP tool")
        if signed_call.get("arguments") != arguments or signed_call.get("sessionId") != session_id:
            raise MCPDispatchError("delegated payload does not bind the MCP arguments and session")
        try:
            isolated_arguments = json.loads(canonical_bytes(signed_call["arguments"]).decode("utf-8"))
            isolated_grant = DelegationGrant.from_dict(grant.to_dict())
            isolated_proof = AgentActionProof.from_dict(proof.to_dict())
        except (KeyError, TypeError, ValueError) as exc:
            raise MCPDispatchError("delegated call contains invalid signed objects") from exc
        if not isinstance(isolated_arguments, dict):
            raise MCPDispatchError("delegated MCP arguments must be an object")
        if isolated_proof.action != name:
            raise MCPDispatchError("action proof does not name the requested MCP tool")
        if isolated_proof.payload_sha256 != payload_digest(payload):
            raise MCPDispatchError("action proof does not bind the delegated payload")
        boundary = self.__delegation_boundary
        issuer_key = boundary.issuer_resolver(isolated_grant.issuer_key_fingerprint)
        if issuer_key is None:
            raise MCPDispatchError("delegation issuer is not trusted")
        if self._ledger is None:
            raise MCPDispatchError("delegated actuation requires a persistent audit ledger")
        ledger_ok, _count, _message = self._ledger.verify()
        if not ledger_ok:
            raise MCPDispatchError("delegated actuation audit ledger failed preflight verification")
        historical_verification = verify_historical_delegated_action(
            isolated_grant,
            isolated_proof,
            payload=payload,
            trusted_issuer_public_key=issuer_key,
        )
        if not historical_verification.ok:
            raise MCPDispatchError(
                f"delegation denied: {historical_verification.reason}"
            )
        recovered = boundary.replay_store.get(isolated_proof.action_id)
        if recovered and recovered.get("outcome") in {"succeeded", "failed"}:
            if not (
                recovered.get("grant_id") == isolated_grant.grant_id
                and recovered.get("proof_id") == isolated_proof.proof_id
                and recovered.get("session_id") == session_id
                and recovered.get("receipt")
                and recovered.get("result")
            ):
                raise MCPDispatchError("stored delegated completion tuple does not match")
            try:
                stored_result = dict(recovered["result"])
                stored_receipt = DelegatedActionReceipt.from_dict(recovered["receipt"])
                result_core = dict(stored_result)
                result_core.pop("delegated_receipt", None)
                receipt_check = verify_delegated_receipt(
                    stored_receipt,
                    expected_executor_public_key=self._delegation_identity.public_key_bytes,
                    expected_grant_id=isolated_grant.grant_id,
                    expected_proof_id=isolated_proof.proof_id,
                    expected_action_id=isolated_proof.action_id,
                    expected_action=name,
                    expected_delegated_agent_id=isolated_proof.agent_id,
                    expected_result_status=str(recovered["outcome"]),
                    expected_target=isolated_proof.target,
                    expected_result=result_core,
                    expected_ledger_head=str(recovered.get("ledger_head", "")),
                )
            except (TypeError, ValueError) as exc:
                raise MCPDispatchError("stored delegated completion receipt is invalid") from exc
            if not receipt_check.ok:
                raise MCPDispatchError(
                    f"stored delegated completion receipt failed verification: {receipt_check.reason}"
                )
            if not self._ledger.contains_verified_hash(stored_receipt.ledger_head):
                raise MCPDispatchError("stored receipt ledger head is not in the verified ledger")
            if stored_result.get("delegated_receipt") != stored_receipt.to_dict():
                raise MCPDispatchError("stored result and delegated receipt disagree")
            return stored_result
        revocations = boundary.revocation_provider()
        try:
            epoch = int(revocations.epoch)
            revoked_grants = revocations.revoked_grant_ids
            revoked_agents = revocations.revoked_agent_key_ids
        except (AttributeError, TypeError, ValueError) as exc:
            raise MCPDispatchError("delegation revocation state is invalid") from exc
        verification = verify_delegated_action(
            isolated_grant,
            isolated_proof,
            now=self._now(),
            payload=payload,
            trusted_issuer_public_key=issuer_key,
            revoked_grant_ids=revoked_grants,
            revoked_agent_key_ids=revoked_agents,
            minimum_revocation_epoch=epoch,
        )
        if not verification.ok:
            raise MCPDispatchError(f"delegation denied: {verification.reason}")
        canonical_target = self.delegation_target_for(name, isolated_arguments)
        if isolated_proof.target != canonical_target:
            raise MCPDispatchError("action proof target does not match the live lease binding")
        if not boundary.replay_store.claim(
            action_id=isolated_proof.action_id,
            grant_id=isolated_grant.grant_id,
            proof_id=isolated_proof.proof_id,
            session_id=session_id,
            consumed_at=self._now(),
        ):
            raise MCPDispatchError("delegation denied: action id has already been consumed")

        authorization = _VerifiedDelegatedCall(
            grant=isolated_grant,
            proof=isolated_proof,
            payload=bytes(payload),
            session_id=str(session_id),
        )
        result = self.__execute_tool(
            name, isolated_arguments, authorization=authorization
        )
        succeeded = bool(result.get("ok"))
        ledger_ok, _count, _message = self._ledger.verify()
        if not ledger_ok:
            raise MCPDispatchError("delegated completion audit ledger failed verification")
        ledger_head = self._ledger.head_hash()
        receipt = sign_delegated_receipt(
            grant=isolated_grant,
            proof=isolated_proof,
            agent_identity=self._delegation_identity,
            result=result,
            result_status="succeeded" if succeeded else "failed",
            ledger_head=ledger_head,
            issued_at=self._now(),
        )
        try:
            result["delegated_receipt"] = receipt.to_dict()
            boundary.replay_store.finish(
                isolated_proof.action_id,
                succeeded=succeeded,
                receipt=receipt.to_dict(),
                ledger_head=ledger_head,
                result=result,
            )
        except Exception:
            raise MCPDispatchError("delegation outcome could not be durably finalized")
        return result

    def _require_verified_delegated_call(
        self,
        name: str,
        arguments: dict[str, Any],
        authorization: _VerifiedDelegatedCall | None,
    ) -> dict[str, Any]:
        if self.profile not in {"enterprise", "government"}:
            return json.loads(canonical_bytes(arguments).decode("utf-8"))
        if authorization is None or self.__delegation_boundary is None:
            raise MCPDispatchError("actuator has no verified delegation authorization")
        if authorization.proof.action != name:
            raise MCPDispatchError("delegated authorization names a different tool")
        try:
            signed = json.loads(authorization.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPDispatchError("delegated authorization payload is invalid") from exc
        if canonical_bytes(signed) != authorization.payload or signed.get("arguments") != arguments:
            raise MCPDispatchError("delegated authorization does not bind actuator arguments")
        boundary = self.__delegation_boundary
        issuer_key = boundary.issuer_resolver(authorization.grant.issuer_key_fingerprint)
        if issuer_key is None:
            raise MCPDispatchError("delegation issuer is not trusted")
        revocations = boundary.revocation_provider()
        checked = verify_delegated_action(
            authorization.grant,
            authorization.proof,
            now=self._now(),
            payload=authorization.payload,
            trusted_issuer_public_key=issuer_key,
            revoked_grant_ids=revocations.revoked_grant_ids,
            revoked_agent_key_ids=revocations.revoked_agent_key_ids,
            minimum_revocation_epoch=revocations.epoch,
        )
        if not checked.ok:
            raise MCPDispatchError(f"delegation denied at actuator: {checked.reason}")
        if authorization.proof.target != self.delegation_target_for(name, arguments):
            raise MCPDispatchError("delegated authorization target changed before actuation")
        if not boundary.replay_store.begin(
            authorization.proof.action_id,
            grant_id=authorization.grant.grant_id,
            proof_id=authorization.proof.proof_id,
            session_id=authorization.session_id,
        ):
            raise MCPDispatchError("delegated authorization is not admitted for one-shot actuation")
        isolated = json.loads(canonical_bytes(arguments).decode("utf-8"))
        if not isinstance(isolated, dict):
            raise MCPDispatchError("actuator arguments must be an object")
        return isolated

    def delegation_target_for(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Derive the signed target solely from validated args and live lease authority."""
        if name in _LEASE_TOOL_ROLES:
            lease_id = str(arguments.get("lease_id", ""))
            lease = self._require_lease(lease_id, int(arguments.get("hwnd", 0)), tool=name)
            return self._lease_delegation_target(lease)
        if name == "sc_revoke_lease":
            lease = self._leases.get(str(arguments.get("lease_id", "")))
            if lease is None:
                raise MCPDispatchError("lease to revoke does not exist")
            canonical = self.__lease_authority_store.verify(lease.lease_id, lease)
            return self._lease_delegation_target(canonical)
        if name == "sc_request_lease":
            report = self._verify_live_target(int(arguments.get("hwnd", 0)))
            target = self._report_delegation_target(report, hwnd=int(arguments["hwnd"]))
            target.update({
                "agent_id": str(arguments.get("agent_id", "")),
                "role": str(arguments.get("role", "")),
                "ttl_seconds": int(arguments.get("ttl_seconds", 300)),
            })
            return target
        if name == "sc_request_target_lease":
            if self._logical_target_resolver is None or self._target_verifier is None:
                raise MCPDispatchError("logical target resolution is unavailable")
            resolved = self._logical_target_resolver.resolve(
                str(arguments.get("logical_target_id", "")),
                role=str(arguments.get("role", "")),
                target_verifier=self._target_verifier,
            )
            target = self._report_delegation_target(resolved.verifier_report(), hwnd=resolved.hwnd)
            target.update({
                "logical_target_id": resolved.logical_id,
                "agent_id": str(arguments.get("agent_id", "")),
                "role": str(arguments.get("role", "")),
                "ttl_seconds": int(arguments.get("ttl_seconds", 300)),
            })
            return target
        if name in {"sc_session_stamp", "sc_channel_route"}:
            hwnd = int(arguments.get("hwnd", 0))
            report = self._verify_live_target(hwnd)
            target = self._report_delegation_target(report, hwnd=hwnd)
            if name == "sc_session_stamp":
                target["use_tpm"] = bool(arguments.get("use_tpm", False))
            else:
                target["preferred_channel"] = str(arguments.get("preferred_channel", "auto"))
            return target
        if name == "sc_identity_sign":
            payload = bytes.fromhex(str(arguments.get("payload_hex", "")))
            return {
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "key_provider": str(arguments.get("key_provider", "software")),
            }
        raise MCPDispatchError(f"protected tool {name!r} has no canonical delegation target")

    @staticmethod
    def _report_delegation_target(report: dict[str, Any], *, hwnd: int) -> dict[str, Any]:
        return {
            "hwnd": hwnd,
            "pid": int(report["pid"]),
            "exe": str(report["exe"]),
            "exe_path": str(report.get("exe_path", "")),
            "class_name": str(report["class"]),
            "title_sha256": _hash_text(str(report.get("title", ""))),
            "logical_target_id": "",
        }

    @staticmethod
    def _lease_delegation_target(lease: RuntimeLease) -> dict[str, Any]:
        return {
            "lease_id": lease.lease_id,
            "hwnd": lease.hwnd,
            "pid": lease.target_pid,
            "exe": lease.target_exe,
            "exe_path": lease.target_exe_path,
            "class_name": lease.target_class,
            "title_sha256": lease.target_title_hash,
            "logical_target_id": lease.logical_target_id,
        }

    def active_leases(self) -> list[RuntimeLease]:
        now = self._now()
        leases = []
        for lease_id, lease in self._leases.items():
            try:
                verified = self.__lease_authority_store.verify(
                    lease_id,
                    lease,
                    allow_revoked=True,
                )
            except _LeaseAuthorityError:
                continue
            if verified.is_active(now):
                leases.append(verified)
        return leases

    def audit_events(self) -> list[AuditEvent]:
        return list(self._audit)

    # ------------------------------------------------------------------
    # Lease and audit helpers
    # ------------------------------------------------------------------

    def _record_audit(
        self,
        tool: str,
        ok: bool,
        arguments: dict[str, Any],
        result: dict[str, Any],
    ) -> AuditEvent:
        agent_id = str(
            arguments.get("agent_id")
            or arguments.get("filter_agent_id")
            or result.get("agent_id")
            or "unknown"
        )[:128]
        details = {
            "argument_hash": _hash_text(json.dumps(arguments, sort_keys=True, default=str)),
            "result_hash": _hash_text(json.dumps(result, sort_keys=True, default=str)),
            "profile": self.profile,
        }
        if "lease_id" in arguments:
            details["lease_id"] = str(arguments["lease_id"])[:128]
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._now(),
            event_type="mcp_tool_call",
            agent_id=agent_id,
            tool=tool,
            ok=ok,
            details=details,
        )
        self._audit.append(event)
        if len(self._audit) > _AUDIT_LIMIT:
            self._audit = self._audit[-_AUDIT_LIMIT:]
        if self._ledger is not None:
            self._ledger.log(
                "mcp_tool_call",
                result="ok" if ok else "denied",
                metadata={"audit_event": event.to_dict()},
            )
        return event

    def _record_lease_role_denial(
        self,
        *,
        lease_id: str,
        tool: str,
        stored_role: str,
        issued_role: str,
        reason: str,
    ) -> None:
        if self._ledger is None:
            raise MCPDispatchError(
                "persistent lease role denial evidence is unavailable"
            )
        self._ledger.log(
            "lease_role_decision",
            result="denied",
            metadata={
                "lease_id": lease_id,
                "tool": tool,
                "stored_role": stored_role,
                "issued_role": issued_role,
                "allowed_roles": sorted(_LEASE_TOOL_ROLES.get(tool, frozenset())),
                "reason": reason,
            },
        )

    def _deny_lease_role(
        self,
        *,
        lease_id: str,
        tool: str,
        stored_role: str,
        issued_role: str,
        reason: str,
    ) -> None:
        try:
            self._record_lease_role_denial(
                lease_id=lease_id,
                tool=tool,
                stored_role=stored_role,
                issued_role=issued_role,
                reason=reason,
            )
        except Exception as exc:  # noqa: BLE001
            raise MCPDispatchError(
                f"{reason}; lease role denial evidence could not be persisted: {exc}"
            ) from exc
        raise MCPDispatchError(reason)

    def _require_lease(
        self,
        lease_id: str,
        hwnd: int | None = None,
        *,
        tool: str,
    ) -> RuntimeLease:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise MCPDispatchError(f"lease {lease_id!r} not found")
        if not lease.is_active(self._now()):
            raise MCPDispatchError(f"lease {lease_id!r} is expired or revoked")
        if hwnd is not None and int(hwnd) != int(lease.hwnd):
            raise MCPDispatchError("lease is not bound to requested HWND")

        try:
            authority = self.__lease_authority_store.verify(lease_id, lease)
        except _LeaseAuthorityError as exc:
            self._deny_lease_role(
                lease_id=lease_id,
                tool=tool,
                stored_role=lease.role,
                issued_role=exc.issued_role,
                reason=str(exc),
            )
        assert authority is not None

        allowed_roles = _LEASE_TOOL_ROLES.get(tool)
        if allowed_roles is None:
            self._deny_lease_role(
                lease_id=lease_id,
                tool=tool,
                stored_role=lease.role,
                issued_role=authority.role,
                reason=f"tool {tool!r} has no lease-role authorization contract",
            )
        assert allowed_roles is not None
        if authority.role not in allowed_roles:
            self._deny_lease_role(
                lease_id=lease_id,
                tool=tool,
                stored_role=lease.role,
                issued_role=authority.role,
                reason=f"lease role {authority.role!r} is not authorized for {tool}",
            )
        return lease

    @staticmethod
    def _load_target_verifier() -> Callable[..., dict[str, Any]] | None:
        try:
            from enterprise_experiments.win32_probe.target_guard import verify_target
        except Exception:  # noqa: BLE001
            return None
        return verify_target

    @staticmethod
    def _load_output_reader() -> Callable[[int], str] | None:
        try:
            from enterprise.uia_output import read_terminal_text
        except Exception:  # noqa: BLE001
            return None
        return read_terminal_text

    def _verify_live_target(
        self,
        hwnd: int,
        *,
        expected: RuntimeLease | None = None,
    ) -> dict[str, Any]:
        if self._target_verifier is None:
            raise MCPDispatchError("governed target verifier is unavailable")
        kwargs: dict[str, Any] = {"require_terminal": True}
        if expected is not None:
            kwargs.update(
                expect_pid=expected.target_pid,
                expect_exe=expected.target_exe,
                expect_exe_path=expected.target_exe_path,
                expect_class=expected.target_class,
                expect_title_sha256=expected.target_title_hash,
            )
        report = self._target_verifier(int(hwnd), **kwargs)
        if not report.get("ok"):
            reasons = report.get("reasons") or ["target verification failed"]
            raise MCPDispatchError("unsafe target: " + "; ".join(str(item) for item in reasons))
        if expected is not None:
            actual_title_hash = _hash_text(str(report.get("title", "")))
            if actual_title_hash != expected.target_title_hash:
                raise MCPDispatchError("unsafe target: title hash changed")
        required = {
            "pid": report.get("pid"),
            "exe": report.get("exe"),
            "class": report.get("class"),
        }
        if not required["pid"] or not required["exe"] or not required["class"]:
            raise MCPDispatchError("target verifier returned an incomplete identity binding")
        return report

    @staticmethod
    def _target_binding(lease: RuntimeLease) -> Any:
        if TargetBinding is None:
            raise MCPDispatchError("immutable target binding support is unavailable")
        return TargetBinding(
            pid=lease.target_pid,
            exe=lease.target_exe,
            exe_path=lease.target_exe_path,
            window_class=lease.target_class,
            title_sha256=lease.target_title_hash,
        )

    def _persist_delivery_disposition(
        self,
        lease: RuntimeLease,
        receipt: Any,
        *,
        disposition: str,
        transport_attempted: bool,
        transport_enqueued: bool,
        delivery_confirmed: bool,
        do_not_retry: bool,
        reason: str = "",
    ) -> None:
        metadata = {
            "lease_id": lease.lease_id,
            "subject_agent_id": lease.agent_id,
            "target_hwnd": lease.hwnd,
            "target_pid": lease.target_pid,
            "receipt_id": str(getattr(receipt, "receipt_id", "")),
            "transport_attempted": transport_attempted,
            "transport_enqueued": transport_enqueued,
            "delivery_confirmed": delivery_confirmed,
            "delivery_disposition": disposition,
            "do_not_retry": do_not_retry,
            "reason": _bound_error(reason),
        }
        try:
            self._ledger.log("delivery_disposition", result=disposition, metadata=metadata)
        except Exception as exc:  # noqa: BLE001
            attempt_state = "after a transport attempt" if transport_attempted else "before transport"
            raise MCPDispatchError(
                f"delivery disposition evidence could not be persisted {attempt_state}; "
                f"delivery state is unknown and must not be retried automatically: {exc}"
            ) from exc

    def _require_execution_authorization(
        self,
        lease: RuntimeLease,
        args: dict[str, Any],
        target: dict[str, Any],
        *,
        action: str,
    ) -> dict[str, Any]:
        if self._ledger is None:
            raise MCPDispatchError("governed execution requires a persistent signed audit ledger")
        if self._policy_enforcer is None:
            raise MCPDispatchError("governed execution requires a signed policy enforcer")
        if not self._control.is_active(lease.agent_id):
            raise MCPDispatchError(f"agent {lease.agent_id!r} is not active in the control plane")

        classification = args.get("classification")
        if self.profile == "government" and not classification:
            raise MCPDispatchError("government profile requires an explicit classification label")
        decision = self._policy_enforcer.check(
            lease.agent_id,
            action,
            app=str(target["exe"]),
            classification=classification or "UNCLASSIFIED",
            identity_type=self._identity_type,
        )
        metadata = decision.to_ledger_metadata()
        metadata.update(
            {
                "subject_agent_id": lease.agent_id,
                "requested_action": action,
                "target_hwnd": lease.hwnd,
                "target_pid": target["pid"],
                "target_exe": target["exe"],
                "target_class": target["class"],
                "requires_approval": bool(decision.requires_approval),
            }
        )
        self._ledger.log(
            "policy_decision",
            result="allowed" if decision.allowed else "denied",
            metadata=metadata,
        )
        if not decision.allowed:
            raise MCPDispatchError(f"policy denied {action}: {decision.reason}")

        operator_id = ""
        if decision.requires_approval:
            approval_id = args.get("approval_id")
            if not approval_id:
                raise MCPDispatchError(f"operator approval is required for {action}")
            if self._operator_queue is None:
                raise MCPDispatchError("operator approval queue is not configured")
            approval_context = self.build_approval_context(
                lease,
                args,
                target,
                action=action,
            )
            approval = self._operator_queue.consume_approved(
                approval_id,
                agent_id=lease.agent_id,
                action=action,
                required_context=approval_context,
            )
            if approval is None:
                raise MCPDispatchError(
                    "operator approval is missing, expired, consumed, or not bound "
                    "to the exact action context"
                )
            if self._approval_binding_verifier is not None and not self._approval_binding_verifier(
                approval,
                agent_id=lease.agent_id,
                action=action,
                required_context=approval_context,
            ):
                raise MCPDispatchError(
                    "operator approval audit receipt is missing or does not match "
                    "the exact action context"
                )
            operator_id = approval.operator_id

        return {
            "policy_id": decision.policy_id,
            "classification": decision.classification,
            "approval_mode": "human_approved" if operator_id else "autonomous",
            "operator_id": operator_id,
        }

    def build_approval_context(
        self,
        lease: RuntimeLease,
        args: dict[str, Any],
        target: dict[str, Any],
        *,
        action: str,
    ) -> dict[str, Any]:
        """Build the non-secret context to which a one-time approval is bound."""
        context: dict[str, Any] = {
            "action": action,
            "lease_id": lease.lease_id,
            "target_hwnd": lease.hwnd,
            "target_pid": int(target["pid"]),
            "target_exe": str(target["exe"]),
            "target_class": str(target["class"]),
            "classification": args.get("classification") or "UNCLASSIFIED",
        }
        if action == "sc_inject_text":
            context["payload_sha256"] = _hash_text(str(args.get("text", "")))
        return context

    def approval_context_for(
        self,
        lease_id: str,
        arguments: dict[str, Any],
        *,
        action: str,
    ) -> dict[str, Any]:
        """Return a freshly target-verified context for operator review."""
        lease = self._require_lease(lease_id, int(arguments["hwnd"]), tool=action)
        target = self._verify_live_target(lease.hwnd, expected=lease)
        return self.build_approval_context(
            lease,
            arguments,
            target,
            action=action,
        )

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    def _sc_request_lease(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_request_lease", args, authorization)
        role = args.get("role")
        if role not in _VALID_LEASE_ROLES:
            raise MCPDispatchError(f"unknown lease role {role!r}")
        target = self._verify_live_target(int(args["hwnd"]))
        return self._issue_verified_lease(
            args=args,
            hwnd=int(args["hwnd"]),
            role=role,
            target=target,
        )

    def _sc_request_target_lease(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_request_target_lease", args, authorization)
        role = args.get("role")
        if role not in _VALID_LEASE_ROLES:
            raise MCPDispatchError(f"unknown lease role {role!r}")
        if self._logical_target_resolver is None:
            raise MCPDispatchError("logical target resolver is not configured")
        if self._target_verifier is None:
            raise MCPDispatchError("governed target verifier is unavailable")
        resolved = self._logical_target_resolver.resolve(
            args["logical_target_id"],
            role=role,
            target_verifier=self._target_verifier,
        )
        return self._issue_verified_lease(
            args=args,
            hwnd=resolved.hwnd,
            role=role,
            target=resolved.verifier_report(),
            logical_target_id=resolved.logical_id,
        )

    def _issue_verified_lease(
        self,
        *,
        args: dict[str, Any],
        hwnd: int,
        role: str,
        target: dict[str, Any],
        logical_target_id: str = "",
    ) -> dict[str, Any]:
        ttl = int(args.get("ttl_seconds", 300))
        now = self._now()
        lease = RuntimeLease(
            lease_id="lease-" + uuid.uuid4().hex[:24],
            agent_id=args["agent_id"],
            hwnd=hwnd,
            role=role,
            issued_at=now,
            expires_at=now + ttl,
            target_pid=int(target["pid"]),
            target_exe=str(target["exe"]),
            target_exe_path=str(target.get("exe_path", "")),
            target_class=str(target["class"]),
            target_title_hash=_hash_text(str(target.get("title", ""))),
            logical_target_id=logical_target_id,
        )
        self.__lease_authority_store.issue(lease)
        self._leases[lease.lease_id] = lease
        self._control.register(lease.agent_id)
        return lease.to_dict(now)

    def _sc_revoke_lease(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_revoke_lease", args, authorization)
        lease_id = args["lease_id"]
        lease = self._leases.get(lease_id)
        if lease is None:
            raise MCPDispatchError(f"lease {lease_id!r} not found")
        try:
            canonical = self.__lease_authority_store.verify(lease_id, lease)
        except _LeaseAuthorityError as exc:
            raise MCPDispatchError(str(exc)) from exc
        revoked = replace(canonical, revoked=True)
        self.__lease_authority_store.revoke(canonical)
        self._leases[lease_id] = revoked
        return {"lease_id": lease_id, "revoked": True, "reason": args.get("reason", "")}

    def _sc_list_leases(self, args: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        role = args.get("filter_role", "all")
        agent_id = args.get("filter_agent_id")
        include_expired = bool(args.get("include_expired", False))
        leases = []
        for lease_id, lease in self._leases.items():
            try:
                lease = self.__lease_authority_store.verify(
                    lease_id,
                    lease,
                    allow_revoked=True,
                )
            except _LeaseAuthorityError:
                continue
            if role not in (None, "all") and lease.role != role:
                continue
            if agent_id and lease.agent_id != agent_id:
                continue
            if not include_expired and not lease.is_active(now):
                continue
            leases.append(lease.to_dict(now))
        return {"leases": leases, "count": len(leases)}

    def _sc_get_lease_info(self, args: dict[str, Any]) -> dict[str, Any]:
        lease_id = args["lease_id"]
        lease = self._leases.get(lease_id)
        if lease is None:
            raise MCPDispatchError(f"lease {lease_id!r} not found")
        try:
            canonical = self.__lease_authority_store.verify(
                lease_id,
                lease,
                allow_revoked=True,
            )
        except _LeaseAuthorityError as exc:
            raise MCPDispatchError(str(exc)) from exc
        return canonical.to_dict(self._now())

    def _sc_inject_text(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_inject_text", args, authorization)
        probe = _delivery_probe(args["text"])
        lease = self._require_lease(
            args["lease_id"],
            int(args["hwnd"]),
            tool="sc_inject_text",
        )
        target = self._verify_live_target(int(args["hwnd"]), expected=lease)
        governance = self._require_execution_authorization(
            lease,
            args,
            target,
            action="sc_inject_text",
        )
        if self._router is None:
            raise MCPDispatchError("channel router unavailable")
        if self._output_reader is None:
            raise MCPDispatchError(
                "delivery cannot be confirmed because UIA TextPattern output is unavailable"
            )
        before = self._read_output_once(lease.hwnd, expected=lease)
        before_count = _normalise_terminal_text(before).count(probe)
        self._verify_live_target(lease.hwnd, expected=lease)
        try:
            receipt = self._router.route(
                int(args["hwnd"]),
                args["text"],
                lease_id=lease.lease_id,
                expected_binding=self._target_binding(lease),
            )
        except ChannelRoutingError as exc:
            raise MCPDispatchError(str(exc)) from exc
        if not bool(getattr(receipt, "success", False)):
            attempted = bool(getattr(receipt, "transport_attempted", False))
            disposition = str(getattr(receipt, "delivery_disposition", "not_attempted"))
            transport_error = str(getattr(receipt, "transport_error", ""))
            self._persist_delivery_disposition(
                lease,
                receipt,
                disposition=disposition,
                transport_attempted=attempted,
                transport_enqueued=False,
                delivery_confirmed=False,
                do_not_retry=attempted,
                reason=transport_error,
            )
            if attempted:
                raise MCPDispatchError(
                    "transport was partially attempted; delivery state is unknown and must not "
                    f"be retried automatically: {transport_error or 'PostMessage failure'}"
                )
            raise MCPDispatchError("transport refused or failed to enqueue the payload")
        try:
            self._verify_live_target(lease.hwnd, expected=lease)
        except MCPDispatchError as exc:
            self._persist_delivery_disposition(
                lease,
                receipt,
                disposition="unknown_delivery",
                transport_attempted=True,
                transport_enqueued=True,
                delivery_confirmed=False,
                do_not_retry=True,
                reason=str(exc),
            )
            raise MCPDispatchError(
                "transport was enqueued but post-action target verification failed; "
                f"delivery state is unknown and must not be retried automatically: {exc}"
            ) from exc

        timeout_ms = int(args.get("delivery_timeout_ms", _DEFAULT_DELIVERY_TIMEOUT_MS))
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        confirmed_snapshot = ""
        try:
            while True:
                current = self._read_output_once(lease.hwnd, expected=lease)
                if _normalise_terminal_text(current).count(probe) > before_count:
                    self._verify_live_target(lease.hwnd, expected=lease)
                    confirmed_snapshot = current
                    break
                if time.monotonic() >= deadline:
                    raise MCPDispatchError(
                        "delivery unconfirmed by UIA readback; the target may have received the "
                        "payload, so do not retry automatically"
                    )
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        except MCPDispatchError as exc:
            self._persist_delivery_disposition(
                lease,
                receipt,
                disposition="enqueued_unconfirmed",
                transport_attempted=True,
                transport_enqueued=True,
                delivery_confirmed=False,
                do_not_retry=True,
                reason=str(exc),
            )
            raise

        data = _jsonable(receipt)
        data["success"] = True
        data["transport_enqueued"] = True
        data["delivery_confirmed"] = True
        data["readback_hash"] = _hash_text(confirmed_snapshot)
        data["delivery_confirmation"] = "uia_echo_confirmed"
        data["delivery_probe_hash"] = _hash_text(probe)
        data["confirmed_at"] = self._now()
        data["lease_id"] = lease.lease_id
        data["agent_id"] = lease.agent_id
        data["governance"] = governance
        self._persist_delivery_disposition(
            lease,
            receipt,
            disposition="delivery_confirmed",
            transport_attempted=True,
            transport_enqueued=True,
            delivery_confirmed=True,
            do_not_retry=False,
        )
        self._injected_text[lease.lease_id] = args["text"]
        self._read_snapshots[lease.lease_id] = confirmed_snapshot
        return data

    def _sc_read_output(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_read_output", args, authorization)
        lease = self._require_lease(
            args["lease_id"],
            int(args["hwnd"]),
            tool="sc_read_output",
        )
        target = self._verify_live_target(int(args["hwnd"]), expected=lease)
        governance = self._require_execution_authorization(
            lease,
            args,
            target,
            action="sc_read_output",
        )
        if self._output_reader is None:
            raise MCPDispatchError("UIA TextPattern output reader is unavailable")

        timeout_seconds = int(args.get("timeout_ms", 5000)) / 1000.0
        deadline = time.monotonic() + timeout_seconds
        previous = self._read_snapshots.get(lease.lease_id)
        current = self._read_output_once(lease.hwnd, expected=lease)
        while previous is not None and current == previous and time.monotonic() < deadline:
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            current = self._read_output_once(lease.hwnd, expected=lease)

        self._read_snapshots[lease.lease_id] = current
        raw_delta = current if previous is None else (
            current[len(previous):] if current.startswith(previous) else current
        )
        injected = self._injected_text.pop(lease.lease_id, "")
        echo_removed = False
        if injected and injected in raw_delta:
            raw_delta = raw_delta.replace(injected, "", 1)
            echo_removed = True
        if args.get("strip_ansi", True):
            raw_delta = _ANSI_ESCAPE_RE.sub("", raw_delta)
        output = raw_delta.strip()
        truncated = len(output) > _MAX_READ_CHARS
        if truncated:
            output = output[-_MAX_READ_CHARS:]
        self._verify_live_target(lease.hwnd, expected=lease)
        return {
            "lease_id": lease.lease_id,
            "hwnd": lease.hwnd,
            "method": "uia_textpattern",
            "classification": "no_signal" if not output else "output",
            "text": output,
            "text_hash": _hash_text(output),
            "snapshot_hash": _hash_text(current),
            "echo_removed": echo_removed,
            "truncated": truncated,
            "governance": governance,
        }

    def _read_output_once(self, hwnd: int, *, expected: RuntimeLease) -> str:
        self._verify_live_target(hwnd, expected=expected)
        try:
            text = self._output_reader(hwnd) if self._output_reader is not None else None
        except Exception as exc:  # noqa: BLE001
            raise MCPDispatchError(f"UIA TextPattern output read failed: {exc}") from exc
        if not isinstance(text, str):
            raise MCPDispatchError("UIA TextPattern output reader returned no text value")
        self._verify_live_target(hwnd, expected=expected)
        return text

    def _sc_verify_target(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._run_target_guard(args)

    def _sc_target_guard_check(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._run_target_guard(args)

    def _run_target_guard(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            from enterprise_experiments.win32_probe.target_guard import verify_target
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "available": False, "reason": f"target guard unavailable: {exc}"}
        report = verify_target(
            int(args["hwnd"]),
            expect_pid=args.get("expected_pid"),
            expect_exe=args.get("expected_exe"),
            expect_class=args.get("expected_class"),
            require_terminal=False,
        )
        report["available"] = True
        return report

    def _sc_audit_tail(self, args: dict[str, Any]) -> dict[str, Any]:
        n = int(args.get("n", 20))
        event_type = args.get("event_type")
        events = self._audit
        if event_type:
            events = [evt for evt in events if evt.event_type == event_type]
        return {"events": [evt.to_dict() for evt in events[-n:]], "count": min(n, len(events))}

    def _sc_audit_search(self, args: dict[str, Any]) -> dict[str, Any]:
        limit = int(args.get("limit", 100))
        events = list(self._audit)
        if args.get("agent_id"):
            events = [evt for evt in events if evt.agent_id == args["agent_id"]]
        if args.get("event_type"):
            events = [evt for evt in events if evt.event_type == args["event_type"]]
        return {"events": [evt.to_dict() for evt in events[-limit:]], "count": min(limit, len(events))}

    def _sc_mesh_peers(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            from enterprise.registry import discover_mesh
            peers = [
                tag.to_dict()
                for tag in discover_mesh(verified_only=not bool(args.get("include_offline", False)))
            ]
        except Exception:
            peers = []
        return {"peers": peers, "count": len(peers)}

    def _sc_channel_status(self, args: dict[str, Any]) -> dict[str, Any]:
        from enterprise.watcher import WatcherState
        state = WatcherState()
        health = state._probe_channels()
        data = asdict(health)
        if not bool(args.get("check_etw", True)):
            data["etw"] = "SKIPPED"
        return data

    def _sc_identity_sign(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_identity_sign", args, authorization)
        if self.profile == "government" and args.get("key_provider", "software") != "tpm":
            raise MCPDispatchError(
                "government profile requires a verified TPM platform claim alongside signing"
            )
        if args.get("key_provider", "software") == "tpm":
            if (
                not _TPM_ATTESTATION_AVAILABLE
                or create_tpm_platform_claim is None
                or verify_tpm_platform_claim is None
            ):
                raise MCPDispatchError("TPM attestation not available on this machine")
            nonce = os.urandom(32)
            tpm_result = create_tpm_platform_claim(nonce)
            if not tpm_result.supported:
                raise MCPDispatchError(
                    f"TPM attestation not available on this machine: {tpm_result.error}"
                )
            if not verify_tpm_platform_claim(tpm_result):
                raise MCPDispatchError("TPM platform claim failed local verification")
            payload = bytes.fromhex(args["payload_hex"])
            sig = self._private_key.sign(payload)
            pub = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return {
                "algorithm": "Ed25519",
                "signature_key_provider": "software",
                "signature_b64": base64.b64encode(sig).decode("ascii"),
                "public_key_b64": base64.b64encode(pub).decode("ascii"),
                "payload_hash": hashlib.sha256(payload).hexdigest(),
                "tpm_attestation": {
                    "supported": tpm_result.supported,
                    "verified_locally": True,
                    "identity_key_bound": tpm_result.identity_key_bound,
                    "algorithm": tpm_result.algorithm,
                    "nonce_hex": tpm_result.nonce.hex(),
                    "pubkey_hex": tpm_result.public_key_blob.hex(),
                    "claim_b64": base64.b64encode(tpm_result.claim_blob).decode("ascii"),
                    "claim_sha256": hashlib.sha256(tpm_result.claim_blob).hexdigest(),
                    "claim_size": len(tpm_result.claim_blob),
                },
            }
        payload = bytes.fromhex(args["payload_hex"])
        sig = self._private_key.sign(payload)
        pub = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            "algorithm": "Ed25519",
            "signature_b64": base64.b64encode(sig).decode("ascii"),
            "public_key_b64": base64.b64encode(pub).decode("ascii"),
            "payload_hash": hashlib.sha256(payload).hexdigest(),
        }

    def _sc_identity_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        algorithm = args.get("algorithm", "Ed25519")
        if algorithm != "Ed25519":
            return {
                "verified": False,
                "algorithm": "Ed25519",
                "reason": f"unsupported signature algorithm: {algorithm}",
            }
        try:
            payload = bytes.fromhex(args["payload_hex"])
            sig = _normalise_b64(args["signature_b64"])
            pub = _normalise_b64(args["public_key_b64"])
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
            verified = True
        except Exception:
            verified = False
        return {"verified": verified, "algorithm": "Ed25519"}

    def _sc_session_stamp(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_session_stamp", args, authorization)
        if self.profile == "government" and not bool(args.get("use_tpm", False)):
            raise MCPDispatchError(
                "government profile requires TPM-backed session stamping"
            )
        if bool(args.get("use_tpm", False)):
            tpm_info: dict[str, Any] = {"available": False, "error": "TPM probe unavailable"}
            if _TPM_ATTESTATION_AVAILABLE and tpm_probe is not None:
                try:
                    tpm_info = tpm_probe()
                except Exception as exc:  # noqa: BLE001
                    tpm_info = {"available": False, "error": str(exc)}
            stamp = {
                "hwnd": int(args["hwnd"]),
                "birth_id": "birth-" + uuid.uuid4().hex[:16],
                "timestamp": self._now(),
                "provider": "tpm" if tpm_info.get("supported") else "software",
                "tpm": tpm_info,
            }
            stamp["stamp_hash"] = _hash_text(json.dumps(stamp, sort_keys=True, default=str))
            return stamp
        stamp = {
            "hwnd": int(args["hwnd"]),
            "birth_id": "birth-" + uuid.uuid4().hex[:16],
            "timestamp": self._now(),
            "provider": "software",
        }
        stamp["stamp_hash"] = _hash_text(json.dumps(stamp, sort_keys=True))
        return stamp

    def _sc_channel_route(
        self, args: dict[str, Any], *, authorization: _VerifiedDelegatedCall | None = None
    ) -> dict[str, Any]:
        args = self._require_verified_delegated_call("sc_channel_route", args, authorization)
        if self._router is None:
            raise MCPDispatchError("channel router unavailable")
        decision = self._router.classify(int(args["hwnd"]))
        data = _jsonable(decision)
        preferred = args.get("preferred_channel", "auto")
        if preferred != "auto" and data.get("channel") != preferred:
            data["preferred_mismatch"] = True
        return data

    def _sc_echo_filter(self, args: dict[str, Any]) -> dict[str, Any]:
        raw = args["raw_text"]
        injected = args["injected_text"]
        token = args.get("probe_token", "")
        cleaned = raw.replace(injected, "")
        if token:
            cleaned = cleaned.replace(token, "")
        cleaned = cleaned.strip()
        return {
            "clean_text": cleaned,
            "classification": "echo_only" if not cleaned else "mixed_echo_and_output",
            "clean_hash": _hash_text(cleaned),
        }

    def _sc_pipe_ping(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            import ctypes
            GENERIC_READ = 0x80000000
            OPEN_EXISTING = 3
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
            started = self._now()
            handle = ctypes.windll.kernel32.CreateFileW(
                args["pipe_name"], GENERIC_READ, 0, None, OPEN_EXISTING, 0, None
            )
            latency_ms = (self._now() - started) * 1000.0
            if handle and handle != INVALID_HANDLE_VALUE:
                ctypes.windll.kernel32.CloseHandle(handle)
                return {"available": True, "latency_ms": latency_ms}
            err = ctypes.windll.kernel32.GetLastError()
            return {"available": False, "latency_ms": latency_ms, "win32_error": err}
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "error": str(exc)}

    def _sc_policy_check(self, args: dict[str, Any]) -> dict[str, Any]:
        agent_id = args["agent_id"]
        if not self._control.is_active(agent_id):
            return {
                "allowed": False,
                "agent_id": agent_id,
                "action_type": args["action_type"],
                "target_hwnd": args["target_hwnd"],
                "governance_profile": self.profile,
                "rule": "control_plane_not_active",
            }
        if self._policy_enforcer is None:
            return {
                "allowed": False,
                "agent_id": agent_id,
                "action_type": args["action_type"],
                "target_hwnd": args["target_hwnd"],
                "governance_profile": self.profile,
                "rule": "signed_policy_enforcer_not_configured",
            }
        target = self._verify_live_target(int(args["target_hwnd"]))
        action_map = {
            "inject": "sc_inject_text",
            "read": "sc_read_output",
            "lease": "sc_request_lease",
            "revoke": "sc_revoke_lease",
            "admin": "sc_admin",
        }
        requested_action = action_map[args["action_type"]]
        decision = self._policy_enforcer.check(
            agent_id,
            requested_action,
            app=str(target["exe"]),
            classification=args.get("classification", "UNCLASSIFIED"),
            identity_type=self._identity_type,
        )
        return {
            "allowed": decision.allowed,
            "agent_id": agent_id,
            "action_type": args["action_type"],
            "requested_action": requested_action,
            "target_hwnd": args["target_hwnd"],
            "governance_profile": self.profile,
            "rule": decision.reason,
            "policy_id": decision.policy_id,
            "classification": decision.classification,
            "requires_approval": decision.requires_approval,
            "target": {
                "pid": target["pid"],
                "exe": target["exe"],
                "class": target["class"],
            },
        }

    def _sc_receipt_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            receipt = json.loads(args["receipt_json"])
        except json.JSONDecodeError as exc:
            raise MCPDispatchError(f"receipt_json is not valid JSON: {exc}") from exc
        sig_b64 = receipt.get("signature_b64") or receipt.get("sig_b64")
        payload_hex = receipt.get("payload_hex")
        if not sig_b64 or not payload_hex:
            return {
                "verified": False,
                "reason": "receipt missing signature_b64/sig_b64 or payload_hex",
            }
        return self._sc_identity_verify(
            {
                "payload_hex": payload_hex,
                "signature_b64": sig_b64,
                "public_key_b64": args["expected_agent_pub_b64"],
                "algorithm": receipt.get("algorithm", "Ed25519"),
            }
        )


_DEFAULT_DISPATCHER: MCPDispatcher | None = None


def get_default_dispatcher() -> MCPDispatcher:
    global _DEFAULT_DISPATCHER
    if _DEFAULT_DISPATCHER is None:
        _DEFAULT_DISPATCHER = MCPDispatcher()
    return _DEFAULT_DISPATCHER


def dispatch_tool(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convenience entry point for MCP servers and CLI wrappers."""
    return get_default_dispatcher().call_tool(name, arguments or {})


__all__ = [
    "AuditEvent",
    "MCPDispatchError",
    "DelegationBoundary",
    "MCPDispatcher",
    "MCPValidationError",
    "RuntimeLease",
    "SchemaValidator",
    "dispatch_tool",
    "get_default_dispatcher",
]
