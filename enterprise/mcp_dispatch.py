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
from dataclasses import asdict, dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.control import ControlPlane
from enterprise.mcp_tools import get_tool, get_tool_registry

try:
    from experiments.win32_probe.channel_router import ChannelRouter, ChannelRoutingError
except Exception:  # noqa: BLE001
    ChannelRouter = None  # type: ignore[assignment]
    ChannelRoutingError = RuntimeError  # type: ignore[assignment]

try:
    from enterprise.tpm_attestation import create_tpm_platform_claim, tpm_probe
    _TPM_ATTESTATION_AVAILABLE = True
except Exception:  # noqa: BLE001
    _TPM_ATTESTATION_AVAILABLE = False
    create_tpm_platform_claim = None  # type: ignore[assignment]
    tpm_probe = None  # type: ignore[assignment]


_AUDIT_LIMIT = 2_000
_MAX_ERROR_LEN = 512
_VALID_PROFILES = frozenset({"normal", "enterprise", "government"})


class MCPDispatchError(RuntimeError):
    """Raised internally for validation or execution failures."""


class MCPValidationError(MCPDispatchError):
    """Tool arguments did not match the registered schema."""


@dataclass(frozen=True)
class RuntimeLease:
    lease_id: str
    agent_id: str
    hwnd: int
    role: str
    issued_at: float
    expires_at: float
    revoked: bool = False

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


def _bound_error(value: str) -> str:
    return value[:_MAX_ERROR_LEN]


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
        now: Callable[[], float] = _now,
    ) -> None:
        if profile not in _VALID_PROFILES:
            raise ValueError(f"profile must be one of {sorted(_VALID_PROFILES)}, got {profile!r}")
        self.profile = profile
        self._validator = SchemaValidator()
        self._router = router if router is not None else (ChannelRouter() if ChannelRouter else None)
        self._control = control_plane or ControlPlane(ledger=ledger)
        self._ledger = ledger
        self._now = now
        self._leases: dict[str, RuntimeLease] = {}
        self._audit: list[AuditEvent] = []
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "sc_inject_text": self._sc_inject_text,
            "sc_read_output": self._sc_read_output,
            "sc_verify_target": self._sc_verify_target,
            "sc_request_lease": self._sc_request_lease,
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
        missing = registered - set(self._handlers)
        if missing:
            raise RuntimeError(f"MCP dispatcher missing handler(s): {sorted(missing)}")

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate and execute a registered MCP tool.

        Returns an MCP-friendly dict.  Validation and execution failures are
        reported as ``{"ok": False, "error": ...}`` rather than escaping to the
        caller.  Unknown tools still fail closed with the same envelope.
        """
        args = {} if arguments is None else arguments
        try:
            if name not in self._handlers:
                get_tool(name)  # raises useful KeyError text if not registered
            validated = self._validator.validate(name, args)
            result = self._handlers[name](validated)
            result.setdefault("profile", self.profile)
            self._record_audit(name, True, validated, result)
            return {"ok": True, "tool": name, "result": result}
        except Exception as exc:  # noqa: BLE001
            error = _bound_error(str(exc))
            self._record_audit(name, False, args if isinstance(args, dict) else {}, {"error": error})
            return {"ok": False, "tool": name, "error": error}

    def active_leases(self) -> list[RuntimeLease]:
        now = self._now()
        return [lease for lease in self._leases.values() if lease.is_active(now)]

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
                metadata=event.to_dict(),
            )
        return event

    def _require_lease(self, lease_id: str, hwnd: int | None = None) -> RuntimeLease:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise MCPDispatchError(f"lease {lease_id!r} not found")
        if not lease.is_active(self._now()):
            raise MCPDispatchError(f"lease {lease_id!r} is expired or revoked")
        if hwnd is not None and int(hwnd) != int(lease.hwnd):
            raise MCPDispatchError("lease is not bound to requested HWND")
        return lease

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    def _sc_request_lease(self, args: dict[str, Any]) -> dict[str, Any]:
        ttl = int(args.get("ttl_seconds", 300))
        now = self._now()
        lease = RuntimeLease(
            lease_id="lease-" + uuid.uuid4().hex[:24],
            agent_id=args["agent_id"],
            hwnd=int(args["hwnd"]),
            role=args["role"],
            issued_at=now,
            expires_at=now + ttl,
        )
        self._leases[lease.lease_id] = lease
        self._control.register(lease.agent_id)
        return lease.to_dict(now)

    def _sc_revoke_lease(self, args: dict[str, Any]) -> dict[str, Any]:
        lease = self._leases.get(args["lease_id"])
        if lease is None:
            raise MCPDispatchError(f"lease {args['lease_id']!r} not found")
        revoked = RuntimeLease(
            lease_id=lease.lease_id,
            agent_id=lease.agent_id,
            hwnd=lease.hwnd,
            role=lease.role,
            issued_at=lease.issued_at,
            expires_at=lease.expires_at,
            revoked=True,
        )
        self._leases[lease.lease_id] = revoked
        return {"lease_id": lease.lease_id, "revoked": True, "reason": args.get("reason", "")}

    def _sc_list_leases(self, args: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        role = args.get("filter_role", "all")
        agent_id = args.get("filter_agent_id")
        include_expired = bool(args.get("include_expired", False))
        leases = []
        for lease in self._leases.values():
            if role not in (None, "all") and lease.role != role:
                continue
            if agent_id and lease.agent_id != agent_id:
                continue
            if not include_expired and not lease.is_active(now):
                continue
            leases.append(lease.to_dict(now))
        return {"leases": leases, "count": len(leases)}

    def _sc_get_lease_info(self, args: dict[str, Any]) -> dict[str, Any]:
        lease = self._leases.get(args["lease_id"])
        if lease is None:
            raise MCPDispatchError(f"lease {args['lease_id']!r} not found")
        return lease.to_dict(self._now())

    def _sc_inject_text(self, args: dict[str, Any]) -> dict[str, Any]:
        lease = self._require_lease(args["lease_id"], int(args["hwnd"]))
        if self._router is None:
            raise MCPDispatchError("channel router unavailable")
        try:
            receipt = self._router.route(int(args["hwnd"]), args["text"], lease_id=lease.lease_id)
        except ChannelRoutingError as exc:
            raise MCPDispatchError(str(exc)) from exc
        data = _jsonable(receipt)
        data["lease_id"] = lease.lease_id
        data["agent_id"] = lease.agent_id
        return data

    def _sc_read_output(self, args: dict[str, Any]) -> dict[str, Any]:
        lease = self._require_lease(args["lease_id"], int(args["hwnd"]))
        return {
            "lease_id": lease.lease_id,
            "hwnd": lease.hwnd,
            "method": "uia_textpattern_runtime_placeholder",
            "classification": "no_signal",
            "text": "",
            "text_hash": _hash_text(""),
            "note": "runtime dispatch wired; live UIA adapter remains a platform probe",
        }

    def _sc_verify_target(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._run_target_guard(args)

    def _sc_target_guard_check(self, args: dict[str, Any]) -> dict[str, Any]:
        report = self._run_target_guard(args)
        report["birth_id_checked"] = bool(args.get("birth_id"))
        report["generation_checked"] = "generation" in args
        return report

    def _run_target_guard(self, args: dict[str, Any]) -> dict[str, Any]:
        try:
            from experiments.win32_probe.target_guard import verify_target
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

    def _sc_identity_sign(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.profile == "government" and args.get("key_provider", "software") != "tpm":
            raise MCPDispatchError(
                "government profile requires TPM-backed identity for signing"
            )
        if args.get("key_provider", "software") == "tpm":
            if not _TPM_ATTESTATION_AVAILABLE or create_tpm_platform_claim is None:
                raise MCPDispatchError("TPM attestation not available on this machine")
            nonce = os.urandom(32)
            tpm_result = create_tpm_platform_claim(nonce)
            if not tpm_result.supported:
                raise MCPDispatchError(
                    f"TPM attestation not available on this machine: {tpm_result.error}"
                )
            payload = bytes.fromhex(args["payload_hex"])
            sig = self._private_key.sign(payload)
            pub = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            return {
                "algorithm": "Ed25519+TPM",
                "signature_b64": base64.b64encode(sig).decode("ascii"),
                "public_key_b64": base64.b64encode(pub).decode("ascii"),
                "payload_hash": hashlib.sha256(payload).hexdigest(),
                "tpm_attestation": {
                    "supported": tpm_result.supported,
                    "algorithm": tpm_result.algorithm,
                    "nonce_hex": tpm_result.nonce.hex(),
                    "pubkey_hex": tpm_result.public_key_blob.hex(),
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
        try:
            payload = bytes.fromhex(args["payload_hex"])
            sig = _normalise_b64(args["signature_b64"])
            pub = _normalise_b64(args["public_key_b64"])
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)
            verified = True
        except Exception:
            verified = False
        return {"verified": verified, "algorithm": args.get("algorithm", "Ed25519")}

    def _sc_session_stamp(self, args: dict[str, Any]) -> dict[str, Any]:
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

    def _sc_channel_route(self, args: dict[str, Any]) -> dict[str, Any]:
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
        active = self._control.is_active(agent_id)
        return {
            "allowed": active,
            "agent_id": agent_id,
            "action_type": args["action_type"],
            "target_hwnd": args["target_hwnd"],
            "governance_profile": self.profile,
            "rule": "control_plane_active" if active else "control_plane_not_active",
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
    "MCPDispatcher",
    "MCPValidationError",
    "RuntimeLease",
    "SchemaValidator",
    "dispatch_tool",
    "get_default_dispatcher",
]
