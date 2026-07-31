"""ACP v1 core shim for SelfConnect governed actions.

The shim exposes a small Agent Client Protocol surface without turning natural
language into authority.  ``session/prompt`` accepts one strict JSON action
envelope whose exact canonical call is bound to an owner-signed delegation grant
and an agent-signed action proof.  Successful action IDs are atomically consumed
in SQLite before the backend is invoked.

Supported ACP v1 methods: ``initialize``, ``session/new``, ``session/prompt``,
and ``session/cancel``.  The transport-neutral :class:`ACPShim` can be embedded
in an official ACP runtime or exercised directly.  Unsupported features fail
explicitly; this module does not claim complete ACP conformance or registry
eligibility.
"""
from __future__ import annotations

import json
import math
import sqlite3
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TextIO

from enterprise.delegation import (
    AgentActionProof,
    DelegationGrant,
    canonical_bytes,
    verify_delegated_action,
)
from enterprise.acp_auth import ACPTrustStore

ACP_PROTOCOL_VERSION = 1
ACP_ACTION_SCHEMA = "selfconnect.acp.governed-action.v1"
JSONRPC_VERSION = "2.0"
_MAX_MESSAGE_BYTES = 1_048_576
_MAX_SESSIONS = 1_024


class ACPShimError(RuntimeError):
    """A bounded client or governance error suitable for a JSON-RPC response."""

    def __init__(self, code: int, message: str, *, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


class GovernedActionBackend(Protocol):
    """Narrow backend boundary; production adapters should wrap GovernedRuntime."""

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


class GovernedRuntimeBackend:
    """Production backend that accepts only the canonical GovernedRuntime type."""

    def __init__(self, runtime: Any) -> None:
        from enterprise.governed_runtime import GovernedRuntime

        if type(runtime) is not GovernedRuntime:
            raise TypeError("ACP production backend requires the exact GovernedRuntime type")
        self.__runtime = runtime

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.__runtime.dispatcher.call_tool(name, arguments)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeError("governed runtime denied the action")
        return result


@dataclass(frozen=True)
class RevocationSnapshot:
    """Deployment-supplied revocation state used for one verification."""

    epoch: int
    revoked_grant_ids: frozenset[str] = frozenset()
    revoked_agent_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.epoch, int) or self.epoch < 0:
            raise ValueError("revocation epoch must be a non-negative integer")


@dataclass
class _Session:
    session_id: str
    cwd: str
    client_name: str
    cancelled: bool = False
    agent_ids: set[str] | None = None

    def __post_init__(self) -> None:
        if self.agent_ids is None:
            self.agent_ids = set()


class SQLiteActionReplayStore:
    """Durably and atomically consume ACP action IDs before actuation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS acp_action_consumption (
                action_id TEXT PRIMARY KEY NOT NULL,
                grant_id TEXT NOT NULL,
                proof_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                consumed_at REAL NOT NULL,
                outcome TEXT NOT NULL DEFAULT 'admitted'
                    CHECK (outcome IN ('admitted', 'succeeded', 'failed'))
            ) STRICT
            """
        )

    def claim(
        self,
        *,
        action_id: str,
        grant_id: str,
        proof_id: str,
        session_id: str,
        consumed_at: float,
    ) -> bool:
        """Return true exactly once for an action ID, across processes/restarts."""
        if not action_id or len(action_id) > 256 or any(ord(ch) < 32 for ch in action_id):
            raise ValueError("action_id is invalid")
        if not isinstance(consumed_at, (int, float)) or not math.isfinite(float(consumed_at)):
            raise ValueError("consumed_at is invalid")
        with self._lock:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO acp_action_consumption
                    (action_id, grant_id, proof_id, session_id, consumed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action_id, grant_id, proof_id, session_id, float(consumed_at)),
            )
            return cursor.rowcount == 1

    def finish(self, action_id: str, *, succeeded: bool) -> None:
        outcome = "succeeded" if succeeded else "failed"
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE acp_action_consumption SET outcome = ? WHERE action_id = ? AND outcome = 'admitted'",
                (outcome, action_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("replay-store action is missing or already finalized")

    def contains(self, action_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM acp_action_consumption WHERE action_id = ?", (action_id,)
            ).fetchone()
            return row is not None

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def acp_action_payload(
    *,
    session_id: str,
    cwd: str,
    tool: str,
    arguments: Mapping[str, Any],
    resource_links: list[dict[str, Any]] | None = None,
) -> bytes:
    """Canonical bytes an agent signs before submitting an ACP action."""
    return canonical_bytes(
        {
            "schema": ACP_ACTION_SCHEMA,
            "sessionId": session_id,
            "cwd": cwd,
            "tool": tool,
            "arguments": dict(arguments),
            "resourceLinks": list(resource_links or []),
        }
    )


class ACPShim:
    """Transport-neutral ACP v1 request handler for governed SelfConnect calls."""

    def __init__(
        self,
        *,
        backend: GovernedActionBackend,
        replay_store: SQLiteActionReplayStore,
        issuer_resolver: Callable[[str], bytes | None],
        revocation_provider: Callable[[], RevocationSnapshot],
        clock: Callable[[], float],
        auth_store: ACPTrustStore | None = None,
        terminal_setup_args: tuple[str, ...] = ("--setup",),
    ) -> None:
        self._backend = backend
        self._replay_store = replay_store
        self._issuer_resolver = issuer_resolver
        self._revocation_provider = revocation_provider
        self._clock = clock
        self._auth_store = auth_store
        self._terminal_setup_args = terminal_setup_args
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.RLock()
        self._client_name = "unknown-acp-client"
        self._initialized = False

    def refresh_revocations(self) -> tuple[str, ...]:
        """Remove sessions bound to agents in the latest revocation snapshot."""
        try:
            revocations = self._revocation_provider()
        except Exception as exc:
            raise ACPShimError(-32010, "revocation state is unavailable") from exc
        if not isinstance(revocations, RevocationSnapshot):
            raise ACPShimError(-32010, "revocation provider returned invalid state")
        return self.apply_revocations(revocations)

    def apply_revocations(self, revocations: RevocationSnapshot) -> tuple[str, ...]:
        """Apply a validated externally observed snapshot to active sessions."""
        if not isinstance(revocations, RevocationSnapshot):
            raise ACPShimError(-32010, "revocation provider returned invalid state")
        removed: list[str] = []
        with self._lock:
            for session_id, session in list(self._sessions.items()):
                if session.agent_ids and session.agent_ids & revocations.revoked_agent_ids:
                    self._sessions.pop(session_id)
                    removed.append(session_id)
        return tuple(sorted(removed))

    def handle(self, message: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Handle one JSON-RPC message and return notifications plus response."""
        request_id = message.get("id")
        try:
            self._validate_envelope(message)
            method = message.get("method")
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise ACPShimError(-32602, "params must be an object")
            if method == "initialize":
                result = self._initialize(params)
            elif method == "session/new":
                result = self._new_session(params)
            elif method == "session/prompt":
                updates, result = self._prompt(params)
                if request_id is None:
                    raise ACPShimError(-32600, "session/prompt must be a request")
                return [*updates, self._response(request_id, result)]
            elif method == "session/cancel":
                self._cancel(params)
                return [] if request_id is None else [self._response(request_id, {})]
            else:
                raise ACPShimError(-32601, "method not found")
            if request_id is None:
                return []
            return [self._response(request_id, result)]
        except ACPShimError as exc:
            if request_id is None:
                return []
            return [self._error(request_id, exc.code, str(exc), exc.data)]
        except Exception:
            if request_id is None:
                return []
            return [self._error(request_id, -32603, "internal error")]

    @staticmethod
    def _validate_envelope(message: Mapping[str, Any]) -> None:
        try:
            size = len(canonical_bytes(dict(message)))
        except (TypeError, ValueError) as exc:
            raise ACPShimError(-32600, "request is not valid JSON data") from exc
        if size > _MAX_MESSAGE_BYTES:
            raise ACPShimError(-32600, "request exceeds maximum size")
        if message.get("jsonrpc") != JSONRPC_VERSION or not isinstance(message.get("method"), str):
            raise ACPShimError(-32600, "invalid JSON-RPC request")
        unknown = set(message) - {"jsonrpc", "id", "method", "params"}
        if unknown:
            raise ACPShimError(-32600, "unexpected JSON-RPC fields")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        version = params.get("protocolVersion")
        if not isinstance(version, int):
            raise ACPShimError(-32602, "protocolVersion must be an integer")
        client_info = params.get("clientInfo")
        if isinstance(client_info, dict) and isinstance(client_info.get("name"), str):
            self._client_name = client_info["name"][:256]
        self._initialized = True
        client_capabilities = params.get("clientCapabilities", {})
        terminal_auth = bool(
            isinstance(client_capabilities, dict)
            and isinstance(client_capabilities.get("auth"), dict)
            and client_capabilities["auth"].get("terminal") is True
            and self._auth_store is not None
        )
        auth_methods = []
        if terminal_auth:
            auth_methods.append(
                {
                    "id": "selfconnect-owner-enrollment",
                    "name": "Enroll SelfConnect owner key",
                    "description": "Prove owner-key possession in an interactive terminal setup",
                    "type": "terminal",
                    "args": list(self._terminal_setup_args),
                    "env": {},
                }
            )
        return {
            "protocolVersion": ACP_PROTOCOL_VERSION,
            "agentCapabilities": {
                "loadSession": False,
                "promptCapabilities": {"image": False, "audio": False, "embeddedContext": False},
                "mcpCapabilities": {"http": False, "sse": False},
                "sessionCapabilities": {},
                "auth": {},
            },
            "authMethods": auth_methods,
            "agentInfo": {
                "name": "selfconnect-governed-acp",
                "title": "SelfConnect Governed ACP",
                "version": "0.1.0",
            },
            "_meta": {
                "selfconnect": {
                    "actionSchema": ACP_ACTION_SCHEMA,
                    "authorization": "owner-signed-grant",
                    "authorship": "agent-signed-action",
                }
            },
        }

    def _new_session(self, params: dict[str, Any]) -> dict[str, Any]:
        if not self._initialized:
            raise ACPShimError(-32002, "initialize must be called first")
        self._require_active_auth()
        cwd = params.get("cwd")
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            raise ACPShimError(-32602, "cwd must be an absolute path")
        mcp_servers = params.get("mcpServers")
        if not isinstance(mcp_servers, list):
            raise ACPShimError(-32602, "mcpServers must be an array")
        if mcp_servers:
            raise ACPShimError(-32602, "MCP server forwarding is not supported by this shim")
        with self._lock:
            if len(self._sessions) >= _MAX_SESSIONS:
                raise ACPShimError(-32003, "session limit reached")
            session_id = uuid.uuid4().hex
            self._sessions[session_id] = _Session(session_id, str(Path(cwd)), self._client_name)
        return {"sessionId": session_id}

    def _prompt(self, params: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        session = self._get_session(params.get("sessionId"))
        try:
            self._require_active_auth()
        except ACPShimError:
            # Emergency trust deactivation terminates existing sessions. A
            # later enrollment must establish a fresh session explicitly.
            with self._lock:
                self._sessions.pop(session.session_id, None)
            raise
        if session.cancelled:
            session.cancelled = False
            return [], {"stopReason": "cancelled"}
        prompt = params.get("prompt")
        if not isinstance(prompt, list) or not prompt:
            raise ACPShimError(-32602, "prompt must be a non-empty array")
        envelope, resource_links = self._parse_prompt(prompt)
        tool = envelope.get("tool")
        arguments = envelope.get("arguments")
        if not isinstance(tool, str) or not tool or len(tool) > 256:
            raise ACPShimError(-32602, "governed action tool is invalid")
        if not isinstance(arguments, dict):
            raise ACPShimError(-32602, "governed action arguments must be an object")
        try:
            grant = DelegationGrant.from_dict(envelope["delegationGrant"])
            proof = AgentActionProof.from_dict(envelope["actionProof"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ACPShimError(-32602, "delegation grant or action proof is invalid") from exc
        if proof.action != tool:
            raise ACPShimError(-32010, "action proof does not name the requested tool")
        issuer_key = self._issuer_resolver(grant.issuer_key_fingerprint)
        if issuer_key is None:
            raise ACPShimError(-32010, "delegation issuer is not trusted")
        try:
            revocations = self._revocation_provider()
        except Exception as exc:
            raise ACPShimError(-32010, "revocation state is unavailable") from exc
        if not isinstance(revocations, RevocationSnapshot):
            raise ACPShimError(-32010, "revocation provider returned invalid state")
        now = self._clock()
        call_payload = acp_action_payload(
            session_id=session.session_id,
            cwd=session.cwd,
            tool=tool,
            arguments=arguments,
            resource_links=resource_links,
        )
        verification = verify_delegated_action(
            grant,
            proof,
            now=now,
            payload=call_payload,
            trusted_issuer_public_key=issuer_key,
            revoked_grant_ids=revocations.revoked_grant_ids,
            revoked_agent_ids=revocations.revoked_agent_ids,
            minimum_revocation_epoch=revocations.epoch,
        )
        if not verification.ok:
            if proof.agent_id in revocations.revoked_agent_ids:
                with self._lock:
                    self._sessions.pop(session.session_id, None)
            raise ACPShimError(-32010, f"delegation denied: {verification.reason}")
        if not self._replay_store.claim(
            action_id=proof.action_id,
            grant_id=grant.grant_id,
            proof_id=proof.proof_id,
            session_id=session.session_id,
            consumed_at=now,
        ):
            raise ACPShimError(-32010, "delegation denied: action id has already been consumed")
        try:
            result = self._backend.call_tool(tool, dict(arguments))
        except Exception as exc:
            self._replay_store.finish(proof.action_id, succeeded=False)
            raise ACPShimError(-32011, "governed backend rejected the action") from exc
        self._replay_store.finish(proof.action_id, succeeded=True)
        with self._lock:
            current_session = self._sessions.get(session.session_id)
            if current_session is not None and current_session.agent_ids is not None:
                current_session.agent_ids.add(proof.agent_id)
        update = {
            "jsonrpc": JSONRPC_VERSION,
            "method": "session/update",
            "params": {
                "sessionId": session.session_id,
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {
                        "type": "text",
                        "text": json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    },
                    "_meta": {
                        "selfconnect": {
                            "grantId": grant.grant_id,
                            "proofId": proof.proof_id,
                            "agentId": proof.agent_id,
                            "authorization": grant.issuer_principal,
                            "authorship": proof.agent_id,
                        }
                    },
                },
            },
        }
        return [update], {"stopReason": "end_turn"}

    def _require_active_auth(self) -> None:
        if self._auth_store is not None and not self._auth_store.has_active_root():
            raise ACPShimError(-32000, "authentication required")

    @staticmethod
    def _parse_prompt(prompt: list[Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        texts: list[str] = []
        links: list[dict[str, Any]] = []
        for block in prompt:
            if not isinstance(block, dict):
                raise ACPShimError(-32602, "prompt content blocks must be objects")
            block_type = block.get("type")
            if block_type == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])
            elif block_type == "resource_link":
                if not isinstance(block.get("name"), str) or not isinstance(block.get("uri"), str):
                    raise ACPShimError(-32602, "resource link requires name and uri")
                links.append(dict(block))
            else:
                raise ACPShimError(-32602, "unsupported prompt content block")
        if len(texts) != 1:
            raise ACPShimError(-32602, "prompt must contain exactly one governed-action text block")
        try:
            envelope = json.loads(texts[0])
        except json.JSONDecodeError as exc:
            raise ACPShimError(-32602, "governed action text must be JSON") from exc
        if not isinstance(envelope, dict) or envelope.get("schema") != ACP_ACTION_SCHEMA:
            raise ACPShimError(-32602, "unsupported governed action schema")
        allowed = {"schema", "tool", "arguments", "delegationGrant", "actionProof"}
        if set(envelope) != allowed:
            raise ACPShimError(-32602, "governed action envelope fields are invalid")
        return envelope, links

    def _cancel(self, params: dict[str, Any]) -> None:
        session = self._get_session(params.get("sessionId"))
        session.cancelled = True

    def _get_session(self, session_id: Any) -> _Session:
        if not isinstance(session_id, str):
            raise ACPShimError(-32602, "sessionId must be a string")
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise ACPShimError(-32001, "unknown session")
        return session

    @staticmethod
    def _response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}


def serve_stdio(
    shim: ACPShim,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> None:
    """Serve newline-delimited ACP JSON-RPC over stdin/stdout.

    Diagnostics must go to stderr; stdout is reserved for protocol messages.
    The loop is synchronous, so ``session/cancel`` marks the next prompt turn
    cancelled but cannot interrupt a backend call already executing.
    """
    source = input_stream or sys.stdin
    sink = output_stream or sys.stdout
    for line in source:
        if len(line.encode("utf-8")) > _MAX_MESSAGE_BYTES:
            messages = [ACPShim._error(None, -32700, "message exceeds maximum size")]
        else:
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                messages = [ACPShim._error(None, -32700, "parse error")]
            else:
                messages = shim.handle(message)
        for response in messages:
            sink.write(json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n")
            sink.flush()


__all__ = [
    "ACP_ACTION_SCHEMA",
    "ACP_PROTOCOL_VERSION",
    "ACPShim",
    "ACPShimError",
    "GovernedActionBackend",
    "GovernedRuntimeBackend",
    "RevocationSnapshot",
    "SQLiteActionReplayStore",
    "acp_action_payload",
    "serve_stdio",
]
