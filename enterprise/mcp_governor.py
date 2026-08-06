"""Dual-era MCP protocol wrapper for the governed SelfConnect dispatcher."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from enterprise.mcp_tools import get_tool, get_tool_registry

JSONRPC_VERSION = "2.0"
LEGACY_VERSION = "2025-11-25"
STATELESS_VERSION = "2026-07-28"
SUPPORTED_VERSIONS = (STATELESS_VERSION, LEGACY_VERSION)
MAX_MESSAGE_BYTES = 1_048_576


class DispatcherProtocol(Protocol):
    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class MCPGovernorError(Exception):
    code: int
    message: str
    data: Any = None


class MCPGovernor:
    """Expose only governed SelfConnect tools over MCP JSON-RPC.

    Legacy connections negotiate once with ``initialize``. The 2026-07-28
    path is stateless and validates protocol metadata on every request.
    """

    def __init__(self, dispatcher: DispatcherProtocol) -> None:
        if not callable(getattr(dispatcher, "call_tool", None)):
            raise TypeError("dispatcher must provide call_tool()")
        self._dispatcher = dispatcher
        self._legacy_initialized = False

    def handle(self, message: Any) -> dict[str, Any] | None:
        request_id = message.get("id") if isinstance(message, dict) else None
        try:
            method, params = self._validate_message(message)
            if method == "notifications/initialized":
                if not self._legacy_initialized:
                    raise MCPGovernorError(-32000, "initialize must be called first")
                return None
            if "id" not in message:
                return None
            result = self._dispatch(method, params)
            return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}
        except MCPGovernorError as exc:
            if isinstance(message, dict) and "id" not in message:
                return None
            error: dict[str, Any] = {"code": exc.code, "message": exc.message}
            if exc.data is not None:
                error["data"] = exc.data
            return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}
        except Exception:  # noqa: BLE001 - never expose internal policy/runtime details
            if isinstance(message, dict) and "id" not in message:
                return None
            return {
                "jsonrpc": JSONRPC_VERSION,
                "id": request_id,
                "error": {"code": -32603, "message": "internal error"},
            }

    def _validate_message(self, message: Any) -> tuple[str, dict[str, Any]]:
        if not isinstance(message, dict):
            raise MCPGovernorError(-32600, "invalid request")
        if message.get("jsonrpc") != JSONRPC_VERSION or not isinstance(message.get("method"), str):
            raise MCPGovernorError(-32600, "invalid request")
        if set(message) - {"jsonrpc", "id", "method", "params"}:
            raise MCPGovernorError(-32600, "invalid request")
        params = message.get("params", {})
        if not isinstance(params, dict):
            raise MCPGovernorError(-32602, "params must be an object")
        return message["method"], params

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return self._initialize(params)
        if method == "server/discover":
            self._require_stateless_meta(params)
            return self._discovery()

        stateless = self._is_stateless(params)
        if stateless:
            self._require_stateless_meta(params)
        elif not self._legacy_initialized:
            raise MCPGovernorError(-32000, "initialize must be called first")

        if method == "tools/list":
            self._validate_list_params(params, stateless=stateless)
            result: dict[str, Any] = {"tools": get_tool_registry()}
            if stateless:
                result.update({"resultType": "complete", "ttlMs": 300_000, "cacheScope": "public"})
            return result
        if method == "tools/call":
            return self._call_tool(params, stateless=stateless)
        raise MCPGovernorError(-32601, "method not found")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        if set(params) - {"protocolVersion", "capabilities", "clientInfo", "_meta"}:
            raise MCPGovernorError(-32602, "invalid initialize parameters")
        version = params.get("protocolVersion")
        capabilities = params.get("capabilities")
        client_info = params.get("clientInfo")
        if not isinstance(version, str) or not isinstance(capabilities, dict):
            raise MCPGovernorError(-32602, "invalid initialize parameters")
        if not self._valid_implementation(client_info):
            raise MCPGovernorError(-32602, "invalid clientInfo")
        if version == STATELESS_VERSION:
            raise MCPGovernorError(
                -32022,
                "initialize is not used by the stateless protocol",
                {"supported": list(SUPPORTED_VERSIONS), "requested": version},
            )
        self._legacy_initialized = True
        return {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": self._capabilities(),
            "serverInfo": self._server_info(),
            "instructions": self._instructions(),
        }

    def _discovery(self) -> dict[str, Any]:
        return {
            "resultType": "complete",
            "supportedVersions": list(SUPPORTED_VERSIONS),
            "capabilities": self._capabilities(),
            "_meta": {"io.modelcontextprotocol/serverInfo": self._server_info()},
            "instructions": self._instructions(),
            "ttlMs": 300_000,
            "cacheScope": "public",
        }

    @staticmethod
    def _capabilities() -> dict[str, Any]:
        return {"tools": {"listChanged": False}}

    @staticmethod
    def _server_info() -> dict[str, str]:
        return {"name": "selfconnect-mcp-governor", "version": "1.0.0"}

    @staticmethod
    def _instructions() -> str:
        return (
            "SelfConnect governed execution. Tool calls remain subject to signed policy, "
            "Cedar when configured, approval, revocation, target validation, and audit."
        )

    @staticmethod
    def _valid_implementation(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and isinstance(value.get("name"), str)
            and bool(value["name"])
            and isinstance(value.get("version"), str)
            and bool(value["version"])
        )

    @staticmethod
    def _is_stateless(params: dict[str, Any]) -> bool:
        meta = params.get("_meta")
        return isinstance(meta, dict) and "io.modelcontextprotocol/protocolVersion" in meta

    @staticmethod
    def _require_stateless_meta(params: dict[str, Any]) -> None:
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            raise MCPGovernorError(-32602, "stateless requests require _meta")
        requested = meta.get("io.modelcontextprotocol/protocolVersion")
        if requested != STATELESS_VERSION:
            raise MCPGovernorError(
                -32022,
                "unsupported protocol version",
                {"supported": list(SUPPORTED_VERSIONS), "requested": requested},
            )
        if not isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict):
            raise MCPGovernorError(-32602, "clientCapabilities must be an object")
        client_info = meta.get("io.modelcontextprotocol/clientInfo")
        if client_info is not None and not MCPGovernor._valid_implementation(client_info):
            raise MCPGovernorError(-32602, "invalid clientInfo")

    @staticmethod
    def _validate_list_params(params: dict[str, Any], *, stateless: bool) -> None:
        allowed = {"_meta", "cursor"} if stateless else {"_meta", "cursor"}
        if set(params) - allowed or params.get("cursor") is not None:
            raise MCPGovernorError(-32602, "pagination is not supported")

    def _call_tool(self, params: dict[str, Any], *, stateless: bool) -> dict[str, Any]:
        allowed = {"name", "arguments", "_meta"}
        if set(params) - allowed:
            raise MCPGovernorError(-32602, "invalid tool call parameters")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise MCPGovernorError(-32602, "invalid tool call parameters")
        try:
            get_tool(name)
        except KeyError as exc:
            raise MCPGovernorError(-32602, "unknown tool") from exc
        outcome = self._dispatcher.call_tool(name, arguments)
        if not isinstance(outcome, dict):
            raise MCPGovernorError(-32603, "dispatcher returned an invalid result")
        ok = outcome.get("ok") is True
        payload: Any = outcome.get("result") if ok else {"error": str(outcome.get("error", "tool denied"))}
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        result = {
            "content": [{"type": "text", "text": serialized}],
            "structuredContent": payload,
            "isError": not ok,
        }
        if stateless:
            result["resultType"] = "complete"
        return result


def serve_stdio(
    governor: MCPGovernor,
    *,
    input_stream: TextIO,
    output_stream: TextIO,
) -> None:
    """Serve newline-delimited JSON-RPC without writing protocol data to stderr."""
    for raw_line in input_stream:
        if len(raw_line.encode("utf-8")) > MAX_MESSAGE_BYTES:
            response = _parse_error("message exceeds size limit")
        else:
            try:
                message = json.loads(raw_line)
            except (json.JSONDecodeError, UnicodeError):
                response = _parse_error("parse error")
            else:
                response = governor.handle(message)
        if response is not None:
            output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
            output_stream.flush()


def _parse_error(message: str) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": None, "error": {"code": -32700, "message": message}}


__all__ = [
    "LEGACY_VERSION",
    "MCPGovernor",
    "MCPGovernorError",
    "STATELESS_VERSION",
    "SUPPORTED_VERSIONS",
    "serve_stdio",
]
