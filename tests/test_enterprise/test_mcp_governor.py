from __future__ import annotations

import io
import json

from enterprise.mcp_governor import (
    LEGACY_VERSION,
    STATELESS_VERSION,
    MCPGovernor,
    serve_stdio,
)


class FakeDispatcher:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if not self.allowed:
            return {"ok": False, "tool": name, "error": "cedar denied"}
        return {"ok": True, "tool": name, "result": {"governed": True}}


def _meta(version=STATELESS_VERSION):
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _request(method, params=None, request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}


def test_stateless_discovery_has_required_2026_shape():
    result = MCPGovernor(FakeDispatcher()).handle(
        _request("server/discover", {"_meta": _meta()})
    )["result"]

    assert result["resultType"] == "complete"
    assert result["supportedVersions"] == [STATELESS_VERSION, LEGACY_VERSION]
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "selfconnect-mcp-governor"
    assert result["cacheScope"] == "public"


def test_stateless_list_requires_metadata_on_every_request():
    governor = MCPGovernor(FakeDispatcher())
    response = governor.handle(_request("tools/list"))
    assert response["error"]["message"] == "initialize must be called first"

    listed = governor.handle(_request("tools/list", {"_meta": _meta()}))["result"]
    assert listed["resultType"] == "complete"
    assert listed["tools"]


def test_stateless_unsupported_version_reports_supported_versions():
    response = MCPGovernor(FakeDispatcher()).handle(
        _request("tools/list", {"_meta": _meta("2099-01-01")})
    )
    assert response["error"]["code"] == -32022
    assert response["error"]["data"]["supported"] == [STATELESS_VERSION, LEGACY_VERSION]


def test_stateless_call_routes_only_through_governed_dispatcher():
    dispatcher = FakeDispatcher()
    response = MCPGovernor(dispatcher).handle(
        _request(
            "tools/call",
            {"_meta": _meta(), "name": "sc_echo_filter", "arguments": {"raw_text": "x", "injected_text": "x"}},
        )
    )
    result = response["result"]
    assert dispatcher.calls == [("sc_echo_filter", {"raw_text": "x", "injected_text": "x"})]
    assert result["structuredContent"] == {"governed": True}
    assert result["isError"] is False
    assert result["resultType"] == "complete"


def test_governance_denial_is_a_tool_result_visible_to_model():
    response = MCPGovernor(FakeDispatcher(allowed=False)).handle(
        _request("tools/call", {"_meta": _meta(), "name": "sc_echo_filter", "arguments": {}})
    )
    assert response["result"]["isError"] is True
    assert response["result"]["structuredContent"] == {"error": "cedar denied"}


def test_unknown_tool_is_protocol_error_and_never_dispatched():
    dispatcher = FakeDispatcher()
    response = MCPGovernor(dispatcher).handle(
        _request("tools/call", {"_meta": _meta(), "name": "evil", "arguments": {}})
    )
    assert response["error"]["code"] == -32602
    assert dispatcher.calls == []


def test_legacy_initialize_then_list_and_call():
    governor = MCPGovernor(FakeDispatcher())
    initialized = governor.handle(
        _request(
            "initialize",
            {
                "protocolVersion": LEGACY_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "1"},
            },
        )
    )
    assert initialized["result"]["protocolVersion"] == LEGACY_VERSION
    assert governor.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    ) is None
    assert governor.handle(_request("tools/list"))["result"]["tools"]


def test_initialize_rejects_stateless_revision():
    response = MCPGovernor(FakeDispatcher()).handle(
        _request(
            "initialize",
            {
                "protocolVersion": STATELESS_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "wrong", "version": "1"},
            },
        )
    )
    assert response["error"]["code"] == -32022


def test_stdio_is_newline_json_and_parse_errors_are_bounded():
    source = io.StringIO(
        "not-json\n"
        + json.dumps(_request("server/discover", {"_meta": _meta()}, request_id="d"))
        + "\n"
    )
    sink = io.StringIO()
    serve_stdio(MCPGovernor(FakeDispatcher()), input_stream=source, output_stream=sink)
    rows = [json.loads(line) for line in sink.getvalue().splitlines()]
    assert rows[0]["error"]["code"] == -32700
    assert rows[1]["id"] == "d"


def test_invalid_notification_emits_no_response():
    governor = MCPGovernor(FakeDispatcher())
    assert governor.handle({"jsonrpc": "2.0", "method": "bad", "params": []}) is None
