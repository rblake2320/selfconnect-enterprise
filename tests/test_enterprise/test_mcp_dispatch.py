"""Tests for enterprise.mcp_dispatch — runtime execution for MCP tools."""
from __future__ import annotations

import json
from types import SimpleNamespace

from enterprise.cli import main
from enterprise.mcp_dispatch import MCPDispatcher, SchemaValidator
from enterprise.mcp_tools import get_tool_registry


class FakeRouter:
    def __init__(self) -> None:
        self.routes: list[tuple[int, str, str | None]] = []
        self.classified: list[int] = []

    def classify(self, hwnd: int):
        self.classified.append(hwnd)
        return SimpleNamespace(
            hwnd=hwnd,
            channel="wm_char",
            window_class="CASCADIA_HOSTING_WINDOW_CLASS",
            window_title="Fake Terminal",
            pid=4242,
            reason="fake terminal",
            timestamp=1000.0,
        )

    def route(self, hwnd: int, text: str, lease_id: str | None = None):
        self.routes.append((hwnd, text, lease_id))
        return SimpleNamespace(
            receipt_id="receipt-1",
            hwnd=hwnd,
            channel="wm_char",
            payload_hash="payload-hash",
            readback_hash="",
            timestamp=1001.0,
            success=True,
        )


def make_dispatcher(now_value: float = 1000.0) -> MCPDispatcher:
    return MCPDispatcher(router=FakeRouter(), now=lambda: now_value)


def issue_lease(dispatcher: MCPDispatcher, *, hwnd: int = 1234, agent_id: str = "SC-AGENT") -> str:
    result = dispatcher.call_tool(
        "sc_request_lease",
        {"hwnd": hwnd, "role": "sender", "agent_id": agent_id, "ttl_seconds": 300},
    )
    assert result["ok"], result
    return result["result"]["lease_id"]


class TestDispatcherCoverage:
    def test_default_profile_is_enterprise(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_echo_filter", {"raw_text": "hello", "injected_text": "hello"})
        assert result["result"]["profile"] == "enterprise"

    def test_invalid_profile_rejected(self):
        try:
            MCPDispatcher(profile="made-up")
        except ValueError as exc:
            assert "profile" in str(exc)
        else:
            raise AssertionError("invalid profile was accepted")

    def test_every_registered_tool_has_runtime_handler(self):
        dispatcher = make_dispatcher()
        registered = {tool["name"] for tool in get_tool_registry()}
        assert registered == set(dispatcher._handlers)

    def test_unknown_tool_fails_closed(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_not_a_real_tool", {})
        assert result["ok"] is False
        assert "Unknown MCP tool" in result["error"]

    def test_dispatcher_records_audit_for_failure(self):
        dispatcher = make_dispatcher()
        dispatcher.call_tool("sc_not_a_real_tool", {})
        events = dispatcher.audit_events()
        assert len(events) == 1
        assert events[0].ok is False

    def test_dispatcher_records_audit_for_success(self):
        dispatcher = make_dispatcher()
        issue_lease(dispatcher)
        events = dispatcher.audit_events()
        assert len(events) == 1
        assert events[0].ok is True
        assert events[0].tool == "sc_request_lease"


class TestSchemaValidation:
    def test_missing_required_field_is_denied(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_request_lease", {"hwnd": 1001, "role": "sender"})
        assert result["ok"] is False
        assert "missing required field: agent_id" in result["error"]

    def test_unknown_field_is_denied(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_request_lease",
            {"hwnd": 1001, "role": "sender", "agent_id": "SC-A", "surprise": True},
        )
        assert result["ok"] is False
        assert "unknown field" in result["error"]

    def test_integer_maximum_is_enforced(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_channel_route", {"hwnd": 0xFFFFFFFF})
        assert result["ok"] is False
        assert "maximum" in result["error"]

    def test_pattern_is_enforced(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_pipe_ping", {"pipe_name": r"\\evil\pipe\sc"})
        assert result["ok"] is False
        assert "pattern" in result["error"]

    def test_local_named_pipe_path_passes_schema_validation(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_pipe_ping",
            {"pipe_name": r"\\.\pipe\SelfConnectEnterprise"},
        )
        assert result["ok"] is True
        assert result["result"]["available"] in (True, False)

    def test_validator_rejects_non_object_arguments(self):
        validator = SchemaValidator()
        try:
            validator.validate("sc_audit_tail", ["not", "object"])  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            assert "JSON object" in str(exc)
        else:
            raise AssertionError("validator accepted non-object arguments")


class TestLeaseRuntime:
    def test_request_lease_returns_active_lease(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=777)
        result = dispatcher.call_tool("sc_get_lease_info", {"lease_id": lease_id})
        assert result["ok"] is True
        assert result["result"]["hwnd"] == 777
        assert result["result"]["active"] is True

    def test_list_leases_filters_by_agent(self):
        dispatcher = make_dispatcher()
        issue_lease(dispatcher, agent_id="SC-A")
        issue_lease(dispatcher, agent_id="SC-B")
        result = dispatcher.call_tool("sc_list_leases", {"filter_agent_id": "SC-A"})
        assert result["ok"] is True
        assert result["result"]["count"] == 1
        assert result["result"]["leases"][0]["agent_id"] == "SC-A"

    def test_revoke_lease_prevents_injection(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=888)
        revoked = dispatcher.call_tool("sc_revoke_lease", {"lease_id": lease_id})
        assert revoked["ok"] is True
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 888, "text": "hello"},
        )
        assert result["ok"] is False
        assert "expired or revoked" in result["error"]

    def test_inject_requires_existing_lease(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": "lease-missing", "hwnd": 888, "text": "hello"},
        )
        assert result["ok"] is False
        assert "not found" in result["error"]

    def test_inject_rejects_wrong_hwnd_for_lease(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=1001)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1002, "text": "hello"},
        )
        assert result["ok"] is False
        assert "not bound" in result["error"]

    def test_inject_calls_router_with_lease_id(self):
        router = FakeRouter()
        dispatcher = MCPDispatcher(router=router, now=lambda: 1000.0)
        lease_id = issue_lease(dispatcher, hwnd=1010)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1010, "text": "hello"},
        )
        assert result["ok"] is True
        assert router.routes == [(1010, "hello", lease_id)]

    def test_read_output_is_lease_gated(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_read_output",
            {"lease_id": "missing", "hwnd": 1},
        )
        assert result["ok"] is False
        assert "not found" in result["error"]


class TestRuntimeTools:
    def test_channel_route_delegates_to_router(self):
        router = FakeRouter()
        dispatcher = MCPDispatcher(router=router)
        result = dispatcher.call_tool("sc_channel_route", {"hwnd": 2020})
        assert result["ok"] is True
        assert result["result"]["channel"] == "wm_char"
        assert router.classified == [2020]

    def test_echo_filter_removes_injected_text(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_echo_filter",
            {"raw_text": "SC_PROBE_1 hello real output", "injected_text": "hello", "probe_token": "SC_PROBE_1"},
        )
        assert result["ok"] is True
        assert result["result"]["clean_text"] == "real output"
        assert result["result"]["classification"] == "mixed_echo_and_output"

    def test_identity_sign_verify_roundtrip(self):
        dispatcher = make_dispatcher()
        signed = dispatcher.call_tool("sc_identity_sign", {"payload_hex": "aabbcc"})
        assert signed["ok"] is True
        verified = dispatcher.call_tool(
            "sc_identity_verify",
            {
                "payload_hex": "aabbcc",
                "signature_b64": signed["result"]["signature_b64"],
                "public_key_b64": signed["result"]["public_key_b64"],
                "algorithm": "Ed25519",
            },
        )
        assert verified["ok"] is True
        assert verified["result"]["verified"] is True

    def test_identity_verify_wrong_payload_fails(self):
        dispatcher = make_dispatcher()
        signed = dispatcher.call_tool("sc_identity_sign", {"payload_hex": "aabbcc"})
        verified = dispatcher.call_tool(
            "sc_identity_verify",
            {
                "payload_hex": "ddeeff",
                "signature_b64": signed["result"]["signature_b64"],
                "public_key_b64": signed["result"]["public_key_b64"],
                "algorithm": "Ed25519",
            },
        )
        assert verified["ok"] is True
        assert verified["result"]["verified"] is False

    def test_receipt_verify_refuses_unsigned_receipt(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_receipt_verify",
            {
                "receipt_json": json.dumps({"payload_hex": "aabbcc"}),
                "expected_agent_pub_b64": "A" * 44,
            },
        )
        assert result["ok"] is True
        assert result["result"]["verified"] is False
        assert "missing" in result["result"]["reason"]

    def test_session_stamp_returns_hash_without_tpm(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_session_stamp", {"hwnd": 4444})
        assert result["ok"] is True
        assert result["result"]["provider"] == "software"
        assert result["result"]["stamp_hash"]

    def test_tpm_session_stamp_includes_tpm_info(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_session_stamp", {"hwnd": 4444, "use_tpm": True})
        assert result["ok"] is True
        # The stamp always returns hwnd, birth_id, timestamp, provider, tpm, stamp_hash.
        assert result["result"]["hwnd"] == 4444
        assert "tpm" in result["result"]
        assert "provider" in result["result"]
        assert "stamp_hash" in result["result"]

    def test_government_profile_requires_tpm_signing(self):
        dispatcher = MCPDispatcher(profile="government", router=FakeRouter())
        result = dispatcher.call_tool("sc_identity_sign", {"payload_hex": "aabbcc"})
        assert result["ok"] is False
        assert "requires TPM-backed identity" in result["error"]

    def test_government_profile_requires_tpm_session_stamp(self):
        dispatcher = MCPDispatcher(profile="government", router=FakeRouter())
        result = dispatcher.call_tool("sc_session_stamp", {"hwnd": 4444})
        assert result["ok"] is False
        assert "requires TPM-backed session" in result["error"]

    def test_normal_profile_does_not_remove_lease_gate_from_enterprise_mcp(self):
        dispatcher = MCPDispatcher(profile="normal", router=FakeRouter())
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": "missing", "hwnd": 999, "text": "daily-use should use normal SDK"},
        )
        assert result["ok"] is False
        assert "not found" in result["error"]

    def test_policy_check_obeys_control_plane_state(self):
        dispatcher = make_dispatcher()
        dispatcher._control.register("SC-A")
        allowed = dispatcher.call_tool(
            "sc_policy_check",
            {"action_type": "read", "agent_id": "SC-A", "target_hwnd": 1},
        )
        assert allowed["result"]["allowed"] is True
        assert allowed["result"]["governance_profile"] == "enterprise"
        dispatcher._control.pause("SC-A", "operator", "test")
        denied = dispatcher.call_tool(
            "sc_policy_check",
            {"action_type": "read", "agent_id": "SC-A", "target_hwnd": 1},
        )
        assert denied["result"]["allowed"] is False

    def test_audit_tail_returns_recent_events(self):
        dispatcher = make_dispatcher()
        issue_lease(dispatcher)
        tail = dispatcher.call_tool("sc_audit_tail", {"n": 1})
        assert tail["ok"] is True
        assert tail["result"]["count"] == 1
        assert tail["result"]["events"][0]["tool"] == "sc_request_lease"

    def test_audit_search_filters_agent(self):
        dispatcher = make_dispatcher()
        issue_lease(dispatcher, agent_id="SC-ONE")
        issue_lease(dispatcher, agent_id="SC-TWO")
        result = dispatcher.call_tool("sc_audit_search", {"agent_id": "SC-ONE", "limit": 10})
        assert result["ok"] is True
        assert result["result"]["count"] == 1
        assert result["result"]["events"][0]["agent_id"] == "SC-ONE"

    def test_mesh_peers_returns_list(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_mesh_peers", {})
        assert result["ok"] is True
        assert isinstance(result["result"]["peers"], list)

    def test_channel_status_returns_health_keys(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool("sc_channel_status", {"check_etw": False})
        assert result["ok"] is True
        assert {"wm_char", "uia", "etw", "pipe"} <= set(result["result"])
        assert result["result"]["etw"] == "SKIPPED"


class TestCliMcpCall:
    def test_cli_mcp_call_executes_echo_filter(self, capsys):
        code = main(
            [
                "mcp-call",
                "sc_echo_filter",
                "--args-json",
                json.dumps({"raw_text": "hello world", "injected_text": "hello"}),
            ]
        )
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert code == 0
        assert payload["ok"] is True
        assert payload["result"]["clean_text"] == "world"

    def test_cli_mcp_call_rejects_bad_json(self, capsys):
        code = main(["mcp-call", "sc_echo_filter", "--args-json", "{bad"])
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert payload["ok"] is False
