"""Tests for enterprise/mcp_tools.py — MCP tool registry."""
from __future__ import annotations

import pytest

from enterprise.mcp_tools import TOOL_COUNT, get_tool, get_tool_registry


class TestToolRegistry:
    def test_registry_returns_list(self):
        tools = get_tool_registry()
        assert isinstance(tools, list)

    def test_tool_count_at_least_20(self):
        assert TOOL_COUNT >= 20, f"Expected >= 20 tools, got {TOOL_COUNT}"

    def test_all_tools_have_required_fields(self):
        for tool in get_tool_registry():
            assert "name" in tool, f"Tool missing 'name': {tool}"
            assert "description" in tool, f"Tool {tool.get('name')} missing 'description'"
            assert "inputSchema" in tool, f"Tool {tool.get('name')} missing 'inputSchema'"

    def test_tool_names_are_unique(self):
        names = [t["name"] for t in get_tool_registry()]
        assert len(names) == len(set(names)), "Duplicate tool names found"

    def test_tool_names_are_strings(self):
        for tool in get_tool_registry():
            assert isinstance(tool["name"], str)
            assert len(tool["name"]) > 0

    def test_descriptions_are_non_empty(self):
        for tool in get_tool_registry():
            assert isinstance(tool["description"], str)
            assert len(tool["description"]) >= 20, f"Tool {tool['name']} description too short"


class TestToolSchemas:
    def test_all_schemas_are_objects(self):
        for tool in get_tool_registry():
            schema = tool["inputSchema"]
            assert isinstance(schema, dict), f"Tool {tool['name']} inputSchema is not a dict"
            assert schema.get("type") == "object", f"Tool {tool['name']} inputSchema type must be 'object'"

    def test_required_fields_listed_in_properties(self):
        for tool in get_tool_registry():
            schema = tool["inputSchema"]
            required = schema.get("required", [])
            props = schema.get("properties", {})
            for req_field in required:
                assert req_field in props, (
                    f"Tool {tool['name']}: required field {req_field!r} not in properties"
                )

    def test_property_types_are_valid(self):
        valid_types = {"string", "integer", "number", "boolean", "array", "object"}
        for tool in get_tool_registry():
            for prop_name, prop_def in tool["inputSchema"].get("properties", {}).items():
                if "type" in prop_def:
                    assert prop_def["type"] in valid_types, (
                        f"Tool {tool['name']}.{prop_name}: invalid type {prop_def['type']!r}"
                    )

    def test_all_schemas_block_additional_properties(self):
        """Every tool schema must set additionalProperties=False to prevent unknown field injection."""
        for tool in get_tool_registry():
            schema = tool["inputSchema"]
            assert schema.get("additionalProperties") is False, (
                f"Tool {tool['name']} inputSchema missing additionalProperties=False"
            )


class TestGetTool:
    def test_get_existing_tool(self):
        tool = get_tool("sc_inject_text")
        assert tool["name"] == "sc_inject_text"

    def test_get_unknown_tool_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown MCP tool"):
            get_tool("nonexistent_tool_xyz")

    def test_get_tool_returns_equal_content_to_registry(self):
        """get_tool() and get_tool_registry() must return equal content (both are deep copies)."""
        registry = {t["name"]: t for t in get_tool_registry()}
        for name in registry:
            assert get_tool(name) == registry[name], (
                f"get_tool({name!r}) content differs from registry entry"
            )

    def test_get_tool_returns_independent_copy(self):
        """Mutating the returned dict must not affect the live registry (thread-safety fix)."""
        tool1 = get_tool("sc_inject_text")
        tool1["inputSchema"]["properties"]["text"]["maxLength"] = 1  # mutate
        tool2 = get_tool("sc_inject_text")
        assert tool2["inputSchema"]["properties"]["text"]["maxLength"] != 1, (
            "get_tool() returned a shared mutable reference — registry is corruptible"
        )

    def test_get_tool_registry_returns_independent_copies(self):
        """Mutating a registry list entry must not affect a subsequent call (thread-safety fix)."""
        reg1 = get_tool_registry()
        reg1[0]["inputSchema"]["properties"] = {}  # mutate
        reg2 = get_tool_registry()
        # The first tool (sc_inject_text) must still have its properties intact
        assert "text" in reg2[0]["inputSchema"]["properties"], (
            "get_tool_registry() returned shared mutable dicts — registry is corruptible"
        )


class TestGovernanceCoverage:
    """Verify governance-critical tool families are present."""

    def test_lease_management_tools_exist(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_request_lease" in names
        assert "sc_revoke_lease" in names
        assert "sc_list_leases" in names

    def test_identity_tools_exist(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_identity_sign" in names
        assert "sc_identity_verify" in names

    def test_audit_tools_exist(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_audit_tail" in names
        assert "sc_audit_search" in names

    def test_guard_tools_exist(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_verify_target" in names
        assert "sc_target_guard_check" in names

    def test_injection_tool_requires_lease(self):
        tool = get_tool("sc_inject_text")
        required = tool["inputSchema"].get("required", [])
        assert "lease_id" in required, "sc_inject_text must require lease_id"

    def test_channel_route_tool_exists(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_channel_route" in names

    def test_echo_filter_tool_exists(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_echo_filter" in names

    def test_receipt_verify_tool_exists(self):
        names = {t["name"] for t in get_tool_registry()}
        assert "sc_receipt_verify" in names


class TestSecurityConstraints:
    """Security-critical schema constraint tests — each covers a specific WRAITH finding."""

    # CRITICAL: FAIL-OPEN — sc_receipt_verify must require expected_agent_pub_b64
    def test_receipt_verify_requires_pub_key(self):
        """Omitting expected_agent_pub_b64 must be a schema violation, not a silent sig skip."""
        tool = get_tool("sc_receipt_verify")
        required = tool["inputSchema"].get("required", [])
        assert "expected_agent_pub_b64" in required, (
            "sc_receipt_verify must require expected_agent_pub_b64 — "
            "optional key = fail-open signature verification"
        )

    # CRITICAL: INJECTION — sc_pipe_ping must restrict pipe_name to local pipes
    def test_pipe_ping_pipe_name_has_pattern(self):
        """pipe_name must carry a pattern constraint to block remote UNC paths."""
        tool = get_tool("sc_pipe_ping")
        prop = tool["inputSchema"]["properties"]["pipe_name"]
        assert "pattern" in prop, (
            "sc_pipe_ping.pipe_name missing pattern — "
            "attacker can supply \\\\evil-host\\pipe\\sc-control (remote UNC bypass)"
        )
        assert "maxLength" in prop, "sc_pipe_ping.pipe_name missing maxLength"

    def test_pipe_ping_timeout_has_maximum(self):
        """timeout_ms must have a maximum to prevent DoS via huge timeout values."""
        tool = get_tool("sc_pipe_ping")
        prop = tool["inputSchema"]["properties"]["timeout_ms"]
        assert "maximum" in prop, "sc_pipe_ping.timeout_ms missing maximum"

    # CRITICAL: MISSING VALIDATION — sc_inject_text.text must have maxLength
    def test_inject_text_text_has_max_length(self):
        """text must enforce the documented 65535-char ceiling in the schema, not just description."""
        tool = get_tool("sc_inject_text")
        prop = tool["inputSchema"]["properties"]["text"]
        assert "maxLength" in prop, (
            "sc_inject_text.text missing maxLength — description says 65535 but schema does not enforce it"
        )
        assert prop["maxLength"] == 65535

    # HIGH: IDENTITY BYPASS — sc_request_lease must require agent_id
    def test_request_lease_requires_agent_id(self):
        """Leases without agent_id cannot be audited — agent_id must be required."""
        tool = get_tool("sc_request_lease")
        required = tool["inputSchema"].get("required", [])
        assert "agent_id" in required, (
            "sc_request_lease must require agent_id — "
            "optional agent_id allows unauthenticated/unauditable lease requests"
        )

    def test_target_metadata_does_not_claim_unverified_bindings(self):
        lease = get_tool("sc_request_lease")
        guard = get_tool("sc_target_guard_check")
        verify = get_tool("sc_verify_target")
        stamp = get_tool("sc_session_stamp")

        assert "SID" not in lease["description"]
        assert "birth" not in lease["description"].lower()
        assert "generation" not in lease["description"].lower()
        assert set(guard["inputSchema"]["properties"]) == {"hwnd"}
        assert "title" not in verify["description"].lower()
        assert "process-identity verification" in stamp["description"]

    # HIGH: MISSING VALIDATION — sc_audit_search.limit must have a maximum
    def test_audit_search_limit_has_maximum(self):
        """Unbounded limit allows an attacker to dump the entire audit log."""
        tool = get_tool("sc_audit_search")
        prop = tool["inputSchema"]["properties"]["limit"]
        assert "maximum" in prop, (
            "sc_audit_search.limit missing maximum — "
            "attacker can request limit=99999999 to dump the audit log"
        )
        assert prop["maximum"] <= 1000, (
            f"sc_audit_search.limit maximum={prop['maximum']} is too large (must be <=1000)"
        )

    # HIGH: MISSING VALIDATION — timestamp fields must have pattern
    def test_audit_search_timestamps_have_pattern(self):
        """since_iso and until_iso must have pattern constraints to prevent injection."""
        tool = get_tool("sc_audit_search")
        for field in ("since_iso", "until_iso"):
            prop = tool["inputSchema"]["properties"][field]
            assert "pattern" in prop, (
                f"sc_audit_search.{field} missing pattern — "
                "unvalidated timestamp string can carry injection payloads"
            )
            assert "maxLength" in prop, f"sc_audit_search.{field} missing maxLength"

    # HIGH: MISSING VALIDATION — crypto fields must have pattern and maxLength
    def test_identity_verify_crypto_fields_constrained(self):
        """payload_hex, signature_b64, public_key_b64 must have maxLength and pattern."""
        tool = get_tool("sc_identity_verify")
        for field in ("payload_hex", "signature_b64", "public_key_b64"):
            prop = tool["inputSchema"]["properties"][field]
            assert "maxLength" in prop, (
                f"sc_identity_verify.{field} missing maxLength — "
                "multi-MB input can OOM the crypto layer"
            )
            assert "pattern" in prop, (
                f"sc_identity_verify.{field} missing pattern — "
                "non-hex/base64 input bypasses format assumptions in the crypto layer"
            )

    def test_identity_sign_payload_hex_constrained(self):
        """payload_hex on sc_identity_sign must have maxLength and hex pattern."""
        tool = get_tool("sc_identity_sign")
        prop = tool["inputSchema"]["properties"]["payload_hex"]
        assert "maxLength" in prop, "sc_identity_sign.payload_hex missing maxLength"
        assert "pattern" in prop, "sc_identity_sign.payload_hex missing pattern"

    # HIGH: THREAD SAFETY — lease_id fields across all tools must be bounded
    def test_lease_id_fields_are_bounded(self):
        """All lease_id properties must have maxLength and pattern to prevent oversized inputs."""
        lease_id_tools = [
            "sc_inject_text", "sc_read_output", "sc_revoke_lease",
            "sc_get_lease_info",
        ]
        for tool_name in lease_id_tools:
            tool = get_tool(tool_name)
            prop = tool["inputSchema"]["properties"].get("lease_id")
            assert prop is not None, f"{tool_name} has no lease_id property"
            assert "maxLength" in prop, f"{tool_name}.lease_id missing maxLength"
            assert "pattern" in prop, f"{tool_name}.lease_id missing pattern"

    def test_hwnd_fields_have_maximum(self):
        """All hwnd / target_hwnd integer fields must have a maximum (Win32 HWND ceiling)."""
        hwnd_fields = {
            "sc_inject_text": "hwnd",
            "sc_read_output": "hwnd",
            "sc_verify_target": "hwnd",
            "sc_request_lease": "hwnd",
            "sc_target_guard_check": "hwnd",
            "sc_session_stamp": "hwnd",
            "sc_channel_route": "hwnd",
            "sc_audit_search": "hwnd",
            "sc_policy_check": "target_hwnd",
        }
        for tool_name, field in hwnd_fields.items():
            tool = get_tool(tool_name)
            prop = tool["inputSchema"]["properties"].get(field)
            assert prop is not None, f"{tool_name} has no {field!r} property"
            assert "maximum" in prop, (
                f"{tool_name}.{field} missing maximum — "
                "attacker can supply arbitrarily large HWND values"
            )
