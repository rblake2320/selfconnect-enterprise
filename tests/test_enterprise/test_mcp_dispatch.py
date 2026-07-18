"""Tests for enterprise.mcp_dispatch — runtime execution for MCP tools."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from enterprise.cli import main
from enterprise.mcp_dispatch import MCPDispatcher, SchemaValidator
from enterprise.mcp_tools import get_tool_registry
from enterprise.operator import OperatorQueue
from enterprise.policy import PolicyDecision


class FakeRouter:
    def __init__(self) -> None:
        self.routes: list[tuple[int, str, str | None]] = []
        self.classified: list[int] = []
        self.rendered = "fake terminal output"
        self.route_success = True
        self.bindings = []

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

    def route(
        self,
        hwnd: int,
        text: str,
        lease_id: str | None = None,
        *,
        expected_binding=None,
    ):
        self.routes.append((hwnd, text, lease_id))
        self.bindings.append(expected_binding)
        if self.route_success:
            self.rendered += text
        return SimpleNamespace(
            receipt_id="receipt-1",
            hwnd=hwnd,
            channel="wm_char",
            payload_hash="payload-hash",
            readback_hash="",
            timestamp=1001.0,
            success=self.route_success,
        )


class RecordingLedger:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, action: str, result: str = "", metadata: dict | None = None, **_kwargs):
        entry = {"action": action, "result": result, "metadata": metadata or {}}
        self.entries.append(entry)
        return entry


class AllowPolicyEnforcer:
    def __init__(self, *, allowed: bool = True, requires_approval: bool = False) -> None:
        self.allowed = allowed
        self.requires_approval = requires_approval

    def check(self, agent_id: str, action: str, **kwargs) -> PolicyDecision:
        return PolicyDecision(
            allowed=self.allowed,
            reason="test policy decision",
            requires_approval=self.requires_approval,
            policy_id="policy-test",
            classification=kwargs.get("classification", "UNCLASSIFIED"),
            approval_mode="human_approved" if self.requires_approval else "autonomous",
            agent_id=agent_id,
            action=action,
        )


def verified_target(hwnd: int, **kwargs) -> dict:
    target = {
        "hwnd": hwnd,
        "valid": True,
        "ok": True,
        "reasons": [],
        "pid": 4242,
        "exe": "WindowsTerminal.exe",
        "exe_path": (
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_test"
            r"\WindowsTerminal.exe"
        ),
        "class": "CASCADIA_HOSTING_WINDOW_CLASS",
        "title": "Fake Terminal",
        "is_terminal": True,
    }
    comparisons = {
        "expect_pid": "pid",
        "expect_exe": "exe",
        "expect_exe_path": "exe_path",
        "expect_class": "class",
        "expect_title_sha256": "title_sha256",
    }
    target["title_sha256"] = hashlib.sha256(target["title"].encode("utf-8")).hexdigest()
    for expected_key, target_key in comparisons.items():
        expected = kwargs.get(expected_key)
        if expected is not None and target[target_key] != expected:
            target["ok"] = False
            target["reasons"].append(f"{target_key} changed")
    return target

def make_dispatcher(now_value: float = 1000.0, *, profile: str = "normal") -> MCPDispatcher:
    router = FakeRouter()
    return MCPDispatcher(
        profile=profile,
        router=router,
        ledger=RecordingLedger(),
        policy_enforcer=AllowPolicyEnforcer(),
        operator_queue=OperatorQueue(),
        target_verifier=verified_target,
        output_reader=lambda _hwnd: router.rendered,
        identity_type="dpapi",
        now=lambda: now_value,
    )


def issue_lease(
    dispatcher: MCPDispatcher,
    *,
    hwnd: int = 1234,
    agent_id: str = "SC-AGENT",
    role: str = "sender",
) -> str:
    result = dispatcher.call_tool(
        "sc_request_lease",
        {"hwnd": hwnd, "role": role, "agent_id": agent_id, "ttl_seconds": 300},
    )
    assert result["ok"], result
    return result["result"]["lease_id"]


class TestDispatcherCoverage:
    def test_default_profile_is_enterprise_and_rejects_legacy_queue(self):
        with pytest.raises(ValueError, match="exact durable operator queue"):
            MCPDispatcher(operator_queue=OperatorQueue())

    def test_enterprise_rejects_duck_typed_binding_verifier(self):
        class FakeQueue:
            @staticmethod
            def verify_consumed_binding(*_args, **_kwargs) -> bool:
                return True

        with pytest.raises(ValueError, match="exact durable operator queue"):
            MCPDispatcher(operator_queue=FakeQueue())

    def test_normal_profile_allows_component_testing_with_legacy_queue(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_echo_filter", {"raw_text": "hello", "injected_text": "hello"}
        )
        assert result["result"]["profile"] == "normal"

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

    @pytest.mark.parametrize("role", ["receiver", "observer"])
    def test_read_only_lease_roles_cannot_inject_and_denial_is_evidenced(self, role):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=889, role=role)

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 889, "text": "must not route"},
        )

        assert result["ok"] is False
        assert f"lease role {role!r} is not authorized" in result["error"]
        assert dispatcher._router.routes == []
        decisions = [
            entry
            for entry in dispatcher._ledger.entries
            if entry["action"] == "lease_role_decision"
        ]
        assert decisions[-1]["result"] == "denied"
        assert decisions[-1]["metadata"]["tool"] == "sc_inject_text"
        assert decisions[-1]["metadata"]["issued_role"] == role
        assert decisions[-1]["metadata"]["allowed_roles"] == ["sender"]

    @pytest.mark.parametrize("role", ["unknown", "*", "admin", ""])
    def test_unknown_or_wildcard_lease_role_is_rejected_at_issuance(self, role):
        dispatcher = make_dispatcher()

        result = dispatcher.call_tool(
            "sc_request_lease",
            {"hwnd": 890, "role": role, "agent_id": "SC-AGENT", "ttl_seconds": 300},
        )

        assert result["ok"] is False
        assert dispatcher.active_leases() == []

    def test_missing_lease_role_does_not_default_to_sender(self):
        dispatcher = make_dispatcher()

        result = dispatcher.call_tool(
            "sc_request_lease",
            {"hwnd": 891, "agent_id": "SC-AGENT", "ttl_seconds": 300},
        )

        assert result["ok"] is False
        assert "missing required field: role" in result["error"]
        assert dispatcher.active_leases() == []

    def test_stored_role_mutation_cannot_widen_issuance_authority(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=892, role="observer")
        dispatcher._leases[lease_id] = replace(
            dispatcher._leases[lease_id],
            role="sender",
        )

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 892, "text": "must not route"},
        )

        assert result["ok"] is False
        assert "immutable issuance authority" in result["error"]
        assert dispatcher._router.routes == []
        decisions = [
            entry
            for entry in dispatcher._ledger.entries
            if entry["action"] == "lease_role_decision"
        ]
        assert decisions[-1]["metadata"]["stored_role"] == "sender"
        assert decisions[-1]["metadata"]["issued_role"] == "observer"

    def test_double_replacement_cannot_forge_signed_issuance_authority(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=896, role="observer")
        original_authority = dispatcher._lease_authorities[lease_id]
        dispatcher._leases[lease_id] = replace(
            dispatcher._leases[lease_id],
            role="sender",
        )
        dispatcher._lease_authorities[lease_id] = replace(
            original_authority,
            role="sender",
        )

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 896, "text": "must not route"},
        )

        assert result["ok"] is False
        assert "authority signature is invalid" in result["error"]
        assert dispatcher._router.routes == []

    def test_deserialized_double_replacement_cannot_reuse_observer_signature(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=897, role="observer")
        authority = dispatcher._lease_authorities[lease_id]
        serialized = json.dumps(
            {
                "lease_id": authority.lease_id,
                "agent_id": authority.agent_id,
                "hwnd": authority.hwnd,
                "role": "sender",
                "signature": base64.b64encode(authority.signature).decode("ascii"),
            }
        )
        restored = json.loads(serialized)
        dispatcher._leases[lease_id] = replace(
            dispatcher._leases[lease_id],
            role=restored["role"],
        )
        dispatcher._lease_authorities[lease_id] = type(authority)(
            lease_id=restored["lease_id"],
            agent_id=restored["agent_id"],
            hwnd=restored["hwnd"],
            role=restored["role"],
            signature=base64.b64decode(restored["signature"]),
        )

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 897, "text": "must not route"},
        )

        assert result["ok"] is False
        assert "authority signature is invalid" in result["error"]
        assert dispatcher._router.routes == []

    def test_role_denial_fails_closed_when_persistent_evidence_is_unavailable(self):
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=None,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=898, role="observer")

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 898, "text": "must not route"},
        )

        assert result["ok"] is False
        assert "denial evidence could not be persisted" in result["error"]
        assert "persistent lease role denial evidence is unavailable" in result["error"]
        assert router.routes == []

    def test_missing_issuance_authority_cannot_fall_back_to_stored_role(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=895, role="sender")
        dispatcher._lease_authorities.pop(lease_id)

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 895, "text": "must not route"},
        )

        assert result["ok"] is False
        assert "issuance authority is missing" in result["error"]
        assert dispatcher._router.routes == []

    def test_sender_role_can_inject(self):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=893, role="sender")

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 893, "text": "sender payload"},
        )

        assert result["ok"] is True
        assert dispatcher._router.routes == [(893, "sender payload", lease_id)]

    @pytest.mark.parametrize("role", ["sender", "receiver", "observer"])
    def test_read_output_roles_are_explicitly_authorized(self, role):
        dispatcher = make_dispatcher()
        lease_id = issue_lease(dispatcher, hwnd=894, role=role)

        result = dispatcher.call_tool(
            "sc_read_output",
            {"lease_id": lease_id, "hwnd": 894, "timeout_ms": 100},
        )

        assert result["ok"] is True
        assert result["result"]["method"] == "uia_textpattern"

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
        ledger = RecordingLedger()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=ledger,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            identity_type="dpapi",
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1010)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1010, "text": "hello"},
        )
        assert result["ok"] is True
        assert router.routes == [(1010, "hello", lease_id)]
        assert result["result"]["delivery_confirmation"] == "uia_echo_confirmed"
        assert result["result"]["readback_hash"]
        disposition = next(
            entry for entry in ledger.entries if entry["action"] == "delivery_disposition"
        )
        assert disposition["result"] == "delivery_confirmed"
        assert disposition["metadata"]["transport_attempted"] is True
        assert disposition["metadata"]["transport_enqueued"] is True
        assert disposition["metadata"]["delivery_confirmed"] is True
        assert disposition["metadata"]["do_not_retry"] is False

    def test_inject_fails_closed_without_signed_policy_enforcer(self):
        dispatcher = MCPDispatcher(
            profile="normal",
            router=FakeRouter(),
            ledger=RecordingLedger(),
            target_verifier=verified_target,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1011)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1011, "text": "hello"},
        )
        assert result["ok"] is False
        assert "signed policy enforcer" in result["error"]

    def test_inject_rejects_transport_enqueue_failure(self):
        router = FakeRouter()
        router.route_success = False
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1017)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1017, "text": "hello"},
        )
        assert result["ok"] is False
        assert "failed to enqueue" in result["error"]

    def test_inject_rejects_enqueue_without_new_readback(self):
        router = FakeRouter()
        ledger = RecordingLedger()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=ledger,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: "unchanged terminal output",
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1018)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1018,
                "text": "hello",
                "delivery_timeout_ms": 100,
            },
        )
        assert result["ok"] is False
        assert "delivery unconfirmed" in result["error"]
        assert "do not retry automatically" in result["error"]
        assert router.routes == [(1018, "hello", lease_id)]
        disposition = next(
            entry for entry in ledger.entries if entry["action"] == "delivery_disposition"
        )
        assert disposition["result"] == "enqueued_unconfirmed"
        assert disposition["metadata"]["do_not_retry"] is True

    def test_identity_change_during_confirmation_read_is_not_accepted(self):
        state = {"replaced": False, "reads": 0}

        def target(hwnd: int, **kwargs) -> dict:
            report = verified_target(hwnd, **kwargs)
            if state["replaced"]:
                report["ok"] = False
                report["reasons"] = ["target replaced during UIA read"]
            return report

        router = FakeRouter()
        ledger = RecordingLedger()

        def replacing_reader(_hwnd: int) -> str:
            state["reads"] += 1
            if state["reads"] == 2:
                state["replaced"] = True
            return router.rendered

        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=ledger,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=target,
            output_reader=replacing_reader,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1026)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1026, "text": "hello"},
        )

        assert result["ok"] is False
        assert "target replaced during UIA read" in result["error"]
        assert router.routes == [(1026, "hello", lease_id)]
        dispositions = [
            entry for entry in ledger.entries if entry["action"] == "delivery_disposition"
        ]
        assert [entry["result"] for entry in dispositions] == ["enqueued_unconfirmed"]
        assert dispositions[0]["metadata"]["do_not_retry"] is True

    def test_partial_transport_attempt_is_persisted_as_unknown_delivery(self):
        class PartialRouter(FakeRouter):
            def route(self, hwnd, text, lease_id=None, *, expected_binding=None):
                self.routes.append((hwnd, text, lease_id))
                self.bindings.append(expected_binding)
                return SimpleNamespace(
                    receipt_id="receipt-partial",
                    success=False,
                    transport_attempted=True,
                    transport_enqueued=False,
                    delivery_disposition="unknown_delivery",
                    do_not_retry=True,
                    transport_error="queue closed",
                )

        router = PartialRouter()
        ledger = RecordingLedger()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=ledger,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1027)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1027, "text": "hello"},
        )

        assert result["ok"] is False
        assert "partially attempted" in result["error"]
        assert "must not be retried automatically" in result["error"]
        disposition = next(
            entry for entry in ledger.entries if entry["action"] == "delivery_disposition"
        )
        assert disposition["result"] == "unknown_delivery"
        assert disposition["metadata"]["transport_attempted"] is True
        assert disposition["metadata"]["transport_enqueued"] is False
        assert disposition["metadata"]["do_not_retry"] is True

    def test_inject_does_not_accept_stale_matching_text(self):
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: "prompt> hello",
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1019)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1019,
                "text": "hello",
                "delivery_timeout_ms": 100,
            },
        )
        assert result["ok"] is False
        assert "delivery unconfirmed" in result["error"]

    def test_inject_fails_closed_without_persistent_ledger(self):
        dispatcher = MCPDispatcher(
            profile="normal",
            router=FakeRouter(),
            policy_enforcer=AllowPolicyEnforcer(),
            target_verifier=verified_target,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1012)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1012, "text": "hello"},
        )
        assert result["ok"] is False
        assert "persistent signed audit ledger" in result["error"]

    def test_inject_revalidates_bound_target_identity(self):
        state = {"pid": 4242}

        def changing_target(hwnd: int, **kwargs) -> dict:
            report = verified_target(hwnd, **kwargs)
            report["pid"] = state["pid"]
            if kwargs.get("expect_pid") not in (None, state["pid"]):
                report["ok"] = False
                report["reasons"] = ["pid changed"]
            return report

        dispatcher = MCPDispatcher(
            profile="normal",
            router=FakeRouter(),
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            target_verifier=changing_target,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1013)
        state["pid"] = 5252
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1013, "text": "hello"},
        )
        assert result["ok"] is False
        assert "pid changed" in result["error"]

    def test_inject_revalidates_bound_target_image_path(self):
        state = {
            "exe_path": (
                r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_test"
                r"\WindowsTerminal.exe"
            )
        }

        def changing_target(hwnd: int, **kwargs) -> dict:
            report = verified_target(hwnd, **kwargs)
            report["exe_path"] = state["exe_path"]
            if kwargs.get("expect_exe_path") not in (None, state["exe_path"]):
                report["ok"] = False
                report["reasons"] = ["exe_path changed"]
            return report

        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=changing_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1020)
        state["exe_path"] = r"C:\Users\Public\WindowsTerminal.exe"
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1020, "text": "hello"},
        )
        assert result["ok"] is False
        assert "exe_path changed" in result["error"]

    def test_inject_revalidates_title_hash_from_lease(self):
        state = {"title": "Original Terminal"}

        def changing_target(hwnd: int, **kwargs) -> dict:
            report = verified_target(hwnd, **kwargs)
            report["title"] = state["title"]
            actual_hash = hashlib.sha256(state["title"].encode("utf-8")).hexdigest()
            if kwargs.get("expect_title_sha256") not in (None, actual_hash):
                report["ok"] = False
                report["reasons"] = ["title hash changed"]
            return report

        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=changing_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1022)
        state["title"] = "Replacement Terminal"
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1022, "text": "hello"},
        )
        assert result["ok"] is False
        assert "title hash changed" in result["error"]
        assert router.routes == []

    def test_inject_revalidates_after_preaction_work_before_route(self):
        calls = 0

        def replaced_at_final_boundary(hwnd: int, **kwargs) -> dict:
            nonlocal calls
            calls += 1
            report = verified_target(hwnd, **kwargs)
            if calls == 3:
                report["ok"] = False
                report["reasons"] = ["target replaced before mutation"]
            return report

        router = FakeRouter()
        ledger = RecordingLedger()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=ledger,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=replaced_at_final_boundary,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1023)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1023, "text": "hello"},
        )
        assert result["ok"] is False
        assert "target replaced before mutation" in result["error"]
        assert any(entry["action"] == "policy_decision" for entry in ledger.entries)
        assert router.routes == []

    def test_policy_ledger_precommit_failure_prevents_route(self):
        class FailingPrecommitLedger(RecordingLedger):
            def log(self, action: str, result: str = "", metadata=None, **kwargs):
                if action == "policy_decision":
                    raise OSError("ledger unavailable")
                return super().log(action, result, metadata, **kwargs)

        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=FailingPrecommitLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1024)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1024, "text": "hello"},
        )
        assert result["ok"] is False
        assert "ledger unavailable" in result["error"]
        assert router.routes == []

    def test_post_action_replacement_is_attempted_unknown_delivery(self):
        state = {"replaced": False}

        def target(hwnd: int, **kwargs) -> dict:
            report = verified_target(hwnd, **kwargs)
            if state["replaced"]:
                report["ok"] = False
                report["reasons"] = ["target changed after enqueue"]
            return report

        class ReplacingRouter(FakeRouter):
            def route(self, *args, **kwargs):
                receipt = super().route(*args, **kwargs)
                state["replaced"] = True
                return receipt

        router = ReplacingRouter()
        ledger = RecordingLedger()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=ledger,
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1025)
        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1025, "text": "hello"},
        )
        assert result["ok"] is False
        assert "transport was enqueued" in result["error"]
        assert "delivery state is unknown" in result["error"]
        assert "must not be retried automatically" in result["error"]
        assert router.routes == [(1025, "hello", lease_id)]
        assert ledger.entries[-1]["result"] == "denied"

    def test_default_router_uses_dispatcher_target_verifier(self):
        dispatcher = MCPDispatcher(profile="normal", target_verifier=verified_target)
        assert dispatcher._router._target_verifier is dispatcher._target_verifier

    def test_required_approval_is_bound_to_agent_and_action(self):
        queue = OperatorQueue()
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(requires_approval=True),
            operator_queue=queue,
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1014)
        missing = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1014, "text": "hello"},
        )
        assert missing["ok"] is False
        approval_context = dispatcher.approval_context_for(
            lease_id,
            {
                "hwnd": 1014,
                "text": "hello",
                "classification": "UNCLASSIFIED",
            },
            action="sc_inject_text",
        )
        approval_id = queue.submit("SC-AGENT", "sc_inject_text", approval_context)
        assert queue.approve(approval_id, "operator-1")
        allowed = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1014,
                "text": "hello",
                "approval_id": approval_id,
            },
        )
        assert allowed["ok"] is True
        assert allowed["result"]["governance"]["operator_id"] == "operator-1"
        assert queue.get_status(approval_id) == "consumed"

        replay = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1014,
                "text": "hello",
                "approval_id": approval_id,
            },
        )
        assert replay["ok"] is False
        assert "consumed" in replay["error"]

    def test_oversized_payload_is_rejected_before_approval_consumption(self):
        queue = OperatorQueue()
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(requires_approval=True),
            operator_queue=queue,
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1028)
        approval_id = queue.submit("SC-AGENT", "sc_inject_text", {})
        assert queue.approve(approval_id, "operator-1")

        result = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1028,
                "text": "x" * 4097,
                "approval_id": approval_id,
            },
        )

        assert result["ok"] is False
        assert "maxLength 4096" in result["error"]
        assert queue.get_status(approval_id) == "approved"
        assert router.routes == []

    @pytest.mark.parametrize(
        ("text", "expected_error"),
        [
            pytest.param("   ", "visible non-whitespace character", id="whitespace"),
            pytest.param("   \t  ", "printable characters or newlines", id="tab"),
            pytest.param("\x1b[31m\x1b[0m", "printable characters or newlines", id="ansi-color"),
            pytest.param("\x07", "printable characters or newlines", id="bel"),
            pytest.param("\x08", "printable characters or newlines", id="backspace"),
            pytest.param("\x1b7", "printable characters or newlines", id="dec-save-cursor"),
            pytest.param("\x1bc", "printable characters or newlines", id="reset-to-initial-state"),
            pytest.param("visible\x07", "printable characters or newlines", id="mixed-visible-and-bel"),
            pytest.param("visible\x85", "printable characters or newlines", id="mixed-visible-and-c1"),
        ],
    )
    def test_non_visible_payload_is_rejected_before_approval_consumption(
        self, text, expected_error
    ):
        calls = {"lease": 0, "target": 0, "policy": 0, "approval": 0}

        class CountingQueue(OperatorQueue):
            def consume_approved(self, *args, **kwargs):
                calls["approval"] += 1
                return super().consume_approved(*args, **kwargs)

        class CountingPolicyEnforcer(AllowPolicyEnforcer):
            def check(self, *args, **kwargs):
                calls["policy"] += 1
                return super().check(*args, **kwargs)

        def target(hwnd, **kwargs):
            calls["target"] += 1
            return verified_target(hwnd, **kwargs)

        queue = CountingQueue()
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=CountingPolicyEnforcer(requires_approval=True),
            operator_queue=queue,
            target_verifier=target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1029)
        approval_context = dispatcher.approval_context_for(
            lease_id,
            {"hwnd": 1029, "text": text, "classification": "UNCLASSIFIED"},
            action="sc_inject_text",
        )
        approval_id = queue.submit("SC-AGENT", "sc_inject_text", approval_context)
        assert queue.approve(approval_id, "operator-1")
        original_require_lease = dispatcher._require_lease

        def require_lease(*args, **kwargs):
            calls["lease"] += 1
            return original_require_lease(*args, **kwargs)

        dispatcher._require_lease = require_lease
        calls.update({"lease": 0, "target": 0, "policy": 0, "approval": 0})

        result = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1029,
                "text": text,
                "approval_id": approval_id,
            },
        )

        assert result["ok"] is False
        assert expected_error in result["error"]
        assert queue.get_status(approval_id) == "approved"
        assert calls == {"lease": 0, "target": 0, "policy": 0, "approval": 0}
        assert router.routes == []

    def test_visible_unicode_and_newline_payload_remains_deliverable(self):
        queue = OperatorQueue()
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(requires_approval=True),
            operator_queue=queue,
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1030)
        text = "hello\n\u4e16\u754c"
        approval_context = dispatcher.approval_context_for(
            lease_id,
            {"hwnd": 1030, "text": text, "classification": "UNCLASSIFIED"},
            action="sc_inject_text",
        )
        approval_id = queue.submit("SC-AGENT", "sc_inject_text", approval_context)
        assert queue.approve(approval_id, "operator-1")

        result = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1030, "text": text, "approval_id": approval_id},
        )

        assert result["ok"] is True
        assert queue.get_status(approval_id) == "consumed"
        assert router.routes == [(1030, text, lease_id)]

    def test_mutation_stops_when_consumed_approval_receipt_binding_fails(self):
        class ReceiptRejectingQueue(OperatorQueue):
            @staticmethod
            def verify_consumed_binding(*_args, **_kwargs) -> bool:
                return False

        queue = ReceiptRejectingQueue()
        router = FakeRouter()
        dispatcher = MCPDispatcher(
            profile="normal",
            router=router,
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(requires_approval=True),
            operator_queue=queue,
            target_verifier=verified_target,
            output_reader=lambda _hwnd: router.rendered,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1021)
        approval_context = dispatcher.approval_context_for(
            lease_id,
            {
                "hwnd": 1021,
                "text": "must-not-route",
                "classification": "UNCLASSIFIED",
            },
            action="sc_inject_text",
        )
        approval_id = queue.submit("SC-AGENT", "sc_inject_text", approval_context)
        assert queue.approve(approval_id, "operator-1")
        result = dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease_id,
                "hwnd": 1021,
                "text": "must-not-route",
                "approval_id": approval_id,
            },
        )
        assert result["ok"] is False
        assert "audit receipt" in result["error"]
        assert router.routes == []

    def test_read_output_is_lease_gated(self):
        dispatcher = make_dispatcher()
        result = dispatcher.call_tool(
            "sc_read_output",
            {"lease_id": "missing", "hwnd": 1},
        )
        assert result["ok"] is False
        assert "not found" in result["error"]

    def test_read_output_uses_real_adapter_contract_and_delta(self):
        snapshots = iter(["prompt> hello", "prompt> hello\nmodel reply"])
        dispatcher = MCPDispatcher(
            profile="normal",
            router=FakeRouter(),
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=lambda _hwnd: next(snapshots),
            identity_type="dpapi",
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1015)
        first = dispatcher.call_tool(
            "sc_read_output",
            {"lease_id": lease_id, "hwnd": 1015, "timeout_ms": 100},
        )
        second = dispatcher.call_tool(
            "sc_read_output",
            {"lease_id": lease_id, "hwnd": 1015, "timeout_ms": 100},
        )
        assert first["ok"] is True
        assert first["result"]["text"] == "prompt> hello"
        assert first["result"]["method"] == "uia_textpattern"
        assert second["ok"] is True
        assert second["result"]["text"] == "model reply"

    def test_read_output_fails_closed_when_reader_errors(self):
        def broken_reader(_hwnd: int) -> str:
            raise RuntimeError("no TextPattern")

        dispatcher = MCPDispatcher(
            profile="normal",
            router=FakeRouter(),
            ledger=RecordingLedger(),
            policy_enforcer=AllowPolicyEnforcer(),
            operator_queue=OperatorQueue(),
            target_verifier=verified_target,
            output_reader=broken_reader,
            now=lambda: 1000.0,
        )
        lease_id = issue_lease(dispatcher, hwnd=1016)
        result = dispatcher.call_tool(
            "sc_read_output",
            {"lease_id": lease_id, "hwnd": 1016, "timeout_ms": 100},
        )
        assert result["ok"] is False
        assert "no TextPattern" in result["error"]


class TestRuntimeTools:
    def test_channel_route_delegates_to_router(self):
        router = FakeRouter()
        dispatcher = MCPDispatcher(profile="normal", router=router)
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

    def test_identity_verify_rejects_unimplemented_algorithm(self):
        dispatcher = make_dispatcher()
        signed = dispatcher.call_tool("sc_identity_sign", {"payload_hex": "aabbcc"})
        verified = dispatcher._sc_identity_verify(
            {
                "payload_hex": "aabbcc",
                "signature_b64": signed["result"]["signature_b64"],
                "public_key_b64": signed["result"]["public_key_b64"],
                "algorithm": "ECDSA-P384",
            }
        )
        assert verified["verified"] is False
        assert verified["algorithm"] == "Ed25519"
        assert "unsupported" in verified["reason"]

    def test_tpm_option_returns_verified_platform_claim_separate_from_signature(
        self,
        monkeypatch,
    ):
        from enterprise.tpm_attestation import TpmAttestationResult
        import enterprise.mcp_dispatch as dispatch_module

        claim = TpmAttestationResult(
            nonce=b"n" * 32,
            public_key_blob=b"p" * 72,
            claim_blob=b"claim" * 16,
            supported=True,
            identity_key_bound=False,
        )
        monkeypatch.setattr(dispatch_module, "_TPM_ATTESTATION_AVAILABLE", True)
        monkeypatch.setattr(dispatch_module, "create_tpm_platform_claim", lambda _nonce: claim)
        monkeypatch.setattr(dispatch_module, "verify_tpm_platform_claim", lambda _claim: True)

        result = MCPDispatcher(profile="government", router=FakeRouter()).call_tool(
            "sc_identity_sign",
            {"payload_hex": "aabbcc", "key_provider": "tpm"},
        )

        assert result["ok"] is True
        assert result["result"]["algorithm"] == "Ed25519"
        assert result["result"]["signature_key_provider"] == "software"
        attestation = result["result"]["tpm_attestation"]
        assert attestation["verified_locally"] is True
        assert attestation["identity_key_bound"] is False
        assert attestation["claim_b64"]
        assert len(attestation["claim_sha256"]) == 64

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
        assert "requires a verified TPM platform claim" in result["error"]

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
        assert allowed["result"]["governance_profile"] == "normal"
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
    def test_cli_mcp_call_executes_echo_filter(self, capsys, monkeypatch):
        import enterprise.mcp_dispatch as mcp_dispatch

        monkeypatch.setattr(mcp_dispatch, "_DEFAULT_DISPATCHER", make_dispatcher())
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
