from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from enterprise.logical_targets import LogicalTargetResolver, LogicalTargetSpec
from enterprise.mcp_dispatch import MCPDispatcher
from enterprise.operator import OperatorQueue
from enterprise.policy import PolicyDecision


PATH = (
    r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_test"
    r"\WindowsTerminal.exe"
)
TITLE = "Alias Target"
TITLE_HASH = hashlib.sha256(TITLE.encode()).hexdigest()


class Ledger:
    def __init__(self):
        self.entries = []

    def log(self, action, result="", metadata=None, **_kwargs):
        entry = {"action": action, "result": result, "metadata": metadata or {}}
        self.entries.append(entry)
        return entry


class Policy:
    @staticmethod
    def check(agent_id, action, **kwargs):
        return PolicyDecision(
            allowed=True,
            reason="test",
            policy_id="policy-test",
            classification=kwargs.get("classification", "UNCLASSIFIED"),
            agent_id=agent_id,
            action=action,
        )


class Router:
    def __init__(self):
        self.rendered = "before"
        self.calls = []

    def route(self, hwnd, text, lease_id=None, *, expected_binding=None):
        self.calls.append((hwnd, text, lease_id, expected_binding))
        self.rendered += text
        return SimpleNamespace(
            receipt_id="r1",
            hwnd=hwnd,
            channel="wm_char",
            payload_hash=hashlib.sha256(text.encode()).hexdigest(),
            readback_hash="",
            timestamp=1001.0,
            success=True,
            transport_enqueued=True,
            transport_attempted=True,
        )


def make_dispatcher(*, state=None, allowed_roles=frozenset({"sender"})):
    current = state or {
        "pid": 4242,
        "exe": "WindowsTerminal.exe",
        "exe_path": PATH,
        "class": "CASCADIA_HOSTING_WINDOW_CLASS",
        "title": TITLE,
    }
    verifier_calls = []

    def verifier(hwnd, **kwargs):
        verifier_calls.append((hwnd, kwargs))
        result = {
            "hwnd": hwnd,
            "valid": True,
            "ok": True,
            "reasons": [],
            "is_terminal": True,
            "is_self": False,
            **current,
        }
        checks = {
            "expect_pid": "pid",
            "expect_exe": "exe",
            "expect_exe_path": "exe_path",
            "expect_class": "class",
        }
        for expected, field in checks.items():
            if kwargs.get(expected) is not None and kwargs[expected] != result[field]:
                result["ok"] = False
                result["reasons"].append(f"{field} changed")
        expected_title = kwargs.get("expect_title_sha256")
        if expected_title is not None and hashlib.sha256(
            result["title"].encode()
        ).hexdigest() != expected_title:
            result["ok"] = False
            result["reasons"].append("title changed")
        return result

    resolver = LogicalTargetResolver(
        [
            LogicalTargetSpec(
                logical_id="ops.terminal.primary",
                expected_exe_path=PATH,
                expected_class="CASCADIA_HOSTING_WINDOW_CLASS",
                expected_title_sha256=TITLE_HASH,
                allowed_roles=allowed_roles,
            )
        ],
        enumerate_windows=lambda: [1234],
    )
    router = Router()
    ledger = Ledger()
    dispatcher = MCPDispatcher(
        profile="normal",
        router=router,
        ledger=ledger,
        policy_enforcer=Policy(),
        operator_queue=OperatorQueue(),
        target_verifier=verifier,
        output_reader=lambda _hwnd: router.rendered,
        now=lambda: 1000.0,
        logical_target_resolver=resolver,
    )
    return dispatcher, router, ledger, verifier_calls, current


def request_alias(dispatcher, *, role="sender"):
    return dispatcher.call_tool(
        "sc_request_target_lease",
        {
            "logical_target_id": "ops.terminal.primary",
            "role": role,
            "agent_id": "SC-ALIAS",
            "ttl_seconds": 300,
        },
    )


class TestLogicalTargetLeaseDispatch:
    def test_unconfigured_resolver_fails_closed(self):
        dispatcher = MCPDispatcher(
            profile="normal",
            router=Router(),
            ledger=Ledger(),
            policy_enforcer=Policy(),
            operator_queue=OperatorQueue(),
            target_verifier=lambda *_args, **_kwargs: {},
        )
        result = request_alias(dispatcher)
        assert result["ok"] is False
        assert "resolver is not configured" in result["error"]

    def test_alias_lease_uses_signed_existing_authority(self):
        dispatcher, _router, _ledger, verifier_calls, _state = make_dispatcher()
        response = request_alias(dispatcher)
        assert response["ok"], response
        lease = response["result"]
        assert lease["logical_target_id"] == "ops.terminal.primary"
        assert lease["hwnd"] == 1234
        assert lease["target_pid"] == 4242
        assert verifier_calls[0][1] == {
            "expect_exe_path": PATH,
            "expect_class": "CASCADIA_HOSTING_WINDOW_CLASS",
            "expect_title_sha256": TITLE_HASH,
            "require_terminal": True,
        }

    def test_forbidden_role_denied_before_verification(self):
        dispatcher, _router, _ledger, verifier_calls, _state = make_dispatcher()
        response = request_alias(dispatcher, role="observer")
        assert response["ok"] is False
        assert "not authorized" in response["error"]
        assert verifier_calls == []

    def test_logical_target_id_is_part_of_signed_lease_authority(self):
        dispatcher, router, ledger, _calls, _state = make_dispatcher()
        response = request_alias(dispatcher)
        lease_id = response["result"]["lease_id"]
        original = dispatcher._leases[lease_id]
        dispatcher._leases[lease_id] = replace(original, logical_target_id="evil.target")
        denied = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1234, "text": "hello"},
        )
        assert denied["ok"] is False
        assert "signed issuance authority" in denied["error"]
        assert router.calls == []
        assert any(entry["action"] == "lease_role_decision" for entry in ledger.entries)

    def test_target_change_after_resolution_denies_before_actuation(self):
        dispatcher, router, _ledger, _calls, state = make_dispatcher()
        response = request_alias(dispatcher)
        lease_id = response["result"]["lease_id"]
        state["title"] = "Reused Target"
        denied = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1234, "text": "hello"},
        )
        assert denied["ok"] is False
        assert "title changed" in denied["error"]
        assert router.calls == []

    def test_valid_alias_lease_reuses_normal_injection_path(self):
        dispatcher, router, _ledger, _calls, _state = make_dispatcher()
        response = request_alias(dispatcher)
        lease_id = response["result"]["lease_id"]
        injected = dispatcher.call_tool(
            "sc_inject_text",
            {"lease_id": lease_id, "hwnd": 1234, "text": "hello"},
        )
        assert injected["ok"], injected
        assert injected["result"]["delivery_confirmed"] is True
        assert len(router.calls) == 1

    def test_schema_rejects_extra_and_malformed_alias(self):
        dispatcher, _router, _ledger, _calls, _state = make_dispatcher()
        extra = request_alias(dispatcher)
        assert extra["ok"] is True
        denied = dispatcher.call_tool(
            "sc_request_target_lease",
            {
                "logical_target_id": "UPPER",
                "role": "sender",
                "agent_id": "SC-ALIAS",
                "unexpected": True,
            },
        )
        assert denied["ok"] is False
