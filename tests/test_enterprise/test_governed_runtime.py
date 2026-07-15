"""Composition tests for the mandatory governed runtime.

These tests use real DPAPI-backed Ed25519 identities, real policy signatures,
and the real signed ledger. The window adapter is deterministic test plumbing;
live HWND/Win32 execution is intentionally a separate conformance run.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from enterprise.governed_runtime import GovernedRuntime, RuntimeConfigurationError
from enterprise.identity import AgentIdentity
from enterprise.policy import make_bundle
from enterprise.policy_sign import sign_policy


class _DeterministicRouter:
    def __init__(self) -> None:
        self.rendered = "runtime prompt> "

    def route(self, hwnd: int, text: str, lease_id: str | None = None):
        self.rendered += text
        return SimpleNamespace(
            receipt_id="receipt-runtime-test",
            hwnd=hwnd,
            channel="wm_char",
            payload_hash="test-payload-hash",
            readback_hash="",
            timestamp=1.0,
            success=True,
            lease_id=lease_id,
            text_length=len(text),
        )


def _target(hwnd: int, **kwargs) -> dict:
    values = {
        "hwnd": hwnd,
        "ok": True,
        "reasons": [],
        "pid": 4242,
        "exe": "WindowsTerminal.exe",
        "exe_path": (
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_test"
            r"\WindowsTerminal.exe"
        ),
        "class": "CASCADIA_HOSTING_WINDOW_CLASS",
        "title": "Governed Runtime Test",
    }
    for expected, key in (
        (kwargs.get("expect_pid"), "pid"),
        (kwargs.get("expect_exe"), "exe"),
        (kwargs.get("expect_exe_path"), "exe_path"),
        (kwargs.get("expect_class"), "class"),
    ):
        if expected is not None and expected != values[key]:
            values["ok"] = False
            values["reasons"].append(f"{key} mismatch")
    return values


def _signed_policy(tmp_path):
    identity_dir = tmp_path / "identities"
    actor = AgentIdentity.init("runtime-actor", data_dir=identity_dir)
    admin = AgentIdentity.init("runtime-admin", data_dir=identity_dir)
    bundle = make_bundle(
        "runtime-policy-v1",
        agents={
            actor.agent_id: {
                "role": "operator-agent",
                "clearance": "CUI",
                "allowed_targets": [],
                "allowed_apps": ["WindowsTerminal.exe"],
                "blocked_apps": [],
                "allowed_actions": ["sc_inject_text", "sc_read_output"],
                "requires_operator_approval": [],
                "max_classification": "CUI",
                "revoked": False,
            }
        },
        signed_by=admin.agent_id,
    )
    signed = sign_policy(bundle.to_dict(), admin)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(signed), encoding="utf-8")
    return identity_dir, policy_path, admin.public_key_bytes, actor.agent_id


def test_real_signed_composition_executes_and_verifies_ledger(tmp_path):
    identity_dir, policy_path, trust_root, actor_id = _signed_policy(tmp_path)
    router = _DeterministicRouter()
    runtime = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "runtime-ledger.jsonl",
        router=router,
        target_verifier=_target,
        output_reader=lambda _hwnd: router.rendered,
    )
    lease = runtime.dispatcher.call_tool(
        "sc_request_lease",
        {"hwnd": 1234, "role": "sender", "agent_id": actor_id, "ttl_seconds": 300},
    )
    assert lease["ok"], lease
    result = runtime.dispatcher.call_tool(
        "sc_inject_text",
        {
            "lease_id": lease["result"]["lease_id"],
            "hwnd": 1234,
            "text": "bounded test payload",
            "classification": "CUI",
        },
    )
    assert result["ok"], result
    assert result["result"]["delivery_confirmation"] == "uia_echo_confirmed"
    assert result["result"]["delivery_confirmed"] is True
    assert result["result"]["readback_hash"]
    assert result["result"]["governance"]["policy_id"] == "runtime-policy-v1"
    router.rendered += "\nruntime output"
    read = runtime.dispatcher.call_tool(
        "sc_read_output",
        {
            "lease_id": lease["result"]["lease_id"],
            "hwnd": 1234,
            "classification": "CUI",
            "timeout_ms": 100,
        },
    )
    assert read["ok"], read
    assert read["result"]["text"] == "runtime output"
    assert runtime.verify_audit()[0] is True

    restarted = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "runtime-ledger.jsonl",
        router=_DeterministicRouter(),
        target_verifier=_target,
        output_reader=lambda _hwnd: "runtime output",
    )
    assert restarted.operator_queue is not None


def test_external_policy_trust_root_is_mandatory(tmp_path):
    identity_dir, policy_path, _trust_root, _actor_id = _signed_policy(tmp_path)
    with pytest.raises(RuntimeConfigurationError, match="external policy trust root"):
        GovernedRuntime.from_signed_policy(
            policy_path=policy_path,
            trust_root_pub=b"",
            agent_name="runtime-actor",
            identity_data_dir=identity_dir,
        )


def test_government_profile_cannot_silently_use_dpapi_factory(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    with pytest.raises(RuntimeConfigurationError, match="CNG/TPM"):
        GovernedRuntime.from_signed_policy(
            policy_path=policy_path,
            trust_root_pub=trust_root,
            agent_name="runtime-actor",
            identity_data_dir=identity_dir,
            profile="government",
        )
