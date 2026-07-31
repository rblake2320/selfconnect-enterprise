"""Composition tests for the mandatory governed runtime.

These tests use real DPAPI-backed Ed25519 identities, real policy signatures,
and the real signed ledger. The window adapter is deterministic test plumbing;
live HWND/Win32 execution is intentionally a separate conformance run.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

from enterprise.approval_audit import DecisionProofVerification
from enterprise.acp_shim import (
    ACP_ACTION_SCHEMA,
    ACPShim,
    GovernedRuntimeBackend,
    RevocationSnapshot,
    SQLiteActionReplayStore,
    acp_action_payload,
)
from enterprise.delegation import issue_delegation_grant, sign_delegated_action
from enterprise.governed_runtime import GovernedRuntime, RuntimeConfigurationError
from enterprise.identity import AgentIdentity
from enterprise.policy import make_bundle
from enterprise.policy_sign import sign_policy
from enterprise.runtime_ownership import RuntimeOwnershipError
from enterprise.runtime_lifetime import RuntimeClosedError, RuntimeCloseReentrantError


class _DeterministicRouter:
    def __init__(self) -> None:
        self.rendered = "runtime prompt> "

    def route(
        self,
        hwnd: int,
        text: str,
        lease_id: str | None = None,
        *,
        expected_binding=None,
    ):
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
    expected_title = kwargs.get("expect_title_sha256")
    if expected_title is not None:
        actual_title = hashlib.sha256(values["title"].encode("utf-8")).hexdigest()
        if expected_title != actual_title:
            values["ok"] = False
            values["reasons"].append("title mismatch")
    return values


def _signed_policy(tmp_path, *, require_approval: bool = False):
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
                "requires_operator_approval": ["sc_inject_text"] if require_approval else [],
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


def _test_decision_verifier(payload, proof):
    if proof != "test-proof":
        return None
    return DecisionProofVerification(
        verifier_id="test-runtime-verifier",
        key_id="test-runtime-key",
        nonce=f"{payload['approval_id']}-{payload['decision']}",
        verified_at=time.time(),
        operator_subject=payload["operator_id"],
    )


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
        decision_writer_verifier=_test_decision_verifier,
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
    runtime.close()

    restarted = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "runtime-ledger.jsonl",
        router=_DeterministicRouter(),
        target_verifier=_target,
        output_reader=lambda _hwnd: "runtime output",
        decision_writer_verifier=_test_decision_verifier,
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


def test_governed_runtime_requires_operator_proof_verifier_at_startup(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    with pytest.raises(RuntimeConfigurationError, match="decision proof verifier"):
        GovernedRuntime.from_signed_policy(
            policy_path=policy_path,
            trust_root_pub=trust_root,
            agent_name="runtime-actor",
            identity_data_dir=identity_dir,
        )


def test_second_governed_runtime_for_same_persistence_pair_fails_startup(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    values = dict(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "runtime-ledger.jsonl",
        approval_db_path=tmp_path / "approvals.sqlite3",
        decision_writer_verifier=_test_decision_verifier,
    )
    first = GovernedRuntime.from_signed_policy(**values)
    try:
        with pytest.raises(RuntimeOwnershipError, match="already has a writer"):
            GovernedRuntime.from_signed_policy(**values)
    finally:
        first.close()
    restarted = GovernedRuntime.from_signed_policy(**values)
    restarted.close()


def test_governed_runtime_rejects_same_ledger_and_approval_path_before_open(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    shared = tmp_path / "shared-persistence"
    with pytest.raises(RuntimeOwnershipError, match="distinct persistence resources"):
        GovernedRuntime.from_signed_policy(
            policy_path=policy_path,
            trust_root_pub=trust_root,
            agent_name="runtime-actor",
            identity_data_dir=identity_dir,
            ledger_path=shared,
            approval_db_path=shared,
            decision_writer_verifier=_test_decision_verifier,
        )
    assert not shared.exists()


def test_governed_runtime_rejects_cross_resource_hardlink_before_open(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"")
    approvals = tmp_path / "approvals.sqlite3"
    try:
        os.link(ledger, approvals)
    except OSError as exc:  # pragma: no cover - filesystem capability boundary
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(RuntimeOwnershipError, match="distinct persistence resources"):
        GovernedRuntime.from_signed_policy(
            policy_path=policy_path,
            trust_root_pub=trust_root,
            agent_name="runtime-actor",
            identity_data_dir=identity_dir,
            ledger_path=ledger,
            approval_db_path=approvals,
            decision_writer_verifier=_test_decision_verifier,
        )
    assert ledger.read_bytes() == b""


def test_closed_runtime_object_graph_cannot_mutate_after_replacement_starts(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    values = dict(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "runtime-ledger.jsonl",
        approval_db_path=tmp_path / "approvals.sqlite3",
        decision_writer_verifier=_test_decision_verifier,
    )
    first = GovernedRuntime.from_signed_policy(**values)
    first.close()
    second = GovernedRuntime.from_signed_policy(**values)
    try:
        with pytest.raises(RuntimeClosedError, match="runtime is closed"):
            first.operator_queue.submit("agent-a", "export", {})
        with pytest.raises(RuntimeClosedError, match="runtime is closed"):
            first.dispatcher.call_tool(
                "sc_echo_filter", {"raw_text": "stale", "injected_text": ""}
            )
        with pytest.raises(RuntimeClosedError, match="runtime is closed"):
            first.control_plane.register("stale-agent")
        with pytest.raises(RuntimeClosedError, match="runtime is closed"):
            first.ledger.log("stale-runtime-write")
        assert second.verify_audit()[0] is True
    finally:
        second.close()


def test_decision_verifier_cannot_close_runtime_reentrantly(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(
        tmp_path, require_approval=True
    )
    holder = {}

    def verifier(_payload, _proof):
        holder["runtime"].close()

    runtime = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "ledger.jsonl",
        decision_writer_verifier=verifier,
    )
    holder["runtime"] = runtime
    approval_id = runtime.operator_queue.submit("agent-a", "export", {})
    try:
        with pytest.raises(RuntimeCloseReentrantError, match="in-flight operation"):
            runtime.operator_queue.approve(
                approval_id, "operator-a", operator_proof="proof"
            )
        assert runtime.operator_queue.get_status(approval_id) == "pending"
    finally:
        runtime.close()


def test_router_callback_cannot_close_runtime_reentrantly(tmp_path):
    identity_dir, policy_path, trust_root, actor_id = _signed_policy(tmp_path)
    holder = {}

    class ClosingRouter(_DeterministicRouter):
        def route(
            self,
            hwnd: int,
            text: str,
            lease_id: str | None = None,
            *,
            expected_binding=None,
        ):
            holder["runtime"].close()
            return super().route(
                hwnd, text, lease_id, expected_binding=expected_binding
            )

    router = ClosingRouter()
    runtime = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "ledger.jsonl",
        router=router,
        target_verifier=_target,
        output_reader=lambda _hwnd: router.rendered,
        decision_writer_verifier=_test_decision_verifier,
    )
    holder["runtime"] = runtime
    lease = runtime.dispatcher.call_tool(
        "sc_request_lease",
        {"hwnd": 1234, "role": "sender", "agent_id": actor_id, "ttl_seconds": 300},
    )
    try:
        result = runtime.dispatcher.call_tool(
            "sc_inject_text",
            {
                "lease_id": lease["result"]["lease_id"],
                "hwnd": 1234,
                "text": "reentrant close probe",
                "classification": "CUI",
            },
        )
        assert result["ok"] is False
        assert "in-flight operation" in result["error"]
    finally:
        runtime.close()


def test_close_waits_while_admitted_flow_finishes_nested_component_mutations(tmp_path):
    identity_dir, policy_path, trust_root, _actor_id = _signed_policy(tmp_path)
    runtime = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "ledger.jsonl",
        decision_writer_verifier=_test_decision_verifier,
    )
    closed = threading.Event()

    def close() -> None:
        runtime.close()
        closed.set()

    with runtime.runtime_lifetime.operation():
        closer = threading.Thread(target=close)
        closer.start()
        assert runtime.runtime_lifetime._revoked.wait(timeout=2)
        runtime.operator_queue.submit("agent-a", "nested-export", {})
        runtime.control_plane.register("nested-agent")
        runtime.ledger.log("nested-before-close")
        assert not closed.is_set()
    closer.join(timeout=2)
    assert closed.is_set()


def test_governed_approval_is_signed_and_bound_before_actuation(tmp_path):
    identity_dir, policy_path, trust_root, actor_id = _signed_policy(
        tmp_path,
        require_approval=True,
    )
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
        decision_writer_verifier=lambda payload, proof: (
            DecisionProofVerification(
                verifier_id="test-verifier",
                key_id="test-key",
                nonce=f"{payload['approval_id']}-{payload['decision']}",
                verified_at=time.time(),
                operator_subject=payload["operator_id"],
            )
            if payload["operator_id"] == "operator-1"
            and payload["decision"] == "approved"
            and proof == "signed-proof"
            else None
        ),
    )
    lease = runtime.dispatcher.call_tool(
        "sc_request_lease",
        {"hwnd": 1234, "role": "sender", "agent_id": actor_id, "ttl_seconds": 300},
    )
    lease_id = lease["result"]["lease_id"]
    context = runtime.dispatcher.approval_context_for(
        lease_id,
        {"hwnd": 1234, "text": "approved payload", "classification": "CUI"},
        action="sc_inject_text",
    )
    approval_id = runtime.operator_queue.submit(actor_id, "sc_inject_text", context)
    assert runtime.operator_queue.approve(
        approval_id,
        "operator-1",
        operator_proof="signed-proof",
    )
    result = runtime.dispatcher.call_tool(
        "sc_inject_text",
        {
            "lease_id": lease_id,
            "hwnd": 1234,
            "text": "approved payload",
            "classification": "CUI",
            "approval_id": approval_id,
        },
    )
    assert result["ok"], result
    transitions = [
        entry["approval_audit"]["transition"]
        for entry in runtime.ledger.tail(runtime.ledger.entry_count())
        if "approval_audit" in entry
    ]
    assert transitions == ["pending", "approved", "consumed"]
    assert runtime.verify_audit()[0] is True


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


def test_acp_cannot_bypass_governed_operator_approval(tmp_path):
    identity_dir, policy_path, trust_root, actor_id = _signed_policy(tmp_path, require_approval=True)
    router = _DeterministicRouter()
    runtime = GovernedRuntime.from_signed_policy(
        policy_path=policy_path,
        trust_root_pub=trust_root,
        agent_name="runtime-actor",
        identity_data_dir=identity_dir,
        ledger_path=tmp_path / "acp-runtime-ledger.jsonl",
        approval_db_path=tmp_path / "acp-runtime-approvals.sqlite3",
        router=router,
        target_verifier=_target,
        output_reader=lambda _hwnd: router.rendered,
        decision_writer_verifier=_test_decision_verifier,
    )
    replay = SQLiteActionReplayStore(tmp_path / "acp-runtime-replay.sqlite3")
    try:
        lease = runtime.dispatcher.call_tool(
            "sc_request_lease",
            {"hwnd": 1234, "role": "sender", "agent_id": actor_id, "ttl_seconds": 300},
        )
        arguments = {
            "lease_id": lease["result"]["lease_id"],
            "hwnd": 1234,
            "text": "must not bypass approval",
            "classification": "CUI",
        }
        owner = AgentIdentity.init("acp-runtime-owner", data_dir=identity_dir)
        author = AgentIdentity.init("acp-runtime-author", data_dir=identity_dir)
        grant = issue_delegation_grant(
            signer=owner,
            issuer_principal="OWNER:RON",
            subject_public_key=author.public_key_bytes,
            allowed_actions=("sc_inject_text",),
            target_constraints={},
            governance_mode="enterprise",
            classification_ceiling="CUI",
            issued_at=1_000.0,
            not_before=1_000.0,
            expires_at=2_000.0,
            revocation_epoch=0,
            nonce="acp-runtime-approval",
        )
        shim = ACPShim(
            backend=GovernedRuntimeBackend(runtime),
            replay_store=replay,
            issuer_resolver=lambda fingerprint: (
                owner.public_key_bytes if fingerprint == grant.issuer_key_fingerprint else None
            ),
            revocation_provider=lambda: RevocationSnapshot(epoch=0),
            clock=lambda: 1_500.0,
        )
        shim.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": 1, "clientCapabilities": {}},
            }
        )
        session_id = shim.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/new",
                "params": {"cwd": str(tmp_path.resolve()), "mcpServers": []},
            }
        )[0]["result"]["sessionId"]
        payload = acp_action_payload(
            session_id=session_id,
            cwd=str(tmp_path.resolve()),
            tool="sc_inject_text",
            arguments=arguments,
        )
        proof = sign_delegated_action(
            grant=grant,
            agent_identity=author,
            action_id="acp-runtime-action",
            action="sc_inject_text",
            target={},
            payload=payload,
            governance_mode="enterprise",
            classification="CUI",
            occurred_at=1_500.0,
        )
        response = shim.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {
                    "sessionId": session_id,
                    "prompt": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "schema": ACP_ACTION_SCHEMA,
                                    "tool": "sc_inject_text",
                                    "arguments": arguments,
                                    "delegationGrant": grant.to_dict(),
                                    "actionProof": proof.to_dict(),
                                }
                            ),
                        }
                    ],
                },
            }
        )[0]
        assert response["error"] == {"code": -32011, "message": "governed backend rejected the action"}
        assert router.rendered == "runtime prompt> "
        assert replay.contains("acp-runtime-action")

        approved_text = "exactly approved ACP payload"
        approval_arguments = {
            "lease_id": lease["result"]["lease_id"],
            "hwnd": 1234,
            "text": approved_text,
            "classification": "CUI",
        }
        approval_context = runtime.dispatcher.approval_context_for(
            lease["result"]["lease_id"],
            approval_arguments,
            action="sc_inject_text",
        )
        approval_id = runtime.operator_queue.submit(actor_id, "sc_inject_text", approval_context)
        assert runtime.operator_queue.approve(
            approval_id,
            "operator-1",
            operator_proof="test-proof",
        )
        approved_arguments = {**approval_arguments, "approval_id": approval_id}
        approved_payload = acp_action_payload(
            session_id=session_id,
            cwd=str(tmp_path.resolve()),
            tool="sc_inject_text",
            arguments=approved_arguments,
        )
        approved_proof = sign_delegated_action(
            grant=grant,
            agent_identity=author,
            action_id="acp-runtime-approved-action",
            action="sc_inject_text",
            target={},
            payload=approved_payload,
            governance_mode="enterprise",
            classification="CUI",
            occurred_at=1_500.0,
        )
        approved_messages = shim.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "session/prompt",
                "params": {
                    "sessionId": session_id,
                    "prompt": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "schema": ACP_ACTION_SCHEMA,
                                    "tool": "sc_inject_text",
                                    "arguments": approved_arguments,
                                    "delegationGrant": grant.to_dict(),
                                    "actionProof": approved_proof.to_dict(),
                                }
                            ),
                        }
                    ],
                },
            }
        )
        assert approved_messages[-1]["result"] == {"stopReason": "end_turn"}
        result = json.loads(approved_messages[0]["params"]["update"]["content"]["text"])
        assert result["ok"] is True
        assert result["result"]["governance"]["approval_mode"] == "human_approved"
        assert router.rendered.endswith(approved_text)
        assert replay.contains("acp-runtime-approved-action")

        before_mismatch = router.rendered
        approved_context_arguments = {
            "lease_id": lease["result"]["lease_id"],
            "hwnd": 1234,
            "text": "operator approved this text",
            "classification": "CUI",
        }
        mismatch_context = runtime.dispatcher.approval_context_for(
            lease["result"]["lease_id"],
            approved_context_arguments,
            action="sc_inject_text",
        )
        mismatch_approval_id = runtime.operator_queue.submit(
            actor_id,
            "sc_inject_text",
            mismatch_context,
        )
        assert runtime.operator_queue.approve(
            mismatch_approval_id,
            "operator-1",
            operator_proof="test-proof",
        )
        substituted_arguments = {
            **approved_context_arguments,
            "text": "agent substituted different text",
            "approval_id": mismatch_approval_id,
        }
        substituted_payload = acp_action_payload(
            session_id=session_id,
            cwd=str(tmp_path.resolve()),
            tool="sc_inject_text",
            arguments=substituted_arguments,
        )
        substituted_proof = sign_delegated_action(
            grant=grant,
            agent_identity=author,
            action_id="acp-runtime-substituted-action",
            action="sc_inject_text",
            target={},
            payload=substituted_payload,
            governance_mode="enterprise",
            classification="CUI",
            occurred_at=1_500.0,
        )
        substituted_response = shim.handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "session/prompt",
                "params": {
                    "sessionId": session_id,
                    "prompt": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "schema": ACP_ACTION_SCHEMA,
                                    "tool": "sc_inject_text",
                                    "arguments": substituted_arguments,
                                    "delegationGrant": grant.to_dict(),
                                    "actionProof": substituted_proof.to_dict(),
                                }
                            ),
                        }
                    ],
                },
            }
        )[0]
        assert substituted_response["error"] == {
            "code": -32011,
            "message": "governed backend rejected the action",
        }
        assert router.rendered == before_mismatch
        assert replay.contains("acp-runtime-substituted-action")
    finally:
        replay.close()
        runtime.close()
