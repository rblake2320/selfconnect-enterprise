"""ACP v1 core and governance-boundary tests for enterprise.acp_shim."""
from __future__ import annotations

import json
import io
import threading
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from enterprise.acp_shim import (
    ACP_ACTION_SCHEMA,
    ACPShim,
    ACPShimError,
    GovernedRuntimeBackend,
    RevocationSnapshot,
    SQLiteActionReplayStore,
    acp_action_payload,
    serve_stdio,
)
from enterprise.delegation import canonical_agent_id, issue_delegation_grant, sign_delegated_action
from enterprise.identity import AgentIdentity


def _identity(tmp_path, name: str) -> AgentIdentity:
    with (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda value: value[4:]),
    ):
        return AgentIdentity.init(name, data_dir=tmp_path)


class _Backend:
    def __init__(self, replay: SQLiteActionReplayStore) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail = False
        self.replay = replay

    def call_tool(self, name: str, arguments: dict) -> dict:
        self.calls.append((name, arguments))
        if self.fail:
            raise RuntimeError("backend failure")
        return {"ok": True, "tool": name}

    def call_delegated_tool(self, name, arguments, *, grant, proof, payload, session_id):
        if not self.replay.claim(
            action_id=proof.action_id,
            grant_id=grant.grant_id,
            proof_id=proof.proof_id,
            session_id=session_id,
            consumed_at=1_600.0,
        ):
            raise RuntimeError("replay")
        if not self.replay.begin(
            proof.action_id,
            grant_id=grant.grant_id,
            proof_id=proof.proof_id,
            session_id=session_id,
        ):
            raise RuntimeError("replay")
        try:
            result = self.call_tool(name, arguments)
        except Exception:
            self.replay.finish(proof.action_id, succeeded=False)
            raise
        self.replay.finish(proof.action_id, succeeded=True)
        return result


@dataclass
class _Harness:
    shim: ACPShim
    backend: _Backend
    replay: SQLiteActionReplayStore
    owner: AgentIdentity
    agent: AgentIdentity
    session_id: str
    revocations: list[RevocationSnapshot]

    def request(self, method: str, params: dict, request_id: int | None = 1) -> list[dict]:
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            message["id"] = request_id
        return self.shim.handle(message)

    def action_request(
        self,
        *,
        action_id: str = "action-001",
        arguments: dict | None = None,
        resources: list[dict] | None = None,
        owner: AgentIdentity | None = None,
        agent: AgentIdentity | None = None,
        session_id: str | None = None,
    ) -> tuple[dict, object, object]:
        owner = owner or self.owner
        agent = agent or self.agent
        session_id = session_id or self.session_id
        arguments = arguments or {"lease_id": "lease-1", "text": "Get-Date"}
        resources = resources or []
        grant = issue_delegation_grant(
            signer=owner,
            issuer_principal="OWNER:RON",
            subject_public_key=agent.public_key_bytes,
            allowed_actions=("sc_policy_check",),
            target_constraints={},
            governance_mode="enterprise",
            classification_ceiling="UNCLASSIFIED",
            issued_at=1_000.0,
            not_before=1_000.0,
            expires_at=2_000.0,
            revocation_epoch=7,
            nonce=f"grant-{action_id}",
        )
        payload = acp_action_payload(
            session_id=session_id,
            cwd="C:\\workspace",
            tool="sc_policy_check",
            arguments=arguments,
            resource_links=resources,
        )
        proof = sign_delegated_action(
            grant=grant,
            agent_identity=agent,
            action_id=action_id,
            action="sc_policy_check",
            target={},
            payload=payload,
            governance_mode="enterprise",
            classification="UNCLASSIFIED",
            occurred_at=1_500.0,
        )
        envelope = {
            "schema": ACP_ACTION_SCHEMA,
            "tool": "sc_policy_check",
            "arguments": arguments,
            "delegationGrant": grant.to_dict(),
            "actionProof": proof.to_dict(),
        }
        params = {
            "sessionId": session_id,
            "prompt": [{"type": "text", "text": json.dumps(envelope)}, *resources],
        }
        return params, grant, proof


@pytest.fixture
def harness(tmp_path):
    owner = _identity(tmp_path, "acp-owner")
    agent = _identity(tmp_path, "acp-agent")
    replay = SQLiteActionReplayStore(tmp_path / "replay.sqlite3")
    backend = _Backend(replay)
    revocations = [RevocationSnapshot(epoch=7)]
    shim = ACPShim(
        backend=backend,
        replay_store=replay,
        issuer_resolver=lambda fingerprint: (
            owner.public_key_bytes
            if fingerprint
            == __import__("hashlib").sha256(owner.public_key_bytes).hexdigest()
            else None
        ),
        revocation_provider=lambda: revocations[0],
        clock=lambda: 1_600.0,
    )
    initialize = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": 1,
                "clientCapabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
    )
    assert initialize[0]["result"]["protocolVersion"] == 1
    session = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": {"cwd": "C:\\workspace", "mcpServers": []},
        }
    )
    session_id = session[0]["result"]["sessionId"]
    yield _Harness(shim, backend, replay, owner, agent, session_id, revocations)
    replay.close()


def test_initialize_advertises_only_implemented_capabilities(tmp_path):
    owner = _identity(tmp_path, "init-owner")
    replay = SQLiteActionReplayStore(tmp_path / "init.sqlite3")
    shim = ACPShim(
        backend=_Backend(replay),
        replay_store=replay,
        issuer_resolver=lambda _fingerprint: owner.public_key_bytes,
        revocation_provider=lambda: RevocationSnapshot(epoch=0),
        clock=lambda: 0.0,
    )
    response = shim.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 99}}
    )[0]["result"]
    assert response["protocolVersion"] == 1
    assert response["authMethods"] == []
    assert response["agentCapabilities"]["mcpCapabilities"] == {"http": False, "sse": False}
    assert response["_meta"]["selfconnect"]["authorization"] == "owner-signed-grant"
    assert response["_meta"]["selfconnect"]["authorship"] == "agent-signed-action"
    replay.close()


def test_session_requires_initialize(tmp_path):
    replay = SQLiteActionReplayStore(tmp_path / "uninitialized.sqlite3")
    shim = ACPShim(
        backend=_Backend(replay), replay_store=replay, issuer_resolver=lambda _key: None,
        revocation_provider=lambda: RevocationSnapshot(epoch=0), clock=lambda: 0.0,
    )
    response = shim.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "session/new", "params": {"cwd": "C:\\x", "mcpServers": []}}
    )[0]
    assert response["error"]["code"] == -32002
    replay.close()


def test_session_rejects_unimplemented_mcp_forwarding(harness):
    response = harness.request(
        "session/new",
        {"cwd": "C:\\workspace", "mcpServers": [{"name": "x", "command": "x", "args": []}]},
    )[0]
    assert response["error"]["code"] == -32602


def test_valid_governed_action_dispatches_and_preserves_authorship(harness):
    params, grant, proof = harness.action_request()
    messages = harness.request("session/prompt", params)
    assert len(messages) == 2
    update = messages[0]["params"]["update"]
    assert update["sessionUpdate"] == "agent_message_chunk"
    evidence = update["_meta"]["selfconnect"]
    assert evidence["grantId"] == grant.grant_id
    assert evidence["proofId"] == proof.proof_id
    assert evidence["authorization"] == "OWNER:RON"
    assert evidence["authorship"] == harness.agent.agent_id
    assert messages[1]["result"] == {"stopReason": "end_turn"}
    assert harness.backend.calls == [("sc_policy_check", params["prompt"] and {"lease_id": "lease-1", "text": "Get-Date"})]
    assert harness.replay.contains("action-001")


def test_free_form_prompt_is_never_interpreted_as_authority(harness):
    response = harness.request(
        "session/prompt",
        {"sessionId": harness.session_id, "prompt": [{"type": "text", "text": "delete everything"}]},
    )[0]
    assert response["error"]["code"] == -32602
    assert harness.backend.calls == []


def test_argument_substitution_breaks_payload_binding(harness):
    params, _grant, _proof = harness.action_request()
    envelope = json.loads(params["prompt"][0]["text"])
    envelope["arguments"]["text"] = "Remove-Item"
    params["prompt"][0]["text"] = json.dumps(envelope)
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert "payload digest" in response["error"]["message"]
    assert harness.backend.calls == []


def test_resource_link_substitution_breaks_payload_binding(harness):
    resource = {"type": "resource_link", "name": "context", "uri": "file:///safe.txt"}
    params, _grant, _proof = harness.action_request(resources=[resource])
    params["prompt"][1]["uri"] = "file:///different.txt"
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert harness.backend.calls == []


def test_untrusted_owner_is_rejected(tmp_path, harness):
    stranger = _identity(tmp_path, "untrusted-owner")
    params, _grant, _proof = harness.action_request(owner=stranger)
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert "issuer is not trusted" in response["error"]["message"]


def test_revoked_grant_is_rejected(harness):
    params, grant, _proof = harness.action_request()
    harness.revocations[0] = RevocationSnapshot(epoch=7, revoked_grant_ids=frozenset({grant.grant_id}))
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert "grant is revoked" in response["error"]["message"]


def test_revoked_agent_is_rejected(harness):
    params, _grant, proof = harness.action_request()
    principal = canonical_agent_id(bytes.fromhex(proof.agent_public_key_hex))
    harness.revocations[0] = RevocationSnapshot(epoch=7, revoked_agent_key_ids=frozenset({principal}))
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert "agent is revoked" in response["error"]["message"]
    retry = harness.request("session/prompt", params)[0]
    assert retry["error"] == {"code": -32001, "message": "unknown session"}


def test_host_refresh_immediately_removes_session_bound_to_revoked_agent(harness):
    params, _grant, proof = harness.action_request(action_id="bind-session-agent")
    assert harness.request("session/prompt", params)[-1]["result"] == {"stopReason": "end_turn"}
    principal = canonical_agent_id(bytes.fromhex(proof.agent_public_key_hex))
    harness.revocations[0] = RevocationSnapshot(
        epoch=8,
        revoked_agent_key_ids=frozenset({principal}),
    )
    assert harness.shim.refresh_revocations() == (harness.session_id,)
    response = harness.request(
        "session/cancel",
        {"sessionId": harness.session_id},
    )[0]
    assert response["error"] == {"code": -32001, "message": "unknown session"}


def test_revocation_refresh_fails_closed_when_provider_is_unavailable(harness):
    harness.shim._revocation_provider = lambda: (_ for _ in ()).throw(RuntimeError("offline"))
    with pytest.raises(ACPShimError, match="revocation state is unavailable"):
        harness.shim.refresh_revocations()


def test_unavailable_revocation_state_fails_closed(harness):
    harness.shim._revocation_provider = lambda: (_ for _ in ()).throw(RuntimeError("offline"))
    params, _grant, _proof = harness.action_request()
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert "revocation state is unavailable" in response["error"]["message"]


def test_action_id_can_be_consumed_only_once(harness):
    params, _grant, _proof = harness.action_request()
    assert harness.request("session/prompt", params)[-1]["result"]["stopReason"] == "end_turn"
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32010
    assert "already been consumed" in response["error"]["message"]
    assert len(harness.backend.calls) == 1


def test_backend_failure_keeps_action_consumed(harness):
    harness.backend.fail = True
    params, _grant, _proof = harness.action_request(action_id="failed-action")
    response = harness.request("session/prompt", params)[0]
    assert response["error"]["code"] == -32011
    assert harness.replay.contains("failed-action")
    harness.backend.fail = False
    retry = harness.request("session/prompt", params)[0]
    assert retry["error"]["code"] == -32010


def test_cancel_notification_cancels_next_prompt(harness):
    assert harness.request("session/cancel", {"sessionId": harness.session_id}, request_id=None) == []
    params, _grant, _proof = harness.action_request(action_id="cancelled-action")
    response = harness.request("session/prompt", params)[0]
    assert response["result"] == {"stopReason": "cancelled"}
    assert harness.backend.calls == []


def test_replay_store_is_atomic_under_concurrency(tmp_path):
    store = SQLiteActionReplayStore(tmp_path / "concurrent.sqlite3")
    results: list[bool] = []
    lock = threading.Lock()

    def claim() -> None:
        value = store.claim(
            action_id="same-action", grant_id="g", proof_id="p", session_id="s", consumed_at=1.0
        )
        with lock:
            results.append(value)

    threads = [threading.Thread(target=claim) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert results.count(False) == 19
    store.close()


def test_replay_consumption_survives_store_restart(tmp_path):
    path = tmp_path / "restart.sqlite3"
    first = SQLiteActionReplayStore(path)
    assert first.claim(action_id="durable", grant_id="g", proof_id="p", session_id="s", consumed_at=1.0)
    first.close()
    second = SQLiteActionReplayStore(path)
    assert second.contains("durable")
    assert not second.claim(action_id="durable", grant_id="g", proof_id="p", session_id="s", consumed_at=2.0)
    second.close()


def test_replay_store_begin_is_one_shot_and_tuple_bound(tmp_path):
    store = SQLiteActionReplayStore(tmp_path / "one-shot.sqlite3")
    assert store.claim(
        action_id="one-shot", grant_id="grant", proof_id="proof",
        session_id="session", consumed_at=1.0,
    )
    assert not store.begin(
        "one-shot", grant_id="wrong", proof_id="proof", session_id="session"
    )
    assert store.begin(
        "one-shot", grant_id="grant", proof_id="proof", session_id="session"
    )
    assert not store.begin(
        "one-shot", grant_id="grant", proof_id="proof", session_id="session"
    )
    store.close()


def test_unknown_jsonrpc_fields_fail_closed(harness):
    response = harness.shim.handle(
        {"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {"protocolVersion": 1}, "extra": True}
    )[0]
    assert response["error"]["code"] == -32600


def test_production_backend_rejects_non_governed_runtime():
    with pytest.raises(TypeError, match="exact GovernedRuntime"):
        GovernedRuntimeBackend(object())


def test_stdio_runner_emits_newline_delimited_json(harness):
    source = io.StringIO(
        json.dumps(
            {"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {"protocolVersion": 1}}
        )
        + "\n"
    )
    sink = io.StringIO()
    serve_stdio(harness.shim, input_stream=source, output_stream=sink)
    lines = sink.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["id"] == 9


def test_stdio_runner_returns_parse_error(harness):
    source = io.StringIO("not-json\n")
    sink = io.StringIO()
    serve_stdio(harness.shim, input_stream=source, output_stream=sink)
    response = json.loads(sink.getvalue())
    assert response["id"] is None
    assert response["error"]["code"] == -32700
