"""Proof-of-possession and ACP terminal-authentication tests."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from enterprise.acp_auth import ACPTrustStore
from enterprise.acp_shim import ACPShim, RevocationSnapshot, SQLiteActionReplayStore
from enterprise.identity import AgentIdentity


def _identity(tmp_path, name: str) -> AgentIdentity:
    with (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda value: value[4:]),
    ):
        return AgentIdentity.init(name, data_dir=tmp_path)


class _Backend:
    def call_tool(self, name: str, arguments: dict) -> dict:
        return {"name": name, "arguments": arguments}


def _initialize(shim: ACPShim, *, terminal: bool) -> dict:
    capabilities = {"auth": {"terminal": terminal}} if terminal else {}
    return shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": 1, "clientCapabilities": capabilities},
        }
    )[0]


def _shim(tmp_path, trust: ACPTrustStore, owner: AgentIdentity) -> tuple[ACPShim, SQLiteActionReplayStore]:
    replay = SQLiteActionReplayStore(tmp_path / "auth-replay.sqlite3")
    shim = ACPShim(
        backend=_Backend(),
        replay_store=replay,
        issuer_resolver=trust.resolve_key,
        revocation_provider=lambda: RevocationSnapshot(epoch=0),
        clock=lambda: 1_000.0,
        auth_store=trust,
        terminal_setup_args=("--setup", "--trust-store", "configured-by-deployment"),
    )
    return shim, replay


def test_owner_possession_proof_enrolls_only_public_key(tmp_path):
    owner = _identity(tmp_path, "auth-owner")
    store = ACPTrustStore(tmp_path / "trust.sqlite3")
    prompts: list[str] = []
    fingerprint = store.enroll_with_signer(
        principal="OWNER:RON",
        signer=owner,
        now=1_000.0,
        confirm=lambda prompt: prompts.append(prompt) or True,
    )
    assert prompts == [f"ENROLL OWNER:RON {fingerprint[:16]}"]
    assert store.has_active_root()
    assert store.resolve_key(fingerprint) == owner.public_key_bytes
    columns = [row[1] for row in store._connection.execute("PRAGMA table_info(acp_owner_trust_root)")]
    assert "private_key" not in columns
    store.close()


def test_enrollment_requires_explicit_confirmation(tmp_path):
    owner = _identity(tmp_path, "denied-owner")
    store = ACPTrustStore(tmp_path / "denied.sqlite3")
    with pytest.raises(PermissionError, match="not confirmed"):
        store.enroll_with_signer(
            principal="OWNER:RON", signer=owner, now=1_000.0, confirm=lambda _prompt: False
        )
    assert not store.has_active_root()
    store.close()


def test_forged_possession_signature_is_rejected(tmp_path):
    owner = _identity(tmp_path, "real-owner")
    attacker = _identity(tmp_path, "attacker")

    class ForgedSigner:
        public_key_bytes = owner.public_key_bytes

        @staticmethod
        def sign(payload: bytes) -> bytes:
            return attacker.sign(payload)

    store = ACPTrustStore(tmp_path / "forged.sqlite3")
    with pytest.raises(PermissionError, match="possession proof failed"):
        store.enroll_with_signer(
            principal="OWNER:RON", signer=ForgedSigner(), now=1_000.0, confirm=lambda _prompt: True
        )
    assert not store.has_active_root()
    store.close()


def test_enrollment_survives_restart_and_can_be_deactivated(tmp_path):
    owner = _identity(tmp_path, "durable-owner")
    path = tmp_path / "durable-trust.sqlite3"
    first = ACPTrustStore(path)
    fingerprint = first.enroll_with_signer(
        principal="OWNER:RON", signer=owner, now=1_000.0, confirm=lambda _prompt: True
    )
    first.close()
    second = ACPTrustStore(path)
    assert second.resolve_key(fingerprint) == owner.public_key_bytes
    assert second.deactivate(fingerprint)
    assert second.resolve_key(fingerprint) is None
    assert not second.has_active_root()
    second.close()


def test_terminal_auth_advertised_only_to_capable_client(tmp_path):
    owner = _identity(tmp_path, "capability-owner")
    trust = ACPTrustStore(tmp_path / "capability.sqlite3")
    shim, replay = _shim(tmp_path, trust, owner)
    without = _initialize(shim, terminal=False)["result"]
    assert without["authMethods"] == []
    with_terminal = _initialize(shim, terminal=True)["result"]
    assert with_terminal["authMethods"] == [
        {
            "id": "selfconnect-owner-enrollment",
            "name": "Enroll SelfConnect owner key",
            "description": "Prove owner-key possession in an interactive terminal setup",
            "type": "terminal",
            "args": ["--setup", "--trust-store", "configured-by-deployment"],
            "env": {},
        }
    ]
    replay.close()
    trust.close()


def test_session_creation_requires_completed_terminal_setup(tmp_path):
    owner = _identity(tmp_path, "gated-owner")
    trust = ACPTrustStore(tmp_path / "gated.sqlite3")
    shim, replay = _shim(tmp_path, trust, owner)
    _initialize(shim, terminal=True)
    denied = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": {"cwd": "C:\\workspace", "mcpServers": []},
        }
    )[0]
    assert denied["error"] == {"code": -32000, "message": "authentication required"}
    trust.enroll_with_signer(
        principal="OWNER:RON", signer=owner, now=1_000.0, confirm=lambda _prompt: True
    )
    allowed = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/new",
            "params": {"cwd": "C:\\workspace", "mcpServers": []},
        }
    )[0]
    assert "sessionId" in allowed["result"]
    replay.close()
    trust.close()


def test_deactivated_owner_forces_authentication_again(tmp_path):
    owner = _identity(tmp_path, "revoked-owner")
    trust = ACPTrustStore(tmp_path / "revoked.sqlite3")
    fingerprint = trust.enroll_with_signer(
        principal="OWNER:RON", signer=owner, now=1_000.0, confirm=lambda _prompt: True
    )
    shim, replay = _shim(tmp_path, trust, owner)
    _initialize(shim, terminal=True)
    assert trust.deactivate(fingerprint)
    denied = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": {"cwd": "C:\\workspace", "mcpServers": []},
        }
    )[0]
    assert denied["error"]["code"] == -32000
    replay.close()
    trust.close()


def test_deactivation_terminates_existing_session(tmp_path):
    owner = _identity(tmp_path, "active-session-owner")
    trust = ACPTrustStore(tmp_path / "active-session.sqlite3")
    fingerprint = trust.enroll_with_signer(
        principal="OWNER:RON", signer=owner, now=1_000.0, confirm=lambda _prompt: True
    )
    shim, replay = _shim(tmp_path, trust, owner)
    _initialize(shim, terminal=True)
    session_id = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": {"cwd": "C:\\workspace", "mcpServers": []},
        }
    )[0]["result"]["sessionId"]

    assert trust.deactivate(fingerprint)
    denied = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/prompt",
            "params": {"sessionId": session_id, "prompt": [{"type": "text", "text": "{}"}]},
        }
    )[0]
    assert denied["error"] == {"code": -32000, "message": "authentication required"}

    trust.enroll_with_signer(
        principal="OWNER:RON", signer=owner, now=1_001.0, confirm=lambda _prompt: True
    )
    stale = shim.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "session/prompt",
            "params": {"sessionId": session_id, "prompt": [{"type": "text", "text": "{}"}]},
        }
    )[0]
    assert stale["error"] == {"code": -32001, "message": "unknown session"}
    replay.close()
    trust.close()
