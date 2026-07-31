"""Durable agent/grant revocation lifecycle tests."""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from enterprise.acp_auth import ACPTrustStore
from enterprise.acp_shim import RevocationSnapshot
from enterprise.identity import AgentIdentity
from enterprise.revocation import RevocationRegistry, RevocationWatcher


def test_revoke_agent_is_durable_and_does_not_name_human_identity(tmp_path):
    path = tmp_path / "revocations.sqlite3"
    first = RevocationRegistry(path)
    assert first.revoke_agent("SC-AGENT-1", operator_id="OWNER:RON", reason="compromise", revoked_at=1.0) == 1
    first.close()
    second = RevocationRegistry(path)
    state = second.snapshot()
    assert state.revoked_agent_ids == {"SC-AGENT-1"}
    assert state.revoked_grant_ids == set()
    columns = [row[1] for row in second._connection.execute("PRAGMA table_info(revocation)")]
    assert "human_id" not in columns
    assert "owner_key" not in columns
    second.close()


def test_revoking_agent_preserves_enrolled_human_owner_key(tmp_path):
    with patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value):
        owner = AgentIdentity.init("owner-stays", data_dir=tmp_path / "identities")
    trust = ACPTrustStore(tmp_path / "owner-trust.sqlite3")
    fingerprint = trust.enroll_with_signer(
        principal="OWNER:RON",
        signer=owner,
        now=1.0,
        confirm=lambda _prompt: True,
    )
    registry = RevocationRegistry(tmp_path / "agent-revocations.sqlite3")
    registry.revoke_agent("SC-COMPROMISED", operator_id="OWNER:RON", reason="replace agent", revoked_at=2.0)
    assert trust.resolve_key(fingerprint) == owner.public_key_bytes
    assert trust.has_active_root()
    registry.close()
    trust.close()


def test_repeated_revocation_is_idempotent_without_epoch_inflation(tmp_path):
    registry = RevocationRegistry(tmp_path / "idempotent.sqlite3")
    first = registry.revoke_agent("SC-1", operator_id="OP-1", reason="risk", revoked_at=1.0)
    second = registry.revoke_agent("SC-1", operator_id="OP-2", reason="repeat", revoked_at=2.0)
    assert first == second == 1
    assert registry.snapshot().epoch == 1
    registry.close()


def test_agent_and_grant_revocations_advance_one_monotonic_epoch(tmp_path):
    registry = RevocationRegistry(tmp_path / "epoch.sqlite3")
    assert registry.revoke_agent("SC-1", operator_id="OP", reason="risk", revoked_at=1.0) == 1
    assert registry.revoke_grant("grant-1", operator_id="OP", reason="scope", revoked_at=2.0) == 2
    state = registry.snapshot()
    assert state.epoch == 2
    assert state.revoked_agent_ids == {"SC-1"}
    assert state.revoked_grant_ids == {"grant-1"}
    registry.close()


def test_registry_provides_exact_acp_snapshot(tmp_path):
    registry = RevocationRegistry(tmp_path / "acp.sqlite3")
    registry.revoke_agent("SC-1", operator_id="OP", reason="risk", revoked_at=1.0)
    snapshot = registry.acp_snapshot()
    assert type(snapshot) is RevocationSnapshot
    assert snapshot.epoch == 1
    assert snapshot.revoked_agent_ids == {"SC-1"}
    registry.close()


@pytest.mark.parametrize("target", ["", "bad\nvalue", "x" * 1_025])
def test_invalid_agent_identifier_is_rejected(tmp_path, target):
    registry = RevocationRegistry(tmp_path / "invalid.sqlite3")
    with pytest.raises(ValueError, match="target_id"):
        registry.revoke_agent(target, operator_id="OP", reason="risk", revoked_at=1.0)
    assert registry.snapshot().epoch == 0
    registry.close()


class _RefreshTarget:
    def __init__(self) -> None:
        self.snapshots = []

    def apply_revocations(self, snapshot):
        self.snapshots.append(snapshot)
        return ("removed-session",) if snapshot.revoked_agent_ids else ()


def test_watcher_applies_only_new_epochs(tmp_path):
    registry = RevocationRegistry(tmp_path / "watch.sqlite3")
    target = _RefreshTarget()
    watcher = RevocationWatcher(registry, target)
    assert watcher.poll_once() == ()
    assert watcher.poll_once() == ()
    assert len(target.snapshots) == 1
    registry.revoke_agent("SC-1", operator_id="OP", reason="risk", revoked_at=1.0)
    assert watcher.poll_once() == ("removed-session",)
    assert watcher.last_epoch == 1
    registry.close()


def test_background_watcher_observes_cross_connection_update(tmp_path):
    path = tmp_path / "cross-process.sqlite3"
    reader = RevocationRegistry(path)
    writer = RevocationRegistry(path)
    target = _RefreshTarget()
    watcher = RevocationWatcher(reader, target, poll_interval=0.05)
    watcher.start()
    try:
        writer.revoke_agent("SC-2", operator_id="OP", reason="risk", revoked_at=1.0)
        deadline = time.time() + 2.0
        while watcher.last_epoch < 1 and time.time() < deadline:
            time.sleep(0.01)
        assert watcher.last_epoch == 1
        assert target.snapshots[-1].revoked_agent_ids == {"SC-2"}
        assert watcher.last_error is None
    finally:
        watcher.stop()
        writer.close()
        reader.close()


def test_watcher_records_bounded_health_error(tmp_path):
    registry = RevocationRegistry(tmp_path / "health.sqlite3")
    target = _RefreshTarget()
    target.apply_revocations = lambda _snapshot: (_ for _ in ()).throw(RuntimeError("secret detail"))
    watcher = RevocationWatcher(registry, target, poll_interval=0.05)
    watcher.start()
    try:
        deadline = time.time() + 1.0
        while watcher.last_error is None and time.time() < deadline:
            time.sleep(0.01)
        assert watcher.last_error == "RuntimeError"
        assert "secret detail" not in watcher.last_error
    finally:
        watcher.stop()
        registry.close()
