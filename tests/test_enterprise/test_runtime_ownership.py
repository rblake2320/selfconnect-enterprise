from __future__ import annotations

import os
import subprocess
import sys

import pytest

import enterprise.runtime_ownership as runtime_ownership
from enterprise.runtime_ownership import RuntimeOwnershipError, RuntimeOwnershipLock


def test_second_process_cannot_own_same_ledger_and_approval_pair(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    script = (
        "import sys; from pathlib import Path; "
        "from enterprise.runtime_ownership import RuntimeOwnershipLock; "
        "lock=RuntimeOwnershipLock(Path(sys.argv[1]),Path(sys.argv[2])); "
        "print('READY',flush=True); sys.stdin.readline(); lock.close()"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(ledger), str(approvals)],
        cwd=str(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(__import__("pathlib").Path.cwd())},
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "READY"
        with pytest.raises(RuntimeOwnershipError, match="already has a writer"):
            RuntimeOwnershipLock(ledger, approvals)
    finally:
        assert child.stdin is not None
        child.stdin.write("stop\n")
        child.stdin.flush()
        child.wait(timeout=10)
    with RuntimeOwnershipLock(ledger, approvals):
        pass


def test_same_ledger_cannot_be_recombined_with_another_approval_store(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    approvals_a = tmp_path / "approvals-a.sqlite3"
    approvals_b = tmp_path / "approvals-b.sqlite3"
    with RuntimeOwnershipLock(ledger, approvals_a):
        with pytest.raises(RuntimeOwnershipError, match="resource already has a writer"):
            RuntimeOwnershipLock(ledger, approvals_b)


def test_same_approval_store_cannot_be_recombined_with_another_ledger(tmp_path):
    ledger_a = tmp_path / "ledger-a.jsonl"
    ledger_b = tmp_path / "ledger-b.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    with RuntimeOwnershipLock(ledger_a, approvals):
        with pytest.raises(RuntimeOwnershipError, match="resource already has a writer"):
            RuntimeOwnershipLock(ledger_b, approvals)


def test_hardlink_alias_cannot_create_another_resource_identity(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"existing-ledger")
    alias = tmp_path / "ledger-alias.jsonl"
    try:
        os.link(ledger, alias)
    except OSError as exc:  # pragma: no cover - filesystem capability boundary
        pytest.skip(f"hard links unavailable: {exc}")

    with RuntimeOwnershipLock(ledger, tmp_path / "approvals-a.sqlite3"):
        with pytest.raises(RuntimeOwnershipError, match="resource already has a writer"):
            RuntimeOwnershipLock(alias, tmp_path / "approvals-b.sqlite3")


def test_cross_resource_hardlink_created_after_acquisition_fails_binding(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    with RuntimeOwnershipLock(ledger, approvals) as lock:
        ledger.write_bytes(b"new-ledger")
        try:
            os.link(ledger, approvals)
        except OSError as exc:  # pragma: no cover - filesystem capability boundary
            pytest.skip(f"hard links unavailable: {exc}")
        with pytest.raises(RuntimeOwnershipError, match="distinct persistence resources"):
            lock.bind_opened_resources()


def test_path_substitution_during_startup_binding_fails_closed(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    ledger.write_bytes(b"ledger")
    approvals.write_bytes(b"approvals")
    lock = RuntimeOwnershipLock(ledger, approvals)
    original = runtime_ownership._resource_identities
    calls = [0]

    def unstable(path):
        calls[0] += 1
        identities = original(path)
        if calls[0] == 3:
            return (*identities, "file:substituted-during-binding")
        return identities

    monkeypatch.setattr(runtime_ownership, "_resource_identities", unstable)
    try:
        with pytest.raises(RuntimeOwnershipError, match="changed during startup binding"):
            lock.bind_opened_resources()
    finally:
        lock.close()
