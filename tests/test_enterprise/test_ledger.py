"""tests/test_enterprise/test_ledger.py — Unit tests for enterprise.ledger

Uses real ed25519 cryptography with mocked DPAPI — produces real signed chains.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from enterprise.identity import AgentIdentity
from enterprise.ledger import GENESIS_HASH, AgentLedger, LedgerIntegrityError

AGENT_NAME = "ledger-test-agent"


# ── Test fixtures ──────────────────────────────────────────────────────────────

def _mock_dpapi():
    return (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda b: b"ENC:" + b),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda b: b[4:]),
    )


def make_identity(tmp_path: Path) -> AgentIdentity:
    enc, dec = _mock_dpapi()
    with enc, dec:
        return AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)


def make_ledger(tmp_path: Path, identity: AgentIdentity = None) -> AgentLedger:
    if identity is None:
        identity = make_identity(tmp_path)
    log_path = tmp_path / "test_ledger.jsonl"
    return AgentLedger(identity, log_path=log_path)


# ── log() ──────────────────────────────────────────────────────────────────────

class TestLog:
    def test_creates_log_file(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.log("booted", result="ok")
        assert ledger.log_path.exists()

    def test_entry_has_required_fields(self, tmp_path):
        ledger = make_ledger(tmp_path)
        entry = ledger.log("test action", result="done")
        for field in ("seq", "agent_id", "action", "result", "ts", "prev_hash", "sig"):
            assert field in entry, f"missing field: {field}"

    def test_seq_increments(self, tmp_path):
        ledger = make_ledger(tmp_path)
        e1 = ledger.log("first")
        e2 = ledger.log("second")
        e3 = ledger.log("third")
        assert e1["seq"] == 1
        assert e2["seq"] == 2
        assert e3["seq"] == 3

    def test_partial_append_failure_restores_tail_for_retry_and_restart(
        self, tmp_path, monkeypatch
    ):
        identity = make_identity(tmp_path)
        ledger = make_ledger(tmp_path, identity)
        original_open = Path.open
        failed = False

        class PartialWriter:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                self.handle.__enter__()
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def write(self, value):
                self.handle.write(value[: max(1, len(value) // 2)])
                self.handle.flush()
                raise OSError("simulated partial append")

            def __getattr__(self, name):
                return getattr(self.handle, name)

        def failing_open(path, mode="r", *args, **kwargs):
            nonlocal failed
            handle = original_open(path, mode, *args, **kwargs)
            if path == ledger.log_path and mode == "a" and not failed:
                failed = True
                return PartialWriter(handle)
            return handle

        monkeypatch.setattr(Path, "open", failing_open)
        with pytest.raises(OSError, match="partial append"):
            ledger.log("first")
        assert ledger.entry_count() == 0
        first = ledger.log("retry")
        assert first["seq"] == 1
        restarted = AgentLedger(identity, log_path=ledger.log_path)
        second = restarted.log("after-restart")
        assert second["seq"] == 2
        assert restarted.verify()[0]

    def test_fsync_failure_does_not_publish_sequence(self, tmp_path, monkeypatch):
        ledger = make_ledger(tmp_path)
        import enterprise.ledger as ledger_module

        real_fsync = ledger_module.os.fsync
        calls = 0

        def fail_once(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated fsync failure")
            return real_fsync(fd)

        monkeypatch.setattr(ledger_module.os, "fsync", fail_once)
        with pytest.raises(OSError, match="fsync failure"):
            ledger.log("not-durable")
        assert ledger.entry_count() == 0
        assert ledger.log("durable")["seq"] == 1
        assert ledger.verify()[0]

    def test_nested_index_rejects_wrong_metadata_type(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.log("bad", metadata={"approval_audit": "not-an-object"})
        with pytest.raises(LedgerIntegrityError, match="must be an object"):
            ledger.find_entries_by_nested_value("approval_audit", "event_id", "event")

    def test_first_entry_uses_genesis_hash(self, tmp_path):
        ledger = make_ledger(tmp_path)
        entry = ledger.log("boot")
        assert entry["prev_hash"] == GENESIS_HASH

    def test_second_entry_prev_hash_matches_first(self, tmp_path):
        ledger = make_ledger(tmp_path)
        e1 = ledger.log("first")
        e2 = ledger.log("second")
        # Recompute hash of e1 (without sig field)
        e1_copy = dict(e1)
        e1_copy.pop("sig")
        e1_bytes = json.dumps(e1_copy, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(e1_bytes).hexdigest()
        assert e2["prev_hash"] == expected

    def test_agent_id_matches_identity(self, tmp_path):
        identity = make_identity(tmp_path)
        ledger = make_ledger(tmp_path, identity)
        entry = ledger.log("action")
        assert entry["agent_id"] == identity.agent_id

    def test_sig_is_hex_string(self, tmp_path):
        ledger = make_ledger(tmp_path)
        entry = ledger.log("action")
        sig_bytes = bytes.fromhex(entry["sig"])
        assert len(sig_bytes) == 64

    def test_metadata_merged_into_entry(self, tmp_path):
        ledger = make_ledger(tmp_path)
        entry = ledger.log("act", metadata={"target_hwnd": 0xABC})
        assert entry["target_hwnd"] == 0xABC

    @pytest.mark.parametrize("field", ["seq", "agent_id", "action", "result", "ts", "prev_hash", "sig"])
    def test_reserved_metadata_cannot_overwrite_signed_core(self, tmp_path, field):
        ledger = make_ledger(tmp_path)
        with pytest.raises(ValueError, match="reserved ledger fields"):
            ledger.log("act", metadata={field: "attacker-controlled"})
        assert ledger.entry_count() == 0

    def test_appends_to_file(self, tmp_path):
        ledger = make_ledger(tmp_path)
        for i in range(5):
            ledger.log(f"action-{i}")
        lines = [ln for ln in ledger.log_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 5


# ── verify() ──────────────────────────────────────────────────────────────────

class TestVerify:
    def test_empty_ledger_is_valid(self, tmp_path):
        ledger = make_ledger(tmp_path)
        valid, count, _msg = ledger.verify()
        assert valid is True
        assert count == 0

    def test_single_entry_is_valid(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.log("boot")
        valid, count, _msg = ledger.verify()
        assert valid is True
        assert count == 1

    def test_many_entries_all_valid(self, tmp_path):
        ledger = make_ledger(tmp_path)
        for i in range(10):
            ledger.log(f"action-{i}", result=str(i))
        valid, count, _msg = ledger.verify()
        assert valid is True
        assert count == 10

    def test_tampered_entry_detected(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.log("legit action", result="ok")
        ledger.log("second action", result="ok")

        # Tamper: rewrite line 1 to change the action text
        lines = ledger.log_path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["action"] = "TAMPERED"
        lines[0] = json.dumps(entry)
        ledger.log_path.write_text("\n".join(lines) + "\n")

        valid, _count, msg = ledger.verify()
        assert valid is False
        assert "signature invalid" in msg or "chain broken" in msg

    def test_deleted_entry_detected(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.log("entry-1")
        ledger.log("entry-2")
        ledger.log("entry-3")

        # Delete entry-2 — breaks chain for entry-3
        lines = [ln for ln in ledger.log_path.read_text().splitlines() if ln.strip()]
        lines.pop(1)  # remove entry-2
        ledger.log_path.write_text("\n".join(lines) + "\n")

        valid, _, _ = ledger.verify()
        assert valid is False

    def test_sig_field_tampered_detected(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.log("action")

        lines = ledger.log_path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["sig"] = "00" * 64  # replace with all-zeros sig
        lines[0] = json.dumps(entry)
        ledger.log_path.write_text("\n".join(lines) + "\n")

        valid, _, msg = ledger.verify()
        assert valid is False
        assert "signature invalid" in msg

    def test_verify_returns_count(self, tmp_path):
        ledger = make_ledger(tmp_path)
        for _ in range(7):
            ledger.log("x")
        valid, count, _ = ledger.verify()
        assert valid is True
        assert count == 7


# ── Continuity across instances ────────────────────────────────────────────────

class TestContinuity:
    def test_new_instance_continues_chain(self, tmp_path):
        identity = make_identity(tmp_path)
        log_path = tmp_path / "chain.jsonl"

        # First session
        ledger1 = AgentLedger(identity, log_path=log_path)
        ledger1.log("session-1-boot")
        ledger1.log("session-1-action")

        # Second session (simulates restart)
        ledger2 = AgentLedger(identity, log_path=log_path)
        ledger2.log("session-2-boot")
        ledger2.log("session-2-action")

        valid, count, _msg = ledger2.verify()
        assert valid is True
        assert count == 4

    def test_seq_continues_from_last(self, tmp_path):
        identity = make_identity(tmp_path)
        log_path = tmp_path / "seq.jsonl"

        ledger1 = AgentLedger(identity, log_path=log_path)
        ledger1.log("a")
        ledger1.log("b")  # seq=2

        ledger2 = AgentLedger(identity, log_path=log_path)
        entry = ledger2.log("c")  # should be seq=3
        assert entry["seq"] == 3


class TestSegmentLifecycle:
    def test_rotation_preserves_cross_segment_chain_and_tail(self, tmp_path):
        identity = make_identity(tmp_path)
        ledger = AgentLedger(
            identity,
            log_path=tmp_path / "rotating.jsonl",
            max_entries_per_segment=2,
        )
        for index in range(5):
            ledger.log(f"action-{index}")

        assert len(ledger.archive_paths) == 2
        assert ledger.entry_count() == 5
        assert [entry["seq"] for entry in ledger.tail(3)] == [3, 4, 5]
        assert ledger.verify()[:2] == (True, 5)

    def test_restart_continues_after_segment_rotation(self, tmp_path):
        identity = make_identity(tmp_path)
        log_path = tmp_path / "restart-rotating.jsonl"
        first = AgentLedger(
            identity,
            log_path=log_path,
            max_entries_per_segment=2,
        )
        for index in range(4):
            first.log(f"before-{index}")

        second = AgentLedger(
            identity,
            log_path=log_path,
            max_entries_per_segment=2,
        )
        entry = second.log("after-restart")
        assert entry["seq"] == 5
        assert second.verify()[:2] == (True, 5)

    def test_missing_archived_segment_is_detected(self, tmp_path):
        identity = make_identity(tmp_path)
        ledger = AgentLedger(
            identity,
            log_path=tmp_path / "missing-segment.jsonl",
            max_entries_per_segment=2,
        )
        for index in range(7):
            ledger.log(f"action-{index}")
        assert len(ledger.archive_paths) == 3

        ledger.archive_paths[1].unlink()
        valid, _, message = ledger.verify()
        assert valid is False
        assert "sequence mismatch" in message or "hash chain broken" in message

    def test_corrupt_existing_tail_refuses_resume(self, tmp_path):
        identity = make_identity(tmp_path)
        log_path = tmp_path / "corrupt-resume.jsonl"
        ledger = AgentLedger(identity, log_path=log_path)
        ledger.log("valid")
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write('{"incomplete":')

        with pytest.raises(LedgerIntegrityError, match="refusing to resume"):
            AgentLedger(identity, log_path=log_path)

    def test_byte_limit_rotates_before_next_append(self, tmp_path):
        identity = make_identity(tmp_path)
        ledger = AgentLedger(
            identity,
            log_path=tmp_path / "byte-limit.jsonl",
            max_bytes_per_segment=1,
        )
        ledger.log("first")
        ledger.log("second")
        assert len(ledger.archive_paths) == 1
        assert ledger.verify()[:2] == (True, 2)


# ── tail() and entry_count() ──────────────────────────────────────────────────

class TestTailCount:
    def test_tail_empty_returns_empty(self, tmp_path):
        ledger = make_ledger(tmp_path)
        assert ledger.tail() == []

    def test_tail_returns_n_entries(self, tmp_path):
        ledger = make_ledger(tmp_path)
        for i in range(5):
            ledger.log(f"action-{i}")
        result = ledger.tail(3)
        assert len(result) == 3

    def test_tail_returns_last_entries(self, tmp_path):
        ledger = make_ledger(tmp_path)
        for i in range(5):
            ledger.log(f"action-{i}")
        result = ledger.tail(2)
        actions = [e["action"] for e in result]
        assert "action-3" in actions
        assert "action-4" in actions

    def test_entry_count_zero_when_empty(self, tmp_path):
        ledger = make_ledger(tmp_path)
        assert ledger.entry_count() == 0

    def test_entry_count_correct(self, tmp_path):
        ledger = make_ledger(tmp_path)
        for _ in range(6):
            ledger.log("x")
        assert ledger.entry_count() == 6

# ── ThreadSafeAgentLedger tests (G-6 fix) ─────────────────────────────────────

import threading as _threading
from enterprise.ledger import ThreadSafeAgentLedger


def _make_ts_ledger(tmp_path: Path) -> ThreadSafeAgentLedger:
    """Helper: create a ThreadSafeAgentLedger with mocked DPAPI."""
    identity = make_identity(tmp_path)
    return ThreadSafeAgentLedger(identity, log_path=tmp_path / "ts_ledger.jsonl")


class TestThreadSafeAgentLedger:
    """Tests for ThreadSafeAgentLedger (G-6 / MED-05 fix).

    Verifies that the RLock wrapper correctly serialises concurrent writes
    and that the hash chain remains intact after concurrent access.
    """

    def test_is_subclass_of_agent_ledger(self, tmp_path):
        ledger = _make_ts_ledger(tmp_path)
        assert isinstance(ledger, AgentLedger)

    def test_single_write(self, tmp_path):
        ledger = _make_ts_ledger(tmp_path)
        entry = ledger.log("single-action", result="ok")
        assert entry["seq"] == 1
        assert entry["action"] == "single-action"

    def test_concurrent_writes_chain_intact(self, tmp_path):
        """20 threads write concurrently; chain must remain valid."""
        ledger = _make_ts_ledger(tmp_path)
        errors = []

        def write(i):
            try:
                ledger.log(f"action-{i}", result=f"result-{i}")
            except Exception as exc:
                errors.append(str(exc))

        threads = [_threading.Thread(target=write, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent write errors: {errors}"
        valid, count, msg = ledger.verify()
        assert valid, msg
        assert count == 20

    def test_concurrent_writes_seq_unique(self, tmp_path):
        """Sequence numbers must be unique after concurrent writes."""
        ledger = _make_ts_ledger(tmp_path)

        def write(i):
            ledger.log(f"action-{i}")

        threads = [_threading.Thread(target=write, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        entries = ledger.tail(10)
        seqs = [e["seq"] for e in entries]
        assert len(set(seqs)) == 10, f"Duplicate seq numbers: {seqs}"

    def test_thread_safe_verify(self, tmp_path):
        ledger = _make_ts_ledger(tmp_path)
        for i in range(5):
            ledger.log(f"a-{i}")
        valid, count, _ = ledger.verify()
        assert valid
        assert count == 5

    def test_thread_safe_tail(self, tmp_path):
        ledger = _make_ts_ledger(tmp_path)
        for i in range(5):
            ledger.log(f"a-{i}")
        result = ledger.tail(3)
        assert len(result) == 3

    def test_thread_safe_entry_count(self, tmp_path):
        ledger = _make_ts_ledger(tmp_path)
        for _ in range(7):
            ledger.log("x")
        assert ledger.entry_count() == 7
