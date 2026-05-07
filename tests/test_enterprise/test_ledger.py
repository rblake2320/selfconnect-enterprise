"""tests/test_enterprise/test_ledger.py — Unit tests for enterprise.ledger

Uses real ed25519 cryptography with mocked DPAPI — produces real signed chains.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from enterprise.identity import AgentIdentity
from enterprise.ledger import GENESIS_HASH, AgentLedger

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
