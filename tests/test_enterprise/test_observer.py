"""tests/test_enterprise/test_observer.py — Unit tests for observer and learning pipeline

Pure logic tests: no NCrypt calls, no subprocess side effects.
TrainingTrigger._fire() is tested with a mock command that never executes.
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

from enterprise.observer import (
    EvidenceExporter,
    EvidenceRecord,
    LedgerObserver,
    ObserverFilter,
    RedactionConfig,
    ShadowHook,
    TrainingTrigger,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

AGENT_A = "SC-AAAA0001"
POLICY_1 = "test-policy-v1"
POLICY_2 = "test-policy-v2"


def _entry(
    seq: int,
    decision: str = "allow",
    action: str = "assign_task",
    classification: str = "UNCLASSIFIED",
    approval_mode: str = "autonomous",
    policy_id: str = POLICY_1,
    agent_id: str = AGENT_A,
    result: str = "ok",
    operator_id: str = "",
) -> dict:
    return {
        "seq": seq,
        "agent_id": agent_id,
        "action": action,
        "result": result,
        "ts": time.time(),
        "policy_id": policy_id,
        "classification": classification,
        "approval_mode": approval_mode,
        "decision": decision,
        "operator_id": operator_id,
    }


def _write_ledger(path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


# ── ObserverFilter ─────────────────────────────────────────────────────────────

class TestObserverFilter:
    def test_default_accepts_allow_entry(self):
        f = ObserverFilter()
        assert f.matches(_entry(1, decision="allow")) is True

    def test_default_rejects_deny(self):
        f = ObserverFilter()
        assert f.matches(_entry(1, decision="deny")) is False

    def test_default_rejects_quarantined(self):
        f = ObserverFilter()
        assert f.matches(_entry(1, decision="quarantined")) is False

    def test_seq_zero_rejected_by_default(self):
        f = ObserverFilter()
        assert f.matches(_entry(0)) is False

    def test_min_seq_respected(self):
        f = ObserverFilter(min_seq=5)
        assert f.matches(_entry(5)) is False   # <= min_seq
        assert f.matches(_entry(6)) is True

    def test_policy_id_whitelist_pass(self):
        f = ObserverFilter(allowed_policy_ids=[POLICY_1])
        assert f.matches(_entry(1, policy_id=POLICY_1)) is True

    def test_policy_id_whitelist_block(self):
        f = ObserverFilter(allowed_policy_ids=[POLICY_1])
        assert f.matches(_entry(1, policy_id=POLICY_2)) is False

    def test_empty_policy_id_whitelist_accepts_any(self):
        f = ObserverFilter(allowed_policy_ids=[])
        assert f.matches(_entry(1, policy_id=POLICY_2)) is True

    def test_max_classification_unclassified(self):
        f = ObserverFilter(max_classification="UNCLASSIFIED")
        assert f.matches(_entry(1, classification="UNCLASSIFIED")) is True
        assert f.matches(_entry(2, classification="CUI")) is False
        assert f.matches(_entry(3, classification="SECRET")) is False
        assert f.matches(_entry(4, classification="TOP_SECRET")) is False

    def test_max_classification_secret(self):
        f = ObserverFilter(max_classification="SECRET")
        assert f.matches(_entry(1, classification="SECRET")) is True
        assert f.matches(_entry(2, classification="TOP_SECRET")) is False

    def test_max_classification_top_secret(self):
        f = ObserverFilter(max_classification="TOP_SECRET")
        assert f.matches(_entry(1, classification="TOP_SECRET")) is True

    def test_action_whitelist_pass(self):
        f = ObserverFilter(allowed_actions=["assign_task"])
        assert f.matches(_entry(1, action="assign_task")) is True

    def test_action_whitelist_block(self):
        f = ObserverFilter(allowed_actions=["assign_task"])
        assert f.matches(_entry(1, action="read_text")) is False

    def test_empty_action_whitelist_accepts_any(self):
        f = ObserverFilter(allowed_actions=[])
        assert f.matches(_entry(1, action="anything")) is True

    def test_approval_mode_filter_autonomous(self):
        f = ObserverFilter(allowed_approval_modes=["autonomous"])
        assert f.matches(_entry(1, approval_mode="autonomous")) is True
        assert f.matches(_entry(2, approval_mode="human_approved")) is False

    def test_approval_mode_filter_human_approved(self):
        f = ObserverFilter(allowed_approval_modes=["human_approved"])
        assert f.matches(_entry(1, approval_mode="human_approved")) is True
        assert f.matches(_entry(2, approval_mode="autonomous")) is False

    def test_default_approval_modes_accept_both(self):
        f = ObserverFilter()
        assert f.matches(_entry(1, approval_mode="autonomous")) is True
        assert f.matches(_entry(2, approval_mode="human_approved")) is True

    def test_all_criteria_must_match(self):
        # All criteria satisfied
        f = ObserverFilter(
            allowed_decisions=["allow"],
            allowed_policy_ids=[POLICY_1],
            max_classification="SECRET",
            allowed_actions=["assign_task"],
            allowed_approval_modes=["autonomous"],
            min_seq=0,
        )
        assert f.matches(_entry(1)) is True

    def test_unknown_classification_treated_as_rank_minus1(self):
        # Unknown classification has rank -1 < UNCLASSIFIED rank 0 → always passes ceiling
        f = ObserverFilter(max_classification="UNCLASSIFIED")
        e = _entry(1)
        e["classification"] = "UNKNOWN_LEVEL"
        # rank -1 <= rank 0 → passes
        assert f.matches(e) is True


# ── RedactionConfig ────────────────────────────────────────────────────────────

class TestRedactionConfig:
    def test_no_redaction_returns_copy(self):
        r = RedactionConfig()
        e = _entry(1)
        result = r.apply(e)
        assert result == e
        assert result is not e  # must be a copy

    def test_remove_fields(self):
        r = RedactionConfig(remove_fields=["result", "operator_id"])
        e = _entry(1, result="sensitive", operator_id="CAC:123")
        result = r.apply(e)
        assert "result" not in result
        assert "operator_id" not in result
        assert "action" in result  # other fields preserved

    def test_remove_nonexistent_field_is_safe(self):
        r = RedactionConfig(remove_fields=["nonexistent_field"])
        e = _entry(1)
        result = r.apply(e)
        assert result == e

    def test_mask_fields(self):
        r = RedactionConfig(mask_fields={"result": "[REDACTED]", "operator_id": "[OP]"})
        e = _entry(1, result="secret output", operator_id="CAC:999")
        result = r.apply(e)
        assert result["result"] == "[REDACTED]"
        assert result["operator_id"] == "[OP]"

    def test_mask_nonexistent_field_is_safe(self):
        r = RedactionConfig(mask_fields={"nonexistent": "[X]"})
        e = _entry(1)
        result = r.apply(e)
        assert "nonexistent" not in result

    def test_input_not_mutated(self):
        r = RedactionConfig(remove_fields=["result"], mask_fields={"action": "[MASKED]"})
        e = _entry(1, result="original", action="assign_task")
        r.apply(e)
        assert e["result"] == "original"
        assert e["action"] == "assign_task"

    def test_remove_and_mask_combined(self):
        r = RedactionConfig(remove_fields=["operator_id"], mask_fields={"result": "[R]"})
        e = _entry(1, result="data", operator_id="CAC:1")
        result = r.apply(e)
        assert "operator_id" not in result
        assert result["result"] == "[R]"


# ── EvidenceRecord ─────────────────────────────────────────────────────────────

class TestEvidenceRecord:
    def _make_record(self, context_before=None) -> EvidenceRecord:
        return EvidenceRecord(
            seq=5,
            agent_id=AGENT_A,
            action="assign_task",
            result="dispatched",
            ts=1000.0,
            policy_id=POLICY_1,
            classification="UNCLASSIFIED",
            approval_mode="autonomous",
            decision="allow",
            operator_id="",
            context_before=context_before or [],
            raw={"seq": 5, "action": "assign_task"},
        )

    def test_to_alpaca_keys(self):
        rec = self._make_record()
        a = rec.to_alpaca()
        assert "instruction" in a
        assert "input" in a
        assert "output" in a
        assert "metadata" in a

    def test_to_alpaca_output_contains_action_and_result(self):
        rec = self._make_record()
        a = rec.to_alpaca()
        assert "assign_task" in a["output"]
        assert "dispatched" in a["output"]

    def test_to_alpaca_metadata_fields(self):
        rec = self._make_record()
        meta = rec.to_alpaca()["metadata"]
        assert meta["seq"] == 5
        assert meta["policy_id"] == POLICY_1
        assert meta["classification"] == "UNCLASSIFIED"
        assert meta["approval_mode"] == "autonomous"

    def test_to_alpaca_no_context_shows_start(self):
        rec = self._make_record(context_before=[])
        a = rec.to_alpaca()
        assert "(start)" in a["input"]

    def test_to_alpaca_context_joined_with_arrow(self):
        rec = self._make_record(context_before=[
            {"action": "init"},
            {"action": "read_text"},
        ])
        a = rec.to_alpaca()
        assert "init → read_text" in a["input"]

    def test_to_chat_keys(self):
        rec = self._make_record()
        c = rec.to_chat()
        assert "messages" in c
        assert "metadata" in c

    def test_to_chat_has_system_user_assistant(self):
        rec = self._make_record()
        roles = [m["role"] for m in rec.to_chat()["messages"]]
        assert roles == ["system", "user", "assistant"]

    def test_to_chat_assistant_content_contains_action_and_result(self):
        rec = self._make_record()
        msgs = rec.to_chat()["messages"]
        assistant = next(m for m in msgs if m["role"] == "assistant")
        assert "assign_task" in assistant["content"]
        assert "dispatched" in assistant["content"]

    def test_to_chat_system_contains_agent_and_policy(self):
        rec = self._make_record()
        msgs = rec.to_chat()["messages"]
        system = next(m for m in msgs if m["role"] == "system")
        assert AGENT_A in system["content"]
        assert POLICY_1 in system["content"]

    def test_to_chat_metadata_fields(self):
        rec = self._make_record()
        meta = rec.to_chat()["metadata"]
        assert meta["seq"] == 5
        assert meta["policy_id"] == POLICY_1


# ── LedgerObserver ─────────────────────────────────────────────────────────────

class TestLedgerObserver:
    def test_nonexistent_ledger_returns_empty(self, tmp_path):
        obs = LedgerObserver(tmp_path / "missing.jsonl", unsafe_unverified=True)
        assert obs.extract() == []

    def test_empty_ledger_returns_empty(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        p.write_text("")
        obs = LedgerObserver(p, unsafe_unverified=True)
        assert obs.extract() == []

    def test_single_allow_entry_extracted(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(1)])
        obs = LedgerObserver(p, unsafe_unverified=True)
        records = obs.extract()
        assert len(records) == 1
        assert records[0].seq == 1
        assert records[0].action == "assign_task"

    def test_deny_entries_excluded(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [
            _entry(1, decision="allow"),
            _entry(2, decision="deny"),
            _entry(3, decision="allow"),
        ])
        obs = LedgerObserver(p, unsafe_unverified=True)
        records = obs.extract()
        assert len(records) == 2
        assert {r.seq for r in records} == {1, 3}

    def test_since_seq_skips_old_entries(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(i) for i in range(1, 6)])
        obs = LedgerObserver(p, unsafe_unverified=True)
        records = obs.extract(since_seq=3)
        assert all(r.seq > 3 for r in records)
        assert len(records) == 2  # seq 4 and 5

    def test_context_window_populated(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        entries = [_entry(i) for i in range(1, 6)]
        _write_ledger(p, entries)
        obs = LedgerObserver(p, context_window=2, unsafe_unverified=True)
        records = obs.extract()
        # First record has no prior entries
        assert records[0].context_before == []
        # Fourth record (seq=4) has up to 2 prior: seq=2,3
        r4 = next(r for r in records if r.seq == 4)
        assert len(r4.context_before) == 2

    def test_context_window_zero(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(i) for i in range(1, 4)])
        obs = LedgerObserver(p, context_window=0, unsafe_unverified=True)
        records = obs.extract()
        for r in records:
            assert r.context_before == []

    def test_redaction_applied_to_records(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(1, operator_id="CAC:SECRET")])
        redact = RedactionConfig(remove_fields=["operator_id"])
        obs = LedgerObserver(p, redaction=redact, unsafe_unverified=True)
        records = obs.extract()
        # raw dict has redaction applied
        assert "operator_id" not in records[0].raw
        # EvidenceRecord fields are populated from the original entry (pre-redaction)
        assert records[0].operator_id == "CAC:SECRET"

    def test_redaction_applied_to_context_before(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        entries = [_entry(i, result=f"result-{i}") for i in range(1, 4)]
        _write_ledger(p, entries)
        redact = RedactionConfig(mask_fields={"result": "[R]"})
        obs = LedgerObserver(p, context_window=2, redaction=redact, unsafe_unverified=True)
        records = obs.extract()
        # Check context entries are redacted
        r3 = next(r for r in records if r.seq == 3)
        for ctx_entry in r3.context_before:
            assert ctx_entry.get("result") == "[R]"

    def test_max_seq_empty_file(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        p.write_text("")
        obs = LedgerObserver(p, unsafe_unverified=True)
        assert obs.max_seq() == 0

    def test_max_seq_nonexistent_file(self, tmp_path):
        obs = LedgerObserver(tmp_path / "missing.jsonl", unsafe_unverified=True)
        assert obs.max_seq() == 0

    def test_max_seq_returns_highest(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(3), _entry(1), _entry(7), _entry(2)])
        obs = LedgerObserver(p, unsafe_unverified=True)
        assert obs.max_seq() == 7

    def test_malformed_json_lines_skipped(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        with p.open("w") as fh:
            fh.write(json.dumps(_entry(1)) + "\n")
            fh.write("NOT_JSON\n")
            fh.write(json.dumps(_entry(2)) + "\n")
        obs = LedgerObserver(p, unsafe_unverified=True)
        records = obs.extract()
        assert len(records) == 2

    def test_blank_lines_skipped(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        with p.open("w") as fh:
            fh.write("\n")
            fh.write(json.dumps(_entry(1)) + "\n")
            fh.write("\n")
        obs = LedgerObserver(p, unsafe_unverified=True)
        assert len(obs.extract()) == 1

    def test_filter_by_policy_id(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [
            _entry(1, policy_id=POLICY_1),
            _entry(2, policy_id=POLICY_2),
        ])
        f = ObserverFilter(allowed_policy_ids=[POLICY_1])
        obs = LedgerObserver(p, observer_filter=f, unsafe_unverified=True)
        records = obs.extract()
        assert len(records) == 1
        assert records[0].policy_id == POLICY_1

    def test_observer_ledger_logged_on_extract(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(1)])
        mock_ledger = MagicMock()
        obs = LedgerObserver(p, observer_ledger=mock_ledger, unsafe_unverified=True)
        obs.extract()
        mock_ledger.log.assert_called_once()
        call_args = mock_ledger.log.call_args
        assert call_args[0][0] == "observer_extracted"

    def test_observer_ledger_not_called_when_no_records(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        _write_ledger(p, [_entry(1, decision="deny")])
        mock_ledger = MagicMock()
        obs = LedgerObserver(p, observer_ledger=mock_ledger, unsafe_unverified=True)
        obs.extract()
        mock_ledger.log.assert_not_called()

    def test_evidence_record_fields_populated(self, tmp_path):
        p = tmp_path / "ledger.jsonl"
        ts = 12345.0
        e = _entry(1)
        e["ts"] = ts
        _write_ledger(p, [e])
        obs = LedgerObserver(p, unsafe_unverified=True)
        rec = obs.extract()[0]
        assert rec.seq == 1
        assert rec.agent_id == AGENT_A
        assert rec.action == "assign_task"
        assert rec.result == "ok"
        assert rec.ts == ts
        assert rec.policy_id == POLICY_1
        assert rec.classification == "UNCLASSIFIED"
        assert rec.approval_mode == "autonomous"
        assert rec.decision == "allow"


# ── EvidenceExporter ───────────────────────────────────────────────────────────

class TestEvidenceExporter:
    def test_export_writes_jsonl(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1), _entry(2)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="alpaca")
        count = exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        assert count == 2
        lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
        assert len(lines) == 2

    def test_export_returns_zero_for_empty_result(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1, decision="deny")])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="alpaca")
        count = exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        assert count == 0
        assert not out.exists()

    def test_export_alpaca_format(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="alpaca")
        exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        record = json.loads(out.read_text().strip())
        assert "instruction" in record
        assert "input" in record
        assert "output" in record

    def test_export_chat_format(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="chat")
        exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        record = json.loads(out.read_text().strip())
        assert "messages" in record

    def test_export_raw_format(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="raw")
        exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        record = json.loads(out.read_text().strip())
        assert "seq" in record
        assert "action" in record

    def test_export_is_append_mode(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1), _entry(2), _entry(3)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="alpaca")
        exp.export_from_ledger(ledger_path, since_seq=0, unsafe_unverified=True)
        exp.export_from_ledger(ledger_path, since_seq=2, unsafe_unverified=True)  # only seq 3
        lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
        assert len(lines) == 4  # 3 from first run + 1 from second

    def test_export_creates_parent_dirs(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1)])
        out = tmp_path / "deep" / "nested" / "training.jsonl"
        exp = EvidenceExporter(out, fmt="raw")
        exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        assert out.exists()

    def test_record_count_zero_when_no_file(self, tmp_path):
        exp = EvidenceExporter(tmp_path / "missing.jsonl")
        assert exp.record_count() == 0

    def test_record_count_after_export(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(i) for i in range(1, 6)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="raw")
        exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        assert exp.record_count() == 5

    def test_observer_ledger_logged_on_export(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(1)])
        out = tmp_path / "training.jsonl"
        mock_ledger = MagicMock()
        exp = EvidenceExporter(out, observer_ledger=mock_ledger)
        exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        mock_ledger.log.assert_called_once()
        assert mock_ledger.log.call_args[0][0] == "evidence_exported"

    def test_since_seq_passed_through(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(i) for i in range(1, 6)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="raw")
        count = exp.export_from_ledger(ledger_path, since_seq=3, unsafe_unverified=True)
        assert count == 2  # seq 4 and 5


# ── TrainingTrigger ────────────────────────────────────────────────────────────

class TestTrainingTrigger:
    def test_does_not_fire_below_threshold(self):
        t = TrainingTrigger(threshold=100, command=["echo", "train"])
        with patch("subprocess.Popen") as mock_popen:
            fired = t.on_records(50)
            assert fired is False
            mock_popen.assert_not_called()

    def test_fires_at_threshold(self):
        t = TrainingTrigger(threshold=10, command=["echo", "train"])
        with patch("subprocess.Popen") as mock_popen:
            fired = t.on_records(10)
            assert fired is True
            mock_popen.assert_called_once_with(["echo", "train"])

    def test_fires_above_threshold(self):
        t = TrainingTrigger(threshold=10, command=["echo", "train"])
        with patch("subprocess.Popen") as mock_popen:
            fired = t.on_records(15)
            assert fired is True
            mock_popen.assert_called_once()

    def test_accumulates_across_calls(self):
        t = TrainingTrigger(threshold=10, command=["echo", "train"])
        with patch("subprocess.Popen") as mock_popen:
            t.on_records(4)
            t.on_records(3)
            assert t.accumulated == 7
            t.on_records(3)  # total = 10 → fires
            mock_popen.assert_called_once()

    def test_accumulator_resets_after_fire(self):
        t = TrainingTrigger(threshold=5, command=["echo", "train"])
        with patch("subprocess.Popen"):
            t.on_records(5)  # fires
            assert t.accumulated == 0

    def test_accumulator_property_returns_current(self):
        t = TrainingTrigger(threshold=100, command=["echo", "x"])
        t.on_records(30)
        assert t.accumulated == 30
        t.on_records(25)
        assert t.accumulated == 55

    def test_overflow_fires_once_and_resets(self):
        t = TrainingTrigger(threshold=10, command=["echo", "train"])
        with patch("subprocess.Popen") as mock_popen:
            t.on_records(100)  # way over threshold
            mock_popen.assert_called_once()
            assert t.accumulated == 0

    def test_observer_ledger_logged_on_fire(self):
        mock_ledger = MagicMock()
        t = TrainingTrigger(threshold=1, command=["echo", "train"], observer_ledger=mock_ledger)
        with patch("subprocess.Popen"):
            t.on_records(1)
        mock_ledger.log.assert_called_once()
        assert mock_ledger.log.call_args[0][0] == "training_trigger_fired"

    def test_observer_ledger_not_called_when_not_fired(self):
        mock_ledger = MagicMock()
        t = TrainingTrigger(threshold=100, command=["echo", "train"], observer_ledger=mock_ledger)
        with patch("subprocess.Popen"):
            t.on_records(1)
        mock_ledger.log.assert_not_called()


# ── ShadowHook ────────────────────────────────────────────────────────────────

class TestShadowHook:
    def test_base_class_returns_none(self):
        hook = ShadowHook()
        rec = EvidenceRecord(
            seq=1, agent_id=AGENT_A, action="assign_task", result="ok",
            ts=0.0, policy_id=POLICY_1, classification="UNCLASSIFIED",
            approval_mode="autonomous", decision="allow", operator_id="",
            context_before=[], raw={},
        )
        assert hook.observe(rec) is None

    def test_subclass_can_propose_alternative(self):
        class MyHook(ShadowHook):
            def observe(self, record, observer_ledger=None):
                return "alternative_action"

        hook = MyHook()
        rec = EvidenceRecord(
            seq=1, agent_id=AGENT_A, action="assign_task", result="ok",
            ts=0.0, policy_id=POLICY_1, classification="UNCLASSIFIED",
            approval_mode="autonomous", decision="allow", operator_id="",
            context_before=[], raw={},
        )
        assert hook.observe(rec) == "alternative_action"

    def test_subclass_receives_record_fields(self):
        captured = {}

        class CapturingHook(ShadowHook):
            def observe(self, record, observer_ledger=None):
                captured["seq"] = record.seq
                captured["action"] = record.action
                return None

        hook = CapturingHook()
        rec = EvidenceRecord(
            seq=42, agent_id=AGENT_A, action="read_text", result="data",
            ts=0.0, policy_id=POLICY_1, classification="SECRET",
            approval_mode="human_approved", decision="allow", operator_id="CAC:1",
            context_before=[], raw={},
        )
        hook.observe(rec)
        assert captured["seq"] == 42
        assert captured["action"] == "read_text"


# ── Integration: filter + extract + export ─────────────────────────────────────

class TestObserverIntegration:
    def test_only_allow_decisions_reach_training_data(self, tmp_path):
        """Core invariant: denied actions never appear in training output."""
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [
            _entry(1, decision="allow"),
            _entry(2, decision="deny"),
            _entry(3, decision="quarantined"),
            _entry(4, decision="allow"),
        ])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="raw")
        count = exp.export_from_ledger(ledger_path, unsafe_unverified=True)
        assert count == 2
        lines = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
        assert all(ln.get("decision") == "allow" for ln in lines)

    def test_incremental_export_no_duplicates(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(i) for i in range(1, 11)])
        out = tmp_path / "training.jsonl"
        exp = EvidenceExporter(out, fmt="raw")

        # First run: entries 1-5
        count1 = exp.export_from_ledger(ledger_path, since_seq=0, unsafe_unverified=True)
        assert count1 == 10

        # Second run: entries 6-10 only
        count2 = exp.export_from_ledger(ledger_path, since_seq=5, unsafe_unverified=True)
        assert count2 == 5

        # Total lines: 15 (no duplicates for seq 1-5)
        lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
        assert len(lines) == 15

    def test_context_window_does_not_include_denied_in_output(self, tmp_path):
        """Context window pulls raw log entries (including denied); they are not training records."""
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [
            _entry(1, decision="deny"),
            _entry(2, decision="allow"),
        ])
        obs = LedgerObserver(ledger_path, context_window=3, unsafe_unverified=True)
        records = obs.extract()
        assert len(records) == 1  # only seq=2 is a training record
        # Context may include the denied entry (it's just context, not training output)
        assert records[0].seq == 2

    def test_trigger_fires_after_enough_exports(self, tmp_path):
        ledger_path = tmp_path / "ledger.jsonl"
        _write_ledger(ledger_path, [_entry(i) for i in range(1, 6)])
        out = tmp_path / "training.jsonl"
        trigger = TrainingTrigger(threshold=5, command=["ollama", "fine-tune"])
        exp = EvidenceExporter(out, fmt="raw")

        with patch("subprocess.Popen") as mock_popen:
            count = exp.export_from_ledger(ledger_path, unsafe_unverified=True)
            trigger.on_records(count)
            mock_popen.assert_called_once_with(["ollama", "fine-tune"])
