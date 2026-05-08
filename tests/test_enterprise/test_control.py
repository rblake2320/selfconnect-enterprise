"""tests/test_enterprise/test_control.py — Unit tests for ControlPlane

Pure logic tests: no NCrypt calls, no ledger I/O.
Ledger and OperatorQueue are mocked where integration is tested.
PolicyEnforcer is tested with require_signature=False.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from enterprise.control import AgentControlRecord, ControlPlane
from enterprise.operator import OperatorQueue
from enterprise.policy import PolicyEnforcer, make_bundle

# ── Fixtures ───────────────────────────────────────────────────────────────────

AGENT_A = "SC-AAAA0001"
AGENT_B = "SC-BBBB0002"
AGENT_C = "SC-CCCC0003"
OP_1    = "CAC:OPERATOR001"
OP_2    = "CAC:OPERATOR002"


def _cp(**kwargs) -> ControlPlane:
    return ControlPlane(**kwargs)


def _enforcer(cp: ControlPlane | None = None) -> PolicyEnforcer:
    b = make_bundle(
        "test-v1",
        agents={
            AGENT_A: {
                "role": "worker",
                "clearance": "SECRET",
                "allowed_targets": [],
                "allowed_apps": [],
                "blocked_apps": [],
                "allowed_actions": ["assign_task", "read_text"],
                "requires_operator_approval": [],
                "max_classification": "SECRET",
                "revoked": False,
            }
        },
        valid_from=time.time() - 10,
    )
    return PolicyEnforcer(b, require_signature=False, control_plane=cp)


# ── AgentControlRecord ─────────────────────────────────────────────────────────

class TestAgentControlRecord:
    def test_is_frozen(self):
        rec = AgentControlRecord(
            agent_id="SC-X", command="pause", operator_id=OP_1,
            reason="test", prev_state="active", new_state="paused", ts=0.0,
        )
        with pytest.raises((AttributeError, TypeError)):
            rec.agent_id = "SC-Y"  # type: ignore[misc]

    def test_fields_accessible(self):
        rec = AgentControlRecord(
            agent_id=AGENT_A, command="quarantine", operator_id=OP_1,
            reason="suspicious", prev_state="active", new_state="quarantined",
            ts=12345.0,
        )
        assert rec.agent_id == AGENT_A
        assert rec.command == "quarantine"
        assert rec.operator_id == OP_1
        assert rec.prev_state == "active"
        assert rec.new_state == "quarantined"
        assert rec.ts == 12345.0


# ── Registration ───────────────────────────────────────────────────────────────

class TestRegistration:
    def test_unregistered_agent_is_active_by_default(self):
        cp = _cp()
        assert cp.get_state("SC-UNKNOWN") == "active"

    def test_register_adds_active_agent(self):
        cp = _cp()
        cp.register(AGENT_A)
        assert cp.get_state(AGENT_A) == "active"

    def test_register_noop_if_already_registered(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.pause(AGENT_A, OP_1)
        cp.register(AGENT_A)  # should not reset state
        assert cp.get_state(AGENT_A) == "paused"


# ── State transitions ──────────────────────────────────────────────────────────

class TestPause:
    def test_pause_active_agent(self):
        cp = _cp()
        rec = cp.pause(AGENT_A, OP_1)
        assert cp.get_state(AGENT_A) == "paused"
        assert rec.prev_state == "active"
        assert rec.new_state == "paused"
        assert rec.command == "pause"
        assert rec.operator_id == OP_1

    def test_pause_already_paused_raises(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        with pytest.raises(ValueError, match="pause"):
            cp.pause(AGENT_A, OP_2)

    def test_pause_quarantined_raises(self):
        cp = _cp()
        cp.quarantine(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.pause(AGENT_A, OP_2)

    def test_pause_revoked_raises(self):
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.pause(AGENT_A, OP_2)


class TestResume:
    def test_resume_paused_agent(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        rec = cp.resume(AGENT_A, OP_2)
        assert cp.get_state(AGENT_A) == "active"
        assert rec.prev_state == "paused"
        assert rec.new_state == "active"

    def test_resume_active_raises(self):
        cp = _cp()
        with pytest.raises(ValueError, match="resume"):
            cp.resume(AGENT_A, OP_1)

    def test_resume_quarantined_raises(self):
        cp = _cp()
        cp.quarantine(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.resume(AGENT_A, OP_2)

    def test_resume_revoked_raises(self):
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.resume(AGENT_A, OP_2)


class TestQuarantine:
    def test_quarantine_active_agent(self):
        cp = _cp()
        rec = cp.quarantine(AGENT_A, OP_1)
        assert cp.get_state(AGENT_A) == "quarantined"
        assert rec.new_state == "quarantined"

    def test_quarantine_paused_agent(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        cp.quarantine(AGENT_A, OP_2)
        assert cp.get_state(AGENT_A) == "quarantined"

    def test_quarantine_already_quarantined_raises(self):
        cp = _cp()
        cp.quarantine(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.quarantine(AGENT_A, OP_2)

    def test_quarantine_revoked_raises(self):
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.quarantine(AGENT_A, OP_2)


class TestRevoke:
    def test_revoke_active_agent(self):
        cp = _cp()
        rec = cp.revoke(AGENT_A, OP_1)
        assert cp.get_state(AGENT_A) == "revoked"
        assert rec.new_state == "revoked"

    def test_revoke_paused_agent(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        cp.revoke(AGENT_A, OP_2)
        assert cp.get_state(AGENT_A) == "revoked"

    def test_revoke_quarantined_agent(self):
        cp = _cp()
        cp.quarantine(AGENT_A, OP_1)
        cp.revoke(AGENT_A, OP_2)
        assert cp.get_state(AGENT_A) == "revoked"

    def test_revoke_already_revoked_raises(self):
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        with pytest.raises(ValueError):
            cp.revoke(AGENT_A, OP_2)

    def test_revoke_is_terminal(self):
        """After revoke, no other command succeeds."""
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        for cmd in ("pause", "resume", "quarantine"):
            with pytest.raises(ValueError):
                getattr(cp, cmd)(AGENT_A, OP_2)


# ── kill_all ───────────────────────────────────────────────────────────────────

class TestKillAll:
    def test_kill_all_revokes_all_active(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        cp.register(AGENT_C)
        records = cp.kill_all(OP_1, reason="emergency")
        assert len(records) == 3
        assert cp.get_state(AGENT_A) == "revoked"
        assert cp.get_state(AGENT_B) == "revoked"
        assert cp.get_state(AGENT_C) == "revoked"

    def test_kill_all_skips_already_revoked(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        cp.revoke(AGENT_A, OP_1)
        records = cp.kill_all(OP_2)
        assert len(records) == 1
        assert records[0].agent_id == AGENT_B

    def test_kill_all_empty_returns_empty_list(self):
        cp = _cp()
        assert cp.kill_all(OP_1) == []

    def test_kill_all_all_already_revoked_returns_empty(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.revoke(AGENT_A, OP_1)
        assert cp.kill_all(OP_2) == []

    def test_kill_all_records_have_correct_command(self):
        cp = _cp()
        cp.register(AGENT_A)
        records = cp.kill_all(OP_1)
        assert records[0].command == "revoke"

    def test_kill_all_includes_paused_and_quarantined(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        cp.pause(AGENT_A, OP_1)
        cp.quarantine(AGENT_B, OP_1)
        records = cp.kill_all(OP_2)
        assert len(records) == 2
        assert all(r.new_state == "revoked" for r in records)


# ── State queries ──────────────────────────────────────────────────────────────

class TestStateQueries:
    def test_get_all_states_snapshot(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        cp.pause(AGENT_A, OP_1)
        states = cp.get_all_states()
        assert states[AGENT_A] == "paused"
        assert states[AGENT_B] == "active"

    def test_get_all_states_is_copy(self):
        cp = _cp()
        cp.register(AGENT_A)
        states = cp.get_all_states()
        states[AGENT_A] = "revoked"
        assert cp.get_state(AGENT_A) == "active"  # original unchanged

    def test_is_active_true_for_active(self):
        cp = _cp()
        cp.register(AGENT_A)
        assert cp.is_active(AGENT_A) is True

    def test_is_active_false_for_paused(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        assert cp.is_active(AGENT_A) is False

    def test_is_active_false_for_revoked(self):
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        assert cp.is_active(AGENT_A) is False

    def test_is_active_true_for_unknown(self):
        cp = _cp()
        assert cp.is_active("SC-NOTHERE") is True


# ── History ────────────────────────────────────────────────────────────────────

class TestHistory:
    def test_history_records_transitions(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        cp.resume(AGENT_A, OP_2)
        history = cp.get_history()
        assert len(history) == 2
        assert history[0].command == "pause"
        assert history[1].command == "resume"

    def test_history_filtered_by_agent(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        cp.pause(AGENT_B, OP_1)
        cp.resume(AGENT_A, OP_2)
        h_a = cp.get_history(AGENT_A)
        assert len(h_a) == 2
        assert all(r.agent_id == AGENT_A for r in h_a)

    def test_history_filtered_returns_empty_for_unknown(self):
        cp = _cp()
        assert cp.get_history("SC-UNKNOWN") == []

    def test_history_is_copy(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        h = cp.get_history()
        h.clear()
        assert len(cp.get_history()) == 1

    def test_history_has_timestamps(self):
        before = time.time()
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        after = time.time()
        rec = cp.get_history()[0]
        assert before <= rec.ts <= after


# ── Ledger integration ─────────────────────────────────────────────────────────

class TestLedgerIntegration:
    def test_ledger_called_on_pause(self):
        mock_ledger = MagicMock()
        cp = ControlPlane(ledger=mock_ledger)
        cp.pause(AGENT_A, OP_1, reason="test reason")
        mock_ledger.log.assert_called_once()
        call = mock_ledger.log.call_args
        assert call[0][0] == "operator_control"
        meta = call[1]["metadata"]
        assert meta["command"] == "pause"
        assert meta["agent_id"] == AGENT_A
        assert meta["operator_id"] == OP_1
        assert meta["reason"] == "test reason"
        assert meta["prev_state"] == "active"
        assert meta["new_state"] == "paused"

    def test_ledger_called_for_each_kill_all_target(self):
        mock_ledger = MagicMock()
        cp = ControlPlane(ledger=mock_ledger)
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        cp.kill_all(OP_1)
        assert mock_ledger.log.call_count == 2

    def test_no_ledger_no_error(self):
        cp = ControlPlane(ledger=None)
        cp.pause(AGENT_A, OP_1)  # must not raise

    def test_ledger_result_field(self):
        mock_ledger = MagicMock()
        cp = ControlPlane(ledger=mock_ledger)
        cp.quarantine(AGENT_A, OP_1)
        result_arg = mock_ledger.log.call_args[1]["result"]
        assert "quarantined" in result_arg


# ── OperatorQueue auto-drain ───────────────────────────────────────────────────

class TestQueueDrain:
    def test_quarantine_drains_pending_for_agent(self):
        q = OperatorQueue()
        aid1 = q.submit(AGENT_A, "export_content")
        aid2 = q.submit(AGENT_A, "read_text")
        aid3 = q.submit(AGENT_B, "assign_task")  # different agent — must not be drained

        cp = ControlPlane(operator_queue=q)
        cp.quarantine(AGENT_A, OP_1)

        assert q.get_status(aid1) == "denied"
        assert q.get_status(aid2) == "denied"
        assert q.get_status(aid3) == "pending"  # untouched

    def test_quarantine_operator_id_in_denial(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        cp = ControlPlane(operator_queue=q)
        cp.quarantine(AGENT_A, OP_1)
        item = q.get(aid)
        assert "quarantine" in item.operator_id
        assert OP_1 in item.operator_id

    def test_kill_all_drains_all_pending(self):
        q = OperatorQueue()
        aid1 = q.submit(AGENT_A, "export_content")
        aid2 = q.submit(AGENT_B, "assign_task")
        aid3 = q.submit(AGENT_C, "read_text")

        cp = ControlPlane(operator_queue=q)
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        cp.register(AGENT_C)
        cp.kill_all(OP_1)

        assert q.get_status(aid1) == "denied"
        assert q.get_status(aid2) == "denied"
        assert q.get_status(aid3) == "denied"

    def test_already_approved_items_not_re_denied(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        q.approve(aid, OP_2)  # already decided

        cp = ControlPlane(operator_queue=q)
        cp.quarantine(AGENT_A, OP_1)

        # approved stays approved (queue deny() returns False on already-decided items)
        assert q.get_status(aid) == "approved"

    def test_no_queue_quarantine_no_error(self):
        cp = ControlPlane(operator_queue=None)
        cp.quarantine(AGENT_A, OP_1)  # must not raise


# ── PolicyEnforcer Step 0 integration ─────────────────────────────────────────

class TestEnforcerControlGate:
    def test_no_control_plane_normal_enforcement(self):
        e = _enforcer(cp=None)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is True

    def test_paused_agent_denied_by_enforcer(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        e = _enforcer(cp=cp)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert d.approval_mode == "paused"
        assert "paused" in d.reason

    def test_quarantined_agent_denied_by_enforcer(self):
        cp = _cp()
        cp.quarantine(AGENT_A, OP_1)
        e = _enforcer(cp=cp)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert d.approval_mode == "quarantined"

    def test_revoked_agent_denied_by_enforcer(self):
        cp = _cp()
        cp.revoke(AGENT_A, OP_1)
        e = _enforcer(cp=cp)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert d.approval_mode == "revoked"

    def test_active_agent_passes_step0_to_normal_checks(self):
        cp = _cp()
        cp.register(AGENT_A)
        e = _enforcer(cp=cp)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is True
        assert d.approval_mode == "autonomous"

    def test_paused_then_resumed_allows_action(self):
        cp = _cp()
        cp.pause(AGENT_A, OP_1)
        cp.resume(AGENT_A, OP_2)
        e = _enforcer(cp=cp)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is True

    def test_step0_fires_before_policy_registration_check(self):
        """Control plane gate checks state even for unregistered-in-policy agents."""
        cp = _cp()
        # AGENT_B is not in the policy bundle used by _enforcer, but we register it
        # in the control plane as revoked — should get revoked denial, not "not registered"
        cp.revoke(AGENT_B, OP_1)
        e = _enforcer(cp=cp)
        d = e.check(AGENT_B, "assign_task")
        assert d.allowed is False
        assert d.approval_mode == "revoked"

    def test_unknown_agent_treated_as_active_in_control_plane(self):
        """Unknown agents pass Step 0 and hit normal policy evaluation."""
        cp = _cp()
        e = _enforcer(cp=cp)
        # AGENT_B not in policy → denied at step 1 (not registered)
        d = e.check(AGENT_B, "assign_task")
        assert d.allowed is False
        assert "not registered" in d.reason


# ── Full workflow: pause → enforce → resume → enforce ─────────────────────────

class TestFullWorkflow:
    def test_operator_pause_blocks_then_resume_unblocks(self):
        cp = _cp()
        cp.register(AGENT_A)
        e  = _enforcer(cp=cp)

        # Before pause: action allowed
        assert e.check(AGENT_A, "assign_task").allowed is True

        # Operator pauses for review
        cp.pause(AGENT_A, OP_1, reason="anomaly detected")
        assert e.check(AGENT_A, "assign_task").allowed is False

        # Operator clears and resumes
        cp.resume(AGENT_A, OP_2, reason="cleared")
        assert e.check(AGENT_A, "assign_task").allowed is True

    def test_quarantine_blocks_and_drains_queue(self):
        q  = OperatorQueue()
        cp_with_q = ControlPlane(operator_queue=q)
        cp_with_q.register(AGENT_A)
        e = _enforcer(cp=cp_with_q)

        aid = q.submit(AGENT_A, "export_content")
        assert q.get_status(aid) == "pending"

        cp_with_q.quarantine(AGENT_A, OP_1, reason="suspicious export rate")

        assert e.check(AGENT_A, "export_content").allowed is False
        assert q.get_status(aid) == "denied"

    def test_kill_all_blocks_entire_mesh(self):
        cp = _cp()
        cp.register(AGENT_A)
        cp.register(AGENT_B)
        e = _enforcer(cp=cp)

        cp.kill_all(OP_1, reason="incident response")

        assert e.check(AGENT_A, "assign_task").allowed is False
        assert e.check(AGENT_B, "assign_task").allowed is False
