"""tests/test_enterprise/test_policy.py — Unit tests for policy engine

Pure logic tests: no NCrypt calls, no file I/O dependencies.
PolicyEnforcer is tested with require_signature=False to isolate enforcement logic.
"""
from __future__ import annotations

import json
import time

from enterprise.operator import OperatorQueue
from enterprise.policy import (
    AgentPolicy,
    PolicyBundle,
    PolicyDecision,
    PolicyEnforcer,
    make_bundle,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

AGENT_A = "SC-AAAA0001"
AGENT_B = "SC-BBBB0002"
AGENT_C = "SC-CCCC0003"


def _agent_dict(**overrides) -> dict:
    defaults = {
        "role":                       "worker",
        "clearance":                  "SECRET",
        "allowed_targets":            [AGENT_B],
        "allowed_apps":               ["WindowsTerminal.exe"],
        "blocked_apps":               ["chrome.exe"],
        "allowed_actions":            ["assign_task", "read_text"],
        "requires_operator_approval": ["export_content"],
        "max_classification":         "SECRET",
        "revoked":                    False,
    }
    defaults.update(overrides)
    return defaults


def _bundle(**agent_overrides) -> PolicyBundle:
    return make_bundle(
        "test-policy-v1",
        agents={AGENT_A: _agent_dict(**agent_overrides)},
        valid_from=time.time() - 10,
    )


def _enforcer(bundle: PolicyBundle | None = None, **kwargs) -> PolicyEnforcer:
    b = bundle or _bundle()
    return PolicyEnforcer(b, require_signature=False, **kwargs)


# ── AgentPolicy.from_dict ──────────────────────────────────────────────────────

class TestAgentPolicy:
    def test_from_dict_defaults(self):
        ap = AgentPolicy.from_dict("SC-X", {})
        assert ap.agent_id == "SC-X"
        assert ap.role == "unknown"
        assert ap.clearance == "UNCLASSIFIED"
        # Fields are frozenset for O(1) lookup — empty frozenset == frozenset()
        assert len(ap.allowed_targets) == 0
        assert len(ap.allowed_apps) == 0
        assert len(ap.blocked_apps) == 0
        assert len(ap.allowed_actions) == 0
        assert len(ap.requires_operator_approval) == 0
        assert ap.max_classification == "UNCLASSIFIED"
        assert ap.revoked is False

    def test_from_dict_full(self):
        ap = AgentPolicy.from_dict(AGENT_A, _agent_dict())
        assert ap.role == "worker"
        assert ap.clearance == "SECRET"
        assert AGENT_B in ap.allowed_targets
        assert "assign_task" in ap.allowed_actions
        assert "export_content" in ap.requires_operator_approval
        assert ap.revoked is False


# ── PolicyBundle ───────────────────────────────────────────────────────────────

class TestPolicyBundle:
    def test_from_dict_parses_agents(self):
        b = _bundle()
        assert AGENT_A in b.agent_ids()
        assert b.get_agent(AGENT_A) is not None
        assert b.get_agent("SC-UNKNOWN") is None

    def test_policy_id_preserved(self):
        b = make_bundle("my-policy-id", agents={AGENT_A: _agent_dict()})
        assert b.policy_id == "my-policy-id"

    def test_to_signable_bytes_excludes_sig_and_pub(self):
        d = _bundle().to_dict()
        d["sig"] = "deadbeef"
        d["signed_by_pub"] = "abcdef"
        b2 = PolicyBundle.from_dict(d)
        signable = b2.to_signable_bytes()
        parsed = json.loads(signable)
        assert "sig" not in parsed
        assert "signed_by_pub" not in parsed

    def test_to_signable_bytes_is_deterministic(self):
        b = _bundle()
        assert b.to_signable_bytes() == b.to_signable_bytes()

    def test_to_dict_roundtrip(self):
        b = _bundle()
        b2 = PolicyBundle.from_dict(b.to_dict())
        assert b.policy_id == b2.policy_id

    def test_from_file_roundtrip(self, tmp_path):
        b = _bundle()
        p = tmp_path / "policy.json"
        b.save(p)
        b2 = PolicyBundle.from_file(p)
        assert b2.policy_id == b.policy_id
        assert b2.get_agent(AGENT_A) is not None

    def test_is_time_valid_current(self):
        b = make_bundle(
            "p", agents={AGENT_A: _agent_dict()},
            valid_from=time.time() - 100,
            valid_until=time.time() + 100,
        )
        assert b.is_time_valid() is True

    def test_is_time_valid_before_valid_from(self):
        b = make_bundle(
            "p", agents={AGENT_A: _agent_dict()},
            valid_from=time.time() + 1000,
        )
        assert b.is_time_valid() is False

    def test_is_time_valid_after_valid_until(self):
        b = make_bundle(
            "p", agents={AGENT_A: _agent_dict()},
            valid_from=time.time() - 200,
            valid_until=time.time() - 100,
        )
        assert b.is_time_valid() is False

    def test_is_time_valid_no_expiry(self):
        b = make_bundle(
            "p", agents={AGENT_A: _agent_dict()},
            valid_from=time.time() - 10,
            valid_until=None,
        )
        assert b.is_time_valid() is True


# ── PolicyDecision ─────────────────────────────────────────────────────────────

class TestPolicyDecision:
    def test_to_ledger_metadata_allowed(self):
        d = PolicyDecision(allowed=True, reason="ok", policy_id="p1",
                           classification="SECRET", approval_mode="autonomous")
        m = d.to_ledger_metadata()
        assert m["decision"] == "allow"
        assert m["policy_id"] == "p1"
        assert m["classification"] == "SECRET"
        assert m["approval_mode"] == "autonomous"

    def test_to_ledger_metadata_denied(self):
        d = PolicyDecision(allowed=False, reason="no", approval_mode="denied")
        assert d.to_ledger_metadata()["decision"] == "deny"


# ── PolicyEnforcer — deny paths ────────────────────────────────────────────────

class TestEnforcerDenyPaths:
    def test_unknown_agent_denied(self):
        e = _enforcer()
        d = e.check("SC-UNKNOWN", "assign_task")
        assert d.allowed is False
        assert "not registered" in d.reason

    def test_revoked_agent_quarantined(self):
        e = _enforcer(_bundle(revoked=True))
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert d.approval_mode == "quarantined"

    def test_expired_policy_denied(self):
        b = make_bundle(
            "p", agents={AGENT_A: _agent_dict()},
            valid_from=time.time() - 200,
            valid_until=time.time() - 100,  # already expired
        )
        e = PolicyEnforcer(b, require_signature=False)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert "time window" in d.reason

    def test_disallowed_target_denied(self):
        e = _enforcer()
        d = e.check(AGENT_A, "assign_task", target_agent=AGENT_C)
        assert d.allowed is False
        assert "allowed_targets" in d.reason

    def test_blocked_app_denied(self):
        e = _enforcer()
        d = e.check(AGENT_A, "assign_task", app="chrome.exe")
        assert d.allowed is False
        assert "blocked" in d.reason

    def test_app_not_in_allowed_list_denied(self):
        e = _enforcer()
        d = e.check(AGENT_A, "assign_task", app="notepad.exe")
        assert d.allowed is False
        assert "allowed_apps" in d.reason

    def test_unlisted_action_denied(self):
        e = _enforcer()
        d = e.check(AGENT_A, "delete_files")
        assert d.allowed is False
        assert "allowed_actions" in d.reason

    def test_classification_ceiling_exceeded(self):
        e = _enforcer(_bundle(max_classification="SECRET"))
        d = e.check(AGENT_A, "assign_task", classification="TOP_SECRET")
        assert d.allowed is False
        assert "exceeds max" in d.reason

    def test_empty_allowed_actions_denies_everything(self):
        e = _enforcer(_bundle(allowed_actions=[]))
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False


# ── PolicyEnforcer — allow paths ──────────────────────────────────────────────

class TestEnforcerAllowPaths:
    def test_basic_allow(self):
        e = _enforcer()
        d = e.check(AGENT_A, "assign_task", target_agent=AGENT_B,
                    app="WindowsTerminal.exe", classification="UNCLASSIFIED")
        assert d.allowed is True
        assert d.approval_mode == "autonomous"
        assert d.requires_approval is False

    def test_allowed_with_matching_classification(self):
        e = _enforcer()
        d = e.check(AGENT_A, "assign_task", classification="SECRET")
        assert d.allowed is True

    def test_no_target_restriction_when_allowed_targets_empty(self):
        e = _enforcer(_bundle(allowed_targets=[]))
        d = e.check(AGENT_A, "assign_task", target_agent="SC-ANYONE")
        assert d.allowed is True

    def test_all_apps_allowed_when_allowed_apps_empty(self):
        e = _enforcer(_bundle(allowed_apps=[]))
        d = e.check(AGENT_A, "assign_task", app="any_app.exe")
        assert d.allowed is True

    def test_approval_gate_flagged_but_allowed(self):
        # export_content requires approval but must be in allowed_actions to pass step 7
        e = _enforcer(_bundle(allowed_actions=["assign_task", "read_text", "export_content"]))
        d = e.check(AGENT_A, "export_content")
        assert d.allowed is True
        assert d.requires_approval is True
        assert d.approval_mode == "human_approved"

    def test_policy_id_propagated(self):
        e = _enforcer()
        d = e.check(AGENT_A, "assign_task")
        assert d.policy_id == "test-policy-v1"

    def test_decision_has_agent_and_action(self):
        e = _enforcer()
        d = e.check(AGENT_A, "read_text")
        assert d.agent_id == AGENT_A
        assert d.action == "read_text"


# ── Signature enforcement ──────────────────────────────────────────────────────

class TestSignatureEnforcement:
    def test_require_signature_true_no_sig_denies(self):
        """require_signature=True with no sig in bundle → deny."""
        b = _bundle()  # unsigned
        assert b.sig == ""
        # No trust_root_pub and no embedded sig → deny
        e = PolicyEnforcer(b, trust_root_pub=None, require_signature=True)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is False
        assert "signature" in d.reason

    def test_require_signature_false_skips_check(self):
        """require_signature=False → signature check skipped, action allowed."""
        b = _bundle()
        e = PolicyEnforcer(b, require_signature=False)
        d = e.check(AGENT_A, "assign_task")
        assert d.allowed is True


# ── OperatorQueue ──────────────────────────────────────────────────────────────

class TestOperatorQueue:
    def test_submit_returns_id(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        assert isinstance(aid, str)
        assert len(aid) > 0

    def test_status_pending_after_submit(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        assert q.get_status(aid) == "pending"

    def test_approve_changes_status(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        ok = q.approve(aid, operator_id="CAC:123456789")
        assert ok is True
        assert q.get_status(aid) == "approved"

    def test_deny_changes_status(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        ok = q.deny(aid, operator_id="CAC:999")
        assert ok is True
        assert q.get_status(aid) == "denied"

    def test_approve_sets_operator_id(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        q.approve(aid, "CAC:12345")
        item = q.get(aid)
        assert item.operator_id == "CAC:12345"
        assert item.decided_at is not None

    def test_approve_twice_returns_false(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        q.approve(aid, "CAC:1")
        assert q.approve(aid, "CAC:2") is False  # already decided

    def test_deny_already_approved_returns_false(self):
        q = OperatorQueue()
        aid = q.submit(AGENT_A, "export_content")
        q.approve(aid, "CAC:1")
        assert q.deny(aid, "CAC:2") is False

    def test_nonexistent_id_returns_not_found(self):
        q = OperatorQueue()
        assert q.get_status("no-such-id") == "not_found"
        assert q.get("no-such-id") is None
        assert q.approve("no-such-id", "CAC:1") is False

    def test_get_pending_returns_only_pending(self):
        q = OperatorQueue()
        aid1 = q.submit(AGENT_A, "action1")
        aid2 = q.submit(AGENT_A, "action2")
        q.approve(aid1, "CAC:1")
        pending = q.get_pending()
        assert len(pending) == 1
        assert pending[0].approval_id == aid2

    def test_len(self):
        q = OperatorQueue()
        assert len(q) == 0
        q.submit(AGENT_A, "a")
        q.submit(AGENT_A, "b")
        assert len(q) == 2

    def test_context_stored(self):
        q = OperatorQueue()
        ctx = {"target": AGENT_B, "payload_size": 1024}
        aid = q.submit(AGENT_A, "export_content", context=ctx)
        item = q.get(aid)
        assert item.context == ctx

    def test_purge_expired_removes_decided(self):
        # max_age_seconds=-1 → cutoff is 1 second in the future → every item qualifies
        q = OperatorQueue(max_age_seconds=-1)
        aid = q.submit(AGENT_A, "action")
        q.approve(aid, "CAC:1")
        removed = q.purge_expired()
        assert removed == 1
        assert len(q) == 0

    def test_purge_does_not_remove_pending(self):
        q = OperatorQueue(max_age_seconds=0)
        q.submit(AGENT_A, "action")
        removed = q.purge_expired()
        assert removed == 0
        assert len(q) == 1


# ── Full workflow: enforcer → queue → ledger metadata ─────────────────────────

class TestFullWorkflow:
    def test_allowed_action_produces_correct_metadata(self):
        e = _enforcer()
        d = e.check(AGENT_A, "read_text", classification="UNCLASSIFIED")
        assert d.allowed is True
        meta = d.to_ledger_metadata()
        assert meta["decision"] == "allow"
        assert meta["approval_mode"] == "autonomous"
        assert meta["policy_id"] == "test-policy-v1"

    def test_denied_action_produces_deny_metadata(self):
        e = _enforcer()
        d = e.check(AGENT_A, "delete_files")
        assert d.allowed is False
        meta = d.to_ledger_metadata()
        assert meta["decision"] == "deny"
        assert meta["approval_mode"] == "denied"

    def test_requires_approval_workflow(self):
        # Action requires approval
        e = _enforcer(_bundle(
            allowed_actions=["assign_task", "read_text", "export_content"]
        ))
        d = e.check(AGENT_A, "export_content")
        assert d.allowed is True
        assert d.requires_approval is True

        # Submit to queue
        q = OperatorQueue()
        aid = q.submit(d.agent_id, d.action, context={"policy_id": d.policy_id})
        assert q.get_status(aid) == "pending"

        # Operator approves
        q.approve(aid, "CAC:OPERATOR123")
        assert q.get_status(aid) == "approved"

        # Build ledger metadata
        item = q.get(aid)
        meta = {**d.to_ledger_metadata(), "operator_id": item.operator_id}
        assert meta["approval_mode"] == "human_approved"
        assert meta["operator_id"] == "CAC:OPERATOR123"
        assert meta["decision"] == "allow"
