"""tests/test_enterprise/test_resource_exhaustion.py — DoS / resource exhaustion tests

Validates that core components handle large-scale inputs without memory errors,
exponential blowup, or crashes.  Uses time.perf_counter() for timing assertions
(no pytest-benchmark dependency).

Targets:
    1. CngLedger with 10,000 entries — write + verify under time budget
    2. OperatorQueue with 1,000 pending approvals — submit + query + deny
    3. PolicyEnforcer with 500 agents — construction + 500 checks
    4. WfpProfile with 200 allow entries — generate_powershell output
    5. PolicyBundle with 10,000 allowed_actions — deep nesting
"""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from enterprise.control import ControlPlane
from enterprise.identity import AgentIdentity
from enterprise.ledger import AgentLedger
from enterprise.operator import OperatorQueue
from enterprise.policy import PolicyBundle, PolicyEnforcer

# WFP imports
_TOOLS = Path(__file__).parent.parent.parent / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from wfp_policy import AllowEntry, WfpProfile, generate_powershell  # noqa: E402

# ── DPAPI mock ───────────────────────────────────────────────────────────────

def _mock_dpapi():
    return (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda b: b"ENC:" + b),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda b: b[4:]),
    )


def _make_identity(tmp_path: Path, name: str = "exhaust-agent") -> AgentIdentity:
    enc, dec = _mock_dpapi()
    with enc, dec:
        return AgentIdentity.init(name, data_dir=tmp_path)


# ══════════════════════════════════════════════════════════════════════════════
# Ledger: 10,000 entries
# ══════════════════════════════════════════════════════════════════════════════

class TestLedgerExhaustion:
    """AgentLedger with 10,000 entries — write and verify under time budget."""

    def test_write_10000_entries(self, tmp_path):
        """Write 10,000 entries without memory error."""
        identity = _make_identity(tmp_path)
        ledger = AgentLedger(identity, log_path=tmp_path / "big_ledger.jsonl")

        t0 = time.perf_counter()
        for i in range(10_000):
            ledger.log(f"action-{i}", result=f"result-{i}")
        elapsed = time.perf_counter() - t0

        assert ledger.entry_count() == 10_000
        # Sanity: writing 10k entries should take under 60s on any modern machine
        assert elapsed < 60, f"Writing 10,000 entries took {elapsed:.1f}s (budget: 60s)"

    def test_verify_10000_entries(self, tmp_path):
        """verify() on 10,000-entry ledger — must return True and complete in <30s."""
        identity = _make_identity(tmp_path, name="verify-agent")
        ledger = AgentLedger(identity, log_path=tmp_path / "verify_ledger.jsonl")

        for i in range(10_000):
            ledger.log(f"action-{i}", result=f"r-{i}")

        t0 = time.perf_counter()
        valid, count, msg = ledger.verify()
        elapsed = time.perf_counter() - t0

        assert valid, f"Verification failed: {msg}"
        assert count == 10_000
        assert elapsed < 30, f"verify() took {elapsed:.1f}s (budget: 30s)"


# ══════════════════════════════════════════════════════════════════════════════
# OperatorQueue: 1,000 pending approvals
# ══════════════════════════════════════════════════════════════════════════════

class TestOperatorQueueExhaustion:
    """OperatorQueue with 1,000 pending items — submit, query, deny under budget."""

    def test_submit_1000_items(self):
        """Submit 1,000 items — queue must not crash."""
        queue = OperatorQueue()
        ids = []
        for i in range(1_000):
            aid = queue.submit(f"SC-AGENT-{i}", f"action_{i}", context={"i": i})
            ids.append(aid)
        assert len(ids) == 1_000
        assert len(set(ids)) == 1_000, "Duplicate IDs detected"

    def test_get_pending_returns_all_1000(self):
        """get_pending() must return all 1,000 items."""
        queue = OperatorQueue()
        for i in range(1_000):
            queue.submit(f"SC-AGENT-{i}", f"action_{i}")

        pending = queue.get_pending()
        assert len(pending) == 1_000

    def test_deny_all_1000_under_budget(self):
        """Deny all 1,000 items — must complete in under 5s."""
        queue = OperatorQueue()
        ids = [queue.submit(f"SC-AGENT-{i}", f"action_{i}") for i in range(1_000)]

        t0 = time.perf_counter()
        for aid in ids:
            result = queue.deny(aid, "CAC:BULK-DENY")
            assert result is True, f"Failed to deny {aid}"
        elapsed = time.perf_counter() - t0

        assert elapsed < 5, f"Denying 1,000 items took {elapsed:.1f}s (budget: 5s)"

        # Verify all are denied
        for aid in ids:
            assert queue.get_status(aid) == "denied"


# ══════════════════════════════════════════════════════════════════════════════
# PolicyBundle: 500 agents
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyExhaustion:
    """PolicyBundle with 500 agents — construct + check all under budget."""

    def _make_bundle_500(self) -> PolicyBundle:
        agents = {
            f"SC-{i:08X}": {
                "role": "worker",
                "clearance": "SECRET",
                "allowed_targets": [f"SC-{(i+1) % 500:08X}"],
                "allowed_apps": ["python.exe", "cmd.exe"],
                "blocked_apps": ["chrome.exe"],
                "allowed_actions": ["assign_task", "read_text", "write_text"],
                "requires_operator_approval": ["export_content"],
                "max_classification": "SECRET",
                "revoked": False,
            }
            for i in range(500)
        }
        return PolicyBundle.from_dict({
            "policy_id": "scale-500",
            "agents": agents,
            "valid_from": time.time() - 10,
            "valid_until": None,
        })

    def test_construct_500_agents(self):
        """Bundle with 500 fully-populated agents must construct."""
        bundle = self._make_bundle_500()
        assert len(bundle.agent_ids()) == 500

    def test_check_500_agents_under_budget(self):
        """PolicyEnforcer.check() for each of the 500 agents in under 2s."""
        bundle = self._make_bundle_500()
        enforcer = PolicyEnforcer(bundle, require_signature=False)

        agent_ids = bundle.agent_ids()
        t0 = time.perf_counter()
        for aid in agent_ids:
            decision = enforcer.check(aid, "assign_task")
            assert decision.allowed, f"Agent {aid} unexpectedly denied: {decision.reason}"
        elapsed = time.perf_counter() - t0

        assert elapsed < 2, f"500 policy checks took {elapsed:.1f}s (budget: 2s)"


# ══════════════════════════════════════════════════════════════════════════════
# WFP: 200 allow entries
# ══════════════════════════════════════════════════════════════════════════════

class TestWfpExhaustion:
    """WfpProfile with 200 allow entries — generate_powershell must produce all."""

    def test_200_allow_entries(self):
        """200-entry profile must generate valid PS script with all entries."""
        entries = [
            AllowEntry(host=f"10.0.{i // 256}.{i % 256}", port=8000 + (i % 100), protocol="tcp")
            for i in range(200)
        ]
        profile = WfpProfile(name="scale-200", process="python.exe", allow=entries)

        t0 = time.perf_counter()
        script = generate_powershell(profile, "wfp-scale-200.ps1")
        elapsed = time.perf_counter() - t0

        assert isinstance(script, str)
        assert len(script) > 0

        # All 200 entries should appear in the output (check host presence)
        for entry in entries:
            # The host may be sanitized (dots replaced with dashes in rule names),
            # but the raw IP should appear in the address fields
            assert entry.host in script, (
                f"Entry {entry.host}:{entry.port} not found in generated script"
            )

        assert elapsed < 5, f"Generating 200-entry script took {elapsed:.1f}s (budget: 5s)"


# ══════════════════════════════════════════════════════════════════════════════
# Deeply nested: 10,000 allowed_actions
# ══════════════════════════════════════════════════════════════════════════════

class TestDeepNesting:
    """PolicyBundle with 10,000 allowed_actions — construction and evaluation."""

    def test_10000_allowed_actions(self):
        """Agent with 10,000 allowed_actions must construct and check correctly."""
        actions = [f"action_{i}" for i in range(10_000)]
        bundle = PolicyBundle.from_dict({
            "policy_id": "deep-nesting-test",
            "agents": {
                "SC-DEEP0001": {
                    "role": "worker",
                    "clearance": "UNCLASSIFIED",
                    "allowed_actions": actions,
                    "max_classification": "UNCLASSIFIED",
                }
            },
            "valid_from": time.time() - 10,
        })

        enforcer = PolicyEnforcer(bundle, require_signature=False)

        # Check first, last, and middle actions
        for action in ["action_0", "action_5000", "action_9999"]:
            decision = enforcer.check("SC-DEEP0001", action)
            assert decision.allowed, f"Action {action} denied: {decision.reason}"

        # Check a non-existent action is denied
        decision = enforcer.check("SC-DEEP0001", "action_99999")
        assert not decision.allowed

    def test_10000_actions_check_timing(self):
        """Checking an action against a 10,000-entry list must be fast."""
        actions = [f"action_{i}" for i in range(10_000)]
        bundle = PolicyBundle.from_dict({
            "policy_id": "timing-test",
            "agents": {
                "SC-TIMING01": {
                    "role": "worker",
                    "clearance": "UNCLASSIFIED",
                    "allowed_actions": actions,
                    "max_classification": "UNCLASSIFIED",
                }
            },
            "valid_from": time.time() - 10,
        })
        enforcer = PolicyEnforcer(bundle, require_signature=False)

        # Check all 10,000 actions
        t0 = time.perf_counter()
        for action in actions:
            decision = enforcer.check("SC-TIMING01", action)
            assert decision.allowed
        elapsed = time.perf_counter() - t0

        assert elapsed < 10, f"10,000 checks took {elapsed:.1f}s (budget: 10s)"
