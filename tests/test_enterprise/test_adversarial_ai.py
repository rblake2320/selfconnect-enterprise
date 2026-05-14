"""tests/test_enterprise/test_adversarial_ai.py — Outside-the-box AI-agent attack tests

Thinking like an attacker against selfconnect-enterprise specifically:

  ATTACK-1: Training data poisoning via ledger injection
    Attacker has write access to the JSONL ledger. Appends a crafted entry with
    decision=allow (no valid sig). verify() DETECTS the invalid sig. BUT if the
    training pipeline uses LedgerObserver without calling verify() first, the entry
    gets through to training data. Defense: WORM backend (G-3), NTFS ACLs,
    allowed_policy_ids filter, always call verify() before extract().

  ATTACK-2: Classification ceiling bypass via signed policy escalation
    Attacker signs a PolicyBundle granting above-ceiling access.
    Defense: ClassifiedModeProfile ceiling checked at step 0.5 before policy content.

  ATTACK-3/6: Control plane state race
    Defense: ControlPlane state machine is atomic (lock-protected + no-op re-register).

  ATTACK-4: Approval token replay after kill_all()
    Defense: kill_all() drains OperatorQueue.

  ATTACK-7: LabelEnvelope classification downgrade
    Defense: LabelEnvelope is frozen — mutation raises TypeError.

  ATTACK-8: Agent self-revival via re-registration
    Defense: register() is no-op for existing IDs; state machine is terminal for revoked.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from enterprise.control import ControlPlane
from enterprise.observer import LedgerObserver, ObserverFilter
from enterprise.operator import OperatorQueue

# ── ledger fixture (mocked DPAPI) ─────────────────────────────────────────────

def _make_ledger(tmp_path: Path, name: str = "test-agent"):
    """Create an AgentLedger with mocked DPAPI for test use."""
    from enterprise.identity import AgentIdentity
    from enterprise.ledger import AgentLedger
    with patch("enterprise.identity._dpapi_encrypt", side_effect=lambda b: b"ENC:" + b), \
         patch("enterprise.identity._dpapi_decrypt", side_effect=lambda b: b[4:]):
        identity = AgentIdentity.init(name, data_dir=tmp_path)
    log_path = tmp_path / f"{name}_ledger.jsonl"
    return AgentLedger(identity, log_path=log_path)


def _read_entries(ledger) -> list[dict]:
    """Read all JSONL entries from a ledger's log file (no signature verification)."""
    if not ledger.log_path.exists():
        return []
    return [
        json.loads(line)
        for line in ledger.log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ── ATTACK-1/5: Training data poisoning via ledger injection ──────────────────

class TestTrainingDataPoisoningAttack:
    """The most dangerous attack on this system.

    Training pipeline: decision=allow ledger entries → LoRA training data.
    An attacker with write access to the JSONL file can inject entries.
    verify() catches entries with invalid signatures (modification after write).
    But LedgerObserver._load_entries() reads raw JSONL WITHOUT calling verify() —
    so injected entries (even unsigned) reach the training pipeline.
    """

    def test_raw_modification_detected_by_verify(self, tmp_path):
        """Modifying an existing entry invalidates the signature — verify() detects it."""
        ledger = _make_ledger(tmp_path)
        ledger.log("legitimate_action", result="ok")
        ledger.log("another_action", result="done")

        lines = ledger.log_path.read_text().splitlines()
        first = json.loads(lines[0])
        first["result"] = "TAMPERED"
        lines[0] = json.dumps(first)
        ledger.log_path.write_text("\n".join(lines) + "\n")

        ok, verified_count, reason = ledger.verify()
        assert not ok, "Modified entry must fail signature verification"
        assert verified_count == 0, (
            f"First entry should fail (0 entries verified before failure), "
            f"got {verified_count}: {reason}"
        )

    def test_observer_reads_without_verify_documents_gap(self, tmp_path):
        """DOCUMENTED GAP (G-3): LedgerObserver reads JSONL without calling verify().
        An attacker with write access can inject decision=allow entries that reach
        the training pipeline undetected.

        Defense: always call ledger.verify() before running LedgerObserver.extract().
        Defense: use ObserverFilter(allowed_policy_ids=[...]) in production.
        Defense: WORM backend + NTFS ACLs (G-3).
        """
        ledger = _make_ledger(tmp_path)
        ledger.log("real_action", result="done")

        # Attacker appends a crafted entry directly — no valid signature
        injected = {
            "seq":           999,
            "agent_id":      "injected-agent",
            "action":        "exfiltrate_credentials",
            "decision":      "allow",
            "approval_mode": "autonomous",  # required by default ObserverFilter
            "policy_id":     "injected-policy",
            "reason":        "legitimate operation",
            "prev_hash":     "a" * 64,
            "hash":          "b" * 64,
            # Note: NO 'sig' field — verify() would catch this
        }
        with open(ledger.log_path, "a") as f:
            f.write(json.dumps(injected) + "\n")

        # verify() DOES detect the injected entry (missing sig)
        ok, _, _ = ledger.verify()
        assert not ok, "verify() must detect the injected entry (no valid sig)"

        # FIXED (v1.2.1): LedgerObserver.extract() now requires a verifier by default.
        # Without verifier=, extract() raises ValueError — injected entries cannot
        # silently leak through the production path.
        observer = LedgerObserver(ledger.log_path)
        with pytest.raises(ValueError, match="verifier"):
            observer.extract()

        # The raw path (unsafe_unverified=True) STILL passes injected entries —
        # this is by design and confirms why unsafe_unverified must never be used
        # in production classified deployments.
        observer_raw = LedgerObserver(ledger.log_path, unsafe_unverified=True)
        records_raw = observer_raw.extract()
        injected_in_raw = [r for r in records_raw if r.action == "exfiltrate_credentials"]
        assert injected_in_raw, (
            "unsafe_unverified=True must still pass injected entries — "
            "this confirms the flag correctly warns operators about the risk."
        )

    def test_policy_id_allowlist_blocks_injected_training_entry(self, tmp_path):
        """DEFENSE: ObserverFilter(allowed_policy_ids=...) blocks injected entries
        even when LedgerObserver doesn't call verify() first."""
        ledger = _make_ledger(tmp_path)
        ledger.log("real_action", result="done")

        entries = _read_entries(ledger)
        last = entries[-1]
        injected = {
            "seq":           last["seq"] + 1,
            "agent_id":      "attacker",
            "action":        "steal_keys",
            "decision":      "allow",
            "approval_mode": "autonomous",
            "policy_id":     "injected-policy",
            "reason":        "injected",
            "prev_hash":     last.get("hash", "0" * 64),
            "hash":          "c" * 64,
        }
        with open(ledger.log_path, "a") as f:
            f.write(json.dumps(injected) + "\n")

        # Observer with policy_id allowlist — only legitimate-pol entries pass
        filt = ObserverFilter(allowed_policy_ids=["legitimate-pol"])
        observer = LedgerObserver(ledger.log_path, observer_filter=filt, unsafe_unverified=True)
        records = observer.extract()

        assert not any(
            r.action == "steal_keys" for r in records
        ), "DEFENSE FAILURE: injected entry with unknown policy_id reached training data"

    def test_default_observer_passes_injected_entry_documents_risk(self, tmp_path):
        """DOCUMENTED RISK: default ObserverFilter (no policy_id restriction) passes
        injected entries. Operators MUST configure allowed_policy_ids in production."""
        ledger = _make_ledger(tmp_path)
        ledger.log("real_action", result="done")

        entries = _read_entries(ledger)
        last = entries[-1]
        injected = {
            "seq":           last["seq"] + 1,
            "agent_id":      "attacker",
            "action":        "poisoned_training_action",
            "decision":      "allow",
            "approval_mode": "autonomous",
            "policy_id":     "any-policy",
            "reason":        "injected",
            "prev_hash":     last.get("hash", "0" * 64),
            "hash":          "d" * 64,
        }
        with open(ledger.log_path, "a") as f:
            f.write(json.dumps(injected) + "\n")

        # FIXED (v1.2.1): production path requires verifier — raises without it.
        # Use unsafe_unverified=True to demonstrate the risk in the raw path.
        filt = ObserverFilter()  # default: no policy_id restriction
        observer = LedgerObserver(ledger.log_path, observer_filter=filt, unsafe_unverified=True)
        records = observer.extract()

        assert any(r.action == "poisoned_training_action" for r in records), (
            "Expected (G-3 risk in raw path): injected entry passes default ObserverFilter "
            "when unsafe_unverified=True.\n"
            "OPERATOR ACTION: use verifier= (production path) + ObserverFilter(allowed_policy_ids=[...])."
        )


# ── ATTACK-2: Classification ceiling bypass via signed policy ──────────────────

class TestClassificationCeilingBypass:

    @pytest.fixture(autouse=True)
    def _cng_key(self):
        """Create a temporary CNG key for policy signing and clean it up after."""
        from enterprise.crypto import CngSigner, cng_delete_key
        self._key_name = f"SelfConnect.TestCeiling.{uuid.uuid4().hex[:8]}"
        signer = CngSigner.create(self._key_name)
        self._signer = signer
        self._pub = signer.public_key_bytes
        yield
        signer.close()
        cng_delete_key(self._key_name)

    def _make_signed_bundle(self, policy_id: str, agents: dict) -> object:
        """Build and sign a PolicyBundle using the test CNG key."""
        from enterprise.policy import make_bundle
        from enterprise.policy_sign import sign_policy

        bundle = make_bundle(
            policy_id=policy_id,
            agents=agents,
            valid_from=time.time() - 100,
            valid_until=time.time() + 10000,
        )
        signed_dict = sign_policy(bundle.to_dict(), self._signer)
        from enterprise.policy import PolicyBundle
        return PolicyBundle.from_dict(signed_dict)

    def test_ceiling_enforced_regardless_of_signed_policy_content(self):
        """Attacker signs a policy granting TOP_SECRET access. Enforcer must deny
        at step 0.5 (ClassifiedModeProfile ceiling) before evaluating policy."""
        from enterprise.classified_mode import ClassifiedModeProfile
        from enterprise.policy import PolicyEnforcer

        profile = ClassifiedModeProfile.secret_baseline()
        signed = self._make_signed_bundle(
            "attacker-policy",
            {
                "target-agent": {
                    "allowed_actions":    ["read_top_secret"],
                    "allowed_targets":    ["*"],
                    "allowed_apps":       ["*"],
                    "max_classification": "TOP_SECRET",  # attacker escalation
                }
            },
        )

        cp = ControlPlane()
        cp.register("target-agent")
        enforcer = PolicyEnforcer(
            policy=signed,
            trust_root_pub=self._pub,
            profile=profile,
            control_plane=cp,
        )

        result = enforcer.check(
            agent_id="target-agent",
            action="read_top_secret",
            classification="TOP_SECRET",
        )

        assert not result.allowed, (
            f"CRITICAL: Ceiling bypass succeeded. "
            f"Decision: {result.approval_mode!r}, reason: {result.reason!r}"
        )

    def test_within_ceiling_policy_is_allowed(self):
        """Confirm the ceiling blocks escalation but not legitimate within-ceiling access."""
        from enterprise.classified_mode import ClassifiedModeProfile
        from enterprise.policy import PolicyEnforcer

        profile = ClassifiedModeProfile.secret_baseline()
        signed = self._make_signed_bundle(
            "legit-policy",
            {
                "legit-agent": {
                    "allowed_actions":    ["read_secret_file"],
                    "allowed_targets":    ["*"],
                    "allowed_apps":       ["*"],
                    "max_classification": "SECRET",  # at ceiling
                }
            },
        )

        cp = ControlPlane()
        cp.register("legit-agent")
        enforcer = PolicyEnforcer(
            policy=signed,
            trust_root_pub=self._pub,
            profile=profile,
            control_plane=cp,
        )

        result = enforcer.check(
            agent_id="legit-agent",
            action="read_secret_file",
            classification="SECRET",
        )
        assert result.allowed, (
            f"Legitimate within-ceiling action was incorrectly denied: {result.reason!r}"
        )


# ── ATTACK-7: LabelEnvelope immutability ──────────────────────────────────────

class TestLabelEnvelopeImmutability:
    """Agent tries to downgrade SECRET→UNCLASSIFIED to pass training filter."""

    def test_label_envelope_is_frozen(self):
        from enterprise.labels import Classification, LabelEnvelope
        env = LabelEnvelope(classification=Classification.SECRET, caveats=frozenset())
        with pytest.raises((TypeError, AttributeError)):
            env.classification = Classification.UNCLASSIFIED  # type: ignore

    def test_observer_max_classification_blocks_secret_entries(self, tmp_path):
        """ObserverFilter(max_classification='UNCLASSIFIED') blocks SECRET entries
        even if they appear in the ledger with decision=allow."""
        ledger = _make_ledger(tmp_path)
        # Write a crafted entry directly (SECRET classification, decision=allow)
        entry = {
            "seq":            1,
            "agent_id":       "attacker",
            "action":         "steal_keys",
            "decision":       "allow",
            "policy_id":      "pol-1",
            "reason":         "approved",
            "classification": "SECRET",
            "prev_hash":      "0" * 64,
            "hash":           "e" * 64,
        }
        with open(ledger.log_path, "w") as f:
            f.write(json.dumps(entry) + "\n")

        filt = ObserverFilter(max_classification="UNCLASSIFIED")
        observer = LedgerObserver(ledger.log_path, observer_filter=filt, unsafe_unverified=True)
        records = observer.extract()
        assert not records, "SECRET entry must not pass UNCLASSIFIED-ceiling filter"


# ── ATTACK-3/6: Control plane race conditions ─────────────────────────────────

class TestControlPlaneRaceConditions:

    def test_revoked_agents_not_active_after_kill_all(self):
        cp = ControlPlane()
        cp.register("agent-1")
        cp.register("agent-2")
        cp.kill_all(operator_id="test-op")
        assert not cp.is_active("agent-1")
        assert not cp.is_active("agent-2")

    def test_kill_all_concurrent_registration_no_survivors(self):
        cp = ControlPlane()
        registered = []
        kill_done = threading.Event()

        def reg():
            for i in range(20):
                try:
                    cp.register(f"race-{i}")
                    registered.append(f"race-{i}")
                except Exception:
                    pass

        def kill():
            time.sleep(0.001)
            cp.kill_all(operator_id="emergency-op")
            kill_done.set()

        threading.Thread(target=reg).start()
        threading.Thread(target=kill).start()
        kill_done.wait(timeout=3.0)
        time.sleep(0.05)  # let reg thread finish

        survivors = [a for a in registered if cp.is_active(a)]
        assert not survivors, f"Race: {len(survivors)} survived kill_all()"

    def test_revoked_agent_re_register_is_noop(self):
        """register() is no-op for existing IDs — revoked agent stays revoked."""
        cp = ControlPlane()
        cp.register("agent-x")
        cp.revoke(agent_id="agent-x", operator_id="op")
        assert not cp.is_active("agent-x")

        cp.register("agent-x")   # no-op (already in _states as "revoked")
        assert not cp.is_active("agent-x"), \
            "Re-registering a revoked agent ID must not restore active status"

    def test_paused_agent_re_register_is_noop(self):
        cp = ControlPlane()
        cp.register("agent-p")
        cp.pause(agent_id="agent-p", operator_id="op")
        assert not cp.is_active("agent-p")
        cp.register("agent-p")  # no-op
        assert not cp.is_active("agent-p")

    def test_quarantined_agent_re_register_is_noop(self):
        cp = ControlPlane()
        cp.register("agent-q")
        cp.quarantine(agent_id="agent-q", operator_id="op")
        assert not cp.is_active("agent-q")
        cp.register("agent-q")  # no-op
        assert not cp.is_active("agent-q")


# ── ATTACK-4: Approval token replay after kill_all() ──────────────────────────

class TestApprovalTokenReplay:

    def test_operator_queue_drained_by_kill_all(self):
        q = OperatorQueue()
        cp = ControlPlane(operator_queue=q)
        cp.register("agent-r")
        q.submit(agent_id="agent-r", action="read_secret", context={})
        assert len(q.get_pending()) == 1

        cp.kill_all(operator_id="emergency-op")
        assert len(q.get_pending()) == 0, \
            "Pending approvals must be drained by kill_all()"

    def test_revoked_agent_not_active_regardless_of_approval(self):
        q = OperatorQueue()
        cp = ControlPlane(operator_queue=q)
        cp.register("agent-stale")
        q.submit(agent_id="agent-stale", action="dangerous_action", context={})
        cp.revoke(agent_id="agent-stale", operator_id="op", reason="compromised")
        assert not cp.is_active("agent-stale")


# ── ATTACK-8: Agent self-revival via re-registration ──────────────────────────

class TestAgentSelfRevival:

    def test_revoked_id_stays_revoked_after_re_register_attempt(self):
        cp = ControlPlane()
        cp.register("victim-agent")
        cp.revoke(agent_id="victim-agent", operator_id="op", reason="compromised")
        cp.register("victim-agent")  # no-op
        assert not cp.is_active("victim-agent"), \
            "Revoked agent must not become active via re-registration"

    def test_new_id_after_revocation_starts_fresh(self):
        """Correct recovery path: new agent_id = new unprivileged agent."""
        cp = ControlPlane()
        cp.register("old-agent")
        cp.revoke(agent_id="old-agent", operator_id="op", reason="expired")
        cp.register("new-agent-recovered")
        assert cp.is_active("new-agent-recovered")
        assert not cp.is_active("old-agent")
