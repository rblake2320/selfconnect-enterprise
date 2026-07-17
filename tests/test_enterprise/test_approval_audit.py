"""Adversarial coverage for durable operator-decision evidence."""
from __future__ import annotations

import json
import sqlite3
import threading
import time

import pytest

from enterprise.approval_audit import (
    ApprovalAuditError,
    ApprovalAuditEvent,
    DecisionProofEnvelope,
    DecisionProofVerification,
    LedgerApprovalDecisionSink,
    approval_event_digest,
    canonical_context_digest,
)
from enterprise.identity import AgentIdentity
from enterprise.ledger import ThreadSafeAgentLedger
from enterprise.operator import DurableOperatorQueue, OperatorQueue


class RecordingSink:
    def __init__(self) -> None:
        self.events: dict[str, ApprovalAuditEvent] = {}
        self.fail = False
        self.fail_after_record = False

    @staticmethod
    def _receipt(event: ApprovalAuditEvent) -> dict:
        return {
            **event.to_dict(),
            "ledger_seq": 1,
            "ledger_sig": "test-signature",
            "event_digest": approval_event_digest(event),
        }

    def record(self, event: ApprovalAuditEvent) -> dict:
        if self.fail:
            raise OSError("audit unavailable")
        existing = self.events.setdefault(event.event_id, event)
        if existing != event:
            raise ApprovalAuditError("conflicting event")
        if self.fail_after_record:
            self.fail_after_record = False
            raise OSError("crash after durable append")
        return self._receipt(event)

    def verify_receipt(self, event: ApprovalAuditEvent, receipt: dict) -> bool:
        return self.events.get(event.event_id) == event and receipt == self._receipt(event)


def _writer(payload: dict[str, str], proof):
    if proof != "signed-proof":
        return None
    return DecisionProofVerification(
        verifier_id="test-verifier",
        key_id="test-key-1",
        nonce=f"nonce-{payload['approval_id']}-{payload['decision']}",
        verified_at=time.time(),
    )


def _queue(tmp_path, sink=None, **kwargs) -> DurableOperatorQueue:
    return DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=sink or RecordingSink(),
        audit_required=True,
        decision_writer_verifier=_writer,
        **kwargs,
    )


def test_required_sink_cannot_be_omitted(tmp_path):
    with pytest.raises(ApprovalAuditError, match="required approval audit sink"):
        DurableOperatorQueue(tmp_path / "approvals.sqlite3", audit_required=True)


def test_unverified_decision_writer_cannot_approve(tmp_path):
    queue = _queue(tmp_path)
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    with pytest.raises(ApprovalAuditError, match="writer"):
        queue.approve(approval_id, "operator-a", operator_proof="wrong")
    assert queue.get_status(approval_id) == "pending"


def test_audit_failure_leaves_transition_non_authorizing_until_reconciled(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    sink.fail = True
    with pytest.raises(ApprovalAuditError, match="not recorded"):
        queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    assert queue.get_status(approval_id) == "audit_pending"
    assert queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
        required_context={"scope": "bounded"},
    ) is None

    sink.fail = False
    assert queue.reconcile() == 1
    assert queue.get_status(approval_id) == "approved"


def test_submit_failure_exposes_recoverable_approval_identifier(tmp_path):
    sink = RecordingSink()
    sink.fail = True
    queue = _queue(tmp_path, sink)
    with pytest.raises(ApprovalAuditError) as captured:
        queue.submit("agent-a", "export", {"scope": "bounded"})
    approval_id = captured.value.approval_id
    assert approval_id
    assert queue.get_status(approval_id) == "audit_pending"
    sink.fail = False
    restarted = _queue(tmp_path, sink)
    assert restarted.get_status(approval_id) == "pending"


def test_deny_transition_is_recorded_before_state_changes(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.deny(
        approval_id,
        "operator-a",
        operator_proof="signed-proof",
    )
    assert queue.get_status(approval_id) == "denied"
    denied = [event for event in sink.events.values() if event.transition == "denied"]
    assert len(denied) == 1
    assert denied[0].operator_id == "operator-a"


def test_raw_context_is_not_written_to_audit_event(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    secret = "customer-secret-not-for-evidence"
    approval_id = queue.submit("agent-a", "export", {"prompt": secret})
    assert queue.approve(
        approval_id,
        "operator-a",
        operator_proof="signed-proof",
    )
    encoded = json.dumps([event.to_dict() for event in sink.events.values()])
    assert secret not in encoded
    assert "context_digest" in encoded


def test_concurrent_decision_race_records_exactly_one_approval(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    outcomes: list[bool] = []

    def approve() -> None:
        outcomes.append(
            DurableOperatorQueue(
                tmp_path / "approvals.sqlite3",
                audit_sink=sink,
                audit_required=True,
                decision_writer_verifier=_writer,
            ).approve(
                approval_id,
                "operator-a",
                operator_proof="signed-proof",
            )
        )

    threads = [threading.Thread(target=approve) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 11
    assert sum(event.transition == "approved" for event in sink.events.values()) == 1


def test_append_before_receipt_marker_is_reconciled_without_duplicate(tmp_path):
    identity = AgentIdentity.init("approval-audit", data_dir=tmp_path / "identities")
    ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "ledger.jsonl")
    real_sink = LedgerApprovalDecisionSink(ledger)
    queue = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=real_sink,
        audit_required=True,
        decision_writer_verifier=_writer,
    )
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})

    class AppendThenFail:
        def __init__(self) -> None:
            self.failed = False

        def record(self, event):
            receipt = real_sink.record(event)
            if not self.failed:
                self.failed = True
                raise OSError("process stopped before SQLite receipt marker")
            return receipt

        def verify_receipt(self, event, receipt):
            return real_sink.verify_receipt(event, receipt)

    queue._audit_sink = AppendThenFail()
    with pytest.raises(ApprovalAuditError):
        queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    count_after_append = ledger.entry_count()
    assert queue.get_status(approval_id) == "audit_pending"

    restarted = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=real_sink,
        audit_required=True,
        decision_writer_verifier=_writer,
    )
    assert restarted.get_status(approval_id) == "approved"
    assert ledger.entry_count() == count_after_append


def test_tampered_pending_outbox_cannot_be_reconciled(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    sink.fail = True
    with pytest.raises(ApprovalAuditError):
        queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    with sqlite3.connect(tmp_path / "approvals.sqlite3") as conn:
        row = conn.execute(
            "SELECT event_id, event_json FROM approval_audit_outbox WHERE state = 'pending'"
        ).fetchone()
        event = json.loads(row[1])
        event["transition"] = "denied"
        conn.execute(
            "UPDATE approval_audit_outbox SET event_json = ? WHERE event_id = ?",
            (json.dumps(event), row[0]),
        )
    sink.fail = False
    with pytest.raises(ApprovalAuditError, match="conflicts"):
        queue.reconcile()
    assert queue.get_status(approval_id) == "audit_pending"


def test_consume_audit_failure_never_returns_authority(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    context = {"scope": "bounded"}
    approval_id = queue.submit("agent-a", "export", context)
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    sink.fail = True
    with pytest.raises(ApprovalAuditError):
        queue.consume_approved(
            approval_id,
            agent_id="agent-a",
            action="export",
            required_context=context,
        )
    assert queue.get_status(approval_id) == "audit_pending"
    sink.fail = False
    queue.reconcile()
    assert queue.get_status(approval_id) == "consumed"
    assert queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
        required_context=context,
    ) is None


def test_consumed_binding_rechecks_signed_ledger_receipt(tmp_path):
    identity = AgentIdentity.init("binding-audit", data_dir=tmp_path / "identities")
    ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "ledger.jsonl")
    queue = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=LedgerApprovalDecisionSink(ledger),
        audit_required=True,
        decision_writer_verifier=_writer,
    )
    context = {"scope": "bounded"}
    approval_id = queue.submit("agent-a", "export", context)
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    consumed = queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
        required_context=context,
    )
    assert consumed is not None
    assert queue.verify_consumed_binding(
        consumed,
        agent_id="agent-a",
        action="export",
        required_context=context,
    )

    with sqlite3.connect(tmp_path / "approvals.sqlite3") as conn:
        conn.execute(
            "UPDATE approval_audit_outbox SET receipt_json = ? WHERE event_id = ?",
            ('{"event_id":"forged"}', consumed.audit_event_id),
        )
        conn.execute(
            "UPDATE approvals SET last_audit_receipt_json = ? WHERE approval_id = ?",
            ('{"event_id":"forged"}', approval_id),
        )
    forged = queue.get(approval_id)
    assert forged is not None
    assert not queue.verify_consumed_binding(
        forged,
        agent_id="agent-a",
        action="export",
        required_context=context,
    )


def test_consumed_binding_fails_when_signed_ledger_chain_is_altered(tmp_path):
    identity = AgentIdentity.init("chain-audit", data_dir=tmp_path / "identities")
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = ThreadSafeAgentLedger(identity, log_path=ledger_path)
    queue = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=LedgerApprovalDecisionSink(ledger),
        audit_required=True,
        decision_writer_verifier=_writer,
    )
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    consumed = queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
    )
    assert consumed is not None
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    altered = json.loads(lines[0])
    altered["action"] = "altered-after-signing"
    lines[0] = json.dumps(altered)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not queue.verify_consumed_binding(
        consumed,
        agent_id="agent-a",
        action="export",
    )


def test_nested_metadata_alias_cannot_forge_a_ledger_receipt(tmp_path):
    identity = AgentIdentity.init("alias-audit", data_dir=tmp_path / "identities")
    ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "ledger.jsonl")
    sink = LedgerApprovalDecisionSink(ledger)
    event = ApprovalAuditEvent(
        event_id="alias-event",
        approval_id="alias-approval",
        transition="pending",
        agent_id="agent-a",
        action="export",
        operator_id="",
        context_digest=canonical_context_digest({}),
        transition_ts=time.time(),
    )
    assert ledger.find_entries_by_nested_value(
        "approval_audit", "event_id", event.event_id
    ) == []
    aliased_metadata = event.to_dict()
    entry = ledger.log(
        "operator_approval_transition",
        result="recorded",
        metadata={"approval_audit": aliased_metadata},
    )
    authentic_receipt = sink._receipt(entry, event)

    aliased_metadata["transition"] = "denied"
    aliased_metadata["operator_id"] = "forged-operator"
    forged_event = ApprovalAuditEvent.from_dict(aliased_metadata)
    forged_receipt = sink._receipt(entry, forged_event)
    assert not sink.verify_receipt(forged_event, forged_receipt)
    assert sink.verify_receipt(event, authentic_receipt)


def test_expiry_is_audited_before_capability_becomes_expired(tmp_path):
    sink = RecordingSink()
    now = [time.time()]
    queue = _queue(tmp_path, sink, approval_ttl_seconds=1, clock=lambda: now[0])
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    decided_at = queue.get(approval_id).decided_at
    assert decided_at is not None
    now[0] = decided_at + 2
    assert queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
    ) is None
    assert queue.get_status(approval_id) == "expired"
    assert any(event.transition == "expired" for event in sink.events.values())


def test_matching_receipt_from_unverifiable_sink_never_clears_audit_pending(tmp_path):
    class LyingSink(RecordingSink):
        def verify_receipt(self, event, receipt):
            return False

    sink = LyingSink()
    queue = _queue(tmp_path, sink)
    with pytest.raises(ApprovalAuditError, match="signed ledger") as captured:
        queue.submit("agent-a", "export", {})
    assert queue.get_status(captured.value.approval_id) == "audit_pending"


def test_state_changed_during_external_append_is_revalidated_under_write_lock(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"

    class MutatingSink(RecordingSink):
        armed = False

        def record(self, event):
            receipt = super().record(event)
            if self.armed:
                with sqlite3.connect(db_path) as conn:
                    altered = {**event.to_dict(), "action": "tampered-during-append"}
                    conn.execute(
                        "UPDATE approval_audit_outbox SET event_json = ? WHERE event_id = ?",
                        (json.dumps(altered), event.event_id),
                    )
            return receipt

    sink = MutatingSink()
    queue = _queue(tmp_path, sink)
    approval_id = queue.submit("agent-a", "export", {})
    sink.armed = True
    with pytest.raises(ApprovalAuditError, match="changed during delivery"):
        queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    assert queue.get_status(approval_id) == "audit_pending"


def test_direct_sqlite_approved_forgery_cannot_create_valid_lineage(tmp_path):
    identity = AgentIdentity.init("forged-lineage", data_dir=tmp_path / "identities")
    ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "ledger.jsonl")
    queue = _queue(tmp_path, LedgerApprovalDecisionSink(ledger))
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    verification = _writer(
        {
            "approval_id": approval_id,
            "agent_id": "agent-a",
            "action": "export",
            "context_digest": queue.get(approval_id).audit_receipt["context_digest"],
            "decision": "approved",
            "operator_id": "operator-a",
        },
        "signed-proof",
    )
    assert verification is not None
    proof = DecisionProofEnvelope.create(
        verification,
        proof="signed-proof",
        approval_id=approval_id,
        agent_id="agent-a",
        action="export",
        context_digest=queue.get(approval_id).audit_receipt["context_digest"],
        decision="approved",
        operator_id="operator-a",
    )
    now = time.time()
    with sqlite3.connect(tmp_path / "approvals.sqlite3") as conn:
        conn.execute(
            """
            UPDATE approvals
               SET status='approved', operator_id='operator-a', decided_at=?, expires_at=?,
                   decision_proof_json=?, decision_nonce=?
             WHERE approval_id=?
            """,
            (
                now, now + 300,
                json.dumps(proof.__dict__, sort_keys=True, separators=(",", ":")),
                proof.nonce, approval_id,
            ),
        )
    consumed = queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
        required_context={"scope": "bounded"},
    )
    assert consumed is not None
    assert not queue.verify_consumed_binding(
        consumed,
        agent_id="agent-a",
        action="export",
        required_context={"scope": "bounded"},
    )


def test_decision_envelope_is_bound_and_raw_proof_is_not_retained(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink)
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    item = queue.get(approval_id)
    assert item.decision_proof is not None
    assert item.decision_proof.verifier_id == "test-verifier"
    assert item.decision_proof.key_id == "test-key-1"
    assert item.decision_proof.verifies_binding(
        approval_id=approval_id,
        agent_id="agent-a",
        action="export",
        context_digest=canonical_context_digest({"scope": "bounded"}),
        decision="approved",
        operator_id="operator-a",
    )
    database = (tmp_path / "approvals.sqlite3").read_bytes()
    assert b"signed-proof" not in database


def test_decision_verifier_receives_the_complete_canonical_binding(tmp_path):
    captured = None

    def verifier(payload, proof):
        nonlocal captured
        captured = dict(payload)
        if proof != "signed-proof":
            return None
        return DecisionProofVerification(
            verifier_id="binding-verifier",
            key_id="binding-key",
            nonce="binding-nonce",
            verified_at=time.time(),
        )

    queue = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=RecordingSink(),
        audit_required=True,
        decision_writer_verifier=verifier,
    )
    approval_id = queue.submit("agent-a", "export", {"scope": "bounded"})
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    assert captured == {
        "approval_id": approval_id,
        "agent_id": "agent-a",
        "action": "export",
        "context_digest": canonical_context_digest({"scope": "bounded"}),
        "decision": "approved",
        "operator_id": "operator-a",
    }


def test_backward_clock_skew_fails_closed(tmp_path):
    now = [time.time()]
    queue = _queue(tmp_path, clock=lambda: now[0])
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    decided_at = queue.get(approval_id).decided_at
    now[0] = decided_at - 1
    with pytest.raises(ApprovalAuditError, match="clock moved backward"):
        queue.consume_approved(
            approval_id,
            agent_id="agent-a",
            action="export",
        )
    with pytest.raises(TypeError, match="unexpected keyword argument 'now'"):
        queue.consume_approved(
            approval_id,
            agent_id="agent-a",
            action="export",
            now=decided_at + 10,
        )
    assert queue.get_status(approval_id) == "approved"


def test_in_memory_expiry_uses_constructor_clock_without_public_override():
    now = [time.time()]
    queue = OperatorQueue(approval_ttl_seconds=1, clock=lambda: now[0])
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.approve(approval_id, "operator-a")
    decided_at = queue.get(approval_id).decided_at
    now[0] = decided_at - 1
    with pytest.raises(ApprovalAuditError, match="clock moved backward"):
        queue.consume_approved(approval_id, agent_id="agent-a", action="export")
    with pytest.raises(TypeError, match="unexpected keyword argument 'now'"):
        queue.consume_approved(
            approval_id,
            agent_id="agent-a",
            action="export",
            now=decided_at + 10,
        )


def test_purge_uses_terminal_and_delivery_time_not_submission_time(tmp_path):
    queue = _queue(tmp_path, max_age_seconds=60)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(tmp_path / "approvals.sqlite3") as conn:
        conn.execute(
            "UPDATE approvals SET submitted_at = ? WHERE approval_id = ?",
            (time.time() - 3600, approval_id),
        )
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    assert queue.consume_approved(approval_id, agent_id="agent-a", action="export")
    assert queue.purge_expired() == 0
    with sqlite3.connect(tmp_path / "approvals.sqlite3") as conn:
        conn.execute(
            "UPDATE approvals SET terminal_at = ? WHERE approval_id = ?",
            (time.time() - 120, approval_id),
        )
        conn.execute(
            "UPDATE approval_audit_outbox SET delivered_at = ? WHERE approval_id = ?",
            (time.time() - 120, approval_id),
        )
    assert queue.purge_expired() == 1


def test_legacy_schema_migrates_to_closed_sets_and_foreign_keys(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE approvals (
                approval_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                action TEXT NOT NULL, context_json TEXT NOT NULL,
                submitted_at REAL NOT NULL, status TEXT NOT NULL,
                operator_id TEXT NOT NULL DEFAULT '', decided_at REAL, consumed_at REAL
            )
            """
        )
        conn.execute(
            "INSERT INTO approvals VALUES ('a','agent','act','{}',1,'pending','',NULL,NULL)"
        )
    queue = DurableOperatorQueue(db_path)
    assert queue.get_status("a") == "pending"
    with queue._connect() as conn:
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name='approvals'"
        ).fetchone()[0]
        assert "CHECK (status IN" in sql
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO approvals "
                "(approval_id,agent_id,action,context_json,submitted_at,status) "
                "VALUES ('bad','a','b','{}',1,'forged')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO approval_audit_outbox "
                "(event_id,approval_id,transition,event_json,state,created_at) "
                "VALUES ('e','missing','pending','{}','pending',1)"
            )


def test_system_safety_denial_is_not_human_attribution_or_approval_bypass(tmp_path):
    queue = _queue(tmp_path)
    denied_id = queue.submit("agent-a", "export", {})
    assert queue.deny(denied_id, "system/control-plane-quarantine")
    denied = queue.get(denied_id)
    assert denied.status == "denied"
    assert denied.decision_proof.verifier_id == "selfconnect.system-safety-denial"
    assert denied.decision_proof.key_id == "runtime-ledger-identity"

    approval_id = queue.submit("agent-a", "export", {})
    with pytest.raises(ApprovalAuditError, match="proof"):
        queue.approve(approval_id, "system/control-plane-quarantine")
    assert queue.get_status(approval_id) == "pending"


def test_reused_decision_nonce_fails_closed(tmp_path):
    fixed_time = time.time()

    def fixed_nonce_writer(_payload, proof):
        if proof != "signed-proof":
            return None
        return DecisionProofVerification(
            verifier_id="test-verifier",
            key_id="test-key",
            nonce="one-use-nonce",
            verified_at=fixed_time,
        )

    queue = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        audit_sink=RecordingSink(),
        audit_required=True,
        decision_writer_verifier=fixed_nonce_writer,
    )
    first = queue.submit("agent-a", "export", {})
    second = queue.submit("agent-a", "export", {})
    assert queue.approve(first, "operator-a", operator_proof="signed-proof")
    with pytest.raises(ApprovalAuditError, match="nonce was reused"):
        queue.approve(second, "operator-a", operator_proof="signed-proof")
    assert queue.get_status(second) == "pending"


def test_decision_nonce_tombstone_survives_approval_purge(tmp_path):
    now = [time.time()]

    def fixed_nonce_writer(_payload, proof):
        if proof != "signed-proof":
            return None
        return DecisionProofVerification(
            verifier_id="test-verifier",
            key_id="test-key",
            nonce="purge-resistant-nonce",
            verified_at=time.time(),
        )

    queue = DurableOperatorQueue(
        tmp_path / "approvals.sqlite3",
        max_age_seconds=10,
        decision_nonce_retention_seconds=100,
        audit_sink=RecordingSink(),
        audit_required=True,
        decision_writer_verifier=fixed_nonce_writer,
        clock=lambda: now[0],
    )
    first = queue.submit("agent-a", "export", {})
    assert queue.approve(first, "operator-a", operator_proof="signed-proof")
    assert queue.consume_approved(first, agent_id="agent-a", action="export")
    now[0] += 20
    assert queue.purge_expired() == 1
    assert queue.get_status(first) == "not_found"

    second = queue.submit("agent-a", "export", {})
    with pytest.raises(ApprovalAuditError, match="nonce was reused"):
        queue.approve(second, "operator-a", operator_proof="signed-proof")
    assert queue.get_status(second) == "pending"


def test_current_schema_outbox_drift_fails_closed_without_rebuild(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TABLE approval_audit_outbox")
        conn.execute(
            """
            CREATE TABLE approval_audit_outbox (
                event_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL,
                transition TEXT NOT NULL, event_json TEXT NOT NULL,
                state TEXT NOT NULL, receipt_json TEXT,
                created_at REAL NOT NULL, delivered_at REAL
            )
            """
        )

    with pytest.raises(ApprovalAuditError, match="columns are invalid"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT status FROM approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()[0] == "pending"


def test_orphaned_legacy_outbox_fails_migration_closed(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DROP TABLE approval_audit_outbox")
        conn.execute(
            """
            CREATE TABLE approval_audit_outbox (
                event_id TEXT PRIMARY KEY, approval_id TEXT NOT NULL,
                transition TEXT NOT NULL, event_json TEXT NOT NULL,
                state TEXT NOT NULL, receipt_json TEXT,
                created_at REAL NOT NULL, delivered_at REAL
            )
            """
        )
        conn.execute(
            "INSERT INTO approval_audit_outbox VALUES "
            "('orphan','missing','pending','{}','pending',NULL,1,NULL)"
        )

    with pytest.raises(ApprovalAuditError, match="columns are invalid"):
        DurableOperatorQueue(db_path)


def test_current_tombstone_constraint_drift_fails_closed(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE decision_nonce_tombstones RENAME TO tombstones_old")
        conn.execute(
            """
            CREATE TABLE decision_nonce_tombstones (
                nonce TEXT NOT NULL, approval_id TEXT NOT NULL,
                recorded_at REAL NOT NULL, retain_until REAL NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO decision_nonce_tombstones VALUES ('legacy-nonce', ?, 1, 100)",
            (approval_id,),
        )
        conn.execute("DROP TABLE tombstones_old")

    with pytest.raises(ApprovalAuditError, match="columns are invalid"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT approval_id FROM decision_nonce_tombstones "
            "WHERE nonce='legacy-nonce'"
        ).fetchone()[0] == approval_id


def test_duplicate_legacy_tombstones_fail_closed_and_rollback(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE decision_nonce_tombstones RENAME TO tombstones_old")
        conn.execute(
            """
            CREATE TABLE decision_nonce_tombstones (
                nonce TEXT, approval_id TEXT NOT NULL,
                recorded_at REAL NOT NULL, retain_until REAL NOT NULL
            )
            """
        )
        conn.executemany(
            "INSERT INTO decision_nonce_tombstones VALUES ('duplicate', ?, 1, 100)",
            [(approval_id,), ("different-approval",)],
        )
        conn.execute("DROP TABLE tombstones_old")

    with pytest.raises(ApprovalAuditError, match="columns are invalid"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM decision_nonce_tombstones WHERE nonce='duplicate'"
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_v3'"
        ).fetchone()[0] == 0


def test_conflicting_legacy_tombstone_owner_fails_closed(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    now = time.time()

    def writer(_payload, _proof):
        return DecisionProofVerification(
            verifier_id="test", key_id="test", nonce="owned-nonce", verified_at=now
        )

    queue = DurableOperatorQueue(
        db_path,
        audit_sink=RecordingSink(),
        audit_required=True,
        decision_writer_verifier=writer,
    )
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.approve(approval_id, "operator-a", operator_proof="proof")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE decision_nonce_tombstones SET approval_id='other' "
            "WHERE nonce='owned-nonce'"
        )
        conn.execute("UPDATE approval_schema_meta SET schema_version=2")

    with pytest.raises(ApprovalAuditError, match="unsupported approval schema version"):
        DurableOperatorQueue(db_path)


def test_comment_spoofed_missing_foreign_key_is_structurally_rebuilt(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DROP TABLE approval_audit_outbox")
        conn.execute(
            """
            CREATE TABLE approval_audit_outbox (
                event_id TEXT NOT NULL PRIMARY KEY,
                approval_id TEXT NOT NULL,
                transition TEXT NOT NULL CHECK (transition IN
                    ('pending','approved','denied','consumed','expired')),
                event_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending','delivered')),
                receipt_json TEXT,
                created_at REAL NOT NULL,
                delivered_at REAL,
                -- FOREIGN KEY (approval_id) REFERENCES approvals(approval_id)
                --     ON DELETE RESTRICT,
                CHECK ((state = 'delivered') = (receipt_json IS NOT NULL)),
                CHECK ((state = 'delivered') = (delivered_at IS NOT NULL))
            )
            """
        )

    with pytest.raises(ApprovalAuditError, match="foreign key"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT status FROM approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()[0] == "pending"


@pytest.mark.parametrize(
    ("status", "pending_status", "pending_event_id"),
    [
        ("forged", None, None),
        ("audit_pending", None, None),
    ],
)
def test_forged_approval_rows_fail_migration_without_destroying_source(
    tmp_path, status, pending_status, pending_event_id
):
    db_path = tmp_path / f"approvals-{status}.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            "UPDATE approvals SET status=?, pending_status=?, pending_event_id=? "
            "WHERE approval_id=?",
            (status, pending_status, pending_event_id, approval_id),
        )

    with pytest.raises(ApprovalAuditError, match="invalid governed state"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT status, pending_status, pending_event_id FROM approvals "
            "WHERE approval_id=?",
            (approval_id,),
        ).fetchone()
        assert row == (status, pending_status, pending_event_id)
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_v3'"
        ).fetchone()[0] == 0


def test_forged_delivered_outbox_row_fails_closed_and_rolls_back(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = _queue(tmp_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        conn.execute(
            "UPDATE approval_audit_outbox SET state='delivered', "
            "receipt_json=NULL, delivered_at=NULL WHERE approval_id=?",
            (approval_id,),
        )

    with pytest.raises(ApprovalAuditError, match="invalid governed state"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT state, receipt_json, delivered_at FROM approval_audit_outbox "
            "WHERE approval_id=?",
            (approval_id,),
        ).fetchone() == ("delivered", None, None)
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_v3'"
        ).fetchone()[0] == 0


def test_current_schema_missing_tombstones_fails_closed_without_replay_reset(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO decision_nonce_tombstones VALUES ('burned','purged',1,100)"
        )
        conn.execute("DROP TABLE decision_nonce_tombstones")

    with pytest.raises(ApprovalAuditError, match="missing governed state"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT schema_version FROM approval_schema_meta WHERE singleton=1"
        ).fetchone()[0] == 3
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name='decision_nonce_tombstones'"
        ).fetchone()[0] == 0


def test_future_schema_version_is_never_downgraded_or_stripped(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE approvals ADD COLUMN future_evidence TEXT")
        conn.execute(
            "UPDATE approvals SET future_evidence='must-preserve' WHERE approval_id=?",
            (approval_id,),
        )
        conn.execute("UPDATE approval_schema_meta SET schema_version=4")

    with pytest.raises(ApprovalAuditError, match="downgrade refused"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT schema_version FROM approval_schema_meta WHERE singleton=1"
        ).fetchone()[0] == 4
        assert conn.execute(
            "SELECT future_evidence FROM approvals WHERE approval_id=?",
            (approval_id,),
        ).fetchone()[0] == "must-preserve"


def test_conflicting_schema_authority_rows_never_trigger_downgrade(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE approvals ADD COLUMN future_evidence TEXT")
        conn.execute(
            "UPDATE approvals SET future_evidence='must-preserve' WHERE approval_id=?",
            (approval_id,),
        )
        conn.execute("DROP TABLE approval_schema_meta")
        conn.execute(
            "CREATE TABLE approval_schema_meta "
            "(singleton INTEGER, schema_version INTEGER NOT NULL)"
        )
        conn.executemany(
            "INSERT INTO approval_schema_meta VALUES (?,?)",
            [(1, 3), (2, 4)],
        )

    with pytest.raises(ApprovalAuditError, match="missing or ambiguous"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT singleton, schema_version FROM approval_schema_meta "
            "ORDER BY singleton"
        ).fetchall() == [(1, 3), (2, 4)]
        assert conn.execute(
            "SELECT future_evidence FROM approvals WHERE approval_id=?",
            (approval_id,),
        ).fetchone()[0] == "must-preserve"


def test_current_partial_nonce_index_fails_closed_without_rebuild(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        approvals_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='approvals'"
        ).fetchone()[0]
        outbox_sql = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='approval_audit_outbox'"
        ).fetchone()[0]
        conn.execute("DROP TABLE approval_audit_outbox")
        conn.execute("ALTER TABLE approvals RENAME TO approvals_old")
        conn.execute(approvals_sql.replace("decision_nonce TEXT UNIQUE", "decision_nonce TEXT"))
        columns = [row[1] for row in conn.execute("PRAGMA table_info(approvals)")]
        joined = ",".join(columns)
        conn.execute(f"INSERT INTO approvals ({joined}) SELECT {joined} FROM approvals_old")
        conn.execute("DROP TABLE approvals_old")
        conn.execute(outbox_sql)
        conn.execute("CREATE INDEX idx_approvals_status ON approvals(status)")
        conn.execute(
            "CREATE UNIQUE INDEX partial_nonce ON approvals(decision_nonce) "
            "WHERE decision_nonce LIKE 'protected-%'"
        )
        conn.execute(
            "CREATE INDEX idx_approval_outbox_lineage "
            "ON approval_audit_outbox(approval_id, created_at, event_id)"
        )

    with pytest.raises(ApprovalAuditError, match="not uniquely indexed"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        indexes = conn.execute("PRAGMA index_list(approvals)").fetchall()
        assert any(row[1] == "partial_nonce" and row[4] == 1 for row in indexes)


def test_legacy_null_replay_keys_fail_closed_and_preserve_source(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE decision_nonce_tombstones RENAME TO tombstones_old")
        conn.execute(
            "CREATE TABLE decision_nonce_tombstones "
            "(nonce TEXT PRIMARY KEY, approval_id TEXT NOT NULL, "
            "recorded_at REAL NOT NULL, retain_until REAL NOT NULL)"
        )
        conn.executemany(
            "INSERT INTO decision_nonce_tombstones VALUES (NULL,?,1,2)",
            [("owner-a",), ("owner-b",)],
        )
        conn.execute("DROP TABLE tombstones_old")

    with pytest.raises(ApprovalAuditError, match="columns are invalid"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM decision_nonce_tombstones WHERE nonce IS NULL"
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_v3'"
        ).fetchone()[0] == 0


def test_deleted_version_authority_never_strips_unknown_state(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE approvals ADD COLUMN future_evidence TEXT")
        conn.execute(
            "UPDATE approvals SET future_evidence='preserve-me' WHERE approval_id=?",
            (approval_id,),
        )
        conn.execute("DROP TABLE approval_schema_meta")

    with pytest.raises(ApprovalAuditError, match="unknown state"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT future_evidence FROM approvals WHERE approval_id=?",
            (approval_id,),
        ).fetchone()[0] == "preserve-me"
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_v3'"
        ).fetchone()[0] == 0


def test_current_version_unknown_state_is_never_repaired_or_stripped(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    approval_id = queue.submit("agent-a", "export", {})
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE approvals ADD COLUMN unknown_evidence TEXT")
        conn.execute(
            "UPDATE approvals SET unknown_evidence='keep' WHERE approval_id=?",
            (approval_id,),
        )

    with pytest.raises(ApprovalAuditError, match="columns are invalid"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT unknown_evidence FROM approvals WHERE approval_id=?",
            (approval_id,),
        ).fetchone()[0] == "keep"


@pytest.mark.parametrize("version", [-1, 0, 2])
def test_unsupported_numbered_schema_is_never_adopted(tmp_path, version):
    db_path = tmp_path / f"approvals-{version}.sqlite3"
    DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE approval_schema_meta SET schema_version=?", (version,)
        )

    with pytest.raises(ApprovalAuditError, match="unsupported approval schema version"):
        DurableOperatorQueue(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT schema_version FROM approval_schema_meta WHERE singleton=1"
        ).fetchone()[0] == version


def test_concurrent_fresh_initialization_converges_under_write_lock(tmp_path):
    for attempt in range(20):
        db_path = tmp_path / f"fresh-{attempt}.sqlite3"
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def initialize() -> None:
            try:
                barrier.wait(timeout=5)
                DurableOperatorQueue(db_path)
            except BaseException as exc:  # captured for assertion in test thread
                errors.append(exc)

        threads = [threading.Thread(target=initialize) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
        assert errors == []
        queue = DurableOperatorQueue(db_path)
        with queue._connect() as conn:
            assert conn.execute(
                "SELECT schema_version FROM approval_schema_meta WHERE singleton=1"
            ).fetchone()[0] == 3


def test_preexisting_migration_staging_is_never_adopted(tmp_path):
    db_path = tmp_path / "approvals.sqlite3"
    queue = DurableOperatorQueue(db_path)
    legitimate = queue.submit("agent-a", "export", {})
    with queue._connect() as conn:
        conn.execute("DROP INDEX idx_approvals_status")
        DurableOperatorQueue._create_tables(conn, "_v3")
        conn.execute(
            "INSERT INTO approvals_v3 "
            "(approval_id,agent_id,action,context_json,submitted_at,status) "
            "VALUES ('forged','attacker','act','{}',1,'pending')"
        )

    with queue._connect() as conn:
        with pytest.raises(ApprovalAuditError, match="staging objects already exist"):
            queue._migrate_schema(conn)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE approval_id=?", (legitimate,)
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE approval_id='forged'"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM approvals_v3 WHERE approval_id='forged'"
        ).fetchone()[0] == 1
