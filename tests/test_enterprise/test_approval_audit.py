"""Adversarial coverage for durable operator-decision evidence."""
from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from enterprise.approval_audit import (
    ApprovalAuditError,
    ApprovalAuditEvent,
    LedgerApprovalDecisionSink,
)
from enterprise.identity import AgentIdentity
from enterprise.ledger import ThreadSafeAgentLedger
from enterprise.operator import DurableOperatorQueue


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


def _writer(_operator: str, _approval: str, _decision: str, proof) -> bool:
    return proof == "signed-proof"


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


def test_expiry_is_audited_before_capability_becomes_expired(tmp_path):
    sink = RecordingSink()
    queue = _queue(tmp_path, sink, approval_ttl_seconds=1)
    approval_id = queue.submit("agent-a", "export", {})
    assert queue.approve(approval_id, "operator-a", operator_proof="signed-proof")
    decided_at = queue.get(approval_id).decided_at
    assert decided_at is not None
    assert queue.consume_approved(
        approval_id,
        agent_id="agent-a",
        action="export",
        now=decided_at + 2,
    ) is None
    assert queue.get_status(approval_id) == "expired"
    assert any(event.transition == "expired" for event in sink.events.values())
