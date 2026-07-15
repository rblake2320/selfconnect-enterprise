"""Real signed-ledger tests for the IRS integration evidence contract."""
from __future__ import annotations

import pytest

from enterprise.identity import AgentIdentity
from enterprise.irs_evidence import (
    HighImpactDetermination,
    IRSActionRecordKind,
    IRSActionEvidence,
    IRSEvidenceRecorder,
    IRSModelDataRecord,
    IRSStage,
    IRSUseCaseRecord,
)
from enterprise.ledger import ThreadSafeAgentLedger


def _recorder(tmp_path) -> IRSEvidenceRecorder:
    identity = AgentIdentity.init("irs-evidence-test", data_dir=tmp_path / "identity")
    ledger = ThreadSafeAgentLedger(identity, log_path=tmp_path / "irs-evidence.jsonl")
    return IRSEvidenceRecorder(ledger)


def test_records_use_case_model_data_and_action_in_verified_chain(tmp_path):
    recorder = _recorder(tmp_path)
    recorder.record_use_case(
        IRSUseCaseRecord(
            use_case_id="UC-001",
            name="Governed tax document transfer",
            intended_purpose="Transfer reviewed fields into approved tax software",
            owner="program-owner",
            stage=IRSStage.DEPLOYED,
            accountable_official="accountable-official",
            approval_date="2026-07-14T12:00:00Z",
            high_impact=HighImpactDetermination.YES,
            impact_assessment_id="AIA-001",
            human_oversight_plan="HOP-001",
            risk_acceptance_id="RA-001",
            model_ids=("MODEL-001",),
            dataset_ids=("DATA-001",),
            last_validated="2026-07-14T12:00:00Z",
        )
    )
    recorder.record_model_data(
        IRSModelDataRecord(
            record_id="MODEL-001",
            record_type="model",
            name="Document extraction model",
            version="1.0",
            owner="model-owner",
            source="approved-model-registry",
            use_case_ids=("UC-001",),
            last_validated="2026-07-14T12:00:00Z",
        )
    )
    recorder.record_action(
        IRSActionEvidence(
            event_id="EV-001",
            timestamp="2026-07-14T12:01:00Z",
            use_case_id="UC-001",
            actor_id="SC-AGENT001",
            action="populate_reviewed_tax_field",
            target_system="approved-tax-software",
            purpose="prepare taxpayer return for human review",
            data_categories=("PII", "FTI"),
            policy_id="policy-001",
            policy_decision="allow",
            outcome="executed",
            input_sha256="a" * 64,
            output_sha256="b" * 64,
            record_kind=IRSActionRecordKind.PROMPT_LOG,
            high_impact=True,
            human_review_status="completed",
            approval_id="approval-001",
            operator_id="operator-001",
        )
    )
    valid, count, message = recorder.verify()
    assert valid, message
    assert count == 3


def test_executed_high_impact_action_requires_completed_human_review(tmp_path):
    recorder = _recorder(tmp_path)
    event = IRSActionEvidence(
        event_id="EV-002",
        timestamp="2026-07-14T12:01:00Z",
        use_case_id="UC-001",
        actor_id="SC-AGENT001",
        action="populate_tax_field",
        target_system="approved-tax-software",
        purpose="prepare return",
        data_categories=("FTI",),
        policy_id="policy-001",
        policy_decision="allow",
        outcome="executed",
        input_sha256="a" * 64,
        output_sha256="b" * 64,
        record_kind=IRSActionRecordKind.PROMPT_LOG,
        high_impact=True,
        human_review_status="pending",
    )
    with pytest.raises(ValueError, match="completed human review"):
        recorder.record_action(event)


def test_deployed_use_case_requires_model_and_data_inventory(tmp_path):
    recorder = _recorder(tmp_path)
    record = IRSUseCaseRecord(
        use_case_id="UC-003",
        name="Incomplete deployment",
        intended_purpose="negative test",
        owner="owner",
        stage=IRSStage.DEPLOYED,
        accountable_official="official",
        approval_date="2026-07-14T12:00:00Z",
    )
    with pytest.raises(ValueError, match="model_ids and dataset_ids"):
        recorder.record_use_case(record)


@pytest.mark.parametrize(
    ("record_kind", "expected_retention"),
    [
        (IRSActionRecordKind.PROMPT_LOG, "prompt_log_1_year"),
        (IRSActionRecordKind.TEST_LOG, "test_log_until_replaced"),
        (IRSActionRecordKind.INCIDENT_LOG, "incident_log_life"),
    ],
)
def test_action_record_kind_derives_irm_retention_class(
    tmp_path,
    record_kind,
    expected_retention,
):
    recorder = _recorder(tmp_path)
    entry = recorder.record_action(
        IRSActionEvidence(
            event_id=f"EV-{record_kind.value}",
            timestamp="2026-07-15T07:00:00Z",
            use_case_id="UC-RETENTION",
            actor_id="SC-AGENT001",
            action="record_retention_test",
            target_system="test-boundary",
            purpose="validate retention classification",
            data_categories=(),
            policy_id="policy-retention",
            policy_decision="allow",
            outcome="recorded",
            input_sha256="a" * 64,
            output_sha256="b" * 64,
            record_kind=record_kind,
        )
    )
    assert entry["retention_class"] == expected_retention
    assert entry["schema"] == "selfconnect.irs-action-evidence.v2"


def test_action_record_rejects_unrecognized_record_kind(tmp_path):
    recorder = _recorder(tmp_path)
    event = IRSActionEvidence(
        event_id="EV-invalid-kind",
        timestamp="2026-07-15T07:00:00Z",
        use_case_id="UC-RETENTION",
        actor_id="SC-AGENT001",
        action="record_retention_test",
        target_system="test-boundary",
        purpose="negative test",
        data_categories=(),
        policy_id="policy-retention",
        policy_decision="allow",
        outcome="recorded",
        input_sha256="a" * 64,
        output_sha256="b" * 64,
        record_kind="other",  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="record_kind"):
        recorder.record_action(event)
