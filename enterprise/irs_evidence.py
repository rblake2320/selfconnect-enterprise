"""Structured evidence helpers for an IRS AI integration.

The records support engineering evidence for IRM 10.24.1 inventory,
recordkeeping, human-oversight, and sensitive-data audit requirements. They do
not replace IRS/Treasury systems of record, privacy review, or authorization.
Raw PII/FTI is intentionally excluded; partner systems retain it in their
approved boundary and provide hashes and resource identifiers here.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


class IRSStage(str, Enum):
    EXPLORATORY = "exploratory"
    PRE_DEPLOYMENT = "pre_deployment"
    PILOT = "pilot"
    DEPLOYED = "deployed"
    RETIRED = "retired"


class HighImpactDetermination(str, Enum):
    PENDING = "pending"
    YES = "yes"
    NO = "no"


class IRSRetentionClass(str, Enum):
    USE_CASE_LIFE_PLUS_3_YEARS = "use_case_life_plus_3_years"
    PROMPT_LOG_1_YEAR = "prompt_log_1_year"
    TEST_LOG_UNTIL_REPLACED = "test_log_until_replaced"
    INCIDENT_LOG_LIFE = "incident_log_life"


class IRSActionRecordKind(str, Enum):
    """IRM 10.24.1.8 record categories that may contain action evidence."""

    PROMPT_LOG = "prompt_log"
    TEST_LOG = "test_log"
    INCIDENT_LOG = "incident_log"


_ACTION_RETENTION = {
    IRSActionRecordKind.PROMPT_LOG: IRSRetentionClass.PROMPT_LOG_1_YEAR,
    IRSActionRecordKind.TEST_LOG: IRSRetentionClass.TEST_LOG_UNTIL_REPLACED,
    IRSActionRecordKind.INCIDENT_LOG: IRSRetentionClass.INCIDENT_LOG_LIFE,
}


def _require_text(name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{name} is required")


def _require_iso_date(name: str, value: str) -> None:
    _require_text(name, value)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc


@dataclass(frozen=True)
class IRSUseCaseRecord:
    use_case_id: str
    name: str
    intended_purpose: str
    owner: str
    stage: IRSStage
    accountable_official: str = ""
    approval_date: str = ""
    high_impact: HighImpactDetermination = HighImpactDetermination.PENDING
    impact_assessment_id: str = ""
    human_oversight_plan: str = ""
    risk_acceptance_id: str = ""
    model_ids: tuple[str, ...] = field(default_factory=tuple)
    dataset_ids: tuple[str, ...] = field(default_factory=tuple)
    last_validated: str = ""

    def validate(self) -> None:
        for name in ("use_case_id", "name", "intended_purpose", "owner"):
            _require_text(name, str(getattr(self, name)))
        if self.stage != IRSStage.EXPLORATORY:
            _require_text("accountable_official", self.accountable_official)
            _require_iso_date("approval_date", self.approval_date)
        if self.stage == IRSStage.DEPLOYED and (not self.model_ids or not self.dataset_ids):
            raise ValueError("deployed use cases require model_ids and dataset_ids")
        if self.high_impact == HighImpactDetermination.YES:
            for name in ("impact_assessment_id", "human_oversight_plan", "risk_acceptance_id"):
                _require_text(name, str(getattr(self, name)))
        if self.last_validated:
            _require_iso_date("last_validated", self.last_validated)


@dataclass(frozen=True)
class IRSModelDataRecord:
    record_id: str
    record_type: str
    name: str
    version: str
    owner: str
    source: str
    use_case_ids: tuple[str, ...]
    last_validated: str

    def validate(self) -> None:
        if self.record_type not in {"model", "dataset"}:
            raise ValueError("record_type must be 'model' or 'dataset'")
        for name in ("record_id", "name", "version", "owner", "source"):
            _require_text(name, str(getattr(self, name)))
        if not self.use_case_ids:
            raise ValueError("use_case_ids is required")
        _require_iso_date("last_validated", self.last_validated)


@dataclass(frozen=True)
class IRSActionEvidence:
    event_id: str
    timestamp: str
    use_case_id: str
    actor_id: str
    action: str
    target_system: str
    purpose: str
    data_categories: tuple[str, ...]
    policy_id: str
    policy_decision: str
    outcome: str
    input_sha256: str
    output_sha256: str
    record_kind: IRSActionRecordKind
    high_impact: bool = False
    human_review_status: str = "not_required"
    approval_id: str = ""
    operator_id: str = ""

    def validate(self) -> None:
        for name in (
            "event_id", "use_case_id", "actor_id", "action", "target_system",
            "purpose", "policy_id", "outcome",
        ):
            _require_text(name, str(getattr(self, name)))
        _require_iso_date("timestamp", self.timestamp)
        if self.policy_decision not in {"allow", "deny"}:
            raise ValueError("policy_decision must be allow or deny")
        if self.human_review_status not in {"not_required", "pending", "completed"}:
            raise ValueError("invalid human_review_status")
        for name in ("input_sha256", "output_sha256"):
            if not _SHA256_RE.fullmatch(str(getattr(self, name))):
                raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")
        sensitive = {"SBU", "CUI", "PII", "FTI"}.intersection(self.data_categories)
        if sensitive and not self.purpose.strip():
            raise ValueError("sensitive-data events require a purpose")
        if (
            self.high_impact
            and self.policy_decision == "allow"
            and self.outcome == "executed"
            and self.human_review_status != "completed"
        ):
            raise ValueError("executed high-impact actions require completed human review")
        if self.human_review_status == "completed" and not (self.approval_id and self.operator_id):
            raise ValueError("completed human review requires approval_id and operator_id")


class IRSEvidenceRecorder:
    """Append validated IRS integration evidence to a supplied signed ledger."""

    def __init__(self, ledger: Any) -> None:
        if ledger is None or not hasattr(ledger, "log"):
            raise ValueError("a signed ledger with log() is required")
        self._ledger = ledger

    def record_use_case(self, record: IRSUseCaseRecord) -> dict:
        record.validate()
        return self._ledger.log(
            "irs_ai_use_case_inventory_evidence",
            result="recorded",
            metadata={
                "irs_use_case": _jsonable(asdict(record)),
                "retention_class": IRSRetentionClass.USE_CASE_LIFE_PLUS_3_YEARS.value,
                "schema": "selfconnect.irs-use-case-evidence.v1",
            },
        )

    def record_model_data(self, record: IRSModelDataRecord) -> dict:
        record.validate()
        return self._ledger.log(
            "irs_ai_model_data_inventory_evidence",
            result="recorded",
            metadata={
                "irs_model_data": _jsonable(asdict(record)),
                "retention_class": IRSRetentionClass.USE_CASE_LIFE_PLUS_3_YEARS.value,
                "schema": "selfconnect.irs-model-data-evidence.v1",
            },
        )

    def record_action(
        self,
        record: IRSActionEvidence,
    ) -> dict:
        record.validate()
        try:
            retention_class = _ACTION_RETENTION[record.record_kind]
        except (KeyError, TypeError) as exc:
            raise ValueError("record_kind must be a supported IRSActionRecordKind") from exc
        return self._ledger.log(
            "irs_ai_action_evidence",
            result=record.outcome,
            metadata={
                "irs_action": _jsonable(asdict(record)),
                "retention_class": retention_class.value,
                "schema": "selfconnect.irs-action-evidence.v2",
            },
        )

    def verify(self) -> tuple[bool, int, str]:
        """Verify the backing signed ledger."""
        if not hasattr(self._ledger, "verify"):
            raise ValueError("configured ledger does not support verification")
        return self._ledger.verify()


__all__ = [
    "HighImpactDetermination",
    "IRSActionRecordKind",
    "IRSActionEvidence",
    "IRSEvidenceRecorder",
    "IRSModelDataRecord",
    "IRSRetentionClass",
    "IRSStage",
    "IRSUseCaseRecord",
]
