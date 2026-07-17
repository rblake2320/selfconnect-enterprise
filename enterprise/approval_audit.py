"""Durable approval-transition evidence for the governed runtime."""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Protocol


class ApprovalAuditError(RuntimeError):
    """An approval transition could not be recorded or reconciled."""

    def __init__(
        self,
        message: str,
        *,
        approval_id: str = "",
        event_id: str = "",
    ) -> None:
        super().__init__(message)
        self.approval_id = approval_id
        self.event_id = event_id


def canonical_context_digest(context: dict[str, Any]) -> str:
    """Return a correlation digest without retaining the raw approval context."""
    encoded = json.dumps(
        context,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def approval_event_digest(event: "ApprovalAuditEvent") -> str:
    """Digest every typed field of an approval transition event."""
    return _canonical_digest(event.to_dict())


@dataclass(frozen=True)
class DecisionProofVerification:
    """Bounded identity metadata returned by a deployment proof verifier."""

    verifier_id: str
    key_id: str
    nonce: str
    verified_at: float


@dataclass(frozen=True)
class DecisionProofEnvelope:
    """Non-secret digest envelope retained with an operator decision."""

    verifier_id: str
    key_id: str
    nonce: str
    verified_at: float
    proof_digest: str
    binding_digest: str

    def __post_init__(self) -> None:
        for name in ("verifier_id", "key_id", "nonce"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"decision proof {name} is invalid")
        if not isinstance(self.verified_at, (int, float)) or not math.isfinite(
            float(self.verified_at)
        ):
            raise ValueError("decision proof verified_at is invalid")
        for name in ("proof_digest", "binding_digest"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(ch not in "0123456789abcdef" for ch in value)
            ):
                raise ValueError(f"decision proof {name} is invalid")

    @classmethod
    def create(
        cls,
        verification: DecisionProofVerification,
        *,
        proof: str | bytes,
        approval_id: str,
        agent_id: str,
        action: str,
        context_digest: str,
        decision: str,
        operator_id: str,
    ) -> "DecisionProofEnvelope":
        proof_bytes = proof.encode("utf-8") if isinstance(proof, str) else bytes(proof)
        proof_digest = hashlib.sha256(proof_bytes).hexdigest()
        values = asdict(verification)
        for key, value in values.items():
            if key == "verified_at":
                if (
                    not isinstance(value, (int, float))
                    or abs(time.time() - float(value)) > 300
                ):
                    raise ApprovalAuditError("decision proof verification time is invalid")
            elif not isinstance(value, str) or not value or len(value) > 256:
                raise ApprovalAuditError(f"decision proof {key} is invalid")
        binding = {
            "approval_id": approval_id,
            "agent_id": agent_id,
            "action": action,
            "context_digest": context_digest,
            "decision": decision,
            "operator_id": operator_id,
            **values,
            "proof_digest": proof_digest,
        }
        return cls(
            **values,
            proof_digest=proof_digest,
            binding_digest=_canonical_digest(binding),
        )

    def verifies_binding(
        self,
        *,
        approval_id: str,
        agent_id: str,
        action: str,
        context_digest: str,
        decision: str,
        operator_id: str,
    ) -> bool:
        binding = {
            "approval_id": approval_id,
            "agent_id": agent_id,
            "action": action,
            "context_digest": context_digest,
            "decision": decision,
            "operator_id": operator_id,
            "verifier_id": self.verifier_id,
            "key_id": self.key_id,
            "nonce": self.nonce,
            "verified_at": self.verified_at,
            "proof_digest": self.proof_digest,
        }
        return _canonical_digest(binding) == self.binding_digest


@dataclass(frozen=True)
class ApprovalAuditEvent:
    event_id: str
    approval_id: str
    transition: str
    agent_id: str
    action: str
    operator_id: str
    context_digest: str
    transition_ts: float
    decision_proof: DecisionProofEnvelope | None = None

    def __post_init__(self) -> None:
        bounded = {
            "event_id": self.event_id,
            "approval_id": self.approval_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "operator_id": self.operator_id,
        }
        for name, value in bounded.items():
            if not isinstance(value, str) or len(value) > 1024:
                raise ValueError(f"approval audit {name} is invalid")
        if not self.event_id or not self.approval_id or not self.agent_id or not self.action:
            raise ValueError("approval audit identifiers and action must be non-empty")
        if self.transition not in {"pending", "approved", "denied", "consumed", "expired"}:
            raise ValueError("approval audit transition is invalid")
        if (
            not isinstance(self.context_digest, str)
            or len(self.context_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in self.context_digest)
        ):
            raise ValueError("approval audit context digest is invalid")
        if not isinstance(self.transition_ts, (int, float)) or not math.isfinite(
            float(self.transition_ts)
        ):
            raise ValueError("approval audit transition time is invalid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ApprovalAuditEvent":
        if not isinstance(value, dict):
            raise TypeError("approval audit event must be an object")
        expected = {
            "event_id", "approval_id", "transition", "agent_id", "action",
            "operator_id", "context_digest", "transition_ts", "decision_proof",
        }
        if set(value) != expected:
            raise ValueError("approval audit event has an invalid field set")
        proof = value.get("decision_proof")
        if proof is not None:
            if not isinstance(proof, dict):
                raise TypeError("decision_proof must be an object")
            proof = DecisionProofEnvelope(**proof)
        return cls(**{**value, "decision_proof": proof})


class ApprovalDecisionSink(Protocol):
    def record(self, event: ApprovalAuditEvent) -> dict[str, Any]:
        """Record one transition idempotently and return a non-secret receipt."""

    def verify_receipt(
        self,
        event: ApprovalAuditEvent,
        receipt: dict[str, Any],
    ) -> bool:
        """Verify that a receipt still names the recorded event."""


class LedgerApprovalDecisionSink:
    """Idempotently append approval transitions to a signed AgentLedger.

    The ledger event is signed by the configured runtime identity. ``operator_id``
    is attribution supplied by the independently verified decision writer; it is
    not itself treated as a cryptographic signature.
    """

    def __init__(self, ledger: Any) -> None:
        self._ledger = ledger
        self._lock = threading.Lock()

    @staticmethod
    def _receipt(entry: dict[str, Any], event: ApprovalAuditEvent) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "approval_id": event.approval_id,
            "transition": event.transition,
            "agent_id": event.agent_id,
            "action": event.action,
            "operator_id": event.operator_id,
            "context_digest": event.context_digest,
            "event_digest": approval_event_digest(event),
            "ledger_seq": entry["seq"],
            "ledger_sig": entry["sig"],
        }

    def _existing(self, event: ApprovalAuditEvent) -> dict[str, Any] | None:
        matches = self._ledger.find_entries_by_nested_value(
            "approval_audit", "event_id", event.event_id
        )
        if not matches:
            return None
        metadata = matches[0].get("approval_audit")
        if (
            len(matches) != 1
            or not isinstance(metadata, dict)
            or metadata != event.to_dict()
            or not isinstance(matches[0].get("seq"), int)
            or not isinstance(matches[0].get("sig"), str)
        ):
            raise ApprovalAuditError("approval audit event id is duplicated or conflicts")
        return matches[0]

    def record(self, event: ApprovalAuditEvent) -> dict[str, Any]:
        with self._lock:
            entry = self._existing(event)
            if entry is None:
                entry = self._ledger.log(
                    "operator_approval_transition",
                    result="recorded",
                    metadata={"approval_audit": event.to_dict()},
                )
            return self._receipt(entry, event)

    def verify_receipt(
        self,
        event: ApprovalAuditEvent,
        receipt: dict[str, Any],
    ) -> bool:
        with self._lock:
            valid, _count, _message = self._ledger.verify()
            if not valid:
                return False
            entry = self._existing(event)
            return entry is not None and self._receipt(entry, event) == receipt


__all__ = [
    "ApprovalAuditError",
    "ApprovalAuditEvent",
    "ApprovalDecisionSink",
    "DecisionProofEnvelope",
    "DecisionProofVerification",
    "LedgerApprovalDecisionSink",
    "canonical_context_digest",
    "approval_event_digest",
]
