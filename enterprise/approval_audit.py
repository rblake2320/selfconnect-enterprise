"""Durable approval-transition evidence for the governed runtime."""
from __future__ import annotations

import hashlib
import json
import threading
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ApprovalAuditEvent":
        return cls(**value)


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
            "ledger_seq": entry["seq"],
            "ledger_sig": entry["sig"],
        }

    def _existing(self, event: ApprovalAuditEvent) -> dict[str, Any] | None:
        # A very large tail bound intentionally scans every retained segment in
        # one ledger lock acquisition.  Counting first would create a race where
        # a concurrent append could push the sought event outside that tail.
        entries = self._ledger.tail(2**63 - 1)
        matches = [
            entry
            for entry in entries
            if entry.get("approval_audit", {}).get("event_id") == event.event_id
        ]
        if not matches:
            return None
        if len(matches) != 1 or matches[0].get("approval_audit") != event.to_dict():
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
    "LedgerApprovalDecisionSink",
    "canonical_context_digest",
]
