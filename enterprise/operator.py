"""enterprise/operator.py — Operator Approval Queue

Thread-safe in-memory queue for step-up human approvals.  When PolicyEnforcer
returns a decision with requires_approval=True, the calling agent submits the
pending action to this queue and waits for an operator to approve or deny it.

Workflow:
    1. Agent calls enforcer.check() → decision.requires_approval = True
    2. Agent calls queue.submit(agent_id, action, context) → approval_id
    3. Agent waits / polls queue.get_status(approval_id)
    4. Operator calls queue.approve(approval_id, operator_id="CAC:12345")
    5. Agent receives "approved", executes action
    6. Agent logs entry with metadata:
           approval_mode = "human_approved"
           operator_id   = queue.get(approval_id).operator_id

Ledger integration:
    entry = ledger.log(
        action,
        result=result,
        metadata={
            **decision.to_ledger_metadata(),
            "operator_id": queue.get(approval_id).operator_id,
        },
    )

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

# ── PendingApproval ────────────────────────────────────────────────────────────

@dataclass
class PendingApproval:
    """A single approval request in the operator queue."""
    approval_id:  str
    agent_id:     str
    action:       str
    context:      dict
    submitted_at: float
    status:       str          = "pending"    # "pending" | "approved" | "denied"
    operator_id:  str          = ""           # set on approve/deny
    decided_at:   Optional[float] = None


# ── OperatorQueue ──────────────────────────────────────────────────────────────

class OperatorQueue:
    """Thread-safe in-memory approval queue.

    All public methods are safe to call from multiple threads simultaneously.
    Approvals are held in memory — create a new queue per agent process.
    Expired decided entries are purged by purge_expired().

    Args:
        max_age_seconds: How long decided (approved/denied) entries are retained
                         before purge_expired() removes them.  Default 3600s.
    """

    def __init__(self, max_age_seconds: float = 3600.0) -> None:
        self._lock    = threading.Lock()
        self._queue:  dict[str, PendingApproval] = {}
        self._max_age = max_age_seconds

    # ── Submit / decide ───────────────────────────────────────────────────────

    def submit(
        self,
        agent_id: str,
        action: str,
        context: Optional[dict] = None,
    ) -> str:
        """Submit an action for operator approval.

        Returns:
            approval_id — a UUID string.  Pass to approve() / deny() / get_status().
        """
        approval_id = str(uuid.uuid4())
        with self._lock:
            self._queue[approval_id] = PendingApproval(
                approval_id  = approval_id,
                agent_id     = agent_id,
                action       = action,
                context      = context or {},
                submitted_at = time.time(),
            )
        return approval_id

    def approve(self, approval_id: str, operator_id: str) -> bool:
        """Approve a pending action.

        Args:
            approval_id: The ID returned by submit().
            operator_id: The authorising operator's identifier (e.g. "CAC:123456789").

        Returns:
            True if the record was found in pending state and updated.
            False if not found or already decided.
        """
        with self._lock:
            item = self._queue.get(approval_id)
            if item is None or item.status != "pending":
                return False
            item.status      = "approved"
            item.operator_id = operator_id
            item.decided_at  = time.time()
        return True

    def deny(self, approval_id: str, operator_id: str) -> bool:
        """Deny a pending action.

        Returns:
            True if updated; False if not found or already decided.
        """
        with self._lock:
            item = self._queue.get(approval_id)
            if item is None or item.status != "pending":
                return False
            item.status      = "denied"
            item.operator_id = operator_id
            item.decided_at  = time.time()
        return True

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_status(self, approval_id: str) -> str:
        """Return the status string for an approval ID.

        Returns:
            "pending" | "approved" | "denied" | "not_found"
        """
        with self._lock:
            item = self._queue.get(approval_id)
            return item.status if item else "not_found"

    def get(self, approval_id: str) -> Optional[PendingApproval]:
        """Return the full PendingApproval record or None."""
        with self._lock:
            return self._queue.get(approval_id)

    def get_pending(self) -> list[PendingApproval]:
        """Return a snapshot of all currently pending (undecided) approvals."""
        with self._lock:
            return [item for item in self._queue.values() if item.status == "pending"]

    def get_all(self) -> list[PendingApproval]:
        """Return a snapshot of all approvals regardless of status."""
        with self._lock:
            return list(self._queue.values())

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def purge_expired(self) -> int:
        """Remove decided entries older than max_age_seconds.

        Returns:
            Number of entries removed.
        """
        cutoff = time.time() - self._max_age
        with self._lock:
            expired = [
                aid for aid, item in self._queue.items()
                if item.status != "pending" and item.submitted_at < cutoff
            ]
            for aid in expired:
                del self._queue[aid]
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)


__all__ = ["PendingApproval", "OperatorQueue"]
