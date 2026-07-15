"""enterprise/operator.py — Operator Approval Queues

Thread-safe queues for step-up human approvals. When PolicyEnforcer
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

``OperatorQueue`` is an in-process implementation for component tests and
short-lived tools. ``DurableOperatorQueue`` stores the same state in SQLite,
uses transactional state changes, and is the required governed-runtime path.

An approval is a single-use capability. Execution consumes it atomically and
checks its agent, action, expiry, and exact bounded context. Merely observing
``status == approved`` is not sufficient authorization.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
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
    status:       str          = "pending"  # pending|approved|denied|consumed|expired
    operator_id:  str          = ""           # set on approve/deny
    decided_at:   Optional[float] = None
    consumed_at:  Optional[float] = None


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

    def __init__(
        self,
        max_age_seconds: float = 3600.0,
        approval_ttl_seconds: float = 300.0,
    ) -> None:
        self._lock    = threading.Lock()
        self._queue:  dict[str, PendingApproval] = {}
        self._max_age = max_age_seconds
        self._approval_ttl = approval_ttl_seconds

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

    def consume_approved(
        self,
        approval_id: str,
        *,
        agent_id: str,
        action: str,
        required_context: Optional[dict] = None,
        now: Optional[float] = None,
    ) -> Optional[PendingApproval]:
        """Atomically consume one matching, unexpired approval.

        ``required_context`` is matched key-for-key against the submitted
        context. Extra submitted keys are permitted, but a required key may not
        be absent or different. Returns the consumed record, or ``None``.
        """
        current = time.time() if now is None else now
        with self._lock:
            item = self._queue.get(approval_id)
            if item is None or item.status != "approved" or item.decided_at is None:
                return None
            if current - item.decided_at > self._approval_ttl:
                item.status = "expired"
                return None
            if item.agent_id != agent_id or item.action != action:
                return None
            if not _context_matches(item.context, required_context or {}):
                return None
            item.status = "consumed"
            item.consumed_at = current
            return item

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


def _context_matches(actual: dict, required: dict) -> bool:
    return all(key in actual and actual[key] == value for key, value in required.items())


class DurableOperatorQueue:
    """SQLite-backed, restart-safe operator approval queue.

    SQLite provides a durable single-host coordination boundary. Multi-host
    deployments still require a deployment-specific shared approval service;
    this class does not claim distributed consensus.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        max_age_seconds: float = 3600.0,
        approval_ttl_seconds: float = 300.0,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_age = max_age_seconds
        self._approval_ttl = approval_ttl_seconds
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    submitted_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    operator_id TEXT NOT NULL DEFAULT '',
                    decided_at REAL,
                    consumed_at REAL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)"
            )

    @staticmethod
    def _from_row(row: sqlite3.Row | None) -> Optional[PendingApproval]:
        if row is None:
            return None
        return PendingApproval(
            approval_id=row["approval_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            context=json.loads(row["context_json"]),
            submitted_at=float(row["submitted_at"]),
            status=row["status"],
            operator_id=row["operator_id"],
            decided_at=row["decided_at"],
            consumed_at=row["consumed_at"],
        )

    def submit(self, agent_id: str, action: str, context: Optional[dict] = None) -> str:
        approval_id = str(uuid.uuid4())
        context_json = json.dumps(context or {}, sort_keys=True, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, 'pending', '', NULL, NULL)",
                (approval_id, agent_id, action, context_json, time.time()),
            )
        return approval_id

    def _decide(self, approval_id: str, operator_id: str, status: str) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE approvals
                   SET status = ?, operator_id = ?, decided_at = ?
                 WHERE approval_id = ? AND status = 'pending'
                """,
                (status, operator_id, time.time(), approval_id),
            )
            conn.commit()
            return cursor.rowcount == 1

    def approve(self, approval_id: str, operator_id: str) -> bool:
        return self._decide(approval_id, operator_id, "approved")

    def deny(self, approval_id: str, operator_id: str) -> bool:
        return self._decide(approval_id, operator_id, "denied")

    def consume_approved(
        self,
        approval_id: str,
        *,
        agent_id: str,
        action: str,
        required_context: Optional[dict] = None,
        now: Optional[float] = None,
    ) -> Optional[PendingApproval]:
        current = time.time() if now is None else now
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            item = self._from_row(row)
            if item is None or item.status != "approved" or item.decided_at is None:
                conn.rollback()
                return None
            if current - item.decided_at > self._approval_ttl:
                conn.execute(
                    "UPDATE approvals SET status = 'expired' WHERE approval_id = ?",
                    (approval_id,),
                )
                conn.commit()
                return None
            if item.agent_id != agent_id or item.action != action:
                conn.rollback()
                return None
            if not _context_matches(item.context, required_context or {}):
                conn.rollback()
                return None
            cursor = conn.execute(
                """
                UPDATE approvals SET status = 'consumed', consumed_at = ?
                 WHERE approval_id = ? AND status = 'approved'
                """,
                (current, approval_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                return None
            conn.commit()
            item.status = "consumed"
            item.consumed_at = current
            return item

    def get(self, approval_id: str) -> Optional[PendingApproval]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        return self._from_row(row)

    def get_status(self, approval_id: str) -> str:
        item = self.get(approval_id)
        return item.status if item else "not_found"

    def _items(self, where: str = "", args: tuple = ()) -> list[PendingApproval]:
        sql = "SELECT * FROM approvals" + (f" WHERE {where}" if where else "")
        with self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [item for row in rows if (item := self._from_row(row)) is not None]

    def get_pending(self) -> list[PendingApproval]:
        return self._items("status = ?", ("pending",))

    def get_all(self) -> list[PendingApproval]:
        return self._items()

    def purge_expired(self) -> int:
        cutoff = time.time() - self._max_age
        with self._connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM approvals
                 WHERE status != 'pending' AND submitted_at < ?
                """,
                (cutoff,),
            )
            return cursor.rowcount

    def __len__(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM approvals").fetchone()
        return int(row["n"])


__all__ = ["DurableOperatorQueue", "PendingApproval", "OperatorQueue"]
