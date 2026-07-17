"""enterprise/operator.py — Operator Approval Queues

Thread-safe queues for step-up human approvals. When PolicyEnforcer
returns a decision with requires_approval=True, the calling agent submits the
pending action to this queue and waits for an operator to approve or deny it.

Workflow:
    1. Agent calls enforcer.check() → decision.requires_approval = True
    2. Agent calls queue.submit(agent_id, action, context) → approval_id
    3. Agent waits / polls queue.get_status(approval_id)
    4. Operator supplies its deployment-verified proof to approve or deny.
    5. Durable queue stages the transition and audit outbox atomically.
    6. Transition remains audit_pending until signed evidence is durable.
    7. Dispatcher consumes once and revalidates the evidence before execution.

``OperatorQueue`` is an in-process implementation for component tests and
short-lived tools. ``DurableOperatorQueue`` stores the same state in SQLite,
uses transactional state changes, and is the required governed-runtime path.
The governed runtime always configures its audit sink as required. Constructing
the durable queue without a sink remains an explicit compatibility posture and
does not carry the governed-runtime audit guarantee.

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
from typing import Any, Callable, Optional

from enterprise.approval_audit import (
    ApprovalAuditError,
    ApprovalAuditEvent,
    ApprovalDecisionSink,
    canonical_context_digest,
)

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
    audit_event_id: str = ""
    audit_receipt: Optional[dict[str, Any]] = None


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
        audit_sink: ApprovalDecisionSink | None = None,
        audit_required: bool = False,
        decision_writer_verifier: Callable[[str, str, str, str | bytes | None], bool] | None = None,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_age = max_age_seconds
        self._approval_ttl = approval_ttl_seconds
        self._audit_sink = audit_sink
        self._audit_required = audit_required
        self._decision_writer_verifier = decision_writer_verifier
        if audit_required and audit_sink is None:
            raise ApprovalAuditError("required approval audit sink is not configured")
        self._init_db()
        if self._audit_sink is not None:
            self.reconcile()

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
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(approvals)").fetchall()
            }
            additions = {
                "pending_status": "TEXT",
                "pending_event_id": "TEXT",
                "last_audit_event_id": "TEXT NOT NULL DEFAULT ''",
                "last_audit_receipt_json": "TEXT",
            }
            for name, definition in additions.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE approvals ADD COLUMN {name} {definition}")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_audit_outbox (
                    event_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    transition TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    receipt_json TEXT,
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    FOREIGN KEY (approval_id) REFERENCES approvals(approval_id)
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
            audit_event_id=(row["last_audit_event_id"] if "last_audit_event_id" in row.keys() else ""),
            audit_receipt=(
                json.loads(row["last_audit_receipt_json"])
                if "last_audit_receipt_json" in row.keys() and row["last_audit_receipt_json"]
                else None
            ),
        )

    @staticmethod
    def _validate_operator_id(operator_id: str) -> None:
        if not operator_id or len(operator_id) > 256 or any(ord(ch) < 32 for ch in operator_id):
            raise ValueError("operator_id must be a bounded non-control identifier")

    def _verify_decision_writer(
        self,
        approval_id: str,
        operator_id: str,
        status: str,
        proof: str | bytes | None,
    ) -> None:
        self._validate_operator_id(operator_id)
        if not self._audit_required:
            return
        if status == "denied" and operator_id.startswith("system/"):
            return
        if self._decision_writer_verifier is None or not self._decision_writer_verifier(
            operator_id,
            approval_id,
            status,
            proof,
        ):
            raise ApprovalAuditError("decision writer is unidentified or its proof is invalid")

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> ApprovalAuditEvent:
        return ApprovalAuditEvent.from_dict(json.loads(row["event_json"]))

    @staticmethod
    def _receipt_matches_event(receipt: dict[str, Any], event: ApprovalAuditEvent) -> bool:
        expected = {
            "event_id": event.event_id,
            "approval_id": event.approval_id,
            "transition": event.transition,
            "agent_id": event.agent_id,
            "action": event.action,
            "operator_id": event.operator_id,
            "context_digest": event.context_digest,
        }
        return all(receipt.get(key) == value for key, value in expected.items())

    def _insert_outbox(self, conn: sqlite3.Connection, event: ApprovalAuditEvent) -> None:
        conn.execute(
            """
            INSERT INTO approval_audit_outbox
                (event_id, approval_id, transition, event_json, state, created_at)
            VALUES (?, ?, ?, ?, 'pending', ?)
            """,
            (
                event.event_id,
                event.approval_id,
                event.transition,
                json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")),
                event.transition_ts,
            ),
        )

    def _flush_event(self, event_id: str) -> None:
        if self._audit_sink is None:
            if self._audit_required:
                raise ApprovalAuditError("required approval audit sink is unavailable")
            return
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT o.*, a.agent_id, a.action, a.context_json, a.operator_id,
                       a.status AS approval_status, a.pending_status, a.pending_event_id,
                       a.last_audit_event_id, a.last_audit_receipt_json
                  FROM approval_audit_outbox AS o
                  JOIN approvals AS a ON a.approval_id = o.approval_id
                 WHERE o.event_id = ?
                """,
                (event_id,),
            ).fetchone()
        if row is None:
            raise ApprovalAuditError("approval audit outbox event is missing")
        event = self._event_from_row(row)
        event_matches_row = (
            event.approval_id == row["approval_id"]
            and event.agent_id == row["agent_id"]
            and event.action == row["action"]
            and event.context_digest
            == canonical_context_digest(json.loads(row["context_json"]))
            and event.operator_id == row["operator_id"]
        )
        if row["state"] == "pending":
            event_matches_row = event_matches_row and (
                row["approval_status"] == "audit_pending"
                and row["pending_status"] == event.transition
                and row["pending_event_id"] == event.event_id
            )
        else:
            event_matches_row = event_matches_row and (
                row["approval_status"] == event.transition
                and row["last_audit_event_id"] == event.event_id
            )
        if not event_matches_row:
            raise ApprovalAuditError(
                "approval audit event conflicts with durable approval state",
                approval_id=event.approval_id,
                event_id=event.event_id,
            )
        if row["state"] == "delivered":
            receipt = json.loads(row["receipt_json"])
        else:
            try:
                receipt = self._audit_sink.record(event)
            except Exception as exc:
                raise ApprovalAuditError(
                    f"approval transition {event.transition!r} was not recorded",
                    approval_id=event.approval_id,
                    event_id=event.event_id,
                ) from exc
        if not self._receipt_matches_event(receipt, event):
            raise ApprovalAuditError(
                "approval audit receipt does not match the transition",
                approval_id=event.approval_id,
                event_id=event.event_id,
            )
        receipt_json = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                "SELECT state FROM approval_audit_outbox WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if current is None:
                conn.rollback()
                raise ApprovalAuditError("approval audit outbox event disappeared")
            approval = conn.execute(
                "SELECT pending_status, pending_event_id FROM approvals WHERE approval_id = ?",
                (event.approval_id,),
            ).fetchone()
            if approval is not None and approval["pending_event_id"] == event_id:
                conn.execute(
                    """
                    UPDATE approvals
                       SET status = pending_status,
                           pending_status = NULL,
                           pending_event_id = NULL,
                           last_audit_event_id = ?,
                           last_audit_receipt_json = ?
                     WHERE approval_id = ? AND status = 'audit_pending'
                    """,
                    (event_id, receipt_json, event.approval_id),
                )
            conn.execute(
                """
                UPDATE approval_audit_outbox
                   SET state = 'delivered', receipt_json = ?, delivered_at = ?
                 WHERE event_id = ?
                """,
                (receipt_json, time.time(), event_id),
            )
            conn.commit()

    def reconcile(self) -> int:
        """Finish pending audit transitions after a process interruption."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_id FROM approval_audit_outbox WHERE state = 'pending' ORDER BY created_at"
            ).fetchall()
        for row in rows:
            self._flush_event(row["event_id"])
        return len(rows)

    def _stage_existing(
        self,
        conn: sqlite3.Connection,
        item: PendingApproval,
        *,
        transition: str,
        operator_id: str,
        transition_ts: float,
    ) -> str:
        event = ApprovalAuditEvent(
            event_id=str(uuid.uuid4()),
            approval_id=item.approval_id,
            transition=transition,
            agent_id=item.agent_id,
            action=item.action,
            operator_id=operator_id,
            context_digest=canonical_context_digest(item.context),
            transition_ts=transition_ts,
        )
        decided_at = transition_ts if transition in {"approved", "denied"} else item.decided_at
        consumed_at = transition_ts if transition == "consumed" else item.consumed_at
        cursor = conn.execute(
            """
            UPDATE approvals
               SET status = 'audit_pending', pending_status = ?, pending_event_id = ?,
                   operator_id = ?, decided_at = ?, consumed_at = ?
             WHERE approval_id = ? AND status = ?
            """,
            (
                transition,
                event.event_id,
                operator_id or item.operator_id,
                decided_at,
                consumed_at,
                item.approval_id,
                item.status,
            ),
        )
        if cursor.rowcount != 1:
            raise ApprovalAuditError("approval transition lost its state race")
        self._insert_outbox(conn, event)
        return event.event_id

    def submit(self, agent_id: str, action: str, context: Optional[dict] = None) -> str:
        approval_id = str(uuid.uuid4())
        context_json = json.dumps(context or {}, sort_keys=True, separators=(",", ":"))
        if self._audit_sink is not None:
            submitted_at = time.time()
            event = ApprovalAuditEvent(
                event_id=str(uuid.uuid4()),
                approval_id=approval_id,
                transition="pending",
                agent_id=agent_id,
                action=action,
                operator_id="",
                context_digest=canonical_context_digest(context or {}),
                transition_ts=submitted_at,
            )
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO approvals
                        (approval_id, agent_id, action, context_json, submitted_at, status,
                         operator_id, decided_at, consumed_at, pending_status, pending_event_id)
                    VALUES (?, ?, ?, ?, ?, 'audit_pending', '', NULL, NULL, 'pending', ?)
                    """,
                    (approval_id, agent_id, action, context_json, submitted_at, event.event_id),
                )
                self._insert_outbox(conn, event)
                conn.commit()
            self._flush_event(event.event_id)
            return approval_id
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals
                    (approval_id, agent_id, action, context_json, submitted_at, status,
                     operator_id, decided_at, consumed_at)
                VALUES (?, ?, ?, ?, ?, 'pending', '', NULL, NULL)
                """,
                (approval_id, agent_id, action, context_json, time.time()),
            )
        return approval_id

    def _decide(
        self,
        approval_id: str,
        operator_id: str,
        status: str,
        operator_proof: str | bytes | None = None,
    ) -> bool:
        self._verify_decision_writer(approval_id, operator_id, status, operator_proof)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            item = self._from_row(row)
            if item is None or item.status != "pending":
                conn.rollback()
                return False
            if self._audit_sink is None:
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
            event_id = self._stage_existing(
                conn,
                item,
                transition=status,
                operator_id=operator_id,
                transition_ts=time.time(),
            )
            conn.commit()
        self._flush_event(event_id)
        return True

    def approve(
        self,
        approval_id: str,
        operator_id: str,
        *,
        operator_proof: str | bytes | None = None,
    ) -> bool:
        return self._decide(approval_id, operator_id, "approved", operator_proof)

    def deny(
        self,
        approval_id: str,
        operator_id: str,
        *,
        operator_proof: str | bytes | None = None,
    ) -> bool:
        return self._decide(approval_id, operator_id, "denied", operator_proof)

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
                if self._audit_sink is None:
                    conn.execute(
                        "UPDATE approvals SET status = 'expired' WHERE approval_id = ?",
                        (approval_id,),
                    )
                    conn.commit()
                    return None
                event_id = self._stage_existing(
                    conn,
                    item,
                    transition="expired",
                    operator_id=item.operator_id,
                    transition_ts=current,
                )
                conn.commit()
                self._flush_event(event_id)
                return None
            if item.agent_id != agent_id or item.action != action:
                conn.rollback()
                return None
            if not _context_matches(item.context, required_context or {}):
                conn.rollback()
                return None
            if self._audit_sink is None:
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
            event_id = self._stage_existing(
                conn,
                item,
                transition="consumed",
                operator_id=item.operator_id,
                transition_ts=current,
            )
            conn.commit()
        self._flush_event(event_id)
        return self.get(approval_id)

    def verify_consumed_binding(
        self,
        item: PendingApproval,
        *,
        agent_id: str,
        action: str,
        required_context: Optional[dict] = None,
    ) -> bool:
        if self._audit_sink is None:
            return not self._audit_required
        if item.status != "consumed" or item.agent_id != agent_id or item.action != action:
            return False
        if not _context_matches(item.context, required_context or {}):
            return False
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM approval_audit_outbox
                 WHERE event_id = ? AND approval_id = ? AND state = 'delivered'
                """,
                (item.audit_event_id, item.approval_id),
            ).fetchone()
        if row is None or not item.audit_receipt:
            return False
        event = self._event_from_row(row)
        outbox_receipt = json.loads(row["receipt_json"])
        expected = (
            event.transition == "consumed"
            and event.agent_id == agent_id
            and event.action == action
            and event.operator_id == item.operator_id
            and event.context_digest == canonical_context_digest(item.context)
            and self._receipt_matches_event(item.audit_receipt, event)
            and outbox_receipt == item.audit_receipt
        )
        if not expected:
            return False
        try:
            return self._audit_sink.verify_receipt(event, item.audit_receipt)
        except Exception:
            return False

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
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT approval_id FROM approvals
                 WHERE status NOT IN ('pending', 'audit_pending') AND submitted_at < ?
                """,
                (cutoff,),
            ).fetchall()
            approval_ids = [row["approval_id"] for row in rows]
            for approval_id in approval_ids:
                conn.execute(
                    "DELETE FROM approval_audit_outbox WHERE approval_id = ? AND state = 'delivered'",
                    (approval_id,),
                )
                conn.execute(
                    "DELETE FROM approvals WHERE approval_id = ?",
                    (approval_id,),
                )
            conn.commit()
            return len(approval_ids)

    def __len__(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM approvals").fetchone()
        return int(row["n"])


__all__ = [
    "ApprovalAuditError",
    "DurableOperatorQueue",
    "PendingApproval",
    "OperatorQueue",
]
