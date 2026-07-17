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
import math
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
    DecisionProofEnvelope,
    DecisionProofVerification,
    approval_event_digest,
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
    expires_at: Optional[float] = None
    terminal_at: Optional[float] = None
    decision_proof: Optional[DecisionProofEnvelope] = None
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
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._lock    = threading.Lock()
        self._queue:  dict[str, PendingApproval] = {}
        self._max_age = max_age_seconds
        self._approval_ttl = approval_ttl_seconds
        self._clock = clock
        self._now()

    def _now(self) -> float:
        value = self._clock()
        if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ApprovalAuditError("approval clock returned an invalid time")
        return float(value)

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
                submitted_at = self._now(),
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
            item.decided_at  = self._now()
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
            item.decided_at  = self._now()
        return True

    def consume_approved(
        self,
        approval_id: str,
        *,
        agent_id: str,
        action: str,
        required_context: Optional[dict] = None,
    ) -> Optional[PendingApproval]:
        """Atomically consume one matching, unexpired approval.

        ``required_context`` is matched key-for-key against the submitted
        context. Extra submitted keys are permitted, but a required key may not
        be absent or different. Returns the consumed record, or ``None``.
        """
        current = self._now()
        with self._lock:
            item = self._queue.get(approval_id)
            if item is None or item.status != "approved" or item.decided_at is None:
                return None
            if current < item.decided_at:
                raise ApprovalAuditError("approval clock moved backward before decision time")
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
        cutoff = self._now() - self._max_age
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
        decision_writer_verifier: Callable[
            [dict[str, str], str | bytes | None], DecisionProofVerification | None
        ] | None = None,
        clock: Callable[[], float] = time.time,
        decision_nonce_retention_seconds: float = 86400.0,
    ) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_age = max_age_seconds
        self._approval_ttl = approval_ttl_seconds
        self._audit_sink = audit_sink
        self._audit_required = audit_required
        self._decision_writer_verifier = decision_writer_verifier
        self._clock = clock
        self._nonce_retention = decision_nonce_retention_seconds
        if (
            not isinstance(self._nonce_retention, (int, float))
            or not math.isfinite(float(self._nonce_retention))
            or self._nonce_retention <= 0
        ):
            raise ValueError("decision_nonce_retention_seconds must be positive and finite")
        self._now()
        if audit_required and audit_sink is None:
            raise ApprovalAuditError("required approval audit sink is not configured")
        self._init_db()
        if self._audit_sink is not None:
            self.reconcile()

    def _now(self) -> float:
        value = self._clock()
        if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ApprovalAuditError("approval clock returned an invalid time")
        return float(value)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            approval_sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='approvals'"
            ).fetchone()
            approval_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(approvals)")
            }
            required_approval_columns = {
                "expires_at", "terminal_at", "decision_proof_json", "decision_nonce",
                "pending_status", "pending_event_id", "last_audit_event_id",
                "last_audit_receipt_json",
            }
            outbox_sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' "
                "AND name='approval_audit_outbox'"
            ).fetchone()
            outbox_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(approval_audit_outbox)")
            }
            required_outbox_columns = {
                "event_id", "approval_id", "transition", "event_json", "state",
                "receipt_json", "created_at", "delivered_at",
            }
            approval_needs_rebuild = approval_sql is not None and (
                "CHECK (status IN" not in approval_sql["sql"]
                or not required_approval_columns.issubset(approval_columns)
            )
            outbox_needs_rebuild = outbox_sql is not None and (
                "CHECK (transition IN" not in outbox_sql["sql"]
                or "FOREIGN KEY (approval_id)" not in outbox_sql["sql"]
                or not required_outbox_columns.issubset(outbox_columns)
            )
            if approval_needs_rebuild or outbox_needs_rebuild:
                self._migrate_schema(conn)
            else:
                self._create_tables(conn)
            self._create_nonce_tombstones(conn)
            now = self._now()
            conn.execute(
                """
                INSERT OR IGNORE INTO decision_nonce_tombstones
                    (nonce, approval_id, recorded_at, retain_until)
                SELECT decision_nonce, approval_id, COALESCE(decided_at, submitted_at), ?
                  FROM approvals
                 WHERE decision_nonce IS NOT NULL
                """,
                (now + self._nonce_retention,),
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_outbox_lineage "
                "ON approval_audit_outbox(approval_id, created_at, event_id)"
            )
            violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise ApprovalAuditError("approval database foreign-key check failed closed")

    @staticmethod
    def _create_nonce_tombstones(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decision_nonce_tombstones (
                nonce TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                recorded_at REAL NOT NULL,
                retain_until REAL NOT NULL,
                CHECK (length(nonce) BETWEEN 1 AND 256),
                CHECK (retain_until > recorded_at)
            )
            """
        )

    @staticmethod
    def _create_tables(conn: sqlite3.Connection, suffix: str = "") -> None:
        approvals = f"approvals{suffix}"
        outbox = f"approval_audit_outbox{suffix}"
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {approvals} (
                approval_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                context_json TEXT NOT NULL,
                submitted_at REAL NOT NULL,
                status TEXT NOT NULL CHECK (status IN
                    ('pending','audit_pending','approved','denied','consumed','expired')),
                operator_id TEXT NOT NULL DEFAULT '',
                decided_at REAL,
                consumed_at REAL,
                expires_at REAL,
                terminal_at REAL,
                decision_proof_json TEXT,
                decision_nonce TEXT UNIQUE,
                pending_status TEXT CHECK (pending_status IS NULL OR pending_status IN
                    ('pending','approved','denied','consumed','expired')),
                pending_event_id TEXT,
                last_audit_event_id TEXT NOT NULL DEFAULT '',
                last_audit_receipt_json TEXT,
                CHECK ((status = 'audit_pending') = (pending_status IS NOT NULL)),
                CHECK ((status = 'audit_pending') = (pending_event_id IS NOT NULL))
            )
            """
        )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {outbox} (
                event_id TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                transition TEXT NOT NULL CHECK (transition IN
                    ('pending','approved','denied','consumed','expired')),
                event_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending','delivered')),
                receipt_json TEXT,
                created_at REAL NOT NULL,
                delivered_at REAL,
                FOREIGN KEY (approval_id) REFERENCES {approvals}(approval_id),
                CHECK ((state = 'delivered') = (receipt_json IS NOT NULL)),
                CHECK ((state = 'delivered') = (delivered_at IS NOT NULL))
            )
            """
        )

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Rebuild the pre-audit schema with closed-set constraints."""
        old_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(approvals)")
        }
        outbox_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='approval_audit_outbox'"
        ).fetchone() is not None
        old_outbox_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(approval_audit_outbox)")
        }
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            self._create_tables(conn, "_v2")
            target_columns = [
                "approval_id", "agent_id", "action", "context_json", "submitted_at",
                "status", "operator_id", "decided_at", "consumed_at", "expires_at",
                "terminal_at", "decision_proof_json", "pending_status", "pending_event_id",
                "decision_nonce", "last_audit_event_id", "last_audit_receipt_json",
            ]
            defaults = {
                "operator_id": "''", "last_audit_event_id": "''",
                "expires_at": "NULL", "terminal_at": "NULL",
                "decision_proof_json": "NULL", "pending_status": "NULL",
                "decision_nonce": "NULL",
                "pending_event_id": "NULL", "last_audit_receipt_json": "NULL",
                "decided_at": "NULL", "consumed_at": "NULL",
            }
            select_values = [
                name if name in old_columns else defaults[name] for name in target_columns
            ]
            conn.execute(
                f"INSERT INTO approvals_v2 ({','.join(target_columns)}) "
                f"SELECT {','.join(select_values)} FROM approvals"
            )
            if outbox_exists:
                required_source = {
                    "event_id", "approval_id", "transition", "event_json", "state",
                    "created_at",
                }
                if not required_source.issubset(old_outbox_columns):
                    raise ApprovalAuditError(
                        "legacy approval outbox is missing required evidence fields"
                    )
                receipt_expr = (
                    "receipt_json" if "receipt_json" in old_outbox_columns else "NULL"
                )
                delivered_expr = (
                    "delivered_at" if "delivered_at" in old_outbox_columns else "NULL"
                )
                conn.execute(
                    f"""
                    INSERT INTO approval_audit_outbox_v2
                    SELECT event_id, approval_id, transition, event_json, state,
                           {receipt_expr}, created_at, {delivered_expr}
                      FROM approval_audit_outbox
                    """
                )
                orphan = conn.execute(
                    """
                    SELECT event_id FROM approval_audit_outbox_v2 AS o
                     WHERE NOT EXISTS (
                         SELECT 1 FROM approvals_v2 AS a
                          WHERE a.approval_id = o.approval_id
                     )
                     LIMIT 1
                    """
                ).fetchone()
                if orphan is not None:
                    raise ApprovalAuditError(
                        "legacy approval outbox contains an orphaned event"
                    )
                conn.execute("DROP TABLE approval_audit_outbox")
            conn.execute("DROP TABLE approvals")
            conn.execute("ALTER TABLE approvals_v2 RENAME TO approvals")
            conn.execute(
                "ALTER TABLE approval_audit_outbox_v2 RENAME TO approval_audit_outbox"
            )
            violations = conn.execute(
                "PRAGMA foreign_key_check(approval_audit_outbox)"
            ).fetchall()
            if violations:
                raise ApprovalAuditError(
                    "migrated approval outbox failed foreign-key validation"
                )
            conn.commit()
        except ApprovalAuditError:
            conn.rollback()
            raise
        except Exception as exc:
            conn.rollback()
            raise ApprovalAuditError("approval schema migration failed closed") from exc
        finally:
            conn.execute("PRAGMA foreign_keys=ON")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ApprovalAuditError("approval database foreign keys are not enabled")
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise ApprovalAuditError("approval database foreign-key check failed closed")

    @staticmethod
    def _from_row(row: sqlite3.Row | None) -> Optional[PendingApproval]:
        if row is None:
            return None
        proof_value = json.loads(row["decision_proof_json"]) if row["decision_proof_json"] else None
        proof = DecisionProofEnvelope(**proof_value) if proof_value is not None else None
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
            expires_at=row["expires_at"],
            terminal_at=row["terminal_at"],
            decision_proof=proof,
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
        item: PendingApproval,
        operator_id: str,
        status: str,
        proof: str | bytes | None,
    ) -> DecisionProofEnvelope | None:
        self._validate_operator_id(operator_id)
        if not self._audit_required:
            return None
        if status == "denied" and operator_id.startswith("system/"):
            verification = DecisionProofVerification(
                verifier_id="selfconnect.system-safety-denial",
                key_id="runtime-ledger-identity",
                nonce=str(uuid.uuid4()),
                verified_at=self._now(),
            )
            proof = b"internal-safety-denial;not-human-attribution"
        else:
            if proof is None or len(proof) == 0 or len(proof) > 16384:
                raise ApprovalAuditError("decision writer proof is absent or unbounded")
            decision_payload = {
                "approval_id": item.approval_id,
                "agent_id": item.agent_id,
                "action": item.action,
                "context_digest": canonical_context_digest(item.context),
                "decision": status,
                "operator_id": operator_id,
            }
            verification = (
                self._decision_writer_verifier(decision_payload, proof)
                if self._decision_writer_verifier is not None
                else None
            )
        if not isinstance(verification, DecisionProofVerification):
            raise ApprovalAuditError("decision writer is unidentified or its proof is invalid")
        return DecisionProofEnvelope.create(
            verification,
            proof=proof or b"",
            approval_id=item.approval_id,
            agent_id=item.agent_id,
            action=item.action,
            context_digest=canonical_context_digest(item.context),
            decision=status,
            operator_id=operator_id,
        )

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
            "event_digest": approval_event_digest(event),
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

    @staticmethod
    def _event_state_row(conn: sqlite3.Connection, event_id: str) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT o.*, a.agent_id, a.action, a.context_json, a.operator_id,
                   a.status AS approval_status, a.pending_status, a.pending_event_id,
                   a.last_audit_event_id, a.last_audit_receipt_json,
                   a.decision_proof_json, a.decided_at, a.consumed_at,
                   a.expires_at, a.terminal_at
              FROM approval_audit_outbox AS o
              JOIN approvals AS a ON a.approval_id = o.approval_id
             WHERE o.event_id = ?
            """,
            (event_id,),
        ).fetchone()

    def _validate_event_state(
        self,
        row: sqlite3.Row,
        event: ApprovalAuditEvent,
    ) -> None:
        proof_json = (
            json.dumps(event.decision_proof.__dict__, sort_keys=True, separators=(",", ":"))
            if event.decision_proof is not None
            else None
        )
        common = (
            event.approval_id == row["approval_id"]
            and event.transition == row["transition"]
            and event.agent_id == row["agent_id"]
            and event.action == row["action"]
            and event.context_digest
            == canonical_context_digest(json.loads(row["context_json"]))
            and event.operator_id == row["operator_id"]
            and proof_json == row["decision_proof_json"]
        )
        if event.transition == "pending":
            common = common and not event.operator_id and event.decision_proof is None
        elif event.transition in {"approved", "denied", "consumed", "expired"}:
            common = common and bool(event.operator_id) and event.decision_proof is not None
        if row["state"] == "pending":
            common = common and (
                row["approval_status"] == "audit_pending"
                and row["pending_status"] == event.transition
                and row["pending_event_id"] == event.event_id
                and row["receipt_json"] is None
                and row["delivered_at"] is None
            )
        elif row["state"] == "delivered":
            common = common and (
                row["approval_status"] == event.transition
                and row["last_audit_event_id"] == event.event_id
                and row["receipt_json"] is not None
                and row["delivered_at"] is not None
            )
        else:
            common = False
        if not common:
            raise ApprovalAuditError(
                "approval audit event conflicts with durable approval state",
                approval_id=event.approval_id,
                event_id=event.event_id,
            )

    def _flush_event(self, event_id: str) -> None:
        if self._audit_sink is None:
            if self._audit_required:
                raise ApprovalAuditError("required approval audit sink is unavailable")
            return
        with self._connect() as conn:
            row = self._event_state_row(conn, event_id)
        if row is None:
            raise ApprovalAuditError("approval audit outbox event is missing")
        event = self._event_from_row(row)
        self._validate_event_state(row, event)
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
        try:
            receipt_verified = self._audit_sink.verify_receipt(event, receipt)
        except Exception as exc:
            raise ApprovalAuditError(
                "approval audit receipt verification failed",
                approval_id=event.approval_id,
                event_id=event.event_id,
            ) from exc
        if not receipt_verified:
            raise ApprovalAuditError(
                "approval audit receipt is not backed by the signed ledger",
                approval_id=event.approval_id,
                event_id=event.event_id,
            )
        receipt_json = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self._event_state_row(conn, event_id)
            if current is None:
                conn.rollback()
                raise ApprovalAuditError("approval audit outbox event disappeared")
            current_event = self._event_from_row(current)
            if current_event != event:
                conn.rollback()
                raise ApprovalAuditError("approval audit event changed during delivery")
            self._validate_event_state(current, event)
            if current["state"] == "delivered":
                if current["receipt_json"] != receipt_json:
                    conn.rollback()
                    raise ApprovalAuditError("delivered approval receipt changed")
                conn.commit()
                return
            finalized = conn.execute(
                """
                UPDATE approvals
                   SET status = pending_status,
                       pending_status = NULL,
                       pending_event_id = NULL,
                       last_audit_event_id = ?,
                       last_audit_receipt_json = ?
                 WHERE approval_id = ? AND status = 'audit_pending'
                   AND pending_status = ? AND pending_event_id = ?
                """,
                (
                    event_id, receipt_json, event.approval_id,
                    event.transition, event_id,
                ),
            )
            if finalized.rowcount != 1:
                conn.rollback()
                raise ApprovalAuditError("approval finalization lost its state race")
            delivered_at = self._now()
            delivered = conn.execute(
                """
                UPDATE approval_audit_outbox
                   SET state = 'delivered', receipt_json = ?, delivered_at = ?
                 WHERE event_id = ? AND state = 'pending'
                   AND receipt_json IS NULL AND delivered_at IS NULL
                """,
                (receipt_json, delivered_at, event_id),
            )
            if delivered.rowcount != 1:
                conn.rollback()
                raise ApprovalAuditError("approval outbox delivery lost its state race")
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
        decision_proof: DecisionProofEnvelope | None = None,
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
            decision_proof=decision_proof or item.decision_proof,
        )
        decided_at = transition_ts if transition in {"approved", "denied"} else item.decided_at
        consumed_at = transition_ts if transition == "consumed" else item.consumed_at
        expires_at = (
            transition_ts + self._approval_ttl
            if transition == "approved"
            else item.expires_at
        )
        terminal_at = transition_ts if transition in {"denied", "consumed", "expired"} else item.terminal_at
        proof_json = (
            json.dumps(
                (decision_proof or item.decision_proof).__dict__,
                sort_keys=True,
                separators=(",", ":"),
            )
            if (decision_proof or item.decision_proof) is not None
            else None
        )
        if decision_proof is not None:
            conn.execute(
                """
                INSERT INTO decision_nonce_tombstones
                    (nonce, approval_id, recorded_at, retain_until)
                VALUES (?, ?, ?, ?)
                """,
                (
                    decision_proof.nonce,
                    item.approval_id,
                    transition_ts,
                    transition_ts + self._nonce_retention,
                ),
            )
        cursor = conn.execute(
            """
            UPDATE approvals
               SET status = 'audit_pending', pending_status = ?, pending_event_id = ?,
                   operator_id = ?, decided_at = ?, consumed_at = ?, expires_at = ?,
                   terminal_at = ?, decision_proof_json = ?, decision_nonce = ?
             WHERE approval_id = ? AND status = ?
            """,
            (
                transition,
                event.event_id,
                operator_id or item.operator_id,
                decided_at,
                consumed_at,
                expires_at,
                terminal_at,
                proof_json,
                (decision_proof or item.decision_proof).nonce
                if (decision_proof or item.decision_proof) is not None
                else None,
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
            submitted_at = self._now()
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
                (approval_id, agent_id, action, context_json, self._now()),
            )
        return approval_id

    def _decide(
        self,
        approval_id: str,
        operator_id: str,
        status: str,
        operator_proof: str | bytes | None = None,
    ) -> bool:
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
            decision_proof = self._verify_decision_writer(
                item, operator_id, status, operator_proof
            )
            transition_ts = self._now()
            if self._audit_sink is None:
                cursor = conn.execute(
                    """
                    UPDATE approvals
                       SET status = ?, operator_id = ?, decided_at = ?,
                           expires_at = ?, terminal_at = ?
                     WHERE approval_id = ? AND status = 'pending'
                    """,
                    (
                        status,
                        operator_id,
                        transition_ts,
                        transition_ts + self._approval_ttl if status == "approved" else None,
                        transition_ts if status == "denied" else None,
                        approval_id,
                    ),
                )
                conn.commit()
                return cursor.rowcount == 1
            try:
                event_id = self._stage_existing(
                    conn,
                    item,
                    transition=status,
                    operator_id=operator_id,
                    transition_ts=transition_ts,
                    decision_proof=decision_proof,
                )
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise ApprovalAuditError(
                    "decision proof nonce was reused or approval state is invalid",
                    approval_id=approval_id,
                ) from exc
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
    ) -> Optional[PendingApproval]:
        current = self._now()
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
            if current < item.decided_at:
                conn.rollback()
                raise ApprovalAuditError("approval clock moved backward before decision time")
            if item.expires_at is None:
                conn.rollback()
                if self._audit_required:
                    raise ApprovalAuditError("approved capability has no explicit expiry")
                return None
            if current >= item.expires_at:
                if self._audit_sink is None:
                    conn.execute(
                        "UPDATE approvals SET status = 'expired', terminal_at = ? "
                        "WHERE approval_id = ? AND status = 'approved'",
                        (current, approval_id),
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
            rows = conn.execute(
                """
                SELECT * FROM approval_audit_outbox
                 WHERE approval_id = ? AND state = 'delivered'
                """,
                (item.approval_id,),
            ).fetchall()
        if len(rows) != 3 or not item.audit_receipt or item.decision_proof is None:
            return False
        pairs = [
            (row, self._event_from_row(row), json.loads(row["receipt_json"]))
            for row in rows
        ]
        if not all(isinstance(pair[2].get("ledger_seq"), int) for pair in pairs):
            return False
        pairs.sort(key=lambda pair: pair[2]["ledger_seq"])
        rows = [pair[0] for pair in pairs]
        events = [pair[1] for pair in pairs]
        if [event.transition for event in events] != ["pending", "approved", "consumed"]:
            return False
        pending, approved, consumed = events
        digest = canonical_context_digest(item.context)
        common = all(
            event.approval_id == item.approval_id
            and event.agent_id == agent_id
            and event.action == action
            and event.context_digest == digest
            for event in events
        )
        receipts = [pair[2] for pair in pairs]
        ledger_sequences = [receipt.get("ledger_seq") for receipt in receipts]
        expected = (
            common
            and pending.operator_id == ""
            and pending.decision_proof is None
            and approved.operator_id == item.operator_id
            and consumed.operator_id == item.operator_id
            and approved.decision_proof == item.decision_proof
            and consumed.decision_proof == item.decision_proof
            and item.decision_proof.verifies_binding(
                approval_id=item.approval_id,
                agent_id=agent_id,
                action=action,
                context_digest=digest,
                decision="approved",
                operator_id=item.operator_id,
            )
            and pending.transition_ts <= approved.transition_ts <= consumed.transition_ts
            and all(isinstance(seq, int) for seq in ledger_sequences)
            and ledger_sequences[0] < ledger_sequences[1] < ledger_sequences[2]
            and consumed.event_id == item.audit_event_id
            and receipts[-1] == item.audit_receipt
        )
        if not expected:
            return False
        for event, receipt in zip(events, receipts, strict=True):
            if not self._receipt_matches_event(receipt, event):
                return False
            try:
                if not self._audit_sink.verify_receipt(event, receipt):
                    return False
            except Exception:
                return False
        return True

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
        current = self._now()
        cutoff = current - self._max_age
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT a.approval_id
                  FROM approvals AS a
                 WHERE a.status IN ('denied', 'consumed', 'expired')
                   AND a.terminal_at IS NOT NULL AND a.terminal_at < ?
                   AND NOT EXISTS (
                       SELECT 1 FROM approval_audit_outbox AS o
                        WHERE o.approval_id = a.approval_id
                          AND (o.state != 'delivered' OR o.delivered_at IS NULL
                               OR o.delivered_at >= ?)
                   )
                """,
                (cutoff, cutoff),
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
            conn.execute(
                "DELETE FROM decision_nonce_tombstones WHERE retain_until <= ?",
                (current,),
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
