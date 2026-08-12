"""Durable monotonic revocation state for delegated agents and grants."""
from __future__ import annotations

import math
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

_TARGET_TYPES = frozenset({"agent", "grant"})
_CANONICAL_AGENT_PREFIX = "SCID-"


def _validate_agent_principal(value: object) -> str:
    if not isinstance(value, str) or not value.startswith(_CANONICAL_AGENT_PREFIX):
        raise ValueError("agent revocation requires a canonical SCID principal")
    digest = value[len(_CANONICAL_AGENT_PREFIX):]
    if len(digest) not in (64, 96) or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError("agent revocation requires a canonical SCID principal")
    return value


@dataclass(frozen=True)
class RevocationState:
    epoch: int
    revoked_agent_key_ids: frozenset[str]
    revoked_grant_ids: frozenset[str]


class RevocationRegistry:
    """SQLite-backed terminal revocations that never target human principals."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS revocation_meta (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), epoch INTEGER NOT NULL) STRICT"
        )
        self._connection.execute("INSERT OR IGNORE INTO revocation_meta(singleton, epoch) VALUES (1, 0)")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS revocation (
                target_type TEXT NOT NULL CHECK (target_type IN ('agent', 'grant')),
                target_id TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                revoked_at REAL NOT NULL,
                epoch INTEGER NOT NULL,
                PRIMARY KEY (target_type, target_id)
            ) STRICT
            """
        )
        try:
            self._reject_legacy_agent_rows()
        except Exception:
            self._connection.close()
            raise

    def _reject_legacy_agent_rows(self) -> None:
        """Refuse an ambiguous 32-bit revocation instead of silently dropping it.

        A legacy ``SC-XXXXXXXX`` row cannot be mapped to one public key after
        the fact because more than one key may share that display identifier.
        An operator must reconcile it using authoritative full-key evidence.
        """
        rows = self._connection.execute(
            "SELECT target_id FROM revocation WHERE target_type = 'agent'"
        ).fetchall()
        for row in rows:
            try:
                _validate_agent_principal(row[0])
            except ValueError as exc:
                raise RuntimeError(
                    "legacy or malformed agent revocation requires explicit full-key reconciliation"
                ) from exc

    def revoke_agent(self, canonical_agent_id: str, *, operator_id: str, reason: str, revoked_at: float) -> int:
        """Revoke one full-key principal, never a collision-prone display ID."""
        return self._revoke(
            "agent", _validate_agent_principal(canonical_agent_id), operator_id, reason, revoked_at
        )

    def revoke_grant(self, grant_id: str, *, operator_id: str, reason: str, revoked_at: float) -> int:
        return self._revoke("grant", grant_id, operator_id, reason, revoked_at)

    def _revoke(
        self,
        target_type: str,
        target_id: str,
        operator_id: str,
        reason: str,
        revoked_at: float,
    ) -> int:
        if target_type not in _TARGET_TYPES:
            raise ValueError("revocation target type is invalid")
        for name, value in (("target_id", target_id), ("operator_id", operator_id), ("reason", reason)):
            if not isinstance(value, str) or not value or len(value) > 1_024 or any(ord(ch) < 32 for ch in value):
                raise ValueError(f"{name} must be a bounded non-control string")
        if not isinstance(revoked_at, (int, float)) or not math.isfinite(float(revoked_at)):
            raise ValueError("revoked_at must be finite")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT epoch FROM revocation WHERE target_type = ? AND target_id = ?",
                    (target_type, target_id),
                ).fetchone()
                if existing is not None:
                    self._connection.execute("COMMIT")
                    return int(existing[0])
                epoch = int(
                    self._connection.execute(
                        "UPDATE revocation_meta SET epoch = epoch + 1 WHERE singleton = 1 RETURNING epoch"
                    ).fetchone()[0]
                )
                self._connection.execute(
                    "INSERT INTO revocation(target_type, target_id, operator_id, reason, revoked_at, epoch) VALUES (?, ?, ?, ?, ?, ?)",
                    (target_type, target_id, operator_id, reason, float(revoked_at), epoch),
                )
                self._connection.execute("COMMIT")
                return epoch
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def snapshot(self) -> RevocationState:
        with self._lock:
            self._reject_legacy_agent_rows()
            epoch = int(self._connection.execute("SELECT epoch FROM revocation_meta WHERE singleton = 1").fetchone()[0])
            rows = self._connection.execute("SELECT target_type, target_id FROM revocation").fetchall()
        return RevocationState(
            epoch=epoch,
            revoked_agent_key_ids=frozenset(target_id for target_type, target_id in rows if target_type == "agent"),
            revoked_grant_ids=frozenset(target_id for target_type, target_id in rows if target_type == "grant"),
        )

    def acp_snapshot(self):
        """Return the exact ACP snapshot type without making storage depend on ACP."""
        from enterprise.acp_shim import RevocationSnapshot

        state = self.snapshot()
        return RevocationSnapshot(
            epoch=state.epoch,
            revoked_agent_key_ids=state.revoked_agent_key_ids,
            revoked_grant_ids=state.revoked_grant_ids,
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class RevocationWatcher:
    """Bounded local watcher that propagates durable epochs into an ACP shim."""

    def __init__(self, registry: RevocationRegistry, target, *, poll_interval: float = 0.25) -> None:
        if not isinstance(poll_interval, (int, float)) or not 0.05 <= float(poll_interval) <= 60.0:
            raise ValueError("poll_interval must be between 0.05 and 60 seconds")
        if not callable(getattr(target, "apply_revocations", None)):
            raise TypeError("revocation watcher target must apply revocation snapshots")
        self._registry = registry
        self._target = target
        self._poll_interval = float(poll_interval)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_epoch = -1
        self._last_error: str | None = None
        self._lock = threading.Lock()

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    @property
    def last_epoch(self) -> int:
        with self._lock:
            return self._last_epoch

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("revocation watcher is already running")
            self._stop.clear()
            self._last_error = None
            self._thread = threading.Thread(target=self._run, name="selfconnect-revocation", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                raise TimeoutError("revocation watcher did not stop")

    def poll_once(self) -> tuple[str, ...]:
        snapshot = self._registry.acp_snapshot()
        with self._lock:
            if snapshot.epoch == self._last_epoch:
                return ()
        removed = tuple(self._target.apply_revocations(snapshot))
        with self._lock:
            self._last_epoch = snapshot.epoch
            self._last_error = None
        return removed

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # noqa: BLE001 - health state is bounded to type
                with self._lock:
                    self._last_error = type(exc).__name__
            self._stop.wait(self._poll_interval)


__all__ = ["RevocationRegistry", "RevocationState", "RevocationWatcher"]
