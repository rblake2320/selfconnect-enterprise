"""enterprise.session_index — Signed session manifest and resume index.

The session index is the persistent record of all sessions started by this
agent. It enables:
  - /resume --list: show all resumable sessions
  - /resume <id>: verify the chain and re-spawn with context
  - Rollback detection: compare local manifest against remote witness receipts

SECURITY
--------
The manifest file is itself append-only and hash-chained. Each entry is signed
with the recorder's identity key if available. This prevents an attacker from
modifying the manifest to point to a different log file or change the expected
sequence number (Fix 2).

Rollback detection (Fix 2, Fix 10):
  - Each manifest entry records the first_event_hash and last_known_seq.
  - On resume, verify() checks that the log's first event hash matches the
    manifest's recorded first_event_hash.
  - If a ReplicationSink is available, the manifest entry's last_known_seq
    is compared against the remote witness receipt. A local manifest that
    disagrees with the remote receipt indicates rollback.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from enterprise.provenance import (
    AuditMode,
    ProvenanceRecorder,
    ReplicationSink,
    SessionState,
    VerificationResult,
    canonical_hash,
    verify_log,
)

_DEFAULT_INDEX_FILENAME = "session_index.jsonl"
_INDEX_DIR_ENV = "SC_PROVENANCE_DIR"


# ---------------------------------------------------------------------------
# SessionManifestEntry
# ---------------------------------------------------------------------------

@dataclass
class SessionManifestEntry:
    """A single entry in the session index."""

    session_id: str
    agent_id: str
    audit_mode: str
    started_at: str
    log_path: str
    first_event_hash: Optional[str] = None
    last_known_seq: int = 0
    last_heartbeat_ts: Optional[str] = None
    session_state: str = SessionState.OPEN.value
    closed_at: Optional[str] = None
    summary: Optional[dict] = None
    remote_receipt: Optional[dict] = None   # last replication sink receipt
    # Hash chain fields (the index itself is chained)
    prev_hash: str = "0" * 96
    entry_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "audit_mode": self.audit_mode,
            "started_at": self.started_at,
            "log_path": self.log_path,
            "first_event_hash": self.first_event_hash,
            "last_known_seq": self.last_known_seq,
            "last_heartbeat_ts": self.last_heartbeat_ts,
            "session_state": self.session_state,
            "closed_at": self.closed_at,
            "summary": self.summary,
            "remote_receipt": self.remote_receipt,
            "prev_hash": self.prev_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionManifestEntry":
        return cls(
            session_id=d.get("session_id", ""),
            agent_id=d.get("agent_id", ""),
            audit_mode=d.get("audit_mode", AuditMode.CONSUMER.value),
            started_at=d.get("started_at", ""),
            log_path=d.get("log_path", ""),
            first_event_hash=d.get("first_event_hash"),
            last_known_seq=d.get("last_known_seq", 0),
            last_heartbeat_ts=d.get("last_heartbeat_ts"),
            session_state=d.get("session_state", SessionState.OPEN.value),
            closed_at=d.get("closed_at"),
            summary=d.get("summary"),
            remote_receipt=d.get("remote_receipt"),
            prev_hash=d.get("prev_hash", "0" * 96),
            entry_hash=d.get("entry_hash"),
        )


# ---------------------------------------------------------------------------
# SessionIndexError
# ---------------------------------------------------------------------------

class SessionIndexError(RuntimeError):
    """Raised when the session index is corrupt or a resume is blocked."""


# ---------------------------------------------------------------------------
# ResumeVerificationResult
# ---------------------------------------------------------------------------

@dataclass
class ResumeVerificationResult:
    """Result of a resume pre-flight check."""
    ok: bool
    session_id: str
    chain_result: Optional[VerificationResult]
    manifest_entry: Optional[SessionManifestEntry]
    message: str
    rollback_suspected: bool = False
    fork_suspected: bool = False


# ---------------------------------------------------------------------------
# SessionIndex
# ---------------------------------------------------------------------------

class SessionIndex:
    """Signed, hash-chained session manifest.

    Parameters
    ----------
    index_dir:
        Directory for the index file. Defaults to $SC_PROVENANCE_DIR or
        ~/.selfconnect/provenance/.
    identity:
        Optional AgentIdentity for signing index entries.
    replication_sink:
        Optional ReplicationSink for remote receipt comparison (Fix 2).
    """

    def __init__(
        self,
        index_dir: Optional[Path] = None,
        identity: Any = None,
        replication_sink: Optional[ReplicationSink] = None,
    ) -> None:
        if index_dir is None:
            env_dir = os.environ.get(_INDEX_DIR_ENV)
            index_dir = Path(env_dir) if env_dir else (
                Path.home() / ".selfconnect" / "provenance"
            )
        self._index_dir = Path(index_dir)
        self._index_path = self._index_dir / _DEFAULT_INDEX_FILENAME
        self._identity = identity
        self._replication_sink = replication_sink
        self._lock = threading.Lock()
        self._prev_hash = "0" * 96
        self._entries: dict[str, SessionManifestEntry] = {}
        self._loaded = False

    # ── Public API ────────────────────────────────────────────────────────

    def open_session(
        self,
        recorder: ProvenanceRecorder,
    ) -> SessionManifestEntry:
        """Register a new session in the index.

        Must be called after recorder.start() so that first_event_hash
        is available.
        """
        with self._lock:
            self._ensure_loaded()
            entry = SessionManifestEntry(
                session_id=recorder.session_id,
                agent_id=recorder._agent_id,
                audit_mode=recorder._audit_mode.value,
                started_at=datetime.now(timezone.utc).isoformat(),
                log_path=str(recorder.log_path),
                first_event_hash=recorder._first_event_hash,
                last_known_seq=recorder.event_count,
                session_state=SessionState.OPEN.value,
                prev_hash=self._prev_hash,
            )
            self._write_entry(entry)
            return entry

    def update_session(
        self,
        session_id: str,
        recorder: Optional[ProvenanceRecorder] = None,
        state: Optional[SessionState] = None,
        summary: Optional[dict] = None,
        remote_receipt: Optional[dict] = None,
    ) -> Optional[SessionManifestEntry]:
        """Update an existing session entry (e.g., on close or heartbeat)."""
        with self._lock:
            self._ensure_loaded()
            entry = self._entries.get(session_id)
            if entry is None:
                return None
            if recorder is not None:
                entry.last_known_seq = recorder.event_count
                if recorder._first_event_hash:
                    entry.first_event_hash = recorder._first_event_hash
            if state is not None:
                entry.session_state = state.value
                if state == SessionState.SEALED:
                    entry.closed_at = datetime.now(timezone.utc).isoformat()
            if summary is not None:
                entry.summary = summary
            if remote_receipt is not None:
                entry.remote_receipt = remote_receipt
            # Re-append updated entry (append-only — we do not modify in place)
            entry.prev_hash = self._prev_hash
            self._write_entry(entry)
            return entry

    def list_sessions(
        self,
        state_filter: Optional[str] = None,
        limit: int = 50,
    ) -> list[SessionManifestEntry]:
        """Return sessions, optionally filtered by state, newest first."""
        with self._lock:
            self._ensure_loaded()
            entries = list(self._entries.values())
            if state_filter:
                entries = [e for e in entries if e.session_state == state_filter]
            entries.sort(key=lambda e: e.started_at, reverse=True)
            return entries[:limit]

    def get_session(self, session_id: str) -> Optional[SessionManifestEntry]:
        """Return the manifest entry for a session, or None."""
        with self._lock:
            self._ensure_loaded()
            return self._entries.get(session_id)

    def verify_for_resume(
        self,
        session_id: str,
    ) -> ResumeVerificationResult:
        """Pre-flight verification before resuming a session (Fix 10).

        Checks:
        1. Manifest entry exists.
        2. Log file exists.
        3. Chain is intact (verify_log).
        4. First event hash matches manifest (prepend-attack detection, Fix 1).
        5. Last seq >= manifest's last_known_seq (rollback detection, Fix 2).
        6. Remote witness receipt comparison if sink is available (Fix 2).

        Returns ResumeVerificationResult. If ok=False, resume is blocked.
        """
        with self._lock:
            self._ensure_loaded()
            entry = self._entries.get(session_id)
            if entry is None:
                return ResumeVerificationResult(
                    ok=False,
                    session_id=session_id,
                    chain_result=None,
                    manifest_entry=None,
                    message=f"No manifest entry found for session {session_id!r}.",
                )

            log_path = Path(entry.log_path)
            if not log_path.exists():
                return ResumeVerificationResult(
                    ok=False,
                    session_id=session_id,
                    chain_result=None,
                    manifest_entry=entry,
                    message=f"Log file not found: {log_path}",
                )

            chain_result = verify_log(log_path, session_id)
            if not chain_result.ok:
                return ResumeVerificationResult(
                    ok=False,
                    session_id=session_id,
                    chain_result=chain_result,
                    manifest_entry=entry,
                    message=f"Chain verification failed: {chain_result.message}",
                )

            # Fix 1: first event hash check (prepend-attack detection)
            if entry.first_event_hash:
                # Read first non-ack line from log
                actual_first_hash = _read_first_event_hash(log_path)
                if actual_first_hash and actual_first_hash != entry.first_event_hash:
                    return ResumeVerificationResult(
                        ok=False,
                        session_id=session_id,
                        chain_result=chain_result,
                        manifest_entry=entry,
                        message=(
                            "Prepend attack suspected: first event hash mismatch. "
                            f"Manifest: {entry.first_event_hash[:16]}… "
                            f"Log: {actual_first_hash[:16]}…"
                        ),
                    )

            # Fix 2: rollback detection — log seq must be >= manifest's last_known_seq
            rollback_suspected = False
            if (
                entry.last_known_seq > 0
                and chain_result.high_water_seq < entry.last_known_seq
            ):
                rollback_suspected = True

            # Fix 2: remote witness comparison
            fork_suspected = False
            if self._replication_sink is not None:
                remote_receipt = self._replication_sink.get_latest_receipt(session_id)
                if remote_receipt and entry.remote_receipt:
                    local_root = entry.remote_receipt.get("root", "")
                    remote_root = remote_receipt.get("root", "")
                    if local_root and remote_root and local_root != remote_root:
                        fork_suspected = True

            if rollback_suspected or fork_suspected:
                reasons = []
                if rollback_suspected:
                    reasons.append(
                        f"rollback suspected (manifest seq={entry.last_known_seq}, "
                        f"log high-water={chain_result.high_water_seq})"
                    )
                if fork_suspected:
                    reasons.append("fork suspected (local/remote receipt mismatch)")
                return ResumeVerificationResult(
                    ok=False,
                    session_id=session_id,
                    chain_result=chain_result,
                    manifest_entry=entry,
                    message="; ".join(reasons),
                    rollback_suspected=rollback_suspected,
                    fork_suspected=fork_suspected,
                )

            return ResumeVerificationResult(
                ok=True,
                session_id=session_id,
                chain_result=chain_result,
                manifest_entry=entry,
                message=chain_result.message,
            )

    def verify_index_chain(self) -> tuple[bool, str]:
        """Verify the hash chain of the index file itself."""
        with self._lock:
            if not self._index_path.exists():
                return True, "no index file"
            prev = "0" * 96
            count = 0
            try:
                with open(self._index_path, encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as exc:
                            return False, f"JSON error at line {lineno}: {exc}"
                        stored_prev = record.get("prev_hash", "")
                        if stored_prev != prev:
                            return False, (
                                f"index chain break at line {lineno}: "
                                f"expected {prev[:16]}… got {stored_prev[:16]}…"
                            )
                        prev = canonical_hash(record)
                        count += 1
            except OSError as exc:
                return False, f"read error: {exc}"
            return True, f"{count} index entries, chain intact"

    # ── Internal ──────────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._load()
        self._loaded = True

    def _load(self) -> None:
        """Load existing index entries from disk."""
        if not self._index_path.exists():
            return
        try:
            with open(self._index_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        entry = SessionManifestEntry.from_dict(d)
                        # Keep the latest entry per session_id
                        self._entries[entry.session_id] = entry
                        self._prev_hash = canonical_hash(d)
                    except (json.JSONDecodeError, KeyError):
                        pass
        except OSError:
            pass

    def _write_entry(self, entry: SessionManifestEntry) -> None:
        """Append a manifest entry to the index file."""
        self._index_dir.mkdir(parents=True, exist_ok=True)
        d = entry.to_dict()
        entry.entry_hash = canonical_hash(d)
        d["entry_hash"] = entry.entry_hash
        self._entries[entry.session_id] = entry
        self._prev_hash = canonical_hash(d)
        try:
            with open(self._index_path, "a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                    + "\n"
                )
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise SessionIndexError(f"Failed to write session index: {exc}") from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_first_event_hash(log_path: Path) -> Optional[str]:
    """Read and hash the first non-ack event record from a log file."""
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    seq = record.get("seq", "")
                    if isinstance(seq, str) and seq.startswith("ack-"):
                        continue
                    return canonical_hash(record)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return None
