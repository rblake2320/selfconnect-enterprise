"""enterprise/ledger.py — Chained, Signed Agent Action Ledger

Every action submitted to this ledger is recorded as a signed, chained log entry.
The class does not intercept action paths that do not call ``log()``.
The chain makes retroactive tampering detectable: each entry hashes the
previous one, so modifying any entry breaks all subsequent hashes.

    from enterprise.identity import AgentIdentity
    from enterprise.ledger import AgentLedger

    identity = AgentIdentity.load("agent-e-orchestrator")
    ledger   = AgentLedger(identity)

    # Record an action
    ledger.log("executed file_count on hwnd 0xABC01234", result="46 files")
    ledger.log("dispatched task to agent-b", result="accepted")

    # Audit the chain
    valid, count, error = ledger.verify()
    assert valid, error
    print(f"{count} entries, all signatures valid, chain intact")

Log format (JSONL — one JSON object per line):
    {
        "seq":       1,                          # monotonic sequence number
        "agent_id":  "SC-A7F3B2E1",             # permanent agent ID
        "action":    "dispatched task to ...",   # what was done
        "result":    "accepted",                 # outcome
        "ts":        1715123642.0,               # Unix timestamp (time.time())
        "prev_hash": "a8c3f1...",               # SHA-256 of previous entry bytes
        "sig":       "3d9f01..."                # ed25519 signature (hex) over entry
    }

    genesis entry prev_hash = "0" * 64

Tamper evidence:
    - sig covers all other fields (seq, agent_id, action, result, ts, prev_hash)
    - prev_hash creates a hash chain — modifying entry N invalidates entry N+1..end
    - verify() checks both signature validity AND chain integrity for every entry

Version: 1.1.0-enterprise  Tier 1 identity hardening

Schema note (v1.1.0): New event types added to `action` field vocabulary.
All new types use the existing JSONL structure — no schema version bump needed
(confirmed: all consumers use lenient dict.get() access with no strict validation).

New action strings (Tier 1+):
    "discovery_candidate_capped"    — discover_mesh hit MAX_CANDIDATES_PER_CYCLE
    "suspicious_pid_stamp_volume"   — single PID stamped more SCID props than MAX_STAMPS_PER_PID
    "handshake_initiated"           — challenge-response started (Tier 2)
    "handshake_succeeded"           — challenge-response completed successfully (Tier 2)
    "handshake_rejected:{reason}"   — challenge-response failed (Tier 2)
    "v1_peer_accepted_during_grace" — unsigned peer accepted while sunset not yet reached (Tier 2)
    "v1_peer_rejected_at_sunset"    — unsigned peer rejected after sunset date (Tier 2)
    "key_rotation"                  — TPM key rotation transaction (Tier 2 + Tier 3)
    "mitigation_policy_applied"     — process hardening flags enabled (Tier 2)
    "birth_time_mismatch"           — per-message birth time validation failed (Tier 2)
    "emergency_override_activated"  — a rollback override flag was set (any tier)

New action strings (Tier 3 — BPC+TSK ultra-gate):
    "ultra_gate_pass"               — injection authorized (full 7-layer or degraded level N)
    "ultra_gate_deny:{reason}"      — injection blocked in enforce mode; reason describes failure
    "bpc_pair_registered"           — BPC pair registered with Ultra Server at bootstrap
    "tsk_provisioned"               — TSK client provisioned with Ultra Server at bootstrap
    "tsk_key_rotated"               — HOTP counter advanced after successful server verification
    "peer_key_rotation_recovery"    — peer agent key recovered; new pubkey accepted
    "emergency_bypass_activated"    — emergency bypass Named Mutex created (pid logged in result)
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Optional

from enterprise.identity import AgentIdentity, _default_data_dir
from enterprise.labels import LabelEnvelope
from enterprise.runtime_lifetime import RuntimeLifetime, governed_operation


_RESERVED_ENTRY_FIELDS = frozenset({
    "seq", "agent_id", "action", "result", "ts", "prev_hash", "sig", "algo",
})

# ── Sentinel for genesis entry ─────────────────────────────────────────────────

GENESIS_HASH = "0" * 64


class LedgerIntegrityError(RuntimeError):
    """Raised when an existing ledger cannot be safely resumed."""


# ── AgentLedger ────────────────────────────────────────────────────────────────

class AgentLedger:
    """Append-only, signed, hash-chained action log for a persistent agent identity.

    Each call to log() atomically appends one signed entry to the JSONL file.
    verify() re-reads the entire file and checks every signature and every
    hash link — any tampering is immediately visible.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        log_path: Optional[Path] = None,
        redact_denied: bool = False,
        max_entries_per_segment: int = 0,
        max_bytes_per_segment: int = 0,
    ) -> None:
        """
        Args:
            identity:      The AgentIdentity that owns this ledger (signs every entry).
            log_path:      Override the default log file path.
                           Default: %APPDATA%\\SelfConnect\\{agent_name}\\ledger.jsonl
            redact_denied: When True, entries where result=="denied" or
                           metadata["decision"]=="deny" are written with their
                           metadata replaced by {"decision": "deny", "redacted": True}.
                           This prevents policy configuration details from being
                           inferred from denial patterns in the raw ledger file.
                           (G-1 fix: NIST AC-4, SI-12)
        """
        self._identity     = identity
        self._log_path     = log_path or self._default_path(identity.agent_name)
        self._redact_denied = redact_denied
        if max_entries_per_segment < 0 or max_bytes_per_segment < 0:
            raise ValueError("ledger segment limits cannot be negative")
        self._max_entries_per_segment = max_entries_per_segment
        self._max_bytes_per_segment = max_bytes_per_segment
        valid, _, message = self.verify()
        if not valid:
            raise LedgerIntegrityError(
                f"refusing to resume an invalid ledger: {message}"
            )
        self._seq          = self._load_last_seq()
        self._prev_hash    = self._load_last_hash()
        self._nested_indexes: dict[
            tuple[str, str], dict[str, list[dict]]
        ] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def log_path(self) -> Path:
        """Absolute path to the JSONL log file."""
        return self._log_path

    @property
    def agent_id(self) -> str:
        """Permanent agent ID (from identity)."""
        return self._identity.agent_id

    def log(
        self,
        action: str,
        result: str = "",
        metadata: Optional[dict] = None,
        label: Optional[LabelEnvelope] = None,
    ) -> dict:
        """Append a signed, chained entry to the ledger.

        Args:
            action:   Human-readable description of what the agent did.
            result:   Outcome or return value of the action.
            metadata: Optional extra fields (merged into entry at top level).
                      Keys must not clash with reserved fields:
                      seq, agent_id, action, result, ts, prev_hash, sig.
            label:    Optional LabelEnvelope.  When provided, its to_dict()
                      is merged after metadata so the label is authoritative
                      for classification and caveat fields.

        Returns:
            The full entry dict as written (including sig).
        """
        collisions = _RESERVED_ENTRY_FIELDS.intersection(metadata or {})
        if collisions:
            raise ValueError(
                "metadata cannot overwrite reserved ledger fields: "
                + ", ".join(sorted(collisions))
            )

        self._rotate_if_needed()
        candidate_seq = self._seq + 1
        candidate_prev_hash = self._prev_hash

        # Determine if this is a deny entry that should be redacted (G-1 fix)
        _is_deny = (
            result == "denied"
            or (metadata is not None and metadata.get("decision") == "deny")
        )

        entry: dict = {
            "seq":       candidate_seq,
            "agent_id":  self._identity.agent_id,
            "action":    action,
            "result":    result,
            "ts":        time.time(),
            "prev_hash": candidate_prev_hash,
        }
        if self._redact_denied and _is_deny:
            # Replace metadata with a redacted stub — preserves the fact of denial
            # without exposing policy configuration details (NIST AC-4, SI-12).
            entry["decision"] = "deny"
            entry["redacted"] = True
        else:
            if metadata:
                entry.update(deepcopy(metadata))
            if label is not None:
                entry.update(deepcopy(label.to_dict()))

        # Sign the entry (canonical JSON, sorted keys, no sig field yet)
        entry_bytes = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        sig_bytes   = self._identity.sign(entry_bytes)
        entry["sig"] = sig_bytes.hex()

        candidate_hash = hashlib.sha256(entry_bytes).hexdigest()

        # Publish in-memory chain state only after the line is durable.  If a
        # partial append occurs, restore the previous file length before a
        # retry so this process and a restarted process see the same tail.
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        original_size = self._log_path.stat().st_size if self._log_path.exists() else 0
        try:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            try:
                if self._log_path.exists():
                    with self._log_path.open("r+b") as recovery:
                        recovery.truncate(original_size)
                        recovery.flush()
                        os.fsync(recovery.fileno())
                valid, _count, message = self.verify()
                if not valid:
                    raise LedgerIntegrityError(
                        f"ledger append recovery failed verification: {message}"
                    )
                self._seq = self._load_last_seq()
                self._prev_hash = self._load_last_hash()
            except Exception as recovery_error:
                raise LedgerIntegrityError(
                    "ledger append failed and the previous durable tail could not be restored"
                ) from recovery_error
            raise

        self._seq = candidate_seq
        self._prev_hash = candidate_hash
        self._update_nested_indexes(entry)

        return deepcopy(entry)

    def find_entries_by_nested_value(
        self,
        container: str,
        field: str,
        value: str,
    ) -> list[dict]:
        """Return indexed entries whose typed nested metadata matches ``value``.

        The first lookup builds one streaming in-memory index. Subsequent
        lookups and appends are O(1) for the requested metadata path. The
        single-writer ledger boundary still applies.
        """
        if not all(isinstance(part, str) and part for part in (container, field, value)):
            raise TypeError("nested ledger index keys and value must be non-empty strings")
        index_key = (container, field)
        index = self._nested_indexes.get(index_key)
        if index is None:
            index = {}
            for path in self._ledger_paths():
                with path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        nested = entry.get(container)
                        if nested is None:
                            continue
                        if not isinstance(nested, dict):
                            raise LedgerIntegrityError(
                                f"ledger field {container!r} must be an object"
                            )
                        nested_value = nested.get(field)
                        if nested_value is None:
                            continue
                        if not isinstance(nested_value, str):
                            raise LedgerIntegrityError(
                                f"ledger field {container}.{field} must be a string"
                            )
                        index.setdefault(nested_value, []).append(deepcopy(entry))
            self._nested_indexes[index_key] = index
        return deepcopy(index.get(value, []))

    def find_verified_entries_by_nested_value(
        self,
        container: str,
        field: str,
        value: str,
    ) -> list[dict]:
        """Return matches from one signature- and chain-verified disk snapshot.

        Unlike the performance index, this method never trusts cached objects.
        Receipts and authorization checks use the exact entries parsed from the
        same immutable byte snapshots whose signatures and links were verified.
        """
        if not all(isinstance(part, str) and part for part in (container, field, value)):
            raise TypeError("nested ledger index keys and value must be non-empty strings")
        valid, _count, message, entries = self._verify_snapshot()
        if not valid:
            raise LedgerIntegrityError(message)
        matches: list[dict] = []
        for entry in entries:
            nested = entry.get(container)
            if nested is None:
                continue
            if not isinstance(nested, dict):
                raise LedgerIntegrityError(f"ledger field {container!r} must be an object")
            nested_value = nested.get(field)
            if nested_value is None:
                continue
            if not isinstance(nested_value, str):
                raise LedgerIntegrityError(
                    f"ledger field {container}.{field} must be a string"
                )
            if nested_value == value:
                matches.append(deepcopy(entry))
        return matches

    def _update_nested_indexes(self, entry: dict) -> None:
        for (container, field), index in self._nested_indexes.items():
            nested = entry.get(container)
            if nested is None:
                continue
            if not isinstance(nested, dict) or not isinstance(nested.get(field), str):
                raise LedgerIntegrityError(
                    f"ledger field {container}.{field} must be a string"
                )
            index.setdefault(nested[field], []).append(deepcopy(entry))

    def verify(self) -> tuple[bool, int, str]:
        """Verify all signatures and hash chain integrity.

        Returns:
            (valid: bool, entry_count: int, message: str)
            valid=True means every signature is valid and every hash link is intact.
            valid=False includes a message describing the first failure.
        """
        valid, count, message, _entries = self._verify_snapshot()
        return valid, count, message

    def _verify_snapshot(self) -> tuple[bool, int, str, list[dict]]:
        """Read each ledger segment once and verify those exact bytes."""
        paths = self._ledger_paths()
        if not paths:
            return True, 0, "ledger is empty", []

        try:
            snapshots = [(path, path.read_bytes()) for path in paths]
        except OSError as exc:
            return False, 0, f"ledger snapshot read failed: {exc}", []

        prev_hash = GENESIS_HASH
        count     = 0
        expected_seq = 1
        verified_entries: list[dict] = []

        for path, snapshot in snapshots:
            for lineno, raw_line in enumerate(snapshot.splitlines(), start=1):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: JSON parse error: {exc}",
                        [],
                    )

                if not isinstance(entry, dict):
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: entry is not an object",
                        [],
                    )
                signed_entry = dict(entry)
                sig_hex = signed_entry.pop("sig", None)
                if sig_hex is None:
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: missing 'sig' field",
                        [],
                    )
                if signed_entry.get("seq") != expected_seq:
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: sequence mismatch "
                        f"(expected {expected_seq}, got {signed_entry.get('seq')!r})",
                        [],
                    )
                if signed_entry.get("agent_id") != self._identity.agent_id:
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: agent identity mismatch",
                        [],
                    )

                stored_prev = signed_entry.get("prev_hash", "")
                if stored_prev != prev_hash:
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: hash chain broken "
                        f"(expected {prev_hash[:12]}..., got {stored_prev!r})",
                        [],
                    )

                entry_bytes = json.dumps(
                    signed_entry, sort_keys=True, separators=(",", ":")
                ).encode()
                try:
                    sig_bytes = bytes.fromhex(sig_hex)
                except (TypeError, ValueError):
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: invalid sig hex",
                        [],
                    )

                pub_key_bytes = self._identity.public_key_bytes
                if not AgentIdentity.verify(entry_bytes, sig_bytes, pub_key_bytes):
                    return (
                        False,
                        count,
                        f"{path.name} line {lineno}: signature invalid",
                        [],
                    )

                prev_hash = hashlib.sha256(entry_bytes).hexdigest()
                count += 1
                expected_seq += 1
                verified_entries.append(entry)

        return (
            True,
            count,
            f"{count} entries, all signatures valid, chain intact",
            verified_entries,
        )

    def tail(self, n: int = 10) -> list[dict]:
        """Return the last n entries from the ledger (most recent last)."""
        lines: list[str] = []
        for path in self._ledger_paths():
            lines.extend(path.read_text(encoding="utf-8").splitlines())
        recent = [ln for ln in lines if ln.strip()][-n:]
        result = []
        for line in recent:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result

    def entry_count(self) -> int:
        """Return the number of entries across sealed and active segments."""
        total = 0
        for path in self._ledger_paths():
            total += sum(
                1
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        return total

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_last_seq(self) -> int:
        """Read the highest seq number from an existing log, or 0 if empty."""
        last = self._last_entry()
        return last.get("seq", 0) if last else 0

    def _load_last_hash(self) -> str:
        """Compute the hash of the last entry bytes (for chain continuation)."""
        last = self._last_entry()
        if not last:
            return GENESIS_HASH
        # Reconstruct the canonical bytes (sig excluded from hash input)
        last.pop("sig", None)
        entry_bytes = json.dumps(last, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(entry_bytes).hexdigest()

    def _last_entry(self) -> Optional[dict]:
        """Return the last non-empty parsed entry, or None."""
        for path in reversed(self._ledger_paths()):
            lines = [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            for line in reversed(lines):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None

    @property
    def archive_paths(self) -> tuple[Path, ...]:
        """Sealed local segment paths, oldest first."""
        return tuple(self._archive_paths())

    def _ledger_paths(self) -> list[Path]:
        paths = self._archive_paths()
        if self._log_path.exists():
            paths.append(self._log_path)
        return paths

    def _archive_dir(self) -> Path:
        return self._log_path.parent / f"{self._log_path.name}.segments"

    def _archive_paths(self) -> list[Path]:
        directory = self._archive_dir()
        if not directory.exists():
            return []
        return sorted(directory.glob("segment-*.jsonl"))

    def _current_entry_count(self) -> int:
        if not self._log_path.exists():
            return 0
        with self._log_path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    def _rotate_if_needed(self) -> None:
        if not self._log_path.exists() or self._log_path.stat().st_size == 0:
            return
        entry_limit_hit = (
            self._max_entries_per_segment > 0
            and self._current_entry_count() >= self._max_entries_per_segment
        )
        byte_limit_hit = (
            self._max_bytes_per_segment > 0
            and self._log_path.stat().st_size >= self._max_bytes_per_segment
        )
        if not entry_limit_hit and not byte_limit_hit:
            return

        valid, _, message = self.verify()
        if not valid:
            raise LedgerIntegrityError(
                f"refusing to rotate an invalid ledger: {message}"
            )
        entries = [
            json.loads(line)
            for line in self._log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not entries:
            return
        first_seq = int(entries[0]["seq"])
        last_seq = int(entries[-1]["seq"])
        archive_dir = self._archive_dir()
        archive_dir.mkdir(parents=True, exist_ok=True)
        target = archive_dir / (
            f"segment-{first_seq:020d}-{last_seq:020d}-{self._prev_hash[:16]}.jsonl"
        )
        if target.exists():
            raise LedgerIntegrityError(
                f"ledger segment already exists: {target.name}"
            )
        os.replace(self._log_path, target)

    @staticmethod
    def _default_path(agent_name: str) -> Path:
        return _default_data_dir() / agent_name / "ledger.jsonl"


# -- ThreadSafeAgentLedger (G-6 fix: NIST AU-9, AU-10) -----------------------

class ThreadSafeAgentLedger(AgentLedger):
    """Thread-safe wrapper around AgentLedger.

    AgentLedger documents a single-writer contract: callers must ensure that
    only one thread calls log() at a time.  ThreadSafeAgentLedger enforces
    that contract automatically via a reentrant lock, making it safe to share
    a single ledger instance across multiple threads.

    All public methods (log, verify, tail, entry_count) are serialised through
    the same lock.  The lock is reentrant so that verify() can call internal
    helpers without deadlocking.

    Usage::

        from enterprise.ledger import ThreadSafeAgentLedger
        ledger = ThreadSafeAgentLedger(identity)
        # Safe to call from multiple threads:
        threading.Thread(target=ledger.log, args=("action-a",)).start()
        threading.Thread(target=ledger.log, args=("action-b",)).start()

    Compliance: NIST AU-9 (audit log protection), AU-10 (non-repudiation).
    Gap closed: G-6 / MED-05 (AgentLedger single-writer contract not enforced).
    """

    def __init__(
        self,
        identity: AgentIdentity,
        log_path: Optional[Path] = None,
        redact_denied: bool = False,
        max_entries_per_segment: int = 0,
        max_bytes_per_segment: int = 0,
        runtime_lifetime: RuntimeLifetime | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._runtime_lifetime = runtime_lifetime
        super().__init__(
            identity,
            log_path,
            redact_denied=redact_denied,
            max_entries_per_segment=max_entries_per_segment,
            max_bytes_per_segment=max_bytes_per_segment,
        )

    @governed_operation
    def log(
        self,
        action: str,
        result: str = "",
        metadata: Optional[dict] = None,
        label: Optional[LabelEnvelope] = None,
    ) -> dict:
        """Thread-safe log() — serialised through an RLock."""
        with self._lock:
            return super().log(action, result=result, metadata=metadata, label=label)

    def verify(self) -> tuple[bool, int, str]:
        """Thread-safe verify() — serialised through an RLock."""
        with self._lock:
            return super().verify()

    def tail(self, n: int = 10) -> list[dict]:
        """Thread-safe tail() — serialised through an RLock."""
        with self._lock:
            return super().tail(n)

    def entry_count(self) -> int:
        """Thread-safe entry_count() — serialised through an RLock."""
        with self._lock:
            return super().entry_count()

    def find_entries_by_nested_value(
        self,
        container: str,
        field: str,
        value: str,
    ) -> list[dict]:
        """Thread-safe indexed nested metadata lookup."""
        with self._lock:
            return super().find_entries_by_nested_value(container, field, value)

    def find_verified_entries_by_nested_value(
        self,
        container: str,
        field: str,
        value: str,
    ) -> list[dict]:
        """Thread-safe lookup from one verified disk snapshot."""
        with self._lock:
            return super().find_verified_entries_by_nested_value(container, field, value)

