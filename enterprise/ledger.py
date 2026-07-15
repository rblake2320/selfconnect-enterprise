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
import threading
import time
from pathlib import Path
from typing import Optional

from enterprise.identity import AgentIdentity, _default_data_dir
from enterprise.labels import LabelEnvelope


_RESERVED_ENTRY_FIELDS = frozenset({
    "seq", "agent_id", "action", "result", "ts", "prev_hash", "sig", "algo",
})

# ── Sentinel for genesis entry ─────────────────────────────────────────────────

GENESIS_HASH = "0" * 64


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
        self._seq          = self._load_last_seq()
        self._prev_hash    = self._load_last_hash()

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

        self._seq += 1

        # Determine if this is a deny entry that should be redacted (G-1 fix)
        _is_deny = (
            result == "denied"
            or (metadata is not None and metadata.get("decision") == "deny")
        )

        entry: dict = {
            "seq":       self._seq,
            "agent_id":  self._identity.agent_id,
            "action":    action,
            "result":    result,
            "ts":        time.time(),
            "prev_hash": self._prev_hash,
        }
        if self._redact_denied and _is_deny:
            # Replace metadata with a redacted stub — preserves the fact of denial
            # without exposing policy configuration details (NIST AC-4, SI-12).
            entry["decision"] = "deny"
            entry["redacted"] = True
        else:
            if metadata:
                entry.update(metadata)
            if label is not None:
                entry.update(label.to_dict())

        # Sign the entry (canonical JSON, sorted keys, no sig field yet)
        entry_bytes = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        sig_bytes   = self._identity.sign(entry_bytes)
        entry["sig"] = sig_bytes.hex()

        # Advance the chain
        self._prev_hash = hashlib.sha256(entry_bytes).hexdigest()

        # Append to log (atomic line write)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

        return entry

    def verify(self) -> tuple[bool, int, str]:
        """Verify all signatures and hash chain integrity.

        Returns:
            (valid: bool, entry_count: int, message: str)
            valid=True means every signature is valid and every hash link is intact.
            valid=False includes a message describing the first failure.
        """
        if not self._log_path.exists():
            return True, 0, "ledger is empty"

        prev_hash = GENESIS_HASH
        count     = 0

        with self._log_path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, count, f"line {lineno}: JSON parse error: {exc}"

                # Extract and remove sig for verification
                sig_hex = entry.pop("sig", None)
                if sig_hex is None:
                    return False, count, f"line {lineno}: missing 'sig' field"

                # Verify hash chain link
                stored_prev = entry.get("prev_hash", "")
                if stored_prev != prev_hash:
                    return (
                        False,
                        count,
                        f"line {lineno}: hash chain broken "
                        f"(expected {prev_hash[:12]}..., got {stored_prev[:12]}...)",
                    )

                # Verify signature over canonical entry bytes (without sig field)
                entry_bytes = json.dumps(
                    entry, sort_keys=True, separators=(",", ":")
                ).encode()
                try:
                    sig_bytes = bytes.fromhex(sig_hex)
                except ValueError:
                    return False, count, f"line {lineno}: invalid sig hex"

                pub_key_bytes = self._identity.public_key_bytes
                if not AgentIdentity.verify(entry_bytes, sig_bytes, pub_key_bytes):
                    return False, count, f"line {lineno}: signature invalid"

                prev_hash = hashlib.sha256(entry_bytes).hexdigest()
                count += 1

        return True, count, f"{count} entries, all signatures valid, chain intact"

    def tail(self, n: int = 10) -> list[dict]:
        """Return the last n entries from the ledger (most recent last)."""
        if not self._log_path.exists():
            return []
        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        recent = [ln for ln in lines if ln.strip()][-n:]
        result = []
        for line in recent:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result

    def entry_count(self) -> int:
        """Return the number of entries currently in the ledger."""
        if not self._log_path.exists():
            return 0
        return sum(1 for ln in self._log_path.read_text(encoding="utf-8").splitlines() if ln.strip())

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_last_seq(self) -> int:
        """Read the highest seq number from an existing log, or 0 if empty."""
        if not self._log_path.exists():
            return 0
        last = self._last_entry()
        return last.get("seq", 0) if last else 0

    def _load_last_hash(self) -> str:
        """Compute the hash of the last entry bytes (for chain continuation)."""
        if not self._log_path.exists():
            return GENESIS_HASH
        last = self._last_entry()
        if not last:
            return GENESIS_HASH
        # Reconstruct the canonical bytes (sig excluded from hash input)
        last.pop("sig", None)
        entry_bytes = json.dumps(last, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(entry_bytes).hexdigest()

    def _last_entry(self) -> Optional[dict]:
        """Return the last non-empty parsed entry, or None."""
        if not self._log_path.exists():
            return None
        lines = [ln for ln in self._log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return None

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
    ) -> None:
        self._lock = threading.RLock()
        super().__init__(identity, log_path, redact_denied=redact_denied)

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

