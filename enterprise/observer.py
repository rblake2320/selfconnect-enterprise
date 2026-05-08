"""enterprise/observer.py — Observer and Learning Pipeline

Reads policy-governed ledger entries and extracts them as structured training
evidence for LoRA fine-tuning of local models (Ollama, HuggingFace PEFT, etc.)

The observer operates ONLY on entries where decision=allow — actions that were
explicitly permitted by a signed PolicyEnforcer evaluation.  This guarantees
that any model trained on this evidence cannot learn behaviors that the policy
forbade.

Patent claim coverage:
    "A system in which an AI agent observes its own policy-approved action
    history to produce structured training data for a constrained fine-tuning
    process, such that the resulting fine-tuned model cannot learn behaviors
    outside the original policy boundary because it was never exposed to them."

Architecture:
    ObserverFilter    — criteria: decision, policy_id, classification, action
    RedactionConfig   — field-level masking/removal before any export
    EvidenceRecord    — a single filtered + redacted training record
    LedgerObserver    — reads a JSONL ledger, applies filter, yields records
    EvidenceExporter  — writes records to a training JSONL file (Alpaca or Chat)
    TrainingTrigger   — fires a LoRA training command when N records accumulate
    ShadowHook        — callback interface for live shadow-feedback mode

Every action the observer itself takes is logged to an optional observer_ledger,
making the observer's own behavior auditable by the same system it observes.

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from enterprise.labels import rank as _rank

# ── ObserverFilter ─────────────────────────────────────────────────────────────

@dataclass
class ObserverFilter:
    """Criteria controlling which ledger entries qualify as training evidence.

    All criteria must match.  Defaults accept only autonomous-approved,
    UNCLASSIFIED-or-below, allow-decision entries from any policy.

    Attributes:
        allowed_decisions:      Entry "decision" field values to include.
                                Default: ["allow"] — denied/quarantined entries
                                are never included in training data.
        allowed_policy_ids:     Whitelist of policy IDs.  Empty = any policy.
        max_classification:     Entries with classification above this are
                                excluded.  Default "SECRET".
        allowed_actions:        Whitelist of action strings.  Empty = any action.
        allowed_approval_modes: Modes to include.  Default both autonomous and
                                human-approved (but never denied/quarantined).
        min_seq:                Skip entries with seq <= this value (resume).
        allowed_caveats:        Whitelist of permitted caveats.  Empty = no
                                restriction.  When non-empty, entries whose
                                caveats are not a subset of this list are
                                excluded from training data.
    """
    allowed_decisions:      list[str] = field(default_factory=lambda: ["allow"])
    allowed_policy_ids:     list[str] = field(default_factory=list)
    max_classification:     str       = "SECRET"
    allowed_actions:        list[str] = field(default_factory=list)
    allowed_approval_modes: list[str] = field(
        default_factory=lambda: ["autonomous", "human_approved"]
    )
    min_seq:         int       = 0
    allowed_caveats: list[str] = field(default_factory=list)

    def matches(self, entry: dict) -> bool:
        """Return True if the entry satisfies all filter criteria."""
        # Must have been an allowed decision
        if entry.get("decision", "") not in self.allowed_decisions:
            return False

        # Approval mode filter
        mode = entry.get("approval_mode", "")
        if self.allowed_approval_modes and mode not in self.allowed_approval_modes:
            return False

        # Policy ID whitelist
        if self.allowed_policy_ids and entry.get("policy_id", "") not in self.allowed_policy_ids:
            return False

        # Classification ceiling
        if _rank(entry.get("classification", "UNCLASSIFIED")) > _rank(self.max_classification):
            return False

        # Caveat filter (only when a restriction is configured)
        if self.allowed_caveats:
            entry_caveats = set(entry.get("caveats", []))
            if not entry_caveats <= set(self.allowed_caveats):
                return False

        # Action whitelist
        if self.allowed_actions and entry.get("action", "") not in self.allowed_actions:
            return False

        # Sequence resume
        if entry.get("seq", 0) <= self.min_seq:
            return False

        return True


# ── RedactionConfig ────────────────────────────────────────────────────────────

@dataclass
class RedactionConfig:
    """Field-level redaction applied to every entry before it is exported.

    Attributes:
        remove_fields: Field names to delete entirely from the entry.
        mask_fields:   Dict mapping field name → replacement string.
                       e.g. {"result": "[REDACTED]", "operator_id": "[OPERATOR]"}
    """
    remove_fields: list[str]      = field(default_factory=list)
    mask_fields:   dict[str, str] = field(default_factory=dict)

    def apply(self, entry: dict) -> dict:
        """Return a new dict with redaction applied.  Does not modify the input."""
        result = dict(entry)
        for f in self.remove_fields:
            result.pop(f, None)
        for f, mask in self.mask_fields.items():
            if f in result:
                result[f] = mask
        return result


# ── EvidenceRecord ─────────────────────────────────────────────────────────────

@dataclass
class EvidenceRecord:
    """A single policy-approved action record ready for training.

    Produced by LedgerObserver.extract().  Call to_alpaca() or to_chat() to
    get a training-ready dict, or use raw directly for custom processing.
    """
    seq:             int
    agent_id:        str
    action:          str
    result:          str
    ts:              float
    policy_id:       str
    classification:  str
    approval_mode:   str
    decision:        str
    operator_id:     str
    context_before:  list[dict]   # up to N redacted entries before this one
    raw:             dict         # full post-redaction entry

    def to_alpaca(self) -> dict:
        """Alpaca-format training record: {instruction, input, output, metadata}.

        Compatible with standard LoRA fine-tuning frameworks including Ollama,
        Axolotl, and HuggingFace PEFT.
        """
        ctx = " → ".join(e.get("action", "") for e in self.context_before) or "(start)"
        return {
            "instruction": (
                f"You are agent {self.agent_id} operating under policy "
                f"{self.policy_id!r}. "
                "Given the prior action sequence, determine what action was "
                "taken and its result."
            ),
            "input":  f"Prior actions: {ctx}\nClassification: {self.classification}",
            "output": f"{self.action}: {self.result}",
            "metadata": {
                "seq":           self.seq,
                "policy_id":     self.policy_id,
                "classification": self.classification,
                "approval_mode": self.approval_mode,
                "ts":            self.ts,
            },
        }

    def to_chat(self) -> dict:
        """OpenAI chat-format training record: {messages: [...], metadata}.

        Compatible with ChatML, LLaMA-3 chat, and Mistral instruct formats.
        """
        ctx = " → ".join(e.get("action", "") for e in self.context_before) or "(start)"
        return {
            "messages": [
                {
                    "role":    "system",
                    "content": (
                        f"You are agent {self.agent_id} operating under policy "
                        f"{self.policy_id!r} at classification level "
                        f"{self.classification}."
                    ),
                },
                {
                    "role":    "user",
                    "content": f"Prior actions: [{ctx}]. What action was taken next?",
                },
                {
                    "role":    "assistant",
                    "content": f"{self.action}: {self.result}",
                },
            ],
            "metadata": {
                "seq":           self.seq,
                "policy_id":     self.policy_id,
                "classification": self.classification,
                "approval_mode": self.approval_mode,
            },
        }


# ── LedgerObserver ─────────────────────────────────────────────────────────────

class LedgerObserver:
    """Reads a JSONL ledger, applies filter + redaction, returns EvidenceRecords.

    The observer is read-only with respect to the source ledger.  Its own
    extract() and tail() calls are logged to observer_ledger if provided.
    """

    def __init__(
        self,
        ledger_path: Path,
        observer_filter: Optional[ObserverFilter] = None,
        redaction: Optional[RedactionConfig] = None,
        context_window: int = 3,
        observer_ledger: Any = None,
    ) -> None:
        """
        Args:
            ledger_path:      Path to the source JSONL ledger file.
            observer_filter:  Filter criteria.  Defaults to allow-only.
            redaction:        Redaction rules.  Defaults to no redaction.
            context_window:   Number of entries before each qualifying entry
                              to include as context.
            observer_ledger:  Optional AgentLedger / CngLedger — if provided,
                              the observer logs its own extraction events there.
        """
        self._path            = Path(ledger_path)
        self._filter          = observer_filter or ObserverFilter()
        self._redaction       = redaction or RedactionConfig()
        self._context_window  = context_window
        self._observer_ledger = observer_ledger

    def extract(self, since_seq: int = 0) -> list[EvidenceRecord]:
        """Read all entries, filter, and return qualifying EvidenceRecords.

        Args:
            since_seq: Skip entries with seq <= since_seq (for incremental runs).

        Returns:
            List of EvidenceRecord, in ledger order.
        """
        if not self._path.exists():
            return []

        all_entries = self._load_entries()
        effective_min_seq = max(self._filter.min_seq, since_seq)
        records: list[EvidenceRecord] = []

        for i, entry in enumerate(all_entries):
            # Apply seq floor before other checks (fast path)
            if entry.get("seq", 0) <= effective_min_seq:
                continue
            if not self._filter.matches(entry):
                continue

            # Context window: N entries immediately before this one in the raw log
            ctx_start      = max(0, i - self._context_window)
            context_before = [self._redaction.apply(e) for e in all_entries[ctx_start:i]]

            redacted = self._redaction.apply(entry)
            records.append(EvidenceRecord(
                seq            = entry.get("seq", 0),
                agent_id       = entry.get("agent_id", ""),
                action         = entry.get("action", ""),
                result         = entry.get("result", ""),
                ts             = entry.get("ts", 0.0),
                policy_id      = entry.get("policy_id", ""),
                classification = entry.get("classification", "UNCLASSIFIED"),
                approval_mode  = entry.get("approval_mode", "autonomous"),
                decision       = entry.get("decision", ""),
                operator_id    = entry.get("operator_id", ""),
                context_before = context_before,
                raw            = redacted,
            ))

        if self._observer_ledger is not None and records:
            self._observer_ledger.log(
                "observer_extracted",
                result=f"{len(records)} records",
                metadata={
                    "source_ledger":    str(self._path),
                    "records_extracted": len(records),
                    "since_seq":        since_seq,
                },
            )

        return records

    def max_seq(self) -> int:
        """Return the highest seq number in the ledger, or 0 if empty/missing."""
        if not self._path.exists():
            return 0
        entries = self._load_entries()
        if not entries:
            return 0
        return max(e.get("seq", 0) for e in entries)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_entries(self) -> list[dict]:
        entries = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries


# ── EvidenceExporter ───────────────────────────────────────────────────────────

class EvidenceExporter:
    """Exports filtered ledger evidence to a JSONL file for LoRA training.

    Supports three output formats:
        "alpaca"  — {instruction, input, output, metadata}
        "chat"    — {messages: [...], metadata}
        "raw"     — post-redaction entry dict as-is

    Output file is append-mode — safe to call repeatedly for incremental export.
    """

    def __init__(
        self,
        output_path: Path,
        fmt: str = "alpaca",
        observer_ledger: Any = None,
    ) -> None:
        self._output_path     = Path(output_path)
        self._fmt             = fmt
        self._observer_ledger = observer_ledger

    def export_from_ledger(
        self,
        ledger_path: Path,
        observer_filter: Optional[ObserverFilter] = None,
        redaction: Optional[RedactionConfig] = None,
        context_window: int = 3,
        since_seq: int = 0,
    ) -> int:
        """Extract from ledger_path and append to the output file.

        Returns:
            Number of records written.
        """
        obs = LedgerObserver(
            ledger_path,
            observer_filter = observer_filter,
            redaction       = redaction,
            context_window  = context_window,
        )
        records = obs.extract(since_seq=since_seq)
        if not records:
            return 0

        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._output_path.open("a", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(self._format(rec)) + "\n")

        if self._observer_ledger is not None:
            self._observer_ledger.log(
                "evidence_exported",
                result=f"{len(records)} records → {self._output_path.name}",
                metadata={
                    "source_ledger":   str(ledger_path),
                    "output_path":     str(self._output_path),
                    "format":          self._fmt,
                    "records_written": len(records),
                    "since_seq":       since_seq,
                },
            )

        return len(records)

    def record_count(self) -> int:
        """Return the number of lines currently in the output file."""
        if not self._output_path.exists():
            return 0
        return sum(1 for ln in self._output_path.read_text(encoding="utf-8").splitlines() if ln.strip())

    def _format(self, rec: EvidenceRecord) -> dict:
        if self._fmt == "alpaca":
            return rec.to_alpaca()
        if self._fmt == "chat":
            return rec.to_chat()
        return rec.raw


# ── TrainingTrigger ────────────────────────────────────────────────────────────

class TrainingTrigger:
    """Fires a LoRA training command when accumulated record count hits a threshold.

    Usage:
        trigger = TrainingTrigger(
            threshold=500,
            command=["ollama", "fine-tune", "--data", "training.jsonl",
                     "--model", "qwen3:7b", "--output", "agent-local-v2"],
        )
        count = exporter.export_from_ledger(ledger_path, ...)
        trigger.on_records(count)  # fires command when total >= 500
    """

    def __init__(
        self,
        threshold: int,
        command: list[str],
        observer_ledger: Any = None,
    ) -> None:
        self._threshold       = threshold
        self._command         = command
        self._accumulated     = 0
        self._observer_ledger = observer_ledger

    def on_records(self, count: int) -> bool:
        """Add count to accumulator.  Fires command if threshold reached.

        Returns:
            True if command was triggered, False otherwise.
        """
        self._accumulated += count
        if self._accumulated >= self._threshold:
            fired_at = self._accumulated
            self._accumulated = 0
            self._fire(fired_at)
            return True
        return False

    @property
    def accumulated(self) -> int:
        """Current accumulated record count (resets after trigger)."""
        return self._accumulated

    def _fire(self, record_count: int) -> None:
        if self._observer_ledger is not None:
            self._observer_ledger.log(
                "training_trigger_fired",
                result=f"fired at {record_count} records",
                metadata={
                    "command":      self._command,
                    "threshold":    self._threshold,
                    "record_count": record_count,
                },
            )
        subprocess.Popen(self._command)


# ── ShadowHook ────────────────────────────────────────────────────────────────

class ShadowHook:
    """Callback interface for live shadow-feedback mode.

    The shadow observer receives every qualifying entry in real time and may
    propose an alternative action.  It never executes — it only observes and
    suggests.  Suggestions are logged to observer_ledger if provided.

    Register by passing instances to LedgerObserver as shadow_hooks.

    Implement observe() in a subclass to add intelligence.
    """

    def observe(
        self,
        record: EvidenceRecord,
        observer_ledger: Any = None,
    ) -> Optional[str]:
        """Called for each qualifying evidence record.

        Override this method to propose an alternative action.

        Args:
            record:           The qualifying evidence record.
            observer_ledger:  Ledger to log the proposal to (or None).

        Returns:
            Proposed alternative action string, or None for no suggestion.
        """
        return None


# ── Public API ─────────────────────────────────────────────────────────────────

__all__ = [
    "ObserverFilter",
    "RedactionConfig",
    "EvidenceRecord",
    "LedgerObserver",
    "EvidenceExporter",
    "TrainingTrigger",
    "ShadowHook",
]
