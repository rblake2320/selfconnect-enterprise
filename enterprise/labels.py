"""enterprise/labels.py — Canonical Classification Labels and LabelEnvelope

Single source of truth for classification vocabulary used across the
enterprise module.  policy.py and observer.py both previously duplicated
_CLASSIFICATION_RANK / _rank(); they now import from here.

Classification levels follow the US government marking scale:
    UNCLASSIFIED < CUI < SECRET < TOP_SECRET

Caveat handling follows the Bell-LaPadula lattice model:
    LabelEnvelope.le(other) is True when
        self.classification ≤ other.classification
        AND self.caveats ⊆ other.caveats

Usage:
    from enterprise.labels import Classification, LabelEnvelope, rank, le

    # Quick ceiling check (replaces inline _rank comparisons)
    if not le(entry_classification, agent_max):
        deny(...)

    # Full label with caveats
    label = LabelEnvelope(
        classification=Classification.SECRET,
        caveats=frozenset({"NOFORN", "SI"}),
        originator="SC-ADMIN1234",
    )
    label.validate()   # True — both caveats are in ALLOWED_CAVEATS
    label.to_dict()    # {"classification": "SECRET", "caveats": ["NOFORN", "SI"], ...}

Version: 1.0.0-enterprise  Session 18
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Union

# ── Classification enum ────────────────────────────────────────────────────────

class Classification(IntEnum):
    """Ordered classification levels.  Integer value = rank for comparison."""
    UNCLASSIFIED = 0
    CUI          = 1
    SECRET       = 2
    TOP_SECRET   = 3


# ── Canonical level list (preserves old CLASSIFICATION_LEVELS interface) ───────

CLASSIFICATION_LEVELS: list[str] = [m.name for m in Classification]


# ── Allowed caveats ────────────────────────────────────────────────────────────

ALLOWED_CAVEATS: frozenset[str] = frozenset({
    "NOFORN",   # Not releasable to foreign nationals
    "ORCON",    # Originator controlled
    "REL_TO",   # Releasable to (specific countries)
    "FISA",     # Foreign Intelligence Surveillance Act
    "HCS",      # HUMINT Control System
    "SI",       # Special Intelligence
    "TK",       # Talent Keyhole (satellite imagery)
    "GAMMA",    # GAMMA (signals intelligence)
})


# ── rank() and le() — canonical comparators ───────────────────────────────────

_RANK_MAP: dict[str, int] = {m.name: m.value for m in Classification}


def rank(level: Union[str, Classification]) -> int:
    """Return numeric rank for a classification value.

    Accepts both string names (case-insensitive) and Classification enum values.
    Unknown strings raise ValueError so an unrecognized marking cannot sort
    below UNCLASSIFIED and bypass a ceiling.
    """
    if isinstance(level, Classification):
        return level.value
    if not isinstance(level, str):
        raise TypeError(f"classification must be str or Classification, got {type(level).__name__}")
    normalized = level.upper()
    if normalized not in _RANK_MAP:
        raise ValueError(f"unknown classification: {level!r}")
    return _RANK_MAP[normalized]


def le(a: Union[str, Classification], b: Union[str, Classification]) -> bool:
    """Return True if classification a is at or below classification b.

    Equivalent to rank(a) <= rank(b).  Convenience wrapper for ceiling checks.
    """
    return rank(a) <= rank(b)


# ── LabelEnvelope ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LabelEnvelope:
    """Immutable label carrier: classification + caveats + provenance.

    Attach to ledger entries, policy decisions, and evidence records so that
    every record in the audit chain carries a verified label.

    Fields:
        classification: Enumerated level (UNCLASSIFIED … TOP_SECRET).
        caveats:        Handling caveats drawn from ALLOWED_CAVEATS.
        originator:     Agent ID or human ID that applied this label.
        ts:             Unix epoch when the label was applied.  Defaults to 0
                        (callers should pass time.time() for production use).

    Lattice semantics (Bell-LaPadula):
        self.le(other) is True when
            self.classification ≤ other.classification
            AND self.caveats ⊆ other.caveats
        Meaning: self is "dominated by" other — self does not exceed other's
        classification ceiling and does not require any compartment that other
        does not also grant.
    """
    classification: Classification
    caveats:        frozenset[str] = field(default_factory=frozenset)
    originator:     str            = ""
    ts:             float          = 0.0

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_classification(cls, level: Union[str, Classification]) -> "LabelEnvelope":
        """Quick factory for label from a classification level only.

        Args:
            level: String name ("SECRET") or Classification enum value.
        """
        if isinstance(level, str):
            try:
                level = Classification[level.upper()]
            except KeyError as exc:
                raise ValueError(f"unknown classification: {level!r}") from exc
        if not isinstance(level, Classification):
            raise TypeError("classification must be str or Classification")
        return cls(classification=level, ts=time.time())

    @classmethod
    def from_dict(cls, d: dict) -> "LabelEnvelope":
        """Reconstruct a LabelEnvelope from a to_dict() output.

        Tolerates missing fields — defaults to UNCLASSIFIED with no caveats.
        """
        raw_cls = d.get("classification", "UNCLASSIFIED")
        if isinstance(raw_cls, str):
            try:
                classification = Classification[raw_cls.upper()]
            except KeyError as exc:
                raise ValueError(f"unknown classification: {raw_cls!r}") from exc
        elif isinstance(raw_cls, int):
            try:
                classification = Classification(raw_cls)
            except ValueError as exc:
                raise ValueError(f"unknown classification rank: {raw_cls!r}") from exc
        else:
            raise TypeError("classification must be a string or integer rank")

        raw_caveats = d.get("caveats", [])
        caveats = frozenset(raw_caveats) if raw_caveats else frozenset()

        return cls(
            classification = classification,
            caveats        = caveats,
            originator     = str(d.get("originator", "")),
            ts             = float(d.get("label_ts", 0.0)),
        )

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dict suitable for ledger metadata.

        Keys:
            classification: str name, e.g. "SECRET"
            caveats:        sorted list of caveat strings
            originator:     str
            label_ts:       float  (uses "label_ts" to avoid collision with
                                    the ledger entry's own "ts" field)
        """
        return {
            "classification": self.classification.name,
            "caveats":        sorted(self.caveats),
            "originator":     self.originator,
            "label_ts":       self.ts,
        }

    # ── Lattice operations ────────────────────────────────────────────────────

    def le(self, other: "LabelEnvelope") -> bool:
        """Return True if self is dominated by other (Bell-LaPadula ≤).

        self ≤ other  ⟺  self.classification ≤ other.classification
                         AND self.caveats ⊆ other.caveats
        """
        return (
            self.classification <= other.classification
            and self.caveats <= other.caveats   # frozenset ≤ is subset test
        )

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self) -> bool:
        """Return True if all caveats are in ALLOWED_CAVEATS."""
        return self.caveats <= ALLOWED_CAVEATS

    def __repr__(self) -> str:
        cav = "/".join(sorted(self.caveats)) if self.caveats else ""
        suffix = f"//{cav}" if cav else ""
        return f"LabelEnvelope({self.classification.name}{suffix})"


# ── Public API ─────────────────────────────────────────────────────────────────

__all__ = [
    "Classification",
    "CLASSIFICATION_LEVELS",
    "ALLOWED_CAVEATS",
    "rank",
    "le",
    "LabelEnvelope",
]
