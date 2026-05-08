"""enterprise/export_guard.py — Evidence Export Restriction Enforcer

Gates EvidenceExporter based on a ClassifiedModeProfile and the LabelEnvelope
of the evidence being exported.  Two conditions must both be true for an
export to be permitted:

    1. profile.allow_export is True
    2. The evidence label is dominated by the profile ceiling
       (label.le(ceiling_label) is True)

Every decision — allowed or denied — is logged to the agent's ledger.

Usage:
    from enterprise.export_guard import ExportGuard
    from enterprise.classified_mode import ClassifiedModeProfile
    from enterprise.labels import LabelEnvelope, Classification

    profile = ClassifiedModeProfile.secret_baseline()
    guard   = ExportGuard(profile, ledger)

    label = LabelEnvelope(classification=Classification.SECRET)
    if guard.can_export(label):
        exporter.export_records(records, label)

    # Or with automatic ledger logging:
    if guard.check_and_log(label, agent_id="SC-AGENT1"):
        exporter.export_records(records, label)

Version: 1.0.0-enterprise  Session 18
"""
from __future__ import annotations

from typing import Any

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.labels import LabelEnvelope


class ExportGuard:
    """Gates evidence export based on profile and label.

    Deny conditions (either stops export):
        1. profile.allow_export is False
        2. label.classification > profile.max_classification
        3. label.caveats ⊄ profile.allowed_caveats (label has caveats not
           permitted in this deployment)

    Args:
        profile: The active ClassifiedModeProfile.
        ledger:  Optional AgentLedger / CngLedger.  Every check is logged
                 as an "export_check" entry.
    """

    def __init__(
        self,
        profile: ClassifiedModeProfile,
        ledger: Any = None,
    ) -> None:
        self._profile = profile
        self._ledger  = ledger
        # Build ceiling envelope once — reused for every can_export() call
        self._ceiling = LabelEnvelope(
            classification = profile.max_classification,
            caveats        = profile.allowed_caveats,
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def can_export(self, label: LabelEnvelope) -> bool:
        """Return True if evidence with this label may be exported.

        Does NOT log.  Use check_and_log() for the auditing path.

        Args:
            label: The LabelEnvelope of the evidence record to be exported.

        Returns:
            True if export is permitted, False if denied.
        """
        if not self._profile.allow_export:
            return False
        # Label must be dominated by the profile ceiling (Bell-LaPadula ≤)
        return label.le(self._ceiling)

    def check_and_log(self, label: LabelEnvelope, agent_id: str = "") -> bool:
        """Return can_export() result and log the decision to the ledger.

        Args:
            label:    LabelEnvelope of the evidence to export.
            agent_id: The agent initiating the export (ledger attribution).

        Returns:
            True if export is permitted, False if denied.
        """
        allowed = self.can_export(label)
        self._log(agent_id=agent_id, label=label, allowed=allowed)
        return allowed

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def profile(self) -> ClassifiedModeProfile:
        return self._profile

    @property
    def ceiling(self) -> LabelEnvelope:
        """The effective ceiling envelope derived from the profile."""
        return self._ceiling

    # ── Internal ──────────────────────────────────────────────────────────────

    def _deny_reason(self, label: LabelEnvelope) -> str:
        if not self._profile.allow_export:
            return "export disabled by profile"
        if label.classification > self._profile.max_classification:
            return (
                f"label classification {label.classification.name!r} exceeds "
                f"profile ceiling {self._profile.max_classification.name!r}"
            )
        bad_caveats = label.caveats - self._profile.allowed_caveats
        if bad_caveats:
            return f"label contains caveats not permitted in this deployment: {sorted(bad_caveats)!r}"
        return "denied"

    def _log(self, agent_id: str, label: LabelEnvelope, allowed: bool) -> None:
        if self._ledger is None:
            return
        meta: dict = {
            "agent_id":          agent_id,
            "profile_id":        self._profile.profile_id,
            "label_classification": label.classification.name,
            "label_caveats":     sorted(label.caveats),
            "decision":          "allow" if allowed else "deny",
        }
        if not allowed:
            meta["deny_reason"] = self._deny_reason(label)
        self._ledger.log(
            "export_check",
            result   = "allowed" if allowed else "denied",
            metadata = meta,
        )


__all__ = ["ExportGuard"]
