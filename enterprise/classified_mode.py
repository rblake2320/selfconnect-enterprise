"""enterprise/classified_mode.py — Classified Deployment Mode Profile

Immutable deployment profile for classified environments.  Loaded once at
agent startup; governs all runtime behavior for the session.

A ClassifiedModeProfile specifies:
    - Classification ceiling for all operations
    - Permitted caveats
    - Whether CNG identity (FIPS 140-2) is required (rejecting DPAPI fallback)
    - Whether unsigned policies are accepted
    - Whether outbound cloud/LLM API calls are permitted
    - Whether EvidenceExporter may write training data to disk
    - Actions that always require operator approval (regardless of policy)

Two hardened baselines are provided:
    ClassifiedModeProfile.secret_baseline()  — SECRET ceiling, CNG required,
                                               no cloud egress, no export
    ClassifiedModeProfile.cui_baseline()     — CUI ceiling, CNG optional,
                                               cloud egress and export allowed

Custom profiles are constructed directly or loaded from signed JSON files via
from_file().  The signature is verified with the bundle's embedded public key
or an external trust root; a tampered or unsigned file fails closed.

Integration:
    Pass a profile to PolicyEnforcer(profile=...) to enforce CNG identity
    requirements.  Pass to EgressGuard and ExportGuard to enforce egress and
    export restrictions.  LedgerObserver automatically inherits the profile's
    allowed_caveats when a profile is attached.

Version: 1.0.0-enterprise  Session 18
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from enterprise.labels import ALLOWED_CAVEATS, Classification

# ── ClassifiedModeProfile ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class ClassifiedModeProfile:
    """Immutable deployment profile for classified environments.

    All fields are read-only after construction.  To create a modified copy,
    use dataclasses.replace().

    Fields:
        max_classification:           Ceiling for all operations.  Requests
                                      for data above this level are denied.
        allowed_caveats:              Subset of ALLOWED_CAVEATS permitted in
                                      this deployment.  Empty = no caveats.
        require_cng_identity:         If True, DPAPI-backed AgentIdentity is
                                      rejected; only CngIdentity is accepted.
        require_signed_policy:        If True, unsigned PolicyBundles fail
                                      closed (equivalent to require_signature
                                      in PolicyEnforcer).
        allow_cloud_egress:           If False, all outbound API calls are
                                      denied and logged by EgressGuard.
        allowed_destinations:         When allow_cloud_egress is True and this
                                      set is non-empty, only destinations in
                                      this set are permitted.  Empty set means
                                      any destination is allowed (use only for
                                      development/CUI profiles).  Has no effect
                                      when allow_cloud_egress is False.
        allow_export:                 If False, EvidenceExporter is disabled
                                      and ExportGuard denies all export
                                      attempts.
        require_operator_approval_for: Actions that always require operator
                                      step-up approval regardless of policy.
        allowed_apps:                 App allowlist overlay.  Empty = defer
                                      to policy-level allowlist.
        blocked_apps:                 App blocklist overlay.  Merged with
                                      policy-level blocked_apps.
        profile_id:                   Unique identifier for this profile
                                      version.
        signed_by:                    agent_id of the authority that signed
                                      this profile file.
    """
    max_classification:            Classification
    allowed_caveats:               frozenset[str]          = field(default_factory=frozenset)
    require_cng_identity:          bool                    = True
    require_signed_policy:         bool                    = True
    allow_cloud_egress:            bool                    = False
    allowed_destinations:          frozenset[str]          = field(default_factory=frozenset)
    allow_export:                  bool                    = False
    require_operator_approval_for: frozenset[str]          = field(default_factory=frozenset)
    allowed_apps:                  frozenset[str]          = field(default_factory=frozenset)
    blocked_apps:                  frozenset[str]          = field(default_factory=frozenset)
    profile_id:                    str                     = ""
    signed_by:                     str                     = ""

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self) -> list[str]:
        """Return a list of validation errors.  Empty list = profile is valid."""
        errors: list[str] = []
        if not isinstance(self.max_classification, Classification):
            errors.append(
                f"max_classification must be a Classification enum, "
                f"got {type(self.max_classification).__name__!r}"
            )
        bad_caveats = self.allowed_caveats - ALLOWED_CAVEATS
        if bad_caveats:
            errors.append(
                f"allowed_caveats contains unrecognised values: {sorted(bad_caveats)!r}"
            )
        return errors

    def is_valid(self) -> bool:
        """Return True if validate() returns no errors."""
        return len(self.validate()) == 0

    # ── Policy constraint export ──────────────────────────────────────────────

    def to_policy_constraints(self) -> dict:
        """Export profile constraints as a dict PolicyEnforcer can consume.

        Returns:
            Dict with keys: max_classification (str), require_cng_identity (bool),
            require_signed_policy (bool), allow_cloud_egress (bool),
            allow_export (bool), require_operator_approval_for (list),
            allowed_apps (list), blocked_apps (list).
        """
        return {
            "max_classification":            self.max_classification.name,
            "require_cng_identity":          self.require_cng_identity,
            "require_signed_policy":         self.require_signed_policy,
            "allow_cloud_egress":            self.allow_cloud_egress,
            "allowed_destinations":          sorted(self.allowed_destinations),
            "allow_export":                  self.allow_export,
            "require_operator_approval_for": sorted(self.require_operator_approval_for),
            "allowed_apps":                  sorted(self.allowed_apps),
            "blocked_apps":                  sorted(self.blocked_apps),
        }

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "profile_id":                    self.profile_id,
            "signed_by":                     self.signed_by,
            "max_classification":            self.max_classification.name,
            "allowed_caveats":               sorted(self.allowed_caveats),
            "require_cng_identity":          self.require_cng_identity,
            "require_signed_policy":         self.require_signed_policy,
            "allow_cloud_egress":            self.allow_cloud_egress,
            "allowed_destinations":          sorted(self.allowed_destinations),
            "allow_export":                  self.allow_export,
            "require_operator_approval_for": sorted(self.require_operator_approval_for),
            "allowed_apps":                  sorted(self.allowed_apps),
            "blocked_apps":                  sorted(self.blocked_apps),
        }

    def save(self, path: Path) -> None:
        """Write the profile as formatted JSON (unsigned)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, d: dict) -> "ClassifiedModeProfile":
        """Reconstruct a ClassifiedModeProfile from a dict."""
        raw_cls = d.get("max_classification", "UNCLASSIFIED")
        try:
            max_cls = Classification[raw_cls.upper()] if isinstance(raw_cls, str) else Classification(raw_cls)
        except (KeyError, ValueError):
            max_cls = Classification.UNCLASSIFIED

        return cls(
            profile_id                    = str(d.get("profile_id", "")),
            signed_by                     = str(d.get("signed_by", "")),
            max_classification            = max_cls,
            allowed_caveats               = frozenset(d.get("allowed_caveats", [])),
            require_cng_identity          = bool(d.get("require_cng_identity", True)),
            require_signed_policy         = bool(d.get("require_signed_policy", True)),
            allow_cloud_egress            = bool(d.get("allow_cloud_egress", False)),
            allowed_destinations          = frozenset(d.get("allowed_destinations", [])),
            allow_export                  = bool(d.get("allow_export", False)),
            require_operator_approval_for = frozenset(d.get("require_operator_approval_for", [])),

            allowed_apps                  = frozenset(d.get("allowed_apps", [])),
            blocked_apps                  = frozenset(d.get("blocked_apps", [])),
        )

    @classmethod
    def from_file(
        cls,
        path: Path,
        verify_signature: bool = True,
        trust_root_pub: Optional[bytes] = None,
    ) -> "ClassifiedModeProfile":
        """Load a ClassifiedModeProfile from a JSON file.

        Args:
            path:             Path to the profile JSON file.
            verify_signature: If True (default), a missing or invalid signature
                              causes a RuntimeError (fail-closed).  Set False
                              only in development/test mode.
            trust_root_pub:   96-byte ECDSA P-384 public key of the signing
                              authority.  If None, uses the 'signed_by_pub'
                              field embedded in the file.

        Raises:
            RuntimeError: If verify_signature=True and signature is absent or
                          invalid.
            FileNotFoundError: If path does not exist.
        """
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        profile = cls.from_dict(raw)

        if verify_signature:
            sig_hex = raw.get("sig", "")
            if not sig_hex:
                raise RuntimeError(
                    f"ClassifiedModeProfile at {path!r} has no signature "
                    f"(require_signature=True)"
                )
            try:
                from enterprise.crypto import cng_verify
                pub_hex = raw.get("signed_by_pub", "")
                pub = trust_root_pub or (bytes.fromhex(pub_hex) if pub_hex else None)
                if pub is None:
                    raise RuntimeError(
                        f"No public key available to verify profile signature at {path!r}"
                    )
                # Signable bytes: all fields except sig and signed_by_pub
                signable = {k: v for k, v in raw.items() if k not in ("sig", "signed_by_pub")}
                msg = json.dumps(signable, sort_keys=True, separators=(",", ":")).encode()
                if not cng_verify(msg, bytes.fromhex(sig_hex), pub):
                    raise RuntimeError(
                        f"ClassifiedModeProfile at {path!r} signature verification failed"
                    )
            except RuntimeError:
                raise
            except Exception as exc:
                raise RuntimeError(
                    f"ClassifiedModeProfile signature verification error: {exc}"
                ) from exc

        return profile

    # ── Hardened baselines ────────────────────────────────────────────────────

    @classmethod
    def secret_baseline(cls) -> "ClassifiedModeProfile":
        """Factory: SECRET-level baseline with conservative classified defaults.

        - Ceiling: SECRET
        - Caveats: SI, NOFORN only
        - CNG identity required (FIPS 140-2)
        - Signed policy required
        - No cloud egress
        - No export (training data write disabled)
        - export_content requires operator approval
        """
        return cls(
            profile_id             = "secret-baseline-v1",
            max_classification     = Classification.SECRET,
            allowed_caveats        = frozenset({"SI", "NOFORN"}),
            require_cng_identity   = True,
            require_signed_policy  = True,
            allow_cloud_egress     = False,
            allow_export           = False,
            require_operator_approval_for = frozenset({"export_content", "write_file"}),
        )

    @classmethod
    def cui_baseline(cls) -> "ClassifiedModeProfile":
        """Factory: CUI-level baseline for high-assurance commercial deployments.

        - Ceiling: CUI
        - Caveats: none
        - CNG identity optional
        - Signed policy required
        - Cloud egress allowed
        - Export allowed
        """
        return cls(
            profile_id             = "cui-baseline-v1",
            max_classification     = Classification.CUI,
            allowed_caveats        = frozenset(),
            require_cng_identity   = False,
            require_signed_policy  = True,
            allow_cloud_egress     = True,
            allow_export           = True,
        )

    def __repr__(self) -> str:
        return (
            f"ClassifiedModeProfile("
            f"id={self.profile_id!r}, "
            f"ceiling={self.max_classification.name}, "
            f"egress={self.allow_cloud_egress}, "
        f"destinations={len(self.allowed_destinations)}, "
        f"export={self.allow_export})"
        )


# ── Public API ─────────────────────────────────────────────────────────────────

__all__ = ["ClassifiedModeProfile"]
