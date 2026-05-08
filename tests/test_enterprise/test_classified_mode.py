"""tests/test_enterprise/test_classified_mode.py — Classified Mode Profile Tests

45 tests across 8 classes covering ClassifiedModeProfile, EgressGuard,
ExportGuard, and PolicyEnforcer profile integration.

Coverage:
    ClassifiedModeProfile construction, validation, serialisation, round-trip
    secret_baseline() and cui_baseline() factory methods
    from_file() with verify_signature=False
    EgressGuard: allow / deny / wrap / ledger logging
    ExportGuard: can_export ceiling check, caveat check, export disabled
    check_and_log() audit trail
    PolicyEnforcer with profile= (CNG enforcement, classification ceiling)
    End-to-end classified mode scenario
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.egress_guard import EgressGuard
from enterprise.export_guard import ExportGuard
from enterprise.labels import Classification, LabelEnvelope

# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_enforcer(max_classification: str = "SECRET", profile=None):
    from enterprise.policy import PolicyEnforcer, make_bundle
    bundle = make_bundle(
        "test-policy",
        agents={
            "SC-AGENT1": {
                "role": "worker",
                "clearance": "SECRET",
                "allowed_actions": ["read_text", "write_file", "export_content"],
                "max_classification": max_classification,
            }
        },
    )
    return PolicyEnforcer(bundle, require_signature=False, profile=profile)


def _mock_ledger() -> MagicMock:
    ledger = MagicMock()
    ledger.log = MagicMock(return_value={})
    return ledger


# ── TestClassifiedModeProfile ─────────────────────────────────────────────────

class TestClassifiedModeProfile:
    def test_construction_minimal(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
        )
        assert profile.max_classification == Classification.SECRET
        assert profile.allow_cloud_egress is False
        assert profile.allow_export is False
        assert profile.require_cng_identity is True
        assert profile.require_signed_policy is True

    def test_frozen_immutable(self):
        profile = ClassifiedModeProfile(max_classification=Classification.CUI)
        with pytest.raises((AttributeError, TypeError)):
            profile.max_classification = Classification.SECRET  # type: ignore[misc]

    def test_validate_valid_profile(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"SI", "NOFORN"}),
        )
        assert profile.validate() == []
        assert profile.is_valid() is True

    def test_validate_invalid_caveats(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"BOGUS", "SI"}),
        )
        errors = profile.validate()
        assert len(errors) == 1
        assert "BOGUS" in errors[0]

    def test_to_dict_keys(self):
        profile = ClassifiedModeProfile(max_classification=Classification.SECRET)
        d = profile.to_dict()
        expected = {
            "profile_id", "signed_by", "max_classification", "allowed_caveats",
            "require_cng_identity", "require_signed_policy", "allow_cloud_egress",
            "allow_export", "require_operator_approval_for", "allowed_apps", "blocked_apps",
        }
        assert set(d.keys()) == expected

    def test_from_dict_roundtrip(self):
        original = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"SI"}),
            allow_cloud_egress=False,
            allow_export=False,
            profile_id="test-profile-v1",
        )
        restored = ClassifiedModeProfile.from_dict(original.to_dict())
        assert restored.max_classification == original.max_classification
        assert restored.allowed_caveats == original.allowed_caveats
        assert restored.profile_id == original.profile_id

    def test_from_dict_unknown_classification_defaults_unclassified(self):
        profile = ClassifiedModeProfile.from_dict({"max_classification": "BOGUS"})
        assert profile.max_classification == Classification.UNCLASSIFIED

    def test_to_policy_constraints_keys(self):
        profile = ClassifiedModeProfile(max_classification=Classification.SECRET)
        c = profile.to_policy_constraints()
        assert "max_classification" in c
        assert "require_cng_identity" in c
        assert "allow_cloud_egress" in c
        assert c["max_classification"] == "SECRET"

    def test_save_and_from_file(self, tmp_path):
        profile = ClassifiedModeProfile(
            max_classification=Classification.CUI,
            profile_id="save-test",
        )
        p = tmp_path / "profile.json"
        profile.save(p)
        loaded = ClassifiedModeProfile.from_file(p, verify_signature=False)
        assert loaded.max_classification == Classification.CUI
        assert loaded.profile_id == "save-test"

    def test_from_file_missing_sig_raises_when_verify_true(self, tmp_path):
        profile = ClassifiedModeProfile(max_classification=Classification.SECRET)
        p = tmp_path / "profile.json"
        profile.save(p)
        with pytest.raises(RuntimeError, match="no signature"):
            ClassifiedModeProfile.from_file(p, verify_signature=True)


# ── TestBaselines ─────────────────────────────────────────────────────────────

class TestBaselines:
    def test_secret_baseline_is_valid(self):
        profile = ClassifiedModeProfile.secret_baseline()
        assert profile.is_valid() is True

    def test_secret_baseline_ceiling(self):
        profile = ClassifiedModeProfile.secret_baseline()
        assert profile.max_classification == Classification.SECRET

    def test_secret_baseline_no_egress(self):
        assert ClassifiedModeProfile.secret_baseline().allow_cloud_egress is False

    def test_secret_baseline_no_export(self):
        assert ClassifiedModeProfile.secret_baseline().allow_export is False

    def test_secret_baseline_requires_cng(self):
        assert ClassifiedModeProfile.secret_baseline().require_cng_identity is True

    def test_cui_baseline_is_valid(self):
        profile = ClassifiedModeProfile.cui_baseline()
        assert profile.is_valid() is True

    def test_cui_baseline_ceiling(self):
        assert ClassifiedModeProfile.cui_baseline().max_classification == Classification.CUI

    def test_cui_baseline_allows_egress(self):
        assert ClassifiedModeProfile.cui_baseline().allow_cloud_egress is True

    def test_cui_baseline_allows_export(self):
        assert ClassifiedModeProfile.cui_baseline().allow_export is True


# ── TestEgressGuard ────────────────────────────────────────────────────────────

class TestEgressGuard:
    def test_check_denied_when_egress_disabled(self):
        profile = ClassifiedModeProfile.secret_baseline()  # allow_cloud_egress=False
        guard = EgressGuard(profile)
        assert guard.check_outbound("api.anthropic.com", "SC-AGENT1") is False

    def test_check_allowed_when_egress_enabled(self):
        profile = ClassifiedModeProfile.cui_baseline()  # allow_cloud_egress=True
        guard = EgressGuard(profile)
        assert guard.check_outbound("api.anthropic.com", "SC-AGENT1") is True

    def test_wrap_returns_none_when_denied(self):
        profile = ClassifiedModeProfile.secret_baseline()
        guard = EgressGuard(profile)
        called = []
        result = guard.wrap(lambda: called.append(1) or "ok", "api.example.com", "SC-AGENT1")
        assert result is None
        assert called == []  # function was not called

    def test_wrap_calls_fn_when_allowed(self):
        profile = ClassifiedModeProfile.cui_baseline()
        guard = EgressGuard(profile)
        result = guard.wrap(lambda: "ok", "api.example.com", "SC-AGENT1")
        assert result == "ok"

    def test_check_logs_to_ledger_denied(self):
        profile = ClassifiedModeProfile.secret_baseline()
        ledger = _mock_ledger()
        guard = EgressGuard(profile, ledger=ledger)
        guard.check_outbound("api.anthropic.com", "SC-AGENT1")
        ledger.log.assert_called_once()
        call_args = ledger.log.call_args
        assert call_args[0][0] == "egress_check"
        assert call_args[1]["metadata"]["decision"] == "deny"

    def test_check_logs_to_ledger_allowed(self):
        profile = ClassifiedModeProfile.cui_baseline()
        ledger = _mock_ledger()
        guard = EgressGuard(profile, ledger=ledger)
        guard.check_outbound("api.anthropic.com", "SC-AGENT1")
        call_args = ledger.log.call_args
        assert call_args[1]["metadata"]["decision"] == "allow"

    def test_no_ledger_no_error(self):
        profile = ClassifiedModeProfile.secret_baseline()
        guard = EgressGuard(profile)   # no ledger
        assert guard.check_outbound("api.example.com") is False  # no exception


# ── TestExportGuard ────────────────────────────────────────────────────────────

class TestExportGuard:
    def _secret_profile_with_export(self) -> ClassifiedModeProfile:
        from dataclasses import replace
        return replace(
            ClassifiedModeProfile.secret_baseline(),
            allow_export=True,
        )

    def test_can_export_denied_when_export_disabled(self):
        profile = ClassifiedModeProfile.secret_baseline()  # allow_export=False
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.UNCLASSIFIED)
        assert guard.can_export(label) is False

    def test_can_export_allowed_within_ceiling(self):
        profile = self._secret_profile_with_export()
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.SECRET)
        assert guard.can_export(label) is True

    def test_can_export_denied_above_ceiling(self):
        profile = self._secret_profile_with_export()
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.TOP_SECRET)
        assert guard.can_export(label) is False

    def test_can_export_denied_caveat_not_allowed(self):
        profile = self._secret_profile_with_export()
        # profile.allowed_caveats = {"SI", "NOFORN"} — HCS not permitted
        guard = ExportGuard(profile)
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"HCS"}),
        )
        assert guard.can_export(label) is False

    def test_can_export_allowed_subset_caveats(self):
        from dataclasses import replace
        profile = replace(
            self._secret_profile_with_export(),
            allowed_caveats=frozenset({"SI", "NOFORN", "HCS"}),
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI"}),
        )
        assert guard.can_export(label) is True

    def test_check_and_log_logs_denial(self):
        profile = ClassifiedModeProfile.secret_baseline()  # allow_export=False
        ledger = _mock_ledger()
        guard = ExportGuard(profile, ledger=ledger)
        label = LabelEnvelope(classification=Classification.UNCLASSIFIED)
        result = guard.check_and_log(label, agent_id="SC-AGENT1")
        assert result is False
        ledger.log.assert_called_once()
        meta = ledger.log.call_args[1]["metadata"]
        assert meta["decision"] == "deny"
        assert "deny_reason" in meta

    def test_check_and_log_logs_allowance(self):
        profile = self._secret_profile_with_export()
        ledger = _mock_ledger()
        guard = ExportGuard(profile, ledger=ledger)
        label = LabelEnvelope(classification=Classification.CUI)
        result = guard.check_and_log(label, agent_id="SC-AGENT1")
        assert result is True
        meta = ledger.log.call_args[1]["metadata"]
        assert meta["decision"] == "allow"


# ── TestPolicyEnforcerWithProfile ──────────────────────────────────────────────

class TestPolicyEnforcerWithProfile:
    def test_profile_ceiling_denies_above_max(self):
        profile = ClassifiedModeProfile(max_classification=Classification.CUI)
        enforcer = _make_enforcer("SECRET", profile=profile)
        # Profile ceiling is CUI — even though policy ceiling is SECRET
        d = enforcer.check("SC-AGENT1", "read_text", classification="SECRET")
        assert d.allowed is False
        assert "profile" in d.reason

    def test_profile_ceiling_allows_at_max(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            require_cng_identity=False,
            require_signed_policy=False,
        )
        enforcer = _make_enforcer("SECRET", profile=profile)
        d = enforcer.check("SC-AGENT1", "read_text", classification="SECRET")
        assert d.allowed is True

    def test_profile_dpapi_rejected_when_cng_required(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            require_cng_identity=True,
        )
        enforcer = _make_enforcer("SECRET", profile=profile)
        d = enforcer.check(
            "SC-AGENT1", "read_text",
            classification="UNCLASSIFIED",
            identity_type="dpapi",
        )
        assert d.allowed is False
        assert "DPAPI" in d.reason

    def test_profile_cng_identity_accepted(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            require_cng_identity=True,
        )
        enforcer = _make_enforcer("SECRET", profile=profile)
        d = enforcer.check(
            "SC-AGENT1", "read_text",
            classification="UNCLASSIFIED",
            identity_type="cng",
        )
        assert d.allowed is True

    def test_no_profile_unchanged_behavior(self):
        """PolicyEnforcer without profile= behaves identically to pre-v0.9.0."""
        enforcer = _make_enforcer("SECRET", profile=None)
        d = enforcer.check("SC-AGENT1", "read_text", classification="SECRET")
        assert d.allowed is True


# ── TestClassifiedModeEndToEnd ────────────────────────────────────────────────

class TestClassifiedModeEndToEnd:
    def test_classified_mode_full_scenario(self, tmp_path):
        """
        Full classified mode scenario:
        - secret_baseline profile (no egress, no export, requires CNG)
        - CUI label passes policy ceiling (SECRET)
        - TOP_SECRET label is denied by profile ceiling
        - Cloud egress attempt denied and logged
        - Export of CUI evidence denied (profile.allow_export=False)
        - DPAPI identity rejected
        """
        profile = ClassifiedModeProfile.secret_baseline()
        ledger = _mock_ledger()
        enforcer = _make_enforcer("SECRET", profile=profile)
        egress = EgressGuard(profile, ledger=ledger)
        export = ExportGuard(profile, ledger=ledger)

        # CUI label (below SECRET ceiling) → allowed
        cui_label = LabelEnvelope(classification=Classification.CUI)
        d_cui = enforcer.check("SC-AGENT1", "read_text", label=cui_label)
        assert d_cui.allowed is True

        # TOP_SECRET label (above SECRET profile ceiling) → denied
        ts_label = LabelEnvelope(classification=Classification.TOP_SECRET)
        d_ts = enforcer.check("SC-AGENT1", "read_text", label=ts_label)
        assert d_ts.allowed is False

        # Cloud egress → denied (allow_cloud_egress=False)
        assert egress.check_outbound("api.anthropic.com", "SC-AGENT1") is False

        # Export of CUI evidence → denied (allow_export=False in secret_baseline)
        assert export.can_export(cui_label) is False

        # DPAPI identity → denied (require_cng_identity=True)
        d_dpapi = enforcer.check(
            "SC-AGENT1", "read_text",
            classification="UNCLASSIFIED",
            identity_type="dpapi",
        )
        assert d_dpapi.allowed is False

    def test_cui_baseline_full_scenario(self):
        """
        CUI baseline: egress allowed, export allowed, CNG not required.
        """
        profile = ClassifiedModeProfile.cui_baseline()
        ledger = _mock_ledger()
        enforcer = _make_enforcer("SECRET", profile=profile)
        egress = EgressGuard(profile, ledger=ledger)
        export = ExportGuard(profile, ledger=ledger)

        # CUI label at or below CUI ceiling → allowed
        cui_label = LabelEnvelope(classification=Classification.CUI)
        d = enforcer.check("SC-AGENT1", "read_text", label=cui_label)
        assert d.allowed is True

        # SECRET label above CUI profile ceiling → denied
        secret_label = LabelEnvelope(classification=Classification.SECRET)
        d_secret = enforcer.check("SC-AGENT1", "read_text", label=secret_label)
        assert d_secret.allowed is False

        # Cloud egress allowed
        assert egress.check_outbound("api.anthropic.com") is True

        # Export of CUI evidence allowed
        assert export.can_export(cui_label) is True

        # DPAPI identity → allowed (require_cng_identity=False)
        d_dpapi = enforcer.check(
            "SC-AGENT1", "read_text",
            classification="UNCLASSIFIED",
            identity_type="dpapi",
        )
        assert d_dpapi.allowed is True
