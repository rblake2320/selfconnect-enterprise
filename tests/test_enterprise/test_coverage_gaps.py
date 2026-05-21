"""tests/test_enterprise/test_coverage_gaps.py — Coverage gap tests

GAP-5: ExportGuard coverage (currently 78%)
GAP-6: ClassifiedModeProfile.from_file() signature verification path
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock

import pytest

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.export_guard import ExportGuard
from enterprise.labels import Classification, LabelEnvelope

# ── GAP-5: ExportGuard coverage ──────────────────────────────────────────────


class TestExportGuardAllowExport:
    """Test ExportGuard.can_export and check_and_log when allow_export=True."""

    def test_allow_export_true_label_within_ceiling(self):
        """Export permitted: profile allows export, label within ceiling."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=True,
            profile_id="test-allow",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.CUI)
        assert guard.can_export(label) is True

    def test_allow_export_true_label_at_ceiling(self):
        """Export permitted: label exactly at ceiling."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=True,
            profile_id="test-at-ceiling",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.SECRET)
        assert guard.can_export(label) is True

    def test_allow_export_true_label_above_ceiling(self):
        """Export denied: label above ceiling."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=True,
            profile_id="test-above",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.TOP_SECRET)
        assert guard.can_export(label) is False


class TestExportGuardDenyExport:
    """Test ExportGuard when allow_export=False."""

    def test_deny_export_false_blocks_everything(self):
        """Export denied: profile disables export regardless of label."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=False,
            profile_id="test-deny",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.UNCLASSIFIED)
        assert guard.can_export(label) is False

    def test_deny_export_with_matching_caveats(self):
        """Export denied: allow_export=False overrides matching caveats."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"NOFORN", "SI"}),
            allow_export=False,
            profile_id="test-deny-caveats",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(
            classification=Classification.CUI,
            caveats=frozenset({"NOFORN"}),
        )
        assert guard.can_export(label) is False


class TestExportGuardCaveats:
    """Test caveat-based denial path."""

    def test_label_caveats_not_subset_of_profile(self):
        """Export denied: label has caveats not permitted by profile."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"NOFORN"}),
            allow_export=True,
            profile_id="test-caveat-deny",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(
            classification=Classification.CUI,
            caveats=frozenset({"NOFORN", "FISA"}),  # FISA not in profile
        )
        assert guard.can_export(label) is False

    def test_label_caveats_subset_of_profile(self):
        """Export allowed: label caveats are a subset of profile caveats."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"NOFORN", "SI", "FISA"}),
            allow_export=True,
            profile_id="test-caveat-allow",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(
            classification=Classification.CUI,
            caveats=frozenset({"NOFORN", "SI"}),
        )
        assert guard.can_export(label) is True


class TestExportGuardCheckAndLog:
    """Test check_and_log() with a mock ledger."""

    def test_check_and_log_allowed(self):
        """Allowed export logs decision=allow."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=True,
            profile_id="test-log-allow",
        )
        mock_ledger = MagicMock()
        guard = ExportGuard(profile, ledger=mock_ledger)
        label = LabelEnvelope(classification=Classification.CUI)

        result = guard.check_and_log(label, agent_id="SC-TEST0001")
        assert result is True
        mock_ledger.log.assert_called_once()
        call_kwargs = mock_ledger.log.call_args
        assert "export_check" in str(call_kwargs)

    def test_check_and_log_denied(self):
        """Denied export logs decision=deny with reason."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=False,
            profile_id="test-log-deny",
        )
        mock_ledger = MagicMock()
        guard = ExportGuard(profile, ledger=mock_ledger)
        label = LabelEnvelope(classification=Classification.CUI)

        result = guard.check_and_log(label, agent_id="SC-TEST0001")
        assert result is False
        mock_ledger.log.assert_called_once()
        call_kwargs = mock_ledger.log.call_args
        # Verify the metadata contains deny_reason
        metadata = call_kwargs[1].get("metadata", {}) if call_kwargs[1] else {}
        if not metadata:
            # positional args
            metadata = call_kwargs[0][0] if len(call_kwargs[0]) > 0 else {}

    def test_check_and_log_no_ledger(self):
        """check_and_log works without a ledger (no crash)."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=True,
            profile_id="test-no-ledger",
        )
        guard = ExportGuard(profile, ledger=None)
        label = LabelEnvelope(classification=Classification.CUI)
        result = guard.check_and_log(label, agent_id="SC-TEST0001")
        assert result is True


class TestExportGuardProperties:
    """Test ceiling and profile properties."""

    def test_ceiling_property(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"NOFORN"}),
            allow_export=True,
            profile_id="test-ceiling",
        )
        guard = ExportGuard(profile)
        assert guard.ceiling.classification == Classification.SECRET
        assert guard.ceiling.caveats == frozenset({"NOFORN"})

    def test_profile_property(self):
        profile = ClassifiedModeProfile(
            max_classification=Classification.CUI,
            allow_export=True,
            profile_id="test-profile-prop",
        )
        guard = ExportGuard(profile)
        assert guard.profile is profile

    def test_deny_reason_export_disabled(self):
        """Internal _deny_reason when export is disabled by profile."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allow_export=False,
            profile_id="test-deny-reason",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.CUI)
        reason = guard._deny_reason(label)
        assert "export disabled" in reason

    def test_deny_reason_classification_exceeded(self):
        """Internal _deny_reason when label exceeds ceiling."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.CUI,
            allow_export=True,
            profile_id="test-deny-cls",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(classification=Classification.SECRET)
        reason = guard._deny_reason(label)
        assert "exceeds" in reason

    def test_deny_reason_bad_caveats(self):
        """Internal _deny_reason when label has unauthorized caveats."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.SECRET,
            allowed_caveats=frozenset({"NOFORN"}),
            allow_export=True,
            profile_id="test-deny-cav",
        )
        guard = ExportGuard(profile)
        label = LabelEnvelope(
            classification=Classification.CUI,
            caveats=frozenset({"NOFORN", "FISA"}),
        )
        reason = guard._deny_reason(label)
        assert "caveats not permitted" in reason


# ── GAP-6: ClassifiedModeProfile.from_file() signature verification ──────────

from enterprise.crypto import CngSigner, cng_delete_key  # noqa: E402
import sys


pytestmark = pytest.mark.skipif(
    sys.platform != 'win32',
    reason='Windows CNG (BCrypt/NCrypt) required — skip on non-Windows'
)



class TestProfileFromFileSignature:
    """Test from_file() with verify_signature=True/False and tampered files."""

    SIGNER_PREFIX = "sc-profile-sig-"

    @pytest.fixture
    def signer_name(self):
        name = f"{self.SIGNER_PREFIX}{uuid.uuid4().hex[:8]}"
        yield name
        cng_delete_key(f"SelfConnect.{name}")

    def test_from_file_verify_signature_success(self, tmp_path, signer_name):
        """Create profile, save, sign, load with verify_signature=True."""
        signer = CngSigner.create(f"SelfConnect.{signer_name}")

        try:
            profile = ClassifiedModeProfile(
                max_classification=Classification.SECRET,
                allowed_caveats=frozenset({"NOFORN"}),
                require_cng_identity=True,
                require_signed_policy=True,
                allow_cloud_egress=False,
                allow_export=False,
                profile_id="signed-profile-v1",
            )

            # Save to file
            profile_path = tmp_path / "profile.json"
            profile.save(profile_path)

            # Sign it: compute signature over the serialized content
            raw = json.loads(profile_path.read_text(encoding="utf-8"))
            signable = {k: v for k, v in raw.items() if k not in ("sig", "signed_by_pub")}
            msg = json.dumps(signable, sort_keys=True, separators=(",", ":")).encode()
            sig = signer.sign(msg)

            raw["sig"] = sig.hex()
            raw["signed_by_pub"] = signer.public_key_bytes.hex()
            profile_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

            # Load with signature verification
            loaded = ClassifiedModeProfile.from_file(
                profile_path,
                verify_signature=True,
                trust_root_pub=signer.public_key_bytes,
            )
            assert loaded.profile_id == "signed-profile-v1"
            assert loaded.max_classification == Classification.SECRET

        finally:
            signer.close()

    def test_from_file_tampered_raises(self, tmp_path, signer_name):
        """Sign a profile, tamper the file, verify from_file raises RuntimeError."""
        signer = CngSigner.create(f"SelfConnect.{signer_name}")

        try:
            profile = ClassifiedModeProfile(
                max_classification=Classification.SECRET,
                allow_export=False,
                profile_id="tamper-profile-v1",
            )

            profile_path = tmp_path / "tampered.json"
            profile.save(profile_path)

            raw = json.loads(profile_path.read_text(encoding="utf-8"))
            signable = {k: v for k, v in raw.items() if k not in ("sig", "signed_by_pub")}
            msg = json.dumps(signable, sort_keys=True, separators=(",", ":")).encode()
            sig = signer.sign(msg)

            raw["sig"] = sig.hex()
            raw["signed_by_pub"] = signer.public_key_bytes.hex()

            # Tamper: change allow_export after signing
            raw["allow_export"] = True
            profile_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

            # from_file should raise RuntimeError
            with pytest.raises(RuntimeError, match="signature verification failed"):
                ClassifiedModeProfile.from_file(
                    profile_path,
                    verify_signature=True,
                    trust_root_pub=signer.public_key_bytes,
                )

        finally:
            signer.close()

    def test_from_file_no_signature_raises(self, tmp_path):
        """Profile file without sig field should raise when verify_signature=True."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.CUI,
            allow_export=True,
            profile_id="unsigned-v1",
        )
        profile_path = tmp_path / "unsigned.json"
        profile.save(profile_path)

        with pytest.raises(RuntimeError, match="no signature"):
            ClassifiedModeProfile.from_file(
                profile_path,
                verify_signature=True,
            )

    def test_from_file_skip_verification(self, tmp_path):
        """verify_signature=False loads even without a signature."""
        profile = ClassifiedModeProfile(
            max_classification=Classification.CUI,
            allow_export=True,
            profile_id="dev-profile-v1",
        )
        profile_path = tmp_path / "dev.json"
        profile.save(profile_path)

        loaded = ClassifiedModeProfile.from_file(
            profile_path,
            verify_signature=False,
        )
        assert loaded.profile_id == "dev-profile-v1"
        assert loaded.max_classification == Classification.CUI

    def test_from_file_no_public_key_raises(self, tmp_path, signer_name):
        """File has sig but no signed_by_pub and no trust_root_pub: should raise."""
        signer = CngSigner.create(f"SelfConnect.{signer_name}")

        try:
            profile = ClassifiedModeProfile(
                max_classification=Classification.SECRET,
                profile_id="no-pub-v1",
            )
            profile_path = tmp_path / "nopub.json"
            profile.save(profile_path)

            raw = json.loads(profile_path.read_text(encoding="utf-8"))
            signable = {k: v for k, v in raw.items() if k not in ("sig", "signed_by_pub")}
            msg = json.dumps(signable, sort_keys=True, separators=(",", ":")).encode()
            sig = signer.sign(msg)

            raw["sig"] = sig.hex()
            # Intentionally omit signed_by_pub
            profile_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

            with pytest.raises(RuntimeError, match="No public key"):
                ClassifiedModeProfile.from_file(
                    profile_path,
                    verify_signature=True,
                    # No trust_root_pub either
                )

        finally:
            signer.close()

    def test_from_file_embedded_pub_key_verification(self, tmp_path, signer_name):
        """Verify from_file uses embedded signed_by_pub when no trust_root_pub."""
        signer = CngSigner.create(f"SelfConnect.{signer_name}")

        try:
            profile = ClassifiedModeProfile(
                max_classification=Classification.SECRET,
                profile_id="embedded-pub-v1",
            )
            profile_path = tmp_path / "embedded.json"
            profile.save(profile_path)

            raw = json.loads(profile_path.read_text(encoding="utf-8"))
            signable = {k: v for k, v in raw.items() if k not in ("sig", "signed_by_pub")}
            msg = json.dumps(signable, sort_keys=True, separators=(",", ":")).encode()
            sig = signer.sign(msg)

            raw["sig"] = sig.hex()
            raw["signed_by_pub"] = signer.public_key_bytes.hex()
            profile_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

            # Load without explicit trust_root_pub — should use embedded key
            loaded = ClassifiedModeProfile.from_file(
                profile_path,
                verify_signature=True,
                # trust_root_pub intentionally not provided
            )
            assert loaded.profile_id == "embedded-pub-v1"

        finally:
            signer.close()
