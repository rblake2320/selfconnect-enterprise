"""tests/test_enterprise/test_labels.py — Classification Labels Substrate Tests

49 tests across 8 classes covering the full enterprise/labels.py surface plus
integration with PolicyEnforcer and ObserverFilter.

Coverage:
    Classification enum ordering and lookup
    rank() with strings, enum values, case-insensitivity, unknown → -1
    le() comparator (all boundary combinations)
    LabelEnvelope construction, serialisation, round-trip
    LabelEnvelope lattice dominance (Bell-LaPadula le())
    LabelEnvelope validation (ALLOWED_CAVEATS membership)
    Backward compatibility: policy._rank, observer._rank, CLASSIFICATION_LEVELS
    PolicyEnforcer.check() with label= kwarg
    ObserverFilter with allowed_caveats=
    Critical invariant: observer never passes entries above max classification
"""
from __future__ import annotations

import time

import pytest

from enterprise.labels import (
    ALLOWED_CAVEATS,
    Classification,
    LabelEnvelope,
    le,
    rank,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_policy(max_classification: str = "SECRET"):
    """Return a minimal require_signature=False PolicyEnforcer."""
    from enterprise.policy import PolicyEnforcer, make_bundle

    bundle = make_bundle(
        "test-policy",
        agents={
            "SC-AGENT1": {
                "role": "worker",
                "clearance": "SECRET",
                "allowed_actions": ["read_text", "write_file"],
                "max_classification": max_classification,
            }
        },
    )
    return PolicyEnforcer(bundle, require_signature=False)


# ── TestClassificationEnum ────────────────────────────────────────────────────

class TestClassificationEnum:
    def test_enum_values(self):
        assert Classification.UNCLASSIFIED == 0
        assert Classification.CUI          == 1
        assert Classification.SECRET       == 2
        assert Classification.TOP_SECRET   == 3

    def test_enum_ordering(self):
        assert Classification.UNCLASSIFIED < Classification.CUI
        assert Classification.CUI          < Classification.SECRET
        assert Classification.SECRET       < Classification.TOP_SECRET

    def test_enum_by_name(self):
        assert Classification["SECRET"] == Classification.SECRET

    def test_enum_by_value(self):
        assert Classification(2) == Classification.SECRET

    def test_enum_is_int(self):
        assert isinstance(Classification.SECRET, int)

    def test_enum_members_count(self):
        assert len(Classification) == 4


# ── TestRank ──────────────────────────────────────────────────────────────────

class TestRank:
    def test_rank_string_unclassified(self):
        assert rank("UNCLASSIFIED") == 0

    def test_rank_string_top_secret(self):
        assert rank("TOP_SECRET") == 3

    def test_rank_enum_value(self):
        assert rank(Classification.SECRET) == 2

    def test_rank_case_insensitive(self):
        assert rank("secret") == 2
        assert rank("Secret") == 2
        assert rank("CUI")    == 1
        assert rank("cui")    == 1

    def test_rank_unknown_string_is_rejected(self):
        for value in ("BOGUS", "", "TS"):
            with pytest.raises(ValueError, match="unknown classification"):
                rank(value)

    def test_rank_all_levels_strictly_ordered(self):
        levels = list(Classification)
        ranks = [rank(m) for m in levels]
        assert ranks == sorted(ranks)
        assert len(set(ranks)) == len(ranks)  # no duplicates

    def test_rank_matches_enum_value(self):
        for member in Classification:
            assert rank(member) == member.value
            assert rank(member.name) == member.value


# ── TestLe ────────────────────────────────────────────────────────────────────

class TestLe:
    def test_le_same_level(self):
        assert le("SECRET", "SECRET") is True

    def test_le_lower_is_dominated(self):
        assert le("CUI", "SECRET") is True
        assert le("UNCLASSIFIED", "TOP_SECRET") is True

    def test_le_higher_not_dominated(self):
        assert le("TOP_SECRET", "SECRET") is False
        assert le("SECRET", "CUI") is False

    def test_le_enum_args(self):
        assert le(Classification.CUI, Classification.SECRET) is True
        assert le(Classification.SECRET, Classification.CUI) is False

    def test_le_mixed_args(self):
        assert le("SECRET", Classification.TOP_SECRET) is True
        assert le(Classification.TOP_SECRET, "SECRET") is False


# ── TestLabelEnvelope ─────────────────────────────────────────────────────────

class TestLabelEnvelope:
    def test_construction_minimal(self):
        label = LabelEnvelope(classification=Classification.SECRET)
        assert label.classification == Classification.SECRET
        assert label.caveats == frozenset()
        assert label.originator == ""

    def test_construction_with_caveats(self):
        label = LabelEnvelope(
            classification=Classification.TOP_SECRET,
            caveats=frozenset({"NOFORN", "SI"}),
            originator="SC-ADMIN1",
        )
        assert label.caveats == frozenset({"NOFORN", "SI"})
        assert label.originator == "SC-ADMIN1"

    def test_frozen_immutable(self):
        label = LabelEnvelope(classification=Classification.CUI)
        with pytest.raises((AttributeError, TypeError)):
            label.classification = Classification.SECRET  # type: ignore[misc]

    def test_to_dict_keys(self):
        label = LabelEnvelope(classification=Classification.SECRET)
        d = label.to_dict()
        assert set(d.keys()) == {"classification", "caveats", "originator", "label_ts"}

    def test_to_dict_classification_is_name(self):
        label = LabelEnvelope(classification=Classification.SECRET)
        assert label.to_dict()["classification"] == "SECRET"

    def test_to_dict_caveats_sorted_list(self):
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI", "NOFORN"}),
        )
        assert label.to_dict()["caveats"] == ["NOFORN", "SI"]

    def test_from_dict_roundtrip(self):
        original = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI", "NOFORN"}),
            originator="SC-AGENT1",
            ts=1234567890.0,
        )
        restored = LabelEnvelope.from_dict(original.to_dict())
        assert restored.classification == original.classification
        assert restored.caveats == original.caveats
        assert restored.originator == original.originator

    def test_from_dict_string_classification(self):
        label = LabelEnvelope.from_dict({"classification": "SECRET"})
        assert label.classification == Classification.SECRET

    def test_from_dict_missing_caveats_defaults_empty(self):
        label = LabelEnvelope.from_dict({"classification": "CUI"})
        assert label.caveats == frozenset()

    def test_from_classification_factory(self):
        label = LabelEnvelope.from_classification("SECRET")
        assert label.classification == Classification.SECRET
        assert label.caveats == frozenset()

    def test_unknown_classification_factories_are_rejected(self):
        with pytest.raises(ValueError, match="unknown classification"):
            LabelEnvelope.from_classification("BOGUS")
        with pytest.raises(ValueError, match="unknown classification"):
            LabelEnvelope.from_dict({"classification": "BOGUS"})

    def test_validate_valid_caveats(self):
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"NOFORN", "SI"}),
        )
        assert label.validate() is True

    def test_validate_invalid_caveat(self):
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"BOGUS_CAVEAT"}),
        )
        assert label.validate() is False

    def test_validate_empty_caveats_always_valid(self):
        for level in Classification:
            label = LabelEnvelope(classification=level)
            assert label.validate() is True

    def test_hashable(self):
        label = LabelEnvelope(classification=Classification.SECRET)
        s = {label}
        assert label in s


# ── TestLabelDominance ────────────────────────────────────────────────────────

class TestLabelDominance:
    def test_le_reflexive(self):
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI"}),
        )
        assert label.le(label) is True

    def test_le_lower_classification_no_caveats(self):
        low  = LabelEnvelope(classification=Classification.CUI)
        high = LabelEnvelope(classification=Classification.SECRET)
        assert low.le(high) is True
        assert high.le(low) is False

    def test_le_same_classification_subset_caveats(self):
        base = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI", "NOFORN"}),
        )
        sub = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI"}),
        )
        assert sub.le(base) is True    # sub's caveats ⊆ base's caveats
        assert base.le(sub) is False   # base has NOFORN which sub doesn't

    def test_le_same_classification_superset_caveats_fails(self):
        a = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI", "NOFORN"}),
        )
        b = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI"}),
        )
        assert a.le(b) is False  # a has NOFORN not in b

    def test_le_lower_classification_superset_caveats_fails(self):
        # Even though classification is lower, extra caveats block dominance
        lower_more_caveats = LabelEnvelope(
            classification=Classification.CUI,
            caveats=frozenset({"SI", "NOFORN"}),
        )
        higher_fewer_caveats = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI"}),
        )
        assert lower_more_caveats.le(higher_fewer_caveats) is False

    def test_le_disjoint_caveats_fails(self):
        a = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"NOFORN"}),
        )
        b = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"SI"}),
        )
        assert a.le(b) is False
        assert b.le(a) is False


# ── TestBackwardCompat ────────────────────────────────────────────────────────

class TestBackwardCompat:
    def test_policy_rank_uses_labels_module(self):
        """policy._rank is now an alias of labels.rank — same behavior."""
        import enterprise.policy as pol
        # policy module imports 'rank as _rank' from labels
        # access it via the module's namespace
        policy_rank = pol._rank  # type: ignore[attr-defined]
        assert policy_rank("SECRET") == 2
        with pytest.raises(ValueError):
            policy_rank("BOGUS")

    def test_observer_rank_uses_labels_module(self):
        """observer._rank is now an alias of labels.rank — same behavior."""
        import enterprise.observer as obs
        observer_rank = obs._rank  # type: ignore[attr-defined]
        assert observer_rank("TOP_SECRET") == 3
        with pytest.raises(ValueError):
            observer_rank("unknown")

    def test_classification_levels_from_policy(self):
        from enterprise.policy import CLASSIFICATION_LEVELS as CL
        assert CL == ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"]

    def test_classification_levels_from_init(self):
        from enterprise import CLASSIFICATION_LEVELS as CL
        assert CL == ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"]


# ── TestPolicyEnforcerWithLabel ───────────────────────────────────────────────

class TestPolicyEnforcerWithLabel:
    def test_check_with_label_below_ceiling_allowed(self):
        enforcer = _make_policy("SECRET")
        label = LabelEnvelope(classification=Classification.SECRET)
        d = enforcer.check("SC-AGENT1", "read_text", label=label)
        assert d.allowed is True
        assert d.classification == "SECRET"

    def test_check_with_label_above_ceiling_denied(self):
        enforcer = _make_policy("SECRET")
        label = LabelEnvelope(classification=Classification.TOP_SECRET)
        d = enforcer.check("SC-AGENT1", "read_text", label=label)
        assert d.allowed is False
        assert "TOP_SECRET" in d.reason

    def test_check_label_overrides_classification_string(self):
        """When label= is provided, it overrides the classification= string."""
        enforcer = _make_policy("SECRET")
        # Pass classification="UNCLASSIFIED" (below ceiling) but label=TOP_SECRET
        label = LabelEnvelope(classification=Classification.TOP_SECRET)
        d = enforcer.check(
            "SC-AGENT1", "read_text",
            classification="UNCLASSIFIED",
            label=label,
        )
        # Label wins → denied because TOP_SECRET > SECRET ceiling
        assert d.allowed is False
        assert "TOP_SECRET" in d.reason

    def test_check_label_invalid_caveats_denied(self):
        enforcer = _make_policy("SECRET")
        label = LabelEnvelope(
            classification=Classification.SECRET,
            caveats=frozenset({"BOGUS_CAVEAT"}),
        )
        d = enforcer.check("SC-AGENT1", "read_text", label=label)
        assert d.allowed is False
        assert "caveat" in d.reason.lower()

    def test_check_without_label_string_only_unchanged(self):
        """Existing string-only callers are unaffected."""
        enforcer = _make_policy("SECRET")
        d = enforcer.check("SC-AGENT1", "read_text", classification="CUI")
        assert d.allowed is True
        assert d.classification == "CUI"


# ── TestObserverWithCaveats ───────────────────────────────────────────────────

class TestObserverWithCaveats:
    def _entry(self, classification: str = "UNCLASSIFIED", caveats=None) -> dict:
        return {
            "seq": 1,
            "agent_id": "SC-AGENT1",
            "action": "read_text",
            "result": "ok",
            "ts": time.time(),
            "prev_hash": "0" * 64,
            "decision": "allow",
            "approval_mode": "autonomous",
            "policy_id": "test",
            "classification": classification,
            "caveats": caveats or [],
            "sig": "aa",
        }

    def test_filter_no_caveat_restriction_passes_any(self):
        """Empty allowed_caveats means no restriction on caveats."""
        from enterprise.observer import ObserverFilter
        flt = ObserverFilter(max_classification="TOP_SECRET", allowed_caveats=[])
        entry = self._entry("SECRET", caveats=["NOFORN", "SI"])
        assert flt.matches(entry) is True

    def test_filter_allowed_caveats_subset_passes(self):
        """Entry caveats ⊆ allowed_caveats → passes."""
        from enterprise.observer import ObserverFilter
        flt = ObserverFilter(
            max_classification="TOP_SECRET",
            allowed_caveats=["NOFORN", "SI", "HCS"],
        )
        entry = self._entry("SECRET", caveats=["NOFORN", "SI"])
        assert flt.matches(entry) is True

    def test_filter_caveats_not_in_allowed_blocked(self):
        """Entry has caveat not in allowed_caveats → filtered out."""
        from enterprise.observer import ObserverFilter
        flt = ObserverFilter(
            max_classification="TOP_SECRET",
            allowed_caveats=["SI"],          # NOFORN not allowed
        )
        entry = self._entry("SECRET", caveats=["NOFORN", "SI"])
        assert flt.matches(entry) is False

    def test_filter_entry_without_caveats_always_passes_caveat_check(self):
        """Entry with no caveats passes regardless of allowed_caveats."""
        from enterprise.observer import ObserverFilter
        flt = ObserverFilter(
            max_classification="SECRET",
            allowed_caveats=["SI"],
        )
        entry = self._entry("CUI", caveats=[])
        assert flt.matches(entry) is True

    def test_observer_never_passes_above_max_classification(self):
        """Critical invariant: TOP_SECRET entry never reaches training data
        when filter max_classification is SECRET."""
        from enterprise.observer import ObserverFilter

        flt = ObserverFilter(max_classification="SECRET")

        levels = ["UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"]
        results = {}
        for lvl in levels:
            entry = {
                "seq": levels.index(lvl) + 1,
                "agent_id": "SC-AGENT1",
                "action": "read_text",
                "result": "ok",
                "ts": time.time(),
                "prev_hash": "0" * 64,
                "decision": "allow",
                "approval_mode": "autonomous",
                "policy_id": "test",
                "classification": lvl,
                "sig": "aa",
            }
            results[lvl] = flt.matches(entry)

        assert results["UNCLASSIFIED"] is True
        assert results["CUI"]          is True
        assert results["SECRET"]       is True
        assert results["TOP_SECRET"]   is False   # ← The invariant


# ── AllowedCaveats completeness ───────────────────────────────────────────────

class TestAllowedCaveats:
    def test_allowed_caveats_is_frozenset(self):
        assert isinstance(ALLOWED_CAVEATS, frozenset)

    def test_allowed_caveats_non_empty(self):
        assert len(ALLOWED_CAVEATS) > 0

    def test_known_caveats_present(self):
        for caveat in ("NOFORN", "ORCON", "REL_TO", "FISA", "HCS", "SI", "TK", "GAMMA"):
            assert caveat in ALLOWED_CAVEATS

    def test_allowed_caveats_immutable(self):
        with pytest.raises(AttributeError):
            ALLOWED_CAVEATS.add("BOGUS")  # type: ignore[attr-defined]
