"""tests/test_enterprise/test_fuzz.py — Property-based fuzzing via Hypothesis

Hammers the two external-input boundaries (AllowEntry.parse, PolicyBundle.from_dict)
and the PowerShell sanitization surface (WfpProfile, _sanitize_ps_string) with
randomized inputs.  A passing test means no unhandled crashes; a failing test means
an input class was not properly defended.

Targets:
    1. AllowEntry.parse()       — arbitrary strings, regex-shaped inputs, port ranges
    2. PolicyBundle.from_dict() — arbitrary nested dicts, weird types for all fields
    3. WfpProfile + _sanitize_ps_string() — arbitrary text for process names
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# ── Import WFP tools (not on sys.path by default) ────────────────────────────

_TOOLS = Path(__file__).parent.parent.parent / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from wfp_policy import AllowEntry, WfpProfile, _sanitize_ps_string, generate_powershell  # noqa: E402
from enterprise.policy import PolicyBundle  # noqa: E402

# ── Shared settings ──────────────────────────────────────────────────────────

_FUZZ_SETTINGS = settings(
    max_examples=200,
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow],
)


# ══════════════════════════════════════════════════════════════════════════════
# Target 1: AllowEntry.parse()
# ══════════════════════════════════════════════════════════════════════════════

class TestAllowEntryFuzz:
    """Fuzz AllowEntry.parse() — must either return a valid AllowEntry or raise
    ValueError.  Never crash with an unhandled exception."""

    @_FUZZ_SETTINGS
    @given(st.text())
    def test_arbitrary_text_never_crashes(self, s: str):
        """Any string must produce AllowEntry or ValueError — nothing else."""
        try:
            entry = AllowEntry.parse(s)
            # If it parsed, the result must be a valid AllowEntry
            assert isinstance(entry.host, str)
            assert entry.port is None or isinstance(entry.port, int)
            assert entry.protocol in ("tcp", "udp", "any")
        except ValueError:
            pass  # Expected for invalid input

    @_FUZZ_SETTINGS
    @given(st.from_regex(r"\S+:\d+(/tcp|/udp|/any)?", fullmatch=True))
    def test_regex_shaped_inputs(self, s: str):
        """Strings matching valid-ish patterns must parse or raise ValueError."""
        try:
            entry = AllowEntry.parse(s)
            assert isinstance(entry.host, str)
            assert entry.port is None or isinstance(entry.port, int)
        except ValueError:
            pass  # Expected — regex matches more than the grammar accepts

    @_FUZZ_SETTINGS
    @given(st.text())
    def test_no_injection_chars_in_host(self, s: str):
        """If parse succeeds, the host field must not contain injection chars."""
        injection_chars = {'$', '`', '\n', '\r', '"'}
        try:
            entry = AllowEntry.parse(s)
            for ch in injection_chars:
                assert ch not in entry.host, (
                    f"Injection char {ch!r} found in parsed host: {entry.host!r}"
                )
        except ValueError:
            pass

    @_FUZZ_SETTINGS
    @given(st.integers())
    def test_invalid_port_range_rejected(self, port: int):
        """Ports outside 1-65535 must always raise ValueError."""
        if port < 1 or port > 65535:
            spec = f"10.0.0.1:{port}"
            with pytest.raises(ValueError):
                AllowEntry.parse(spec)

    @_FUZZ_SETTINGS
    @given(st.integers(min_value=1, max_value=65535))
    def test_valid_port_range_accepted(self, port: int):
        """Ports within 1-65535 with a valid host must always parse."""
        spec = f"10.0.0.1:{port}"
        entry = AllowEntry.parse(spec)
        assert entry.port == port
        assert entry.host == "10.0.0.1"


# ══════════════════════════════════════════════════════════════════════════════
# Target 2: PolicyBundle.from_dict()
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyBundleFuzz:
    """Fuzz PolicyBundle.from_dict() — must construct or raise a clean exception.
    Unhandled AttributeError / IndexError = bug."""

    # Strategy for arbitrary agent dicts
    _agent_dict = st.fixed_dictionaries({}, optional={
        "role": st.text(),
        "clearance": st.text(),
        "allowed_targets": st.lists(st.text(), max_size=5),
        "allowed_apps": st.lists(st.text(), max_size=5),
        "blocked_apps": st.lists(st.text(), max_size=5),
        "allowed_actions": st.lists(st.text(), max_size=5),
        "requires_operator_approval": st.lists(st.text(), max_size=5),
        "max_classification": st.text(),
        "revoked": st.booleans(),
    })

    @_FUZZ_SETTINGS
    @given(st.dictionaries(st.text(max_size=50), _agent_dict, max_size=10))
    def test_arbitrary_agent_dicts(self, agents: dict):
        """Arbitrary nested dicts as the agents field must not crash."""
        try:
            bundle = PolicyBundle.from_dict({
                "policy_id": "fuzz-test",
                "agents": agents,
                "valid_from": 0.0,
            })
            # If constructed, basic properties must work
            assert isinstance(bundle.policy_id, str)
            assert isinstance(bundle.agent_ids(), list)
        except (KeyError, TypeError, ValueError):
            pass  # Acceptable clean failures

    @_FUZZ_SETTINGS
    @given(st.text(max_size=100))
    def test_arbitrary_agent_id_keys(self, agent_id: str):
        """Agent ID keys can be arbitrary text — must not crash."""
        try:
            bundle = PolicyBundle.from_dict({
                "policy_id": "fuzz-key-test",
                "agents": {
                    agent_id: {
                        "role": "worker",
                        "allowed_actions": ["test"],
                    }
                },
                "valid_from": 0.0,
            })
            assert agent_id in bundle.agent_ids()
        except (KeyError, TypeError, ValueError):
            pass

    @_FUZZ_SETTINGS
    @given(st.floats())
    def test_float_valid_from(self, f: float):
        """floats including NaN, inf, -inf for valid_from must not crash."""
        try:
            bundle = PolicyBundle.from_dict({
                "policy_id": "fuzz-float",
                "agents": {},
                "valid_from": f,
            })
            # is_time_valid should not crash even with NaN/inf
            bundle.is_time_valid()
        except (TypeError, ValueError, OverflowError):
            pass

    @_FUZZ_SETTINGS
    @given(st.floats())
    def test_float_valid_until(self, f: float):
        """floats including NaN, inf, -inf for valid_until must not crash."""
        try:
            bundle = PolicyBundle.from_dict({
                "policy_id": "fuzz-until",
                "agents": {},
                "valid_from": 0.0,
                "valid_until": f,
            })
            bundle.is_time_valid()
        except (TypeError, ValueError, OverflowError):
            pass

    def test_bundle_with_1000_agents(self):
        """Bundle with 1000 agents must construct without error."""
        agents = {
            f"SC-{i:08X}": {
                "role": "worker",
                "clearance": "UNCLASSIFIED",
                "allowed_actions": ["action_a", "action_b"],
                "max_classification": "UNCLASSIFIED",
            }
            for i in range(1000)
        }
        bundle = PolicyBundle.from_dict({
            "policy_id": "scale-test-1000",
            "agents": agents,
            "valid_from": 0.0,
        })
        assert len(bundle.agent_ids()) == 1000

    def test_very_long_policy_id(self):
        """10,000-char policy_id must not crash."""
        long_id = "P" * 10000
        bundle = PolicyBundle.from_dict({
            "policy_id": long_id,
            "agents": {},
            "valid_from": 0.0,
        })
        assert bundle.policy_id == long_id


# ══════════════════════════════════════════════════════════════════════════════
# Target 3: WfpProfile + _sanitize_ps_string()
# ══════════════════════════════════════════════════════════════════════════════

class TestSanitizeFuzz:
    """Fuzz _sanitize_ps_string and WfpProfile construction."""

    @_FUZZ_SETTINGS
    @given(st.text())
    def test_sanitize_arbitrary_text(self, s: str):
        """Must either return a sanitized string or raise ValueError for control chars."""
        try:
            result = _sanitize_ps_string(s)
            # If it succeeded, no control chars should remain in the output
            # (single quotes are escaped, not removed)
            assert isinstance(result, str)
            # Verify no unescaped control chars leaked through
            control_chars = {'\n', '\r', '\t', '\x00', '\x0b', '\x0c'}
            for ch in control_chars:
                assert ch not in result, f"Control char {ch!r} leaked through sanitize"
        except ValueError:
            pass  # Expected for inputs with control chars

    @_FUZZ_SETTINGS
    @given(st.text(
        alphabet=st.characters(whitelist_categories=('L', 'N', 'P'))
    ))
    def test_printable_chars_always_succeed(self, s: str):
        """Printable chars (letters, numbers, punctuation) must always sanitize."""
        if not s:
            return  # Empty string is trivially valid
        result = _sanitize_ps_string(s)
        assert isinstance(result, str)

    @_FUZZ_SETTINGS
    @given(st.text())
    def test_wfp_profile_arbitrary_process_name(self, name: str):
        """WfpProfile construction with arbitrary process name — must succeed or
        raise ValueError (control chars), never crash."""
        try:
            profile = WfpProfile(
                name="test-profile",
                process=name,
                allow=[AllowEntry(host="127.0.0.1", port=None, protocol="tcp")],
            )
            # If constructed, process name should be sanitized
            assert isinstance(profile.process, str)
        except ValueError:
            pass  # Expected for control-char inputs

    @_FUZZ_SETTINGS
    @given(st.text())
    def test_wfp_profile_arbitrary_profile_name(self, name: str):
        """WfpProfile construction with arbitrary profile name."""
        try:
            profile = WfpProfile(
                name=name,
                process="python.exe",
                allow=[AllowEntry(host="127.0.0.1", port=None, protocol="tcp")],
            )
            assert isinstance(profile.name, str)
        except ValueError:
            pass
