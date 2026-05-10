"""tests/test_wfp_policy.py — Tests for WFP policy generator (G-2 remediation).

Validates: AllowEntry.parse(), WfpProfile, generate_powershell(), and CLI.
No network calls, no file I/O in most tests. Output script correctness is
verified by string inspection (not executed — requires Windows Admin rights).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

# Import from tools/ (not on sys.path by default — add it)
_TOOLS = Path(__file__).parent.parent / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from wfp_policy import (  # noqa: E402
    BUILTIN_PROFILES,
    AllowEntry,
    WfpProfile,
    _validate_host,
    generate_powershell,
    main,
)

# ── AllowEntry.parse ──────────────────────────────────────────────────────────

class TestAllowEntryParse:
    def test_ip_only(self):
        e = AllowEntry.parse("10.0.0.1")
        assert e.host == "10.0.0.1"
        assert e.port is None
        assert e.protocol == "tcp"

    def test_ip_port(self):
        e = AllowEntry.parse("10.0.0.1:443")
        assert e.host == "10.0.0.1"
        assert e.port == 443

    def test_ip_port_proto(self):
        e = AllowEntry.parse("10.0.0.1:53/udp")
        assert e.host == "10.0.0.1"
        assert e.port == 53
        assert e.protocol == "udp"

    def test_cidr(self):
        e = AllowEntry.parse("192.168.1.0/24")
        assert e.host == "192.168.1.0/24"
        assert e.port is None

    def test_hostname(self):
        e = AllowEntry.parse("api.anthropic.com:443")
        assert e.host == "api.anthropic.com"
        assert e.port == 443

    def test_any_proto(self):
        e = AllowEntry.parse("127.0.0.1/any")
        assert e.protocol == "any"

    def test_any_proto_with_port(self):
        e = AllowEntry.parse("127.0.0.1:8100/any")
        assert e.port == 8100
        assert e.protocol == "any"

    def test_invalid_port_rejected(self):
        with pytest.raises(ValueError):
            AllowEntry.parse("10.0.0.1:99999")

    def test_invalid_host_rejected(self):
        with pytest.raises(ValueError):
            _validate_host("not a valid host !@#")

    def test_loopback(self):
        e = AllowEntry.parse("127.0.0.1")
        assert e.host == "127.0.0.1"

    def test_ipv6_loopback(self):
        e = AllowEntry.parse("::1")
        assert e.host == "::1"


# ── WfpProfile ────────────────────────────────────────────────────────────────

class TestWfpProfile:
    def test_from_dict_minimal(self):
        d = {"name": "test", "process": "python.exe", "allow": ["127.0.0.1"]}
        p = WfpProfile.from_dict(d)
        assert p.name == "test"
        assert len(p.allow) == 1

    def test_from_dict_full(self):
        d = {
            "name": "full",
            "process": "python.exe",
            "allow": ["10.0.0.1:443/tcp", "127.0.0.1"],
            "description": "Test profile",
            "wfp_native": False,
        }
        p = WfpProfile.from_dict(d)
        assert len(p.allow) == 2
        assert p.allow[0].port == 443

    def test_from_json(self):
        data = '{"name": "json_test", "process": "python.exe", "allow": ["10.0.0.1:8080"]}'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(data)
            tmp = Path(f.name)
        try:
            p = WfpProfile.from_json(tmp)
            assert p.name == "json_test"
            assert p.allow[0].port == 8080
        finally:
            tmp.unlink(missing_ok=True)


# ── Built-in profiles ─────────────────────────────────────────────────────────

class TestBuiltinProfiles:
    def test_all_profiles_parseable(self):
        for name, data in BUILTIN_PROFILES.items():
            p = WfpProfile.from_dict(data)
            assert p.name == name

    def test_mode_c_allows_only_loopback(self):
        p = WfpProfile.from_dict(BUILTIN_PROFILES["mode_c"])
        hosts = {e.host for e in p.allow}
        # All entries should be loopback addresses
        for host in hosts:
            assert host in ("127.0.0.1", "::1", "localhost"), \
                f"Mode C has non-loopback allowlist entry: {host}"

    def test_mode_c_strict_is_more_restrictive_than_mode_c(self):
        strict = WfpProfile.from_dict(BUILTIN_PROFILES["mode_c_strict"])
        # Strict has ports specified; standard has port-wildcard entries
        strict_ports = [e.port for e in strict.allow]
        assert all(p is not None for p in strict_ports), \
            "Mode C Strict should have all ports specified"

    def test_mode_a_allows_all(self):
        p = WfpProfile.from_dict(BUILTIN_PROFILES["mode_a"])
        assert any("0.0.0.0/0" in e.host for e in p.allow), \
            "Mode A should allow all outbound"


# ── generate_powershell ───────────────────────────────────────────────────────

class TestGeneratePowershell:
    def _gen(self, allow_specs: list[str], name: str = "test") -> str:
        entries = [AllowEntry.parse(s) for s in allow_specs]
        profile = WfpProfile(name=name, process="python.exe", allow=entries)
        return generate_powershell(profile, f"wfp-{name}.ps1")

    def test_block_rule_present(self):
        script = self._gen(["127.0.0.1"])
        assert "BLOCK-ALL-OUTBOUND" in script

    def test_allow_rule_present(self):
        script = self._gen(["10.0.0.1:443"])
        assert "ALLOW" in script
        assert "10-0-0-1" in script or "10.0.0.1" in script

    def test_remove_flag_present(self):
        script = self._gen(["127.0.0.1"])
        assert "-Remove" in script

    def test_verify_flag_present(self):
        script = self._gen(["127.0.0.1"])
        assert "-Verify" in script

    def test_process_name_embedded(self):
        script = self._gen(["127.0.0.1"])
        assert "python.exe" in script

    def test_requires_administrator(self):
        script = self._gen(["127.0.0.1"])
        assert "#Requires -RunAsAdministrator" in script

    def test_multiple_allow_rules(self):
        script = self._gen(["10.0.0.1:443", "192.168.1.0/24", "127.0.0.1:8100"])
        assert script.count("ALLOW") >= 3

    def test_mode_c_script_is_loopback_only(self):
        p = WfpProfile.from_dict(BUILTIN_PROFILES["mode_c"])
        script = generate_powershell(p, "wfp-mode-c.ps1")
        # Should not have cloud API hosts in it
        assert "anthropic" not in script
        assert "openai" not in script
        assert "amazonaws" not in script

    def test_no_arbitrary_code_in_output(self):
        """Verify output is purely firewall commands — no exec/eval/invoke-expression."""
        script = self._gen(["127.0.0.1"])
        dangerous = ["Invoke-Expression", "iex ", "eval(", "exec(", "; rm ", "| sh"]
        for d in dangerous:
            assert d not in script, f"Dangerous pattern in output: {d!r}"

    def test_output_is_utf8_decodable(self):
        script = self._gen(["127.0.0.1:8100/tcp"])
        assert isinstance(script, str)
        # Verify it round-trips through UTF-8
        encoded = script.encode("utf-8")
        assert encoded.decode("utf-8") == script


# ── CLI ────────────────────────────────────────────────────────────────────────

class TestCLI:
    def test_list_profiles(self, capsys):
        rc = main(["--list-profiles"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "mode_c" in out
        assert "mode_b" in out

    def test_builtin_profile_to_stdout(self, capsys):
        rc = main(["--profile", "mode_c"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "BLOCK-ALL-OUTBOUND" in out

    def test_custom_allow_to_stdout(self, capsys):
        rc = main(["--allow", "10.0.0.1:443", "--allow", "127.0.0.1"])
        assert rc == 0

    def test_output_to_file(self, tmp_path):
        out = tmp_path / "wfp-test.ps1"
        rc = main(["--profile", "mode_c", "--out", str(out)])
        assert rc == 0
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "BLOCK-ALL-OUTBOUND" in content
        assert "127.0.0.1" in content

    def test_no_args_errors(self, capsys):
        rc = main([])
        assert rc != 0

    def test_invalid_allow_errors(self, capsys):
        rc = main(["--allow", "not!a!valid!host!#@$"])
        assert rc != 0

    def test_missing_config_errors(self, capsys):
        rc = main(["--config", "/nonexistent/path/profile.json"])
        assert rc != 0

    def test_mode_c_strict_profile(self, capsys):
        rc = main(["--profile", "mode_c_strict"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "5432" in out or "8100" in out  # specific ports should appear
