"""tests/test_enterprise/test_supply_chain.py — Supply chain & zero-day CVE tests

Defends against the threat classes identified in the May 2026 zero-day briefing:

  - LiteLLM supply chain (sonatype-2026-001357): backdoored versions 1.82.7 and 1.82.8
    were live on PyPI for ~40 minutes on 2026-03-24. Any environment that pip-installed
    litellm during that window may have a credential stealer + persistent backdoor.

  - CVE-2026-26007 (cryptography < 46.0.5): small-subgroup ECDH attack on SECT curves.
    selfconnect-enterprise uses P-384 and ed25519 (NOT SECT curves), so not exploitable
    via our code paths — but the version floor enforces we stay ahead of this class.

  - CVE-2026-34073 (cryptography < 46.0.6): X.509 name-constraint bypass in the
    x509.verification path. selfconnect-enterprise does not do TLS peer verification
    via the cryptography library — crypto is delegated to Windows NCrypt/CNG. Not
    exploitable via our code paths — again, version floor enforces hygiene.

A passing test proves our environment is not in a known-vulnerable state.
A failing test is a real signal: update the dependency or investigate the environment.
"""
from __future__ import annotations

import importlib.metadata
import subprocess
import sys

import pytest

# ── LiteLLM backdoored version check ─────────────────────────────────────────

LITELLM_BACKDOORED_VERSIONS = {"1.82.7", "1.82.8"}
"""sonatype-2026-001357: TeamPCP supply chain. Credential stealer + persistent backdoor.
These two versions were live on PyPI for ~40 minutes on 2026-03-24. Any environment
that installed either version should be treated as compromised until audited."""


def _get_installed_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


class TestLiteLLMSupplyChain:
    """Verify that no backdoored LiteLLM version is installed."""

    def test_litellm_not_backdoored_version(self):
        """CRITICAL: LiteLLM 1.82.7 and 1.82.8 contain a credential stealer
        (sonatype-2026-001357, TeamPCP). If either version is installed in this
        environment, the environment should be treated as compromised.

        Reference: https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
        """
        version = _get_installed_version("litellm")
        if version is None:
            # litellm not installed — no exposure
            return
        assert version not in LITELLM_BACKDOORED_VERSIONS, (
            f"CRITICAL SUPPLY CHAIN: litellm=={version} is a known-backdoored version. "
            f"This environment may contain a credential stealer and persistent backdoor. "
            f"Affected versions: {LITELLM_BACKDOORED_VERSIONS}. "
            f"Reference: sonatype-2026-001357 (TeamPCP, 2026-03-24). "
            f"Action: pip install --upgrade litellm, rotate all credentials in this environment."
        )

    def test_litellm_version_documented_if_present(self):
        """Document the installed litellm version for audit trail purposes."""
        version = _get_installed_version("litellm")
        if version is None:
            return  # not installed — nothing to document; passes trivially
        # version must be parseable as a semver-like tuple for comparison
        parts = version.split(".")
        assert len(parts) >= 2, f"Unexpected litellm version format: {version!r}"
        # Backdoored versions are 1.82.7 and 1.82.8 — anything in 1.82.x < 1.82.9 is suspect
        major, minor = int(parts[0]), int(parts[1])
        patch = int(parts[2]) if len(parts) > 2 else 0
        if major == 1 and minor == 82:
            assert patch not in (7, 8), (
                f"litellm=={version} is backdoored. See sonatype-2026-001357."
            )


# ── cryptography version checks ───────────────────────────────────────────────

class TestCryptographyVersion:
    """Enforce minimum cryptography version that contains CVE-2026-26007 and
    CVE-2026-34073 fixes.

    Note on actual exploitability in selfconnect-enterprise:
    - CVE-2026-26007 (SECT curve ECDH small-subgroup): we use P-384 and ed25519
      (both prime-order, cofactor=1). SECT curves are not used anywhere.
      Not exploitable via our code, but version floor enforces hygiene.
    - CVE-2026-34073 (X.509 name constraint bypass): we delegate TLS/cert validation
      to Windows NCrypt/CNG (Schannel), not to cryptography's x509.verification path.
      Not exploitable via our code, but version floor enforces hygiene.
    """

    MINIMUM_SAFE_VERSION = (46, 0, 6)  # CVE-2026-34073 fix

    def test_cryptography_at_minimum_safe_version(self):
        """cryptography must be >= 46.0.6 (fixes CVE-2026-26007 + CVE-2026-34073).

        CVE-2026-26007: fixed in 46.0.5 — SECT curve ECDH small-subgroup attack
        CVE-2026-34073: fixed in 46.0.6 — X.509 name constraint bypass in x509.verification
        """
        version_str = _get_installed_version("cryptography")
        assert version_str is not None, "cryptography package not found — cannot verify security posture"
        parts = version_str.split(".")
        installed = tuple(int(p) for p in parts[:3])
        assert installed >= self.MINIMUM_SAFE_VERSION, (
            f"cryptography=={version_str} is below minimum safe version "
            f"{'.'.join(str(x) for x in self.MINIMUM_SAFE_VERSION)}. "
            f"CVE-2026-26007 (ECDH subgroup, fixed 46.0.5) and "
            f"CVE-2026-34073 (X.509 name constraint bypass, fixed 46.0.6) are unpatched. "
            f"Run: pip install 'cryptography>=46.0.6'"
        )

    def test_cryptography_not_using_sect_curves(self):
        """Verify that selfconnect-enterprise code never instantiates SECT (binary) curves.

        CVE-2026-26007 only affects SECT curves (SECT163k1, SECT233k1, SECT283k1, etc.)
        via the cofactor ECDH path. We use SECP384R1 (P-384) and ed25519 — both safe.

        This test statically scans source imports to confirm no SECT curve is referenced.
        """
        from pathlib import Path

        sect_pattern = "SECT"
        enterprise_src = Path(__file__).parent.parent.parent / "enterprise"
        tools_src = Path(__file__).parent.parent.parent / "tools"

        violations = []
        for src_dir in (enterprise_src, tools_src):
            for py_file in src_dir.rglob("*.py"):
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if sect_pattern in content:
                    # Find the lines
                    for i, line in enumerate(content.splitlines(), 1):
                        if sect_pattern in line and not line.strip().startswith("#"):
                            violations.append(f"{py_file}:{i}: {line.strip()}")

        assert not violations, (
            "CVE-2026-26007 scope: SECT curve references found in source — "
            "verify these are not used in ECDH operations:\n" + "\n".join(violations)
        )

    def test_x509_verification_path_not_used(self):
        """Verify selfconnect-enterprise does not use cryptography's x509.verification
        module (the path affected by CVE-2026-34073).

        TLS/cert validation in our stack goes through Windows NCrypt/CNG (Schannel).
        The cryptography library is used only for ed25519 key operations and hashing.
        """
        from pathlib import Path

        x509_verify_pattern = "x509.verification"
        enterprise_src = Path(__file__).parent.parent.parent / "enterprise"

        violations = []
        for py_file in enterprise_src.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for i, line in enumerate(content.splitlines(), 1):
                if x509_verify_pattern in line and not line.strip().startswith("#"):
                    violations.append(f"{py_file}:{i}: {line.strip()}")

        assert not violations, (
            "CVE-2026-34073 scope: x509.verification usage found — "
            "review these for name constraint bypass exposure:\n" + "\n".join(violations)
        )


# ── WFP script integrity ──────────────────────────────────────────────────────

import hashlib  # noqa: E402

from tools.wfp_policy import AllowEntry, WfpProfile, generate_powershell  # noqa: E402


class TestWfpScriptIntegrity:
    """Verify that the script integrity (SHA-256) feature works correctly.

    Defense against: TOCTOU file substitution between script generation and
    execution. An operator who verifies the hash before running the .ps1 elevated
    cannot be tricked into running a substituted script.

    CVE-2026-33825 (BlueHammer): This specific exploit targets Defender's internal
    temp/staging paths — it does NOT affect operator-controlled .ps1 paths. The
    hash feature is defense-in-depth for general file substitution scenarios.
    """

    def test_generate_powershell_is_deterministic(self):
        """Same profile must produce identical script bytes every time.
        Non-determinism would break hash verification."""
        profile = WfpProfile(
            name="integrity-test",
            process="python.exe",
            allow=[AllowEntry(host="127.0.0.1", port=443, protocol="tcp")],
        )
        script_a = generate_powershell(profile, "test.ps1")
        script_b = generate_powershell(profile, "test.ps1")
        assert script_a == script_b, "generate_powershell must be deterministic"

    def test_sha256_of_script_is_stable(self):
        """SHA-256 of the generated script matches what the operator would compute."""
        profile = WfpProfile(
            name="integrity-test",
            process="python.exe",
            allow=[AllowEntry(host="10.0.0.1", port=443, protocol="tcp")],
        )
        script = generate_powershell(profile, "out.ps1")
        computed = hashlib.sha256(script.encode("utf-8")).hexdigest()
        # Re-run and confirm hash is stable
        assert hashlib.sha256(generate_powershell(profile, "out.ps1").encode("utf-8")).hexdigest() == computed

    def test_different_profiles_produce_different_hashes(self):
        """Distinct allow lists must produce distinct scripts — hash distinguishes them."""
        profile_a = WfpProfile(
            name="test",
            process="python.exe",
            allow=[AllowEntry(host="10.0.0.1", port=443, protocol="tcp")],
        )
        profile_b = WfpProfile(
            name="test",
            process="python.exe",
            allow=[AllowEntry(host="192.168.1.1", port=443, protocol="tcp")],
        )
        script_a = generate_powershell(profile_a, "out.ps1")
        script_b = generate_powershell(profile_b, "out.ps1")
        hash_a = hashlib.sha256(script_a.encode("utf-8")).hexdigest()
        hash_b = hashlib.sha256(script_b.encode("utf-8")).hexdigest()
        assert hash_a != hash_b, "Different profiles must produce different hashes"

    def test_tampered_script_has_different_hash(self):
        """If the script on disk is tampered, the hash will not match what was printed."""
        profile = WfpProfile(
            name="test",
            process="python.exe",
            allow=[AllowEntry(host="127.0.0.1", port=None, protocol="tcp")],
        )
        script = generate_powershell(profile, "out.ps1")
        original_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()

        # Simulate an attacker appending a malicious command to the script
        tampered = script + "\nRemove-Item -Recurse C:\\Windows\\System32 -Force"
        tampered_hash = hashlib.sha256(tampered.encode("utf-8")).hexdigest()

        assert tampered_hash != original_hash, \
            "Tampered script must produce a different SHA-256 hash than the original"


# ── Generic dependency audit ──────────────────────────────────────────────────

class TestDependencyAudit:
    """Run pip-audit against all installed packages in this environment.

    Two tiers:
    - HARD GATE (test_direct_deps_no_known_cves): direct dependencies of
      selfconnect-enterprise (cryptography, selfconnect) must have zero CVEs.
      Fails the test run if any are found — blocks deployment.
    - INFORMATIONAL (test_all_installed_packages_audit): scans the full
      environment and prints findings for operator review. Always passes —
      catches the next CVE you didn't pre-enumerate.

    Why both: the custom named-version tests catch *known* bad actors instantly;
    pip-audit catches *newly disclosed* advisories automatically. Neither alone
    is sufficient.
    """

    # Direct dependencies declared in pyproject.toml
    DIRECT_DEPS = {"cryptography", "selfconnect"}

    def _run_pip_audit(self) -> tuple[int, list]:
        """Run pip-audit --local and return (returncode, dependencies_list)."""
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--local", "--format", "json"],
            capture_output=True,
            text=True,
        )
        if result.returncode not in (0, 1):
            return result.returncode, []
        import json as _json
        try:
            data = _json.loads(result.stdout)
            dependencies = data.get("dependencies")
            if not isinstance(dependencies, list):
                return 2, []
            return result.returncode, dependencies
        except (_json.JSONDecodeError, AttributeError):
            return 2, []

    def test_direct_deps_no_known_cves(self):
        """HARD GATE: direct dependencies (cryptography, selfconnect) must have
        zero known CVEs. If pip-audit reports a finding against either, this test
        fails and blocks deployment until the dependency is updated.

        This test catches newly disclosed CVEs automatically — it is not limited
        to the named versions in TestCryptographyVersion or TestLiteLLMSupplyChain.
        """
        returncode, deps = self._run_pip_audit()
        if returncode not in (0, 1):
            pytest.fail(
                "pip-audit hard gate did not produce a valid audit result; "
                "install pip-audit and correct the scanner failure"
            )

        findings = [
            dep for dep in deps
            if dep.get("name", "").lower() in self.DIRECT_DEPS and dep.get("vulns")
        ]

        if findings:
            lines = ["DIRECT DEPENDENCY CVE FINDINGS — DEPLOYMENT BLOCKED:"]
            for dep in findings:
                lines.append(f"\n  {dep['name']}=={dep['version']}:")
                for vuln in dep["vulns"]:
                    fix = ", ".join(vuln.get("fix_versions", [])) or "no fix available"
                    lines.append(f"    [{vuln['id']}] fix: {fix}")
            lines.append("\nRun: pip install --upgrade cryptography selfconnect")
            pytest.fail("\n".join(lines))

    def test_all_installed_packages_audit_informational(self, capsys):
        """INFORMATIONAL REPORTING FIXTURE — not a security gate.

        Scans all installed packages and prints a CVE inventory to stdout so it
        appears in the test log for operator review.  This fixture intentionally
        never fails: hard enforcement of CVEs in *direct* dependencies is done by
        ``test_direct_deps_no_known_cves``.  This one exists solely
        to capture the transitive-dependency picture as an audit trail.

        The assertion below verifies only that the reporting code executed and
        produced output — it does NOT assert that the environment is CVE-free.
        """
        returncode, deps = self._run_pip_audit()
        if returncode not in (0, 1):
            pytest.skip("pip-audit unavailable; skipping informational audit")

        all_findings = [dep for dep in deps if dep.get("vulns")]

        if all_findings:
            print(f"\n=== PIP-AUDIT: {len(all_findings)} packages with known CVEs ===")
            for dep in sorted(all_findings, key=lambda d: d.get("name", "")):
                print(f"\n  {dep['name']}=={dep['version']} ({len(dep['vulns'])} CVEs):")
                for vuln in dep["vulns"]:
                    fix = ", ".join(vuln.get("fix_versions", [])) or "no fix"
                    print(f"    [{vuln['id']}] fix: {fix}")
            print(f"\n  Direct deps (hard gate): {', '.join(sorted(self.DIRECT_DEPS))}")
            print("=============================================")
        else:
            print("\n=== PIP-AUDIT: 0 packages with known CVEs — CLEAN ===")

        # Verify the reporting branch executed and produced output.
        # This is the only property being asserted: the code ran and wrote something.
        # CVE enforcement is the responsibility of test_direct_dependencies_have_no_known_cves.
        captured = capsys.readouterr()
        assert "PIP-AUDIT" in captured.out, (
            "Informational audit produced no output — reporting code did not execute"
        )
