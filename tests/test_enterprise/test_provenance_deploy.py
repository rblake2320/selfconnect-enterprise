from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_windows_service_runtime_dependency_and_admin_command_are_packaged():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = config["project"]["dependencies"]
    assert "pywin32>=306; sys_platform == 'win32'" in dependencies
    assert config["project"]["scripts"]["scent-provenance-admin"] == (
        "enterprise.provenance_admin:main"
    )


@pytest.mark.skipif(os.name != "nt", reason="PowerShell deployment contract")
@pytest.mark.parametrize(
    "relative_path",
    [
        "deploy/provenance_service.ps1",
        "deploy/provenance_service_acceptance.ps1",
    ],
)
def test_powershell_deployment_scripts_parse(relative_path):
    path = ROOT / relative_path
    escaped_path = str(path).replace("'", "''")
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped_path}',[ref]$tokens,[ref]$errors) | Out-Null; "
        "if($errors.Count){$errors | ForEach-Object {$_.Message}; exit 1}"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_acceptance_helper_imports_and_compiles():
    completed = subprocess.run(
        [sys.executable, "-m", "py_compile", "deploy/provenance_acceptance_client.py"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_installer_has_explicit_acl_repair_and_no_silent_hardened_fallback():
    installer = (ROOT / "deploy/provenance_service.ps1").read_text(encoding="utf-8")
    assert "'RepairAcl'" in installer
    assert "Set-ProvenanceAcls" in installer
    assert "pip install --force-reinstall --no-deps $wheel" in installer
    service = (ROOT / "enterprise/provenance_service.py").read_text(encoding="utf-8")
    assert "dedicated provenance service refuses consumer audit mode" in service
    assert "process token is not the dedicated SelfConnectProvenance service SID" in service


def test_acceptance_requires_exact_source_and_proves_cross_restart_recovery():
    acceptance = (ROOT / "deploy/provenance_service_acceptance.ps1").read_text(
        encoding="utf-8"
    )
    assert "status --short --untracked-files=all" in acceptance
    assert "--untracked-files=no" not in acceptance
    assert '$AgentUser = "scpa-$UserId"' in acceptance
    assert '$AnonymousUser = "scpx-$UserId"' in acceptance
    assert "recovered_after_error_count -gt 0" in acceptance
    assert "restartedService.ProcessId -eq $killedProcessId" in acceptance

    helper = (ROOT / "deploy/provenance_acceptance_client.py").read_text(encoding="utf-8")
    assert 'burst_parser.add_argument("--ready", type=Path, required=True)' in helper
    assert 'burst_parser.add_argument("--go", type=Path, required=True)' in helper
    assert '"recovered_after_error_count": recovered' in helper
