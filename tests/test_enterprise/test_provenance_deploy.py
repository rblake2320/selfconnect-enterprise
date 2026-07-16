from __future__ import annotations

import os
import json
import subprocess
import sys
import tomllib
import zipfile
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


@pytest.mark.skipif(os.name != "nt", reason="Windows completion receipt contract")
def test_acceptance_helper_writes_atomic_completion_receipts(tmp_path):
    helper = ROOT / "deploy/provenance_acceptance_client.py"
    identity_dir = tmp_path / "identity"
    output = tmp_path / "bootstrap.json"
    completion = tmp_path / "completion.json"
    invocation_id = "receipt-success"
    command = [
        sys.executable,
        str(helper),
        "bootstrap",
        "--identity-dir",
        str(identity_dir),
        "--output",
        str(output),
        "--completion",
        str(completion),
        "--invocation-id",
        invocation_id,
    ]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completion.read_text(encoding="utf-8"))
    assert receipt["schema"] == "selfconnect.provenance.acceptance-completion.v1"
    assert receipt["invocation_id"] == invocation_id
    assert receipt["ok"] is True
    assert receipt["exit_code"] == 0
    assert receipt["error_type"] is None
    assert receipt["sid"].startswith("S-1-")
    assert not list(tmp_path.glob(".*.tmp"))

    failure_output = tmp_path / "output-is-a-directory"
    failure_output.mkdir()
    failure_receipt = tmp_path / "failure-completion.json"
    failed = subprocess.run(
        [
            sys.executable,
            str(helper),
            "bootstrap",
            "--identity-dir",
            str(tmp_path / "failure-identity"),
            "--output",
            str(failure_output),
            "--completion",
            str(failure_receipt),
            "--invocation-id",
            "receipt-failure",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failed.returncode != 0
    receipt = json.loads(failure_receipt.read_text(encoding="utf-8"))
    assert receipt["ok"] is False
    assert receipt["exit_code"] == 1
    assert receipt["error_type"].endswith("Error")


def test_wheel_binding_compares_every_runtime_source_file(tmp_path):
    wheel = tmp_path / "runtime.whl"
    output = tmp_path / "result.json"
    sources = sorted((ROOT / "enterprise").rglob("*.py"))
    with zipfile.ZipFile(wheel, "w") as archive:
        for source in sources:
            archive.write(source, source.relative_to(ROOT).as_posix())
    command = [
        sys.executable,
        "deploy/provenance_acceptance_client.py",
        "verify-wheel",
        "--wheel",
        str(wheel),
        "--repo-root",
        str(ROOT),
        "--output",
        str(output),
    ]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr

    with zipfile.ZipFile(wheel, "w") as archive:
        for source in sources:
            content = source.read_bytes()
            if source.name == "session_index.py":
                content += b"\n# injected mismatch\n"
            archive.writestr(source.relative_to(ROOT).as_posix(), content)
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 1


def test_acceptance_helper_prefers_exact_repository_sources():
    helper = (ROOT / "deploy/provenance_acceptance_client.py").read_text(encoding="utf-8")
    path_binding = "REPO_ROOT = Path(__file__).resolve().parents[1]"
    enterprise_import = "from enterprise.identity import AgentIdentity"
    assert path_binding in helper
    assert helper.index(path_binding) < helper.index(enterprise_import)


def test_acceptance_verification_uses_structured_helper_commands():
    acceptance = (ROOT / "deploy/provenance_service_acceptance.ps1").read_text(
        encoding="utf-8"
    )
    helper = (ROOT / "deploy/provenance_acceptance_client.py").read_text(
        encoding="utf-8"
    )
    assert "-c @'" not in acceptance
    for command in ("verify-dacl", "verify-ledger", "verify-index"):
        assert command in acceptance
        assert f'add_parser("{command}")' in helper


def test_installer_has_explicit_acl_repair_and_no_silent_hardened_fallback():
    installer = (ROOT / "deploy/provenance_service.ps1").read_text(encoding="utf-8")
    assert "'RepairAcl'" in installer
    assert "Set-ProvenanceAcls" in installer
    assert "Set-HardenedTreeFileAcls" in installer
    assert "Set-HardenedTreeDirectoryAcls" in installer
    assert "Grant-ServiceRuntimeAccess" in installer
    assert "Resolve-ServiceRuntimeRoots" in installer
    assert "PythonExe must belong to a dedicated runtime below" in installer
    assert "The base Python runtime must not be installed below a user profile" in installer
    assert "sys.base_prefix" in installer
    assert "ProvenanceRuntimeAclPaths" in installer
    assert "Revoke-ServiceRuntimeAccess" in installer
    assert "FileSystemRights]::Traverse" in installer
    assert "FileSystemRights]::ReadAndExecute" in installer
    assert "[IO.DirectoryInfo]::new($runtimeRoot).Parent" not in installer
    assert "pip install --force-reinstall --no-deps $wheel" in installer
    assert "$serviceHostProbe" in installer
    assert "service_class._exe_name_ == sys.executable" in installer
    assert "service_class._exe_args_ == sys.argv[1]" in installer
    assert "'-m enterprise.provenance_service'" in installer
    assert "Failed to remove partial $ServiceName registration" in installer
    assert "operator-requested post-registration acceptance fault" in installer
    assert "SC_PROVENANCE_BOOTSTRAP_IDENTITY=1" in installer
    assert "Wait-IdentityBootstrap" in installer
    assert "Wait-ProvenanceReady" in installer
    service = (ROOT / "enterprise/provenance_service.py").read_text(encoding="utf-8")
    assert "dedicated provenance service refuses consumer audit mode" in service
    assert "process token is not the dedicated SelfConnectProvenance service SID" in service


def test_acceptance_requires_exact_source_and_proves_cross_restart_recovery():
    acceptance = (ROOT / "deploy/provenance_service_acceptance.ps1").read_text(
        encoding="utf-8"
    )
    assert "status --short --untracked-files=all" in acceptance
    assert "--untracked-files=no" not in acceptance
    assert "if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)" in acceptance
    assert '$AgentUser = "scpa-$UserId"' in acceptance
    assert '$AnonymousUser = "scpx-$UserId"' in acceptance
    assert "recovered_after_error_count -gt 0" in acceptance
    assert "SelfConnect\\Runtime\\ProvenanceAcceptance-$RunId" in acceptance
    assert "-m venv $RuntimeRoot" in acceptance
    assert "ProvenanceClientAcceptance-$RunId" in acceptance
    assert "-m venv $ClientRuntimeRoot" in acceptance
    assert "Start-Process -FilePath $ClientPythonExe" in acceptance
    assert "separate_client_runtime_provisioned" in acceptance
    assert "$ClientPythonExe -ne $ServicePythonExe" in acceptance
    assert "-m pip check" in acceptance
    assert "Refused to remove service root outside acceptance scope" in acceptance
    assert "Wait-AsUserCompletion" in acceptance
    assert "function Wait-ProvenanceEndpoint" in acceptance
    assert acceptance.count("Wait-ProvenanceEndpoint -Path $endpointFile") == 3
    assert "provenance service stopped before publishing a ready endpoint" in acceptance
    assert "provenance service did not publish a valid fresh endpoint before the deadline" in acceptance
    assert "[Text.UTF8Encoding]::new($false)" in acceptance
    assert "Set-Content -LiteralPath $ConfigPath -Encoding UTF8" not in acceptance
    assert "Read-OptionalText" in acceptance
    assert "acceptance-completion.v1" in acceptance
    assert "disposable_user_workspaces_isolated" in acceptance
    assert "Get-SidAllowMask" in acceptance
    assert "Test-ReadExecuteOnly" in acceptance
    assert "$anonymousOnAgent -eq 0" in acceptance
    assert "$agentOnAnonymous -eq 0" in acceptance
    assert "*$($agent.Sid):(OI)(CI)M" in acceptance
    assert "*$($anonymous.Sid):(OI)(CI)M" in acceptance
    assert "*$($agent.Sid):(OI)(CI)RX" in acceptance
    assert "*$($anonymous.Sid):(OI)(CI)RX" in acceptance
    assert "acceptance client runtime descendant ACL inheritance" in acceptance
    assert "shared acceptance descendant ACL inheritance" in acceptance
    assert "foreach ($candidateRuntime in @($RuntimeRoot, $ClientRuntimeRoot))" in acceptance
    assert "runtime_cleanup" in acceptance
    assert "disposable_user_cleanup" in acceptance
    assert "acceptance_workspace_cleanup" in acceptance
    assert "Refused to remove acceptance workspace outside" in acceptance
    assert "stderr=$stderrDetail stdout=$stdoutDetail" in acceptance
    assert "restartedService.ProcessId -eq $killedProcessId" in acceptance
    assert "pipe_rotation_survives_old_name_squatting" in acceptance
    assert "dacl_tamper_preflight" in acceptance
    assert "session_index.jsonl" in acceptance
    assert "verify-index" in acceptance
    helper = (ROOT / "deploy/provenance_acceptance_client.py").read_text(
        encoding="utf-8"
    )
    assert "verify_index_file" in helper
    assert "verify-wheel" in acceptance
    assert "wheel_matches_source_commit" in acceptance
    assert "partial_install_rolls_back" in acceptance

    helper = (ROOT / "deploy/provenance_acceptance_client.py").read_text(encoding="utf-8")
    assert 'burst_parser.add_argument("--ready", type=Path, required=True)' in helper
    assert 'burst_parser.add_argument("--go", type=Path, required=True)' in helper
    assert '"recovered_after_error_count": recovered' in helper
    assert "def verify_wheel(" in helper
