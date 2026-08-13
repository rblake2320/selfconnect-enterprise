from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _record_hash(value: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode("ascii")
    return f"sha256={encoded.rstrip('=')}"


def _write_bound_wheel(
    path: Path,
    *,
    mutations: dict[str, bytes] | None = None,
    extras: dict[str, bytes] | None = None,
    corrupt_record_for: str | None = None,
) -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    normalized = re.sub(r"[-_.]+", "_", project["name"])
    dist_info = f"{normalized}-{project['version']}.dist-info"
    members = {
        source.relative_to(ROOT).as_posix(): source.read_bytes()
        for package in ("enterprise", "enterprise_experiments")
        for source in (ROOT / package).rglob("*.py")
    }
    members.update({
        f"{dist_info}/METADATA": (
            ROOT / "selfconnect_enterprise.egg-info" / "PKG-INFO"
        ).read_bytes(),
        f"{dist_info}/entry_points.txt": (
            ROOT / "selfconnect_enterprise.egg-info" / "entry_points.txt"
        ).read_bytes(),
        f"{dist_info}/top_level.txt": (
            ROOT / "selfconnect_enterprise.egg-info" / "top_level.txt"
        ).read_bytes(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: acceptance-test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n\n"
        ),
    })
    members.update(mutations or {})
    members.update(extras or {})
    record_name = f"{dist_info}/RECORD"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, value in sorted(members.items()):
        digest = "sha256=invalid" if name == corrupt_record_for else _record_hash(value)
        writer.writerow((name, digest, len(value)))
    writer.writerow((record_name, "", ""))
    members[record_name] = output.getvalue().encode("utf-8")
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in sorted(members.items()):
            archive.writestr(name, value)


def test_windows_service_runtime_dependency_and_admin_command_are_packaged():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = config["project"]["dependencies"]
    assert "pywin32>=306; sys_platform == 'win32'" in dependencies
    assert config["project"]["scripts"]["scent-provenance-admin"] == (
        "enterprise.provenance_admin:main"
    )


def test_packaged_win32_probes_declare_runtime_dependencies_and_package_imports():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = config["project"]["dependencies"]
    assert "comtypes>=1.4; sys_platform == 'win32'" in dependencies

    target_guard_load = ast.parse(
        (ROOT / "enterprise_experiments" / "win32_probe" / "target_guard_load_test.py").read_text(
            encoding="utf-8"
        )
    )
    chained_channel = ast.parse(
        (ROOT / "enterprise_experiments" / "win32_probe" / "chained_channel.py").read_text(
            encoding="utf-8"
        )
    )
    relative_imports = {
        node.module
        for tree in (target_guard_load, chained_channel)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 1
    }
    assert {"target_guard", "named_pipe_identity", "tpm_identity", "uia_textpattern"} <= (
        relative_imports
    )


def test_enterprise_wheel_owns_no_core_wheel_paths():
    """Installing or uninstalling either distribution must not alter the other."""
    sdk_root = ROOT / "sdk"
    core_config = tomllib.loads((sdk_root / "pyproject.toml").read_text(encoding="utf-8"))
    core_includes = core_config["tool"]["hatch"]["build"]["targets"]["wheel"]["include"]
    core_paths: set[str] = set()
    for pattern in core_includes:
        for candidate in sdk_root.glob(pattern):
            if candidate.is_file():
                core_paths.add(candidate.relative_to(sdk_root).as_posix())

    enterprise_paths = {
        source.relative_to(ROOT).as_posix()
        for package in ("enterprise", "enterprise_experiments")
        for source in (ROOT / package).rglob("*.py")
    }
    overlap = sorted(core_paths & enterprise_paths)
    assert overlap == [], f"Core and Enterprise wheels both own: {overlap}"


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


def test_acceptance_helper_record_requests_bind_explicit_sessions():
    helper_path = ROOT / "deploy/provenance_acceptance_client.py"
    tree = ast.parse(helper_path.read_text(encoding="utf-8"), filename=str(helper_path))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "build_record_request"
    ]
    assert calls
    missing = [
        node.lineno
        for node in calls
        if not any(keyword.arg == "session_id" for keyword in node.keywords)
    ]
    assert missing == [], f"build_record_request calls missing session_id at lines {missing}"


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


def test_wheel_binding_covers_complete_archive_and_record(tmp_path):
    wheel = tmp_path / "runtime.whl"
    output = tmp_path / "result.json"
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
    _write_bound_wheel(wheel)
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr

    target = "enterprise/session_index.py"
    _write_bound_wheel(
        wheel,
        mutations={target: (ROOT / target).read_bytes() + b"\n# injected mismatch\n"},
    )
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 1

    _write_bound_wheel(wheel, extras={"payload.pth": b"import payload\n"})
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 1
    assert "extra:payload.pth" in json.loads(output.read_text(encoding="utf-8"))["mismatches"]

    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dist_info = (
        f"{re.sub(r'[-_.]+', '_', config['project']['name'])}-"
        f"{config['project']['version']}.dist-info"
    )
    metadata_name = f"{dist_info}/METADATA"
    metadata = (ROOT / "selfconnect_enterprise.egg-info" / "PKG-INFO").read_bytes()
    _write_bound_wheel(wheel, mutations={metadata_name: metadata + b"X-Forged: yes\n"})
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 1
    assert f"metadata:{metadata_name}" in json.loads(
        output.read_text(encoding="utf-8")
    )["mismatches"]

    _write_bound_wheel(wheel, corrupt_record_for="enterprise/provenance_service.py")
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 1
    assert "record:hash:enterprise/provenance_service.py" in json.loads(
        output.read_text(encoding="utf-8")
    )["mismatches"]


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
    assert "'partial service registration removal'" in installer
    assert "partial $ServiceName registration remains after removal" in installer
    assert "$rollbackFailures -join '; '" in installer
    assert "operator-requested post-registration acceptance fault" in installer
    assert "SC_PROVENANCE_BOOTSTRAP_IDENTITY=1" in installer
    assert "Wait-IdentityBootstrap" in installer
    assert "Wait-ProvenanceReady" in installer
    assert "WaitNamedPipe" in installer
    assert "Remove-Item -LiteralPath $endpointFile" in installer
    service = (ROOT / "enterprise/provenance_service.py").read_text(encoding="utf-8")
    assert "dedicated provenance service refuses consumer audit mode" in service
    assert "process token is not the dedicated SelfConnectProvenance service SID" in service
    assert '"instance_id": secrets.token_hex(16)' in service
    assert '"service_pid": os.getpid()' in service
    assert 'self._runtime.stop(stop_reason)' in service


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
    assert acceptance.count("Wait-ProvenanceEndpoint -Path $endpointFile") == 4
    assert "-PreviousPipeName $preEnrollmentPipeName" in acceptance
    assert "provenance service stopped before publishing a ready endpoint" in acceptance
    assert "provenance service did not publish a valid fresh endpoint before the deadline" in acceptance
    assert "[Text.UTF8Encoding]::new($false)" in acceptance
    assert "Set-Content -LiteralPath $ConfigPath -Encoding UTF8" not in acceptance
    assert "ProvenanceAcceptanceEvidence" in acceptance
    assert "Join-Path $AcceptanceRoot 'acceptance-report.json'" not in acceptance
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
