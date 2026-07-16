"""Regression tests for the cross-repository portfolio lock."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.portfolio_conformance import (
    ROOT,
    WINDOWS_CLEANUP_FINALLY_GUARDS,
    WINDOWS_LIVE_STEP,
    _powershell_keyword_blocks,
    _workflow_step,
    run_checks,
)


def _write_manifest(path: Path, *, name: str, version: str) -> None:
    path.write_text(json.dumps({"name": name, "version": version}), encoding="utf-8")


def _git(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def test_repository_configuration_matches_portfolio_lock() -> None:
    report = run_checks()
    assert report["overall"] == "PASS", report["errors"]
    assert report["errors"] == []


def test_component_checkout_must_match_commit_and_package_metadata(tmp_path: Path) -> None:
    component = tmp_path / "bpc"
    component.mkdir()
    _git(["git", "init"], component)
    _git(["git", "config", "user.email", "conformance@example.invalid"], component)
    _git(["git", "config", "user.name", "Portfolio Conformance"], component)
    _write_manifest(component / "package.json", name="bpc-protocol", version="0.2.0")
    _git(["git", "add", "package.json"], component)
    _git(["git", "commit", "-m", "fixture"], component)

    lock = json.loads((ROOT / "portfolio-lock.json").read_text(encoding="utf-8"))
    lock["components"]["bpc-protocol"]["commit"] = "0" * 40
    lock_path = tmp_path / "portfolio-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    report = run_checks(lock_path=lock_path, component_roots={"bpc-protocol": component})
    assert report["overall"] == "FAIL"
    assert any("checkout" in error and "does not match lock" in error for error in report["errors"])


def test_invalid_or_missing_component_pins_fail_closed(tmp_path: Path) -> None:
    lock = json.loads((ROOT / "portfolio-lock.json").read_text(encoding="utf-8"))
    del lock["components"]["tsk-protocol"]
    lock["components"]["bpc-protocol"]["commit"] = "not-a-commit"
    lock_path = tmp_path / "portfolio-lock.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    report = run_checks(lock_path=lock_path)
    assert report["overall"] == "FAIL"
    assert any("missing components" in error for error in report["errors"])
    assert any("40-character Git SHA" in error for error in report["errors"])


def test_windows_native_command_failures_cannot_be_masked(tmp_path: Path) -> None:
    root = tmp_path / "root"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow = workflow.replace(
        "          $PSNativeCommandUseErrorActionPreference = $true\n",
        "",
        1,
    )
    (workflow_dir / "ci.yml").write_text(workflow, encoding="utf-8")

    report = run_checks(root=root)
    assert report["overall"] == "FAIL"
    assert any("must fail fast on native command errors" in error for error in report["errors"])


def test_windows_powershell_errors_must_be_terminating(tmp_path: Path) -> None:
    root = tmp_path / "root"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow = workflow.replace(
        "          $ErrorActionPreference = 'Stop'\n",
        "",
        1,
    )
    (workflow_dir / "ci.yml").write_text(workflow, encoding="utf-8")

    report = run_checks(root=root)
    assert report["overall"] == "FAIL"
    assert any("must stop on PowerShell errors" in error for error in report["errors"])


def test_windows_live_sidecar_cannot_cross_step_boundary(tmp_path: Path) -> None:
    root = tmp_path / "root"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow = workflow.replace(
        "          $process = Start-Process node -ArgumentList 'server.js' `\n",
        "",
        1,
    )
    (workflow_dir / "ci.yml").write_text(workflow, encoding="utf-8")

    report = run_checks(root=root)
    assert report["overall"] == "FAIL"
    assert any("must contain 'Start-Process node'" in error for error in report["errors"])


def test_windows_live_cleanup_must_remain_inside_finally(tmp_path: Path) -> None:
    root = tmp_path / "root"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    cleanup = """            try {
              if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
              }
            } catch {
              Write-Warning \"Ultra Server stop cleanup failed: $($_.Exception.Message)\"
            }
            try {
              Get-Content $stdout -ErrorAction Stop
            } catch {
              Write-Warning \"Ultra Server stdout capture failed: $($_.Exception.Message)\"
            }
            try {
              Get-Content $stderr -ErrorAction Stop
            } catch {
              Write-Warning \"Ultra Server stderr capture failed: $($_.Exception.Message)\"
            }
"""
    assert cleanup in workflow
    workflow = workflow.replace(cleanup, "", 1)
    workflow = workflow.replace(
        "          }\n\n  ultra-production-restart:",
        "          }\n" + cleanup + "\n  ultra-production-restart:",
        1,
    )
    (workflow_dir / "ci.yml").write_text(workflow, encoding="utf-8")

    report = run_checks(root=root)
    assert report["overall"] == "FAIL"
    assert any("cleanup guards must appear together" in error for error in report["errors"])


def test_windows_live_cleanup_errors_cannot_mask_contract_failure(tmp_path: Path) -> None:
    root = tmp_path / "root"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow = workflow.replace(
        "Stop-Process -Id $process.Id -Force -ErrorAction Stop",
        "Stop-Process -Id $process.Id -Force",
        1,
    )
    (workflow_dir / "ci.yml").write_text(workflow, encoding="utf-8")

    report = run_checks(root=root)
    assert report["overall"] == "FAIL"
    assert any("cleanup guards must appear together" in error for error in report["errors"])


def test_windows_live_cleanup_preserves_the_primary_failure(tmp_path: Path) -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    live_step = _workflow_step(workflow, WINDOWS_LIVE_STEP)
    cleanup = next(
        block
        for block in _powershell_keyword_blocks(live_step, "finally")
        if all(marker in block for marker in WINDOWS_CLEANUP_FINALLY_GUARDS)
    )
    stdout = str(tmp_path / "missing-stdout.log").replace("'", "''")
    stderr = str(tmp_path / "missing-stderr.log").replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$process = [pscustomobject]@{{}}
$process | Add-Member -MemberType ScriptProperty -Name HasExited -Value {{
  throw 'STOP_CLEANUP_FAILURE'
}}
$stdout = '{stdout}'
$stderr = '{stderr}'
try {{
  throw 'PRIMARY_CONTRACT_FAILURE'
}} finally {{
{cleanup}
}}
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "PRIMARY_CONTRACT_FAILURE" in output
    assert "Ultra Server stop cleanup failed" in output
    assert "Ultra Server stdout capture failed" in output
    assert "Ultra Server stderr capture failed" in output
