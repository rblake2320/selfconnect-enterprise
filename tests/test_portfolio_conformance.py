"""Regression tests for the cross-repository portfolio lock."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.portfolio_conformance import ROOT, run_checks


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
