"""Validate the exact cross-repository sources used by Enterprise CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "portfolio-lock.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VCS_PIN_RE = re.compile(r"selfconnect\.git@([0-9a-f]{40})(?:\b|$)")
WINDOWS_NATIVE_FAIL_FAST = "$PSNativeCommandUseErrorActionPreference = $true"
WINDOWS_TERMINATING_ERRORS = "$ErrorActionPreference = 'Stop'"
WINDOWS_NATIVE_STEPS = (
    "Install dependencies",
    "Checkout pinned BPC and TSK protocol sources",
    "Build pinned protocol dependencies",
    "Install Python contract dependencies",
    "Run live Node and Python contracts",
)
WINDOWS_LIVE_STEP = "Run live Node and Python contracts"
WINDOWS_LIVE_STEP_MARKERS = (
    "Start-Process node",
    "Invoke-RestMethod http://127.0.0.1:7777/health",
    "npm run test:live",
    "python -m pytest tests/test_e2e_ultra_gate.py tests/test_identity_gate.py",
    "finally {",
    "Stop-Process -Id $process.Id",
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _git_head(path: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"{path} is not a readable Git checkout: {result.stderr.strip()}")
    return result.stdout.strip()


def _package_version(path: Path, manifest: str) -> tuple[str, str]:
    manifest_path = path / manifest
    if manifest == "package.json":
        data = _load_json(manifest_path)
        return str(data.get("name", "")), str(data.get("version", ""))
    if manifest == "pyproject.toml":
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        project = data.get("project", {})
        return str(project.get("name", "")), str(project.get("version", ""))
    raise ValueError(f"unsupported component manifest: {manifest}")


def _parse_component_roots(values: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path:
            raise ValueError("--component-root must use NAME=PATH")
        if name in roots:
            raise ValueError(f"duplicate component root: {name}")
        roots[name] = Path(raw_path).resolve()
    return roots


def _workflow_step(workflow_text: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = workflow_text.find(marker)
    if start < 0:
        return ""
    end = workflow_text.find("\n      - ", start + len(marker))
    return workflow_text[start:] if end < 0 else workflow_text[start:end]


def run_checks(
    *,
    root: Path = ROOT,
    lock_path: Path = LOCK_PATH,
    component_roots: dict[str, Path] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    checks: list[dict[str, Any]] = []
    component_roots = component_roots or {}
    lock = _load_json(lock_path)

    if lock.get("schema_version") != 1:
        errors.append("portfolio lock schema_version must be 1")
    components = lock.get("components")
    if not isinstance(components, dict) or not components:
        errors.append("portfolio lock must define components")
        components = {}

    required_components = {"selfconnect", "bpc-protocol", "tsk-protocol"}
    missing = required_components - set(components)
    if missing:
        errors.append(f"portfolio lock missing components: {sorted(missing)}")

    for name, component in components.items():
        if not isinstance(component, dict):
            errors.append(f"{name}: component entry must be an object")
            continue
        commit = component.get("commit")
        repository = component.get("repository")
        if not isinstance(commit, str) or not SHA_RE.fullmatch(commit):
            errors.append(f"{name}: commit must be a lowercase 40-character Git SHA")
        if not isinstance(repository, str) or not repository.startswith("https://github.com/"):
            errors.append(f"{name}: repository must be an explicit GitHub HTTPS URL")
        if name not in component_roots:
            checks.append({"component": name, "status": "PIN_ONLY", "commit": commit})
            continue
        checkout = component_roots[name]
        try:
            actual_commit = _git_head(checkout)
            actual_name, actual_version = _package_version(checkout, component["manifest"])
        except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        if actual_commit != commit:
            errors.append(f"{name}: checkout {actual_commit} does not match lock {commit}")
        if actual_name != component.get("package_name"):
            errors.append(
                f"{name}: package name {actual_name!r} does not match "
                f"{component.get('package_name')!r}"
            )
        if actual_version != component.get("package_version"):
            errors.append(
                f"{name}: package version {actual_version!r} does not match "
                f"{component.get('package_version')!r}"
            )
        checks.append({
            "component": name,
            "status": "PASS" if not any(item.startswith(f"{name}:") for item in errors) else "FAIL",
            "commit": actual_commit,
            "package_name": actual_name,
            "package_version": actual_version,
            "path": str(checkout),
        })

    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    sdk_pins = [
        match.group(1)
        for dependency in dependencies
        if isinstance(dependency, str)
        for match in [VCS_PIN_RE.search(dependency)]
        if match
    ]
    expected_sdk_pin = components.get("selfconnect", {}).get("commit")
    if sdk_pins != [expected_sdk_pin]:
        errors.append(
            "pyproject SelfConnect VCS pin does not match portfolio-lock.json: "
            f"declared={sdk_pins!r}, expected={[expected_sdk_pin]!r}"
        )

    workflow_text = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    if workflow_text.count("portfolio-lock.json") < 2:
        errors.append("both protocol composition jobs must read portfolio-lock.json")
    for name in required_components:
        commit = components.get(name, {}).get("commit")
        if isinstance(commit, str) and commit in workflow_text:
            errors.append(f"ci.yml duplicates the {name} commit instead of reading the portfolio lock")
    for step_name in WINDOWS_NATIVE_STEPS:
        step = _workflow_step(workflow_text, step_name)
        if WINDOWS_TERMINATING_ERRORS not in step:
            errors.append(
                f"ci.yml Windows step {step_name!r} must stop on PowerShell errors"
            )
        if WINDOWS_NATIVE_FAIL_FAST not in step:
            errors.append(
                f"ci.yml Windows step {step_name!r} must fail fast on native command errors"
            )
    if "      - name: Start development sidecar\n" in workflow_text:
        errors.append(
            "ci.yml must not start the Windows development sidecar in a separate step"
        )
    live_step = _workflow_step(workflow_text, WINDOWS_LIVE_STEP)
    for marker in WINDOWS_LIVE_STEP_MARKERS:
        if marker not in live_step:
            errors.append(
                f"ci.yml Windows live-contract step must contain {marker!r}"
            )

    return {
        "schema_version": 1,
        "overall": "PASS" if not errors else "FAIL",
        "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "checks": checks,
        "errors": errors,
        "blind_spots": [
            "A pin proves source identity, not that the source is secure or authorized.",
            "PIN_ONLY components are verified only when their checkout is supplied.",
            "Deployment configuration, external storage, key custody, and authorization remain separate evidence.",
            "Workflow structure checks prove declared lifecycle composition, not runner process behavior.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--component-root",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="verify a checked-out component against its locked commit and package metadata",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        component_roots = _parse_component_roots(args.component_root)
        report = run_checks(component_roots=component_roots)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        report = {"schema_version": 1, "overall": "FAIL", "checks": [], "errors": [str(exc)]}
    encoded = json.dumps(report, indent=2)
    print(encoded)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
