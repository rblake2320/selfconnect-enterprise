"""Fail-closed coherence check for Enterprise's sole SelfConnect SDK source."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VCS_RE = re.compile(r"selfconnect\s*@\s*git\+https://github\.com/rblake2320/selfconnect\.git@([0-9a-f]{40})")
LEGACY_SDK_SHA = "8cf151dbc5f312ce888e51aa429f62960e1a2ee6"


def _gitlink(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "ls-files", "-s", "sdk"], cwd=root, text=True, capture_output=True, check=False
    )
    match = re.match(r"160000\s+([0-9a-f]{40})\s+0\s+sdk$", result.stdout.strip())
    return match.group(1) if match else None


def check(*, root: Path = ROOT, required_core_sha: str | None = None) -> dict[str, Any]:
    """Compare every executable/install selector; any ambiguity is a release HOLD."""
    errors: list[str] = []
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    pins = [match.group(1) for item in dependencies if isinstance(item, str) for match in [VCS_RE.search(item)] if match]
    if len(pins) != 1:
        errors.append("pyproject must contain exactly one immutable SelfConnect VCS pin")
    pyproject_pin = pins[0] if len(pins) == 1 else None

    lock = json.loads((root / "portfolio-lock.json").read_text(encoding="utf-8"))
    lock_pin = lock.get("components", {}).get("selfconnect", {}).get("commit")
    if not isinstance(lock_pin, str) or not SHA_RE.fullmatch(lock_pin):
        errors.append("portfolio lock SelfConnect commit must be a lowercase 40-character SHA")
        lock_pin = None

    gitlink = _gitlink(root)
    if gitlink is None:
        errors.append("sdk must be a tracked gitlink, not a copied compatibility directory")

    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    if "git submodule update --init --recursive" not in ci:
        errors.append("CI must initialize the SDK submodule before coherence verification")
    if "tools.sdk_coherence" not in ci:
        errors.append("CI must run the SDK coherence verifier")

    selectors = {value for value in (pyproject_pin, lock_pin, gitlink) if value}
    if len(selectors) != 1:
        errors.append(f"SelfConnect selectors disagree: pyproject={pyproject_pin}, lock={lock_pin}, gitlink={gitlink}")
    selected = next(iter(selectors)) if len(selectors) == 1 else None
    if selected == LEGACY_SDK_SHA:
        errors.append("legacy warm-standby SDK 8cf151d is forbidden as an executable or parity source")
    if required_core_sha is not None:
        if not SHA_RE.fullmatch(required_core_sha):
            errors.append("required core SHA must be a lowercase 40-character SHA")
        elif selected != required_core_sha:
            errors.append(f"selected SelfConnect SHA {selected} does not match reviewed core SHA {required_core_sha}")

    return {"overall": "PASS" if not errors else "HOLD", "selected_core_sha": selected, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--required-core-sha", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    report = check(root=args.root.resolve(), required_core_sha=args.required_core_sha)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
