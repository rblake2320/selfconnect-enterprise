"""Run tiered assertions from the SelfConnect Enterprise control catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "assurance" / "control_catalog.json"
TIER_RANK = {"quick": 0, "release": 1, "live": 2}


def _load_catalog() -> dict[str, Any]:
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def _run_control(control: dict[str, Any]) -> dict[str, Any]:
    command = [sys.executable if part == "{python}" else part for part in control["command"]]
    resolved = shutil.which(command[0])
    if resolved:
        command[0] = resolved
    cwd = ROOT / control.get("cwd", ".")
    started = time.time()
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    return {
        "id": control["id"],
        "status": "PASS" if result.returncode == 0 else "FAIL",
        "command": command,
        "cwd": str(cwd),
        "returncode": result.returncode,
        "duration_seconds": round(time.time() - started, 3),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "scope": control["scope"],
        "blind_spots": control["blind_spots"],
    }


def run(tier: str) -> dict[str, Any]:
    catalog = _load_catalog()
    results: list[dict[str, Any]] = []
    executed: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for control in catalog["controls"]:
        control_tier = control["tier"]
        if control_tier == "description":
            results.append({
                "id": control["id"],
                "status": "DESCRIPTION",
                "scope": control["scope"],
                "assertion": control["assertion"],
                "expected": control["expected"],
                "evidence": control["evidence"],
                "blind_spots": control["blind_spots"],
            })
        elif TIER_RANK[control_tier] <= TIER_RANK[tier]:
            raw_command = tuple(control["command"])
            raw_cwd = control.get("cwd", ".")
            cache_key = (raw_command, raw_cwd)
            if cache_key in executed:
                reused = dict(executed[cache_key])
                reused.update({
                    "id": control["id"],
                    "scope": control["scope"],
                    "blind_spots": control["blind_spots"],
                    "reused_execution_from": executed[cache_key]["id"],
                })
                results.append(reused)
            else:
                result = _run_control(control)
                executed[cache_key] = result
                results.append(result)
        else:
            results.append({
                "id": control["id"],
                "status": "NOT_RUN",
                "required_tier": control_tier,
                "scope": control["scope"],
                "blind_spots": control["blind_spots"],
            })
    failed = [item["id"] for item in results if item["status"] == "FAIL"]
    return {
        "schema_version": 1,
        "catalog_sha256": hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
        "selected_tier": tier,
        "overall": "FAIL" if failed else "PASS_WITH_NAMED_BLIND_SPOTS",
        "failed": failed,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier", choices=tuple(TIER_RANK), default="quick")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.tier)
    encoded = json.dumps(report, indent=2)
    print(encoded)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
