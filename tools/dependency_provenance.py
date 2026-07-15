"""Verify that installed VCS dependencies match this checkout's exact pins."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
SELFCONNECT_PIN_RE = re.compile(r"selfconnect\.git@([0-9a-f]{40})$")


def expected_selfconnect_commit() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependency = next(
        (item for item in project["dependencies"] if item.startswith("selfconnect @ ")),
        None,
    )
    if dependency is None:
        raise RuntimeError("pyproject.toml has no exact SelfConnect VCS dependency")
    match = SELFCONNECT_PIN_RE.search(dependency)
    if match is None:
        raise RuntimeError("SelfConnect dependency is not pinned to a full Git commit")
    return match.group(1)


def installed_selfconnect() -> dict[str, str]:
    distribution = importlib.metadata.distribution("selfconnect")
    raw = distribution.read_text("direct_url.json")
    if not raw:
        raise RuntimeError("installed SelfConnect has no direct_url.json provenance")
    direct = json.loads(raw)
    vcs = direct.get("vcs_info") or {}
    if vcs.get("vcs") != "git" or not vcs.get("commit_id"):
        raise RuntimeError("installed SelfConnect is not traceable to a Git commit")
    return {
        "version": distribution.version,
        "commit": str(vcs["commit_id"]),
        "url": str(direct.get("url", "")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    args = parser.parse_args(argv)

    try:
        expected = expected_selfconnect_commit()
        installed = installed_selfconnect()
        if installed["commit"] != expected:
            raise RuntimeError(
                f"installed SelfConnect commit {installed['commit']} does not match {expected}"
            )
        result = {
            "ok": True,
            "dependency": "selfconnect",
            "declared_commit": expected,
            "installed_commit": installed["commit"],
            "installed_version": installed["version"],
            "source_url": installed["url"],
        }
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("PASS" if result["ok"] else "FAIL", json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
