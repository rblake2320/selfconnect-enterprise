"""Fail-closed readiness check for a future ACP registry submission.

This is intentionally not a publisher.  It prevents a local console entry point
from being mistaken for a registry-installable distribution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence


def readiness_issues(
    metadata: Any,
    *,
    icon_path: Path | None,
    terminal_auth_verified: bool,
) -> list[str]:
    """Return bounded reasons why registry publication must remain on hold."""
    issues: list[str] = []
    if not isinstance(metadata, dict):
        return ["agent metadata is not a JSON object"]
    for field in ("id", "name", "version", "description"):
        if not isinstance(metadata.get(field), str) or not metadata[field].strip():
            issues.append(f"missing non-empty {field}")

    distribution = metadata.get("distribution")
    if not isinstance(distribution, dict) or not distribution:
        issues.append("missing published distribution")
    else:
        kinds = set(distribution)
        if not kinds <= {"binary", "npx", "uvx"}:
            issues.append("unsupported distribution kind")
        if not kinds & {"binary", "npx", "uvx"}:
            issues.append("missing binary, npx, or uvx distribution")

    if icon_path is None or not icon_path.is_file() or icon_path.suffix.lower() != ".svg":
        issues.append("missing local icon.svg")
    if not terminal_auth_verified:
        issues.append("terminal authentication has no recorded client acceptance")
    return issues


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assess ACP registry publication readiness")
    parser.add_argument("metadata", type=Path, help="Candidate agent.json")
    parser.add_argument("--icon", type=Path, help="Candidate icon.svg")
    parser.add_argument(
        "--terminal-auth-verified",
        action="store_true",
        help="Assert that a real ACP client completed the terminal setup/reconnect flow",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"HOLD: metadata unreadable ({type(exc).__name__})")
        return 1
    issues = readiness_issues(
        metadata,
        icon_path=args.icon,
        terminal_auth_verified=args.terminal_auth_verified,
    )
    if issues:
        print("HOLD: " + "; ".join(issues))
        return 1
    print("READY FOR REGISTRY CI REVIEW (not published)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
