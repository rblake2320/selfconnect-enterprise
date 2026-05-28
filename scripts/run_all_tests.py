#!/usr/bin/env python3
"""run_all_tests.py — single-command verifier across the trust-layer repos.

Runs each repo's suite, records a machine-readable session log to
logs/test_runs.jsonl with: UTC timestamp, per-repo git HEAD (so the result is
pinned to an exact code version), suite pass/fail/skip counts, the command used,
and overall green/red. Appendable JSONL = audit-friendly, no parsing needed.

Usage:
    python3 run_all_tests.py                 # full run
    python3 run_all_tests.py --fast          # skip slow suites (bpc server long tests)

Configure repo paths via env or the REPOS table below.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
import sys

# repo_key -> (path, test command). Override paths via env REPO_<KEY>_DIR.
_NPM = "npm.cmd" if sys.platform == "win32" else "npm"

REPOS = {
    "bpc-protocol":          (os.environ.get("REPO_BPC_DIR",  "../bpc-protocol"),          [_NPM, "test", "--workspaces"]),
    "tsk-protocol":          (os.environ.get("REPO_TSK_DIR",  "../tsk-protocol"),          [_NPM, "test"]),
    "selfconnect-enterprise": (os.environ.get("REPO_SC_DIR",  "."),                         [sys.executable, "-m", "pytest", "-q"]),
}

LOG_PATH = pathlib.Path(os.environ.get("TEST_RUN_LOG", "logs/test_runs.jsonl"))

_PYTEST_RE = re.compile(r"(\d+)\s+passed(?:,\s*(\d+)\s+skipped)?(?:,\s*(\d+)\s+failed)?")
_VITEST_RE = re.compile(r"Tests\s+(\d+)\s+passed")
_VITEST_FAIL_RE = re.compile(r"Tests\s+(?:\d+\s+passed.*?)?(\d+)\s+failed")


def git_head(path: pathlib.Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"


def parse_counts(output: str) -> dict:
    """Best-effort pass/skip/fail extraction. vitest XOR pytest to avoid
    double-counting (both runners print 'N passed')."""
    passed = skipped = failed = 0
    vitest_pass = _VITEST_RE.findall(output)
    if vitest_pass:
        # vitest repo (bpc): one 'Tests N passed' per workspace.
        passed = sum(int(n) for n in vitest_pass)
        failed = sum(int(m) for m in _VITEST_FAIL_RE.findall(output))
        return {"passed": passed, "skipped": 0, "failed": failed}
    for m in _PYTEST_RE.finditer(output):
        passed += int(m.group(1))
        skipped += int(m.group(2) or 0)
        failed += int(m.group(3) or 0)
    return {"passed": passed, "skipped": skipped, "failed": failed}


def run_repo(key: str, path: pathlib.Path, cmd: list[str]) -> dict:
    print(f"\n=== {key} ({path}) ===")
    proc = subprocess.run(cmd, cwd=str(path), capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    counts = parse_counts(out)
    green = proc.returncode == 0 and counts["failed"] == 0
    safe_out = out.strip()[-600:].encode(sys.stdout.encoding or "utf-8", errors="replace").decode(sys.stdout.encoding or "utf-8", errors="replace")
    print(safe_out)
    print(f"-> {key}: passed={counts['passed']} skipped={counts['skipped']} "
          f"failed={counts['failed']} exit={proc.returncode} green={green}")
    return {
        "repo": key,
        "git_head": git_head(path),
        "command": " ".join(cmd),
        "exit_code": proc.returncode,
        "green": green,
        **counts,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="skip slow suites")
    args = ap.parse_args()

    started = _dt.datetime.now(_dt.timezone.utc).isoformat()
    results = []
    for key, (rel, cmd) in REPOS.items():
        path = pathlib.Path(rel).resolve()
        if not path.exists():
            results.append({"repo": key, "error": f"path not found: {path}", "green": False})
            continue
        if args.fast and key == "bpc-protocol":
            cmd = cmd + ["--", "--exclude", "**/server.test.ts"]
        results.append(run_repo(key, path, cmd))

    total_pass = sum(r.get("passed", 0) for r in results)
    total_skip = sum(r.get("skipped", 0) for r in results)
    total_fail = sum(r.get("failed", 0) for r in results)
    all_green = all(r.get("green") for r in results)

    record = {
        "timestamp": started,
        "mode": "fast" if args.fast else "full",
        "platform": sys.platform,
        "all_green": all_green,
        "totals": {"passed": total_pass, "skipped": total_skip, "failed": total_fail},
        "repos": results,
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    print("\n" + "=" * 60)
    print(f"AGGREGATE: {total_pass} passed, {total_skip} skipped, {total_fail} failed "
          f"| all_green={all_green}")
    print(f"session logged -> {LOG_PATH}")
    for r in results:
        print(f"  {r['repo']:24} HEAD={r.get('git_head','?')[:12]} "
              f"pass={r.get('passed','?')} skip={r.get('skipped','?')} fail={r.get('failed','?')}")
    return 0 if all_green else 1


if __name__ == "__main__":
    raise SystemExit(main())
