"""Run the authoritative CI suite once and enforce structured result policy."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class StructuredResults:
    passed: int = 0
    failed: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def pytest_runtest_logreport(self, report: Any) -> None:
        if report.skipped:
            reason = (
                str(report.longrepr[2])
                if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3
                else str(report.longrepr)
            )
            self.skipped.append((str(report.nodeid), reason))
        elif report.when == "call" and report.passed:
            self.passed += 1
        elif report.failed:
            self.failed.append(f"{report.nodeid}::{report.when}")


def _allowed_skip(nodeid: str, reason: str) -> bool:
    path = nodeid.replace("\\", "/")
    if path.startswith("tests/test_e2e_ultra_gate.py"):
        return "Ultra Server not available" in reason
    if path.startswith("tests/test_identity_gate.py"):
        return (
            "Ultra Server not available" in reason
            or "ULTRA_ADMIN_TOKEN is not configured" in reason
        )
    if path.startswith("tests/test_enterprise/test_runtime_ownership.py"):
        return any(
            allowed_reason in reason
            for allowed_reason in (
                "POSIX ownership/mode semantics",
                "POSIX ownership semantics",
                "Windows denies unlink of locked file",
                "POSIX no-follow file-symlink semantics",
            )
        )
    return False


def main() -> int:
    results = StructuredResults()
    exit_code = pytest.main(["-q", "--tb=short", "-rs"], plugins=[results])
    payload = {
        "failed": results.failed,
        "passed": results.passed,
        "schema": "selfconnect.ci-pytest-result.v1",
        "skipped": [
            {"nodeid": nodeid, "reason": reason}
            for nodeid, reason in results.skipped
        ],
    }
    print("SELFCONNECT_CI_RESULT=" + json.dumps(payload, sort_keys=True))

    if exit_code != pytest.ExitCode.OK or results.failed:
        print(f"FAIL: pytest exited with status {int(exit_code)}")
        return 1

    unexpected = [
        (nodeid, reason)
        for nodeid, reason in results.skipped
        if not _allowed_skip(nodeid, reason)
    ]
    if unexpected:
        print("FAIL: unexpected skipped test or reason")
        for nodeid, reason in unexpected:
            print(f"{nodeid}: {reason}")
        return 1
    if results.passed < 880:
        print(f"FAIL: only {results.passed} tests passed (expected >= 880)")
        return 1

    print(
        f"OK: {results.passed} passed, {len(results.failed)} failed, "
        f"{len(results.skipped)} named skips"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
