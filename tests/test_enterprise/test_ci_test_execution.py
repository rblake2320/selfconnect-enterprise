"""Regression tests for the authoritative CI test execution."""

from __future__ import annotations

import ast
from pathlib import Path

from tools.ci_test_gate import (
    ALLOWED_SKIPS,
    EXPECTED_COLLECTION_COUNT,
    EXPECTED_COLLECTION_SHA256,
    StructuredResults,
    TRUSTED_CONFTEST_SHA256,
    _allowed_skip,
)


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CI_RUNNER = ROOT / "tools" / "ci_test_gate.py"


def test_workflow_has_one_dedicated_test_entrypoint() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    test_job = workflow.split("  test:\n", 1)[1].split(
        "  runtime-ownership-posix:\n", 1
    )[0]
    posix_job = workflow.split("  runtime-ownership-posix:\n", 1)[1].split(
        "  ultra-contract-windows:\n", 1
    )[0]
    isolated_entrypoint = (
        "run: python -I -c \"import runpy; "
        "runpy.run_path('tools/ci_test_gate.py', run_name='__main__')\""
    )

    assert test_job.count(isolated_entrypoint) == 1
    for bypass in (
        "python -m pytest",
        "pytest.main",
        "pytest -q",
        "Invoke-Expression",
        "cmd /c pytest",
        "shell=True",
    ):
        assert bypass not in test_job
    assert posix_job.count("python -m pytest") == 1
    for nodeid in (
        "test_permissive_lock_directory_is_rejected",
        "test_wrong_owner_lock_directory_is_rejected",
        "test_precreated_symlink_lock_file_is_rejected",
        "test_replaced_lock_file_during_binding_is_rejected",
    ):
        assert posix_job.count(nodeid) == 1


def test_runner_invokes_pytest_once_without_shell_or_summary_parsing() -> None:
    source = CI_RUNNER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    pytest_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
        and node.func.attr == "main"
    ]

    assert len(pytest_calls) == 1
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "subprocess" not in imported
    assert not any(
        isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for node in ast.walk(tree)
    )
    assert "re.search" not in source
    assert " passed'" not in source
    assert source.index('os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"]') < source.index(
        "pytest = _load_trusted_pytest()"
    )
    assert "spec_from_file_location" in source
    assert "pytest package hash does not match RECORD" in source
    assert "item.parts[0] in {\"pytest\", \"_pytest\"}" in source


def test_collection_and_conftest_inputs_are_pinned() -> None:
    assert EXPECTED_COLLECTION_COUNT == 1_771
    assert len(EXPECTED_COLLECTION_SHA256) == 64
    assert len(TRUSTED_CONFTEST_SHA256) == 64


def test_structured_results_count_reports_not_terminal_text() -> None:
    results = StructuredResults()

    class Report:
        nodeid = "tests/test_example.py::test_ok"
        when = "call"
        passed = True
        failed = False
        skipped = False
        longrepr = "spoofed output: 999999 passed"

    results.pytest_runtest_logreport(Report())
    assert results.passed == 1
    assert results.failed == []
    assert results.skipped == []


def test_skip_policy_uses_nodeid_and_reason() -> None:
    assert len(ALLOWED_SKIPS) == 41
    assert _allowed_skip(
        "tests/test_e2e_ultra_gate.py::test_live",
        "Skipped: Ultra Server not available on localhost:7777",
    ) is False
    allowed_nodeid, allowed_reason = next(iter(ALLOWED_SKIPS.items()))
    assert _allowed_skip(allowed_nodeid, allowed_reason)
    assert not _allowed_skip(allowed_nodeid, allowed_reason + " extra")
    assert not _allowed_skip("tests/test_other.py::test_hidden", allowed_reason)
