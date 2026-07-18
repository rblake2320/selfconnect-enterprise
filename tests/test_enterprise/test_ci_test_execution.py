"""Regression tests for the authoritative CI test execution."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_runs_the_full_pytest_suite_once() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    assert workflow.count('["python", "-m", "pytest"') == 1
    assert "run: python -m pytest" not in workflow


def test_ci_prints_the_authoritative_pytest_output() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    print_output = workflow.index('print(output, end="")')
    enforce_exit = workflow.index("if result.returncode != 0:")
    assert print_output < enforce_exit
