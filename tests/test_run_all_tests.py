"""Regression tests for the cross-repository test-result collector."""

from scripts.run_all_tests import parse_counts


def test_parse_counts_reads_custom_ha_suite_ratios() -> None:
    output = """
    TSK replication stream suite: 6/6 passed
    TSK replica receiver suite: 7/8 passed
    TSK fenced promotion suite: 8/8 passed
    """

    assert parse_counts(output) == {"passed": 21, "skipped": 0, "failed": 1}


def test_parse_counts_reads_multiple_vitest_workspaces() -> None:
    output = """
    Tests  26 passed (26)
    Tests  121 passed (121)
    """

    assert parse_counts(output) == {"passed": 147, "skipped": 0, "failed": 0}


def test_parse_counts_reads_pytest_summary_in_standard_failure_first_order() -> None:
    output = "2 failed, 1305 passed, 21 skipped in 48.1s"

    assert parse_counts(output) == {"passed": 1305, "skipped": 21, "failed": 2}
