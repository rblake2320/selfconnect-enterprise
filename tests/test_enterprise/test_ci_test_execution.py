"""Regression tests for the authoritative CI test execution."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
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


def test_ci_never_installs_below_the_declared_cryptography_floor() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    requirements = re.findall(r'cryptography>=(\d+(?:\.\d+){0,2})', workflow)

    assert requirements
    assert all(int(version.split(".", 1)[0]) >= 50 for version in requirements)
    assert "cryptography>=48" not in workflow


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
    assert EXPECTED_COLLECTION_COUNT == 1_895
    assert len(EXPECTED_COLLECTION_SHA256) == 64


def test_ultra_conformance_import_is_platform_safe() -> None:
    code = """
import sys
import tempfile
from pathlib import Path
sys.platform = 'linux'
from enterprise import identity
from enterprise.identity import AgentIdentity
from enterprise.ultra_gate import UltraGate
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
assert identity.crypt32 is None
for operation in (
    lambda: identity._dpapi_encrypt(b'test'),
    lambda: identity._dpapi_decrypt(b'test'),
):
    try:
        operation()
    except OSError as exc:
        assert 'unavailable' in str(exc)
    else:
        raise AssertionError('non-Windows DPAPI must fail closed')
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    try:
        AgentIdentity.init('posix-init', data_dir=root)
    except OSError as exc:
        assert 'unavailable' in str(exc)
    else:
        raise AssertionError('non-Windows persistent init must fail closed')
    assert not (root / 'posix-init' / 'identity.dpapi').exists()
    assert not (root / 'posix-init' / 'identity.pub').exists()
    planted = root / 'posix-load'
    planted.mkdir()
    (planted / 'identity.dpapi').write_bytes(b'not-dpapi')
    try:
        AgentIdentity.load('posix-load', data_dir=root)
    except OSError as exc:
        assert 'unavailable' in str(exc)
    else:
        raise AssertionError('non-Windows persistent load must fail closed')
private_key = Ed25519PrivateKey.generate()
ephemeral = AgentIdentity(private_key, private_key.public_key(), 'posix-test-only')
message = b'posix-test-proof'
assert ephemeral.verify(message, ephemeral.sign(message), ephemeral.public_key_bytes)
assert ephemeral.canonical_id.startswith('SCID-')
assert UltraGate.__name__ == 'UltraGate'
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
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
    assert len(ALLOWED_SKIPS) == 38
    assert _allowed_skip(
        "tests/test_e2e_ultra_gate.py::test_live",
        "Skipped: Ultra Server not available on localhost:7777",
    ) is False
    allowed_nodeid, allowed_reason = next(iter(ALLOWED_SKIPS.items()))
    assert _allowed_skip(allowed_nodeid, allowed_reason)
    assert not _allowed_skip(allowed_nodeid, allowed_reason + " extra")
    assert not _allowed_skip("tests/test_other.py::test_hidden", allowed_reason)
