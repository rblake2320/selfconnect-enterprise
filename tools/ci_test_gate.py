"""Run one candidate-local CI suite and enforce deterministic result policy."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sys
from dataclasses import dataclass, field
from importlib.metadata import distribution
from pathlib import Path
from typing import Any

# Do not execute repository- or environment-selected third-party plugins.
os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
os.environ["PYTEST_PLUGINS"] = ""
os.environ.pop("PYTEST_ADDOPTS", None)


_ULTRA_REASON = "Skipped: Ultra Server not available on localhost:7777"
_E2E_ULTRA_TESTS = (
    "TestUltraGateBootstrap::test_bootstrap_assigns_pair_id",
    "TestUltraGateBootstrap::test_bootstrap_assigns_tsk_state",
    "TestUltraGateBootstrap::test_bootstrap_is_idempotent",
    "TestUltraGateBootstrap::test_server_status_shows_pair_registered",
    "TestBuildInjectionRequest::test_headers_contain_required_keys",
    "TestBuildInjectionRequest::test_pair_id_matches_bootstrap",
    "TestBuildInjectionRequest::test_tsk_key_has_checksum",
    "TestBuildInjectionRequest::test_signed_data_is_valid_base64url",
    "TestAuthorizeInjection::test_authorize_injection_succeeds_for_valid_text",
    "TestAuthorizeInjection::test_authorize_injection_succeeds_for_empty_text",
    "TestAuthorizeInjection::test_authorize_injection_succeeds_for_unicode",
    "TestAuthorizeInjection::test_authorize_injection_raises_before_bootstrap",
    "TestVerifyServer::test_valid_request_passes_server_verification",
    "TestVerifyServer::test_multiple_sequential_requests_pass",
    "TestVerifyServer::test_tampered_body_hash_is_rejected",
    "TestVerifyServer::test_wrong_pair_id_is_rejected",
    "TestVerifyServer::test_missing_tsk_key_is_rejected",
    "TestVerifyServer::test_truncated_signature_is_rejected",
    "TestFullE2EFlow::test_full_flow_two_agents_cross_verify",
    "TestFullE2EFlow::test_full_flow_high_frequency",
    "TestLifecycleAuth::test_bind_identity_no_auth_is_rejected",
    "TestLifecycleAuth::test_bind_identity_wrong_token_is_rejected",
    "TestLifecycleAuth::test_tsk_keys_patch_no_auth_is_rejected",
    "TestLifecycleAuth::test_tsk_keys_patch_wrong_token_is_rejected",
    "TestLifecycleAuth::test_bpc_pairs_patch_no_auth_is_rejected",
    "TestLifecycleAuth::test_bpc_pairs_patch_wrong_token_is_rejected",
    "TestLifecycleAuth::test_all_lifecycle_endpoints_reject_empty_bearer",
    "TestLifecycleAuth::test_all_lifecycle_endpoints_reject_malformed_auth_header",
    "TestSignedLifecycleAuth::test_signed_proof_is_body_bound_and_single_use",
    "TestSignedLifecycleAuth::test_signed_agent_cannot_provision_for_another_identity",
    "TestSignedLifecycleAuth::test_recovery_requires_operator_authorization_too",
    "TestLiveBpcLockoutBoundary::test_automatic_quarantine_cannot_become_shadow_authorization",
    "TestLiveTskRotation::test_rotation_survives_new_client_instance",
)
ALLOWED_SKIPS = {
    **{
        f"tests/test_e2e_ultra_gate.py::{test}": _ULTRA_REASON
        for test in _E2E_ULTRA_TESTS
    },
    "tests/test_identity_gate.py::TestKeyRecovery::test_recovery_pub_write_read": _ULTRA_REASON,
    "tests/test_enterprise/test_runtime_ownership.py::test_permissive_lock_directory_is_rejected": "Skipped: POSIX ownership/mode semantics",
    "tests/test_enterprise/test_runtime_ownership.py::test_wrong_owner_lock_directory_is_rejected": "Skipped: POSIX ownership semantics",
    "tests/test_enterprise/test_runtime_ownership.py::test_precreated_symlink_lock_file_is_rejected": "Skipped: POSIX no-follow file-symlink semantics",
    "tests/test_enterprise/test_runtime_ownership.py::test_replaced_lock_file_during_binding_is_rejected": "Skipped: Windows denies unlink of locked file",
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TRUSTED_CONFTEST_SHA256 = "4455e076e35ccf23bc9658ef7d10b3700d421f7de98b86d59306ee4fa1e34f5a"
EXPECTED_COLLECTION_COUNT = 1_751
EXPECTED_COLLECTION_SHA256 = "d2517b086dc44aa2e6e6f5ac6fe7903a5520969e168a4a30598502d74212c3fd"


def _verify_record_file(dist: Any, package_file: Any) -> Path:
    if package_file.hash is None:
        raise RuntimeError(f"pytest RECORD entry lacks a hash: {package_file}")
    path = Path(dist.locate_file(package_file)).resolve()
    digest = hashlib.new(package_file.hash.mode, path.read_bytes()).digest()
    actual_digest = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if actual_digest != package_file.hash.value:
        raise RuntimeError(f"pytest package hash does not match RECORD: {package_file}")
    return path


def _load_trusted_pytest() -> Any:
    """Verify pytest's installed bytes before importing that exact package."""
    dist = distribution("pytest")
    files = dist.files or []
    package_file = next(
        (item for item in files if item.as_posix() == "pytest/__init__.py"),
        None,
    )
    if package_file is None:
        raise RuntimeError("installed pytest distribution lacks a RECORD-bound package")
    python_files = [
        item
        for item in files
        if item.suffix == ".py"
        and item.parts
        and item.parts[0] in {"pytest", "_pytest"}
    ]
    if not python_files:
        raise RuntimeError("installed pytest distribution has no RECORD-bound Python files")
    verified = {item.as_posix(): _verify_record_file(dist, item) for item in python_files}
    expected_path = verified.get("pytest/__init__.py")
    if expected_path is None:
        raise RuntimeError("pytest/__init__.py was not included in the verified closure")
    spec = importlib.util.spec_from_file_location(
        "pytest",
        expected_path,
        submodule_search_locations=[str(expected_path.parent)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not construct trusted pytest import specification")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pytest"] = module
    spec.loader.exec_module(module)
    if Path(module.__file__ or "").resolve() != expected_path:
        raise RuntimeError("trusted pytest import resolved to an unexpected origin")
    return module


pytest = _load_trusted_pytest()


def _verify_repository_pytest_inputs() -> None:
    conftests = sorted(
        path.resolve()
        for path in REPOSITORY_ROOT.rglob("conftest.py")
        if ".git" not in path.parts
    )
    expected = (REPOSITORY_ROOT / "conftest.py").resolve()
    if conftests != [expected]:
        raise RuntimeError(f"unexpected pytest conftest set: {conftests}")
    actual = hashlib.sha256(expected.read_bytes()).hexdigest()
    if actual != TRUSTED_CONFTEST_SHA256:
        raise RuntimeError("repository conftest.py does not match its trusted digest")

@dataclass
class StructuredResults:
    passed: int = 0
    failed: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    collected: list[str] = field(default_factory=list)

    def pytest_collection_finish(self, session: Any) -> None:
        self.collected = sorted(
            str(item.nodeid).replace("\\", "/") for item in session.items
        )

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
    return ALLOWED_SKIPS.get(nodeid.replace("\\", "/")) == reason


def main() -> int:
    _verify_repository_pytest_inputs()
    results = StructuredResults()
    exit_code = pytest.main(
        [
            "-q",
            "--tb=short",
            "-rs",
            "-c",
            os.devnull,
            "--rootdir",
            str(REPOSITORY_ROOT),
            "--confcutdir",
            str(REPOSITORY_ROOT),
            str(REPOSITORY_ROOT / "tests"),
        ],
        plugins=[results],
    )
    collection_digest = hashlib.sha256(
        "\n".join(results.collected).encode("utf-8")
    ).hexdigest()
    payload = {
        "failed": results.failed,
        "passed": results.passed,
        "schema": "selfconnect.ci-pytest-result.v1",
        "collection_count": len(results.collected),
        "collection_sha256": collection_digest,
        "skipped": [
            {"nodeid": nodeid, "reason": reason}
            for nodeid, reason in results.skipped
        ],
    }
    print("SELFCONNECT_CI_RESULT=" + json.dumps(payload, sort_keys=True))

    if exit_code != pytest.ExitCode.OK or results.failed:
        print(f"FAIL: pytest exited with status {int(exit_code)}")
        return 1
    if (
        len(results.collected) != EXPECTED_COLLECTION_COUNT
        or collection_digest != EXPECTED_COLLECTION_SHA256
    ):
        print(
            "FAIL: collected test identity differs from the reviewed set: "
            f"count={len(results.collected)} sha256={collection_digest}"
        )
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
    observed_skips = dict(results.skipped)
    if observed_skips != ALLOWED_SKIPS or len(results.skipped) != len(ALLOWED_SKIPS):
        print("FAIL: exact reviewed skip set was not observed")
        missing = sorted(set(ALLOWED_SKIPS.items()) - set(results.skipped))
        if missing:
            print("Missing: " + json.dumps(missing))
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
