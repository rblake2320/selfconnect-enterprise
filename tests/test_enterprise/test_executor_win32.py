"""tests/test_enterprise/test_executor_win32.py — Unit tests for Win32Executor.

All Win32/UIA calls are mocked — no live desktop required.
AgentLedger and PolicyEnforcer are replaced with MagicMock to isolate lifecycle.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from unittest.mock import MagicMock, patch, call

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.executor_win32 import (
    PERMITTED_ACTIONS,
    ExecutorActionRequest,
    ExecutorActionResult,
    Win32Executor,
)
from enterprise.labels import Classification
from enterprise.policy import PolicyDecision
from enterprise.target_registry import (
    GFE_FILE_WORKSPACE,
    GFE_TERMINAL_POWERSHELL,
    TargetAccessDeniedError,
    TargetNotFoundError,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

AGENT_A   = "SC-AAAA0001"
FAKE_HWND = 0xABC01234

_FAKE_ENTRY = {
    "seq":       1,
    "agent_id":  AGENT_A,
    "action":    "executor.read_window_text",
    "result":    "SUCCESS",
    "ts":        1000.0,
    "prev_hash": "0" * 64,
}


def _fake_entry_hash() -> str:
    canonical = json.dumps(_FAKE_ENTRY, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _allow_decision(action: str = "read_window_text") -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        reason="permitted",
        approval_mode="autonomous",
        agent_id=AGENT_A,
        action=action,
    )


def _deny_decision(reason: str = "denied by policy", action: str = "read_window_text") -> PolicyDecision:
    return PolicyDecision(
        allowed=False,
        reason=reason,
        approval_mode="denied",
        agent_id=AGENT_A,
        action=action,
    )


def _make_profile(
    allowed_paths: frozenset[str] = frozenset({"C:\\workspace"}),
    allowed_script_hashes: frozenset[str] = frozenset({"abc123"}),
) -> ClassifiedModeProfile:
    return ClassifiedModeProfile(
        max_classification=Classification.SECRET,
        allowed_paths=allowed_paths,
        allowed_script_hashes=allowed_script_hashes,
    )


def _make_mock_ledger() -> MagicMock:
    mock = MagicMock()
    mock.log.return_value = dict(_FAKE_ENTRY)
    return mock


def _make_mock_policy(decision: PolicyDecision | None = None) -> MagicMock:
    mock = MagicMock()
    mock.check.return_value = decision or _allow_decision()
    return mock


def _make_mock_registry(hwnd: int = FAKE_HWND) -> MagicMock:
    mock = MagicMock()
    mock.resolve_to_hwnd.return_value = hwnd
    return mock


def _make_executor(
    profile:  ClassifiedModeProfile | None = None,
    ledger:   MagicMock | None = None,
    policy:   MagicMock | None = None,
    registry: MagicMock | None = None,
) -> Win32Executor:
    return Win32Executor(
        profile         = profile  or _make_profile(),
        ledger          = ledger   or _make_mock_ledger(),
        policy          = policy   or _make_mock_policy(),
        target_registry = registry or _make_mock_registry(),
    )


def _make_request(
    action_type: str = "read_window_text",
    target:      str = GFE_TERMINAL_POWERSHELL,
    **overrides,
) -> ExecutorActionRequest:
    defaults = dict(
        request_id        = str(uuid.uuid4()),
        action_type       = action_type,
        target_logical_id = target,
        parameters        = {},
        proposed_by       = AGENT_A,
        classification    = Classification.UNCLASSIFIED,
        timestamp         = time.time(),
    )
    defaults.update(overrides)
    return ExecutorActionRequest(**defaults)


# ── PERMITTED_ACTIONS constant ─────────────────────────────────────────────────

class TestPermittedActions:
    def test_all_eleven_strings_present(self):
        expected = {
            "read_window_text", "read_named_element", "focus_window",
            "click_named_element", "set_text", "type_string",
            "write_file_allowed_path", "read_file_allowed_path",
            "run_signed_script", "capture_window_screenshot", "list_open_windows",
        }
        assert PERMITTED_ACTIONS == expected

    def test_is_frozenset(self):
        assert isinstance(PERMITTED_ACTIONS, frozenset)


# ── is_action_allowed ─────────────────────────────────────────────────────────

class TestIsActionAllowed:
    def test_all_permitted_return_true(self):
        e = _make_executor()
        for action in PERMITTED_ACTIONS:
            assert e.is_action_allowed(action) is True, f"{action} should be allowed"

    def test_unknown_returns_false(self):
        e = _make_executor()
        assert e.is_action_allowed("execute_shell") is False
        assert e.is_action_allowed("") is False
        assert e.is_action_allowed("propose_action") is False


# ── Step 1: unknown action_type ───────────────────────────────────────────────

class TestStep1UnknownAction:
    def test_unknown_action_returns_failed_result(self):
        ledger = _make_mock_ledger()
        e = _make_executor(ledger=ledger)
        result = e.execute(_make_request(action_type="not_a_real_action"))
        assert result.success is False
        assert result.error == "action_type not in permitted set"

    def test_unknown_action_no_ledger_entry(self):
        ledger = _make_mock_ledger()
        e = _make_executor(ledger=ledger)
        e.execute(_make_request(action_type="not_a_real_action"))
        ledger.log.assert_not_called()

    def test_unknown_action_ledger_hash_empty(self):
        e = _make_executor()
        result = e.execute(_make_request(action_type="inject_sql"))
        assert result.ledger_entry_hash == ""


# ── Step 2: target resolution failures ───────────────────────────────────────

class TestStep2TargetFailures:
    def test_unknown_target_returns_failed_result(self):
        registry = _make_mock_registry()
        registry.resolve_to_hwnd.side_effect = TargetNotFoundError("no.such.target")
        e = _make_executor(registry=registry)
        result = e.execute(_make_request())
        assert result.success is False
        assert "no.such.target" in result.error

    def test_unknown_target_writes_ledger_entry(self):
        ledger   = _make_mock_ledger()
        registry = _make_mock_registry()
        registry.resolve_to_hwnd.side_effect = TargetNotFoundError("no.such.target")
        e = _make_executor(ledger=ledger, registry=registry)
        result = e.execute(_make_request())
        assert ledger.log.call_count == 1
        assert result.ledger_entry_hash != ""

    def test_access_denied_target_returns_failed_result(self):
        registry = _make_mock_registry()
        registry.resolve_to_hwnd.side_effect = TargetAccessDeniedError(
            GFE_TERMINAL_POWERSHELL, "executor"
        )
        e = _make_executor(registry=registry)
        result = e.execute(_make_request())
        assert result.success is False
        assert result.ledger_entry_hash != ""

    def test_file_path_not_in_allowed_paths_denied(self):
        profile = _make_profile(allowed_paths=frozenset({"C:\\safe"}))
        e = _make_executor(profile=profile)
        req = _make_request(
            action_type="write_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={"path": "C:\\evil\\payload.txt", "content": "x"},
        )
        result = e.execute(req)
        assert result.success is False
        assert "not under any profile allowed_paths" in result.error
        assert result.ledger_entry_hash != ""

    def test_empty_allowed_paths_denies_all_file_ops(self):
        profile = _make_profile(allowed_paths=frozenset())
        e = _make_executor(profile=profile)
        req = _make_request(
            action_type="read_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={"path": "C:\\workspace\\file.txt"},
        )
        result = e.execute(req)
        assert result.success is False
        assert "fail-closed" in result.error

    def test_script_hash_not_allowed_denied(self):
        profile = _make_profile(allowed_script_hashes=frozenset({"goodhash"}))
        e = _make_executor(profile=profile)
        req = _make_request(
            action_type="run_signed_script",
            target=GFE_FILE_WORKSPACE,
            parameters={"script_hash": "badhash", "script_path": "x.ps1"},
        )
        result = e.execute(req)
        assert result.success is False
        assert "badhash" in result.error


# ── Step 3: policy deny ────────────────────────────────────────────────────────

class TestStep3PolicyDeny:
    def test_policy_deny_returns_failed_result(self):
        policy = _make_mock_policy(_deny_decision("action blocked by operator"))
        e = _make_executor(policy=policy)
        result = e.execute(_make_request())
        assert result.success is False
        assert "action blocked by operator" in result.error

    def test_policy_deny_writes_ledger_entry(self):
        ledger = _make_mock_ledger()
        policy = _make_mock_policy(_deny_decision())
        e = _make_executor(ledger=ledger, policy=policy)
        result = e.execute(_make_request())
        assert ledger.log.call_count == 1
        assert result.ledger_entry_hash != ""

    def test_policy_check_called_with_executor_mode(self):
        policy = _make_mock_policy()
        e = _make_executor(policy=policy)
        with patch.object(e, "_read_window_text", return_value="text"):
            e.execute(_make_request(action_type="read_window_text"))
        _, kwargs = policy.check.call_args
        assert kwargs.get("participant_mode") == "executor"


# ── Step 4: precommit ledger failure ─────────────────────────────────────────

class TestStep4PrecommitFailure:
    def test_precommit_failure_returns_error(self):
        ledger = _make_mock_ledger()
        ledger.log.side_effect = RuntimeError("disk full")
        e = _make_executor(ledger=ledger)
        result = e.execute(_make_request())
        assert result.success is False
        assert "ledger precommit failure" in result.error

    def test_precommit_failure_execution_not_reached(self):
        ledger = _make_mock_ledger()
        ledger.log.side_effect = RuntimeError("disk full")
        e = _make_executor(ledger=ledger)
        with patch.object(e, "_read_window_text", return_value="x") as mock_prim:
            e.execute(_make_request(action_type="read_window_text"))
            mock_prim.assert_not_called()

    def test_precommit_failure_no_postcommit_hash(self):
        ledger = _make_mock_ledger()
        ledger.log.side_effect = RuntimeError("disk full")
        e = _make_executor(ledger=ledger)
        result = e.execute(_make_request())
        assert result.ledger_entry_hash == ""


# ── Steps 5–7: successful execution of all 11 primitives ─────────────────────

class TestPrimitiveExecution:
    def _run(self, action: str, params: dict | None = None, **executor_kwargs) -> ExecutorActionResult:
        e = _make_executor(**executor_kwargs)
        req = _make_request(
            action_type=action,
            target=GFE_FILE_WORKSPACE if "file" in action or "script" in action else GFE_TERMINAL_POWERSHELL,
            parameters=params or {},
        )
        method = f"_{action}"
        with patch.object(e, method, return_value=f"{action}_output") as mock_m:
            result = e.execute(req)
        assert mock_m.call_count == 1, f"{method} should have been called once"
        return result

    def _assert_success(self, result: ExecutorActionResult, action: str) -> None:
        assert result.success is True, f"{action}: success should be True"
        assert result.output == f"{action}_output", f"{action}: output mismatch"
        assert result.error == "", f"{action}: error should be empty"
        assert result.ledger_entry_hash != "", f"{action}: ledger_entry_hash must be populated"

    def test_read_window_text(self):
        self._assert_success(self._run("read_window_text"), "read_window_text")

    def test_read_named_element(self):
        self._assert_success(self._run("read_named_element", {"element_name": "Submit"}), "read_named_element")

    def test_focus_window(self):
        self._assert_success(self._run("focus_window"), "focus_window")

    def test_click_named_element(self):
        self._assert_success(self._run("click_named_element", {"element_name": "OK"}), "click_named_element")

    def test_set_text(self):
        self._assert_success(self._run("set_text", {"text": "hello"}), "set_text")

    def test_type_string(self):
        self._assert_success(self._run("type_string", {"text": "hello"}), "type_string")

    def test_write_file_allowed_path(self):
        profile = _make_profile(allowed_paths=frozenset({"C:\\workspace"}))
        params  = {"path": "C:\\workspace\\out.txt", "content": "data"}
        self._assert_success(self._run("write_file_allowed_path", params, profile=profile), "write_file_allowed_path")

    def test_read_file_allowed_path(self):
        profile = _make_profile(allowed_paths=frozenset({"C:\\workspace"}))
        params  = {"path": "C:\\workspace\\in.txt"}
        self._assert_success(self._run("read_file_allowed_path", params, profile=profile), "read_file_allowed_path")

    def test_run_signed_script(self):
        profile = _make_profile(allowed_script_hashes=frozenset({"abc123"}))
        params  = {"script_hash": "abc123", "script_path": "run.ps1"}
        self._assert_success(self._run("run_signed_script", params, profile=profile), "run_signed_script")

    def test_capture_window_screenshot(self):
        self._assert_success(self._run("capture_window_screenshot"), "capture_window_screenshot")

    def test_list_open_windows(self):
        self._assert_success(self._run("list_open_windows"), "list_open_windows")


# ── Postcommit always written ─────────────────────────────────────────────────

class TestPostcommitAlwaysWritten:
    def test_execution_error_still_writes_postcommit(self):
        ledger = _make_mock_ledger()
        e = _make_executor(ledger=ledger)
        with patch.object(e, "_read_window_text", side_effect=RuntimeError("UIA failed")):
            result = e.execute(_make_request(action_type="read_window_text"))
        assert result.success is False
        assert "UIA failed" in result.error
        # precommit + postcommit both written
        assert ledger.log.call_count == 2
        assert result.ledger_entry_hash != ""

    def test_success_writes_precommit_and_postcommit(self):
        ledger = _make_mock_ledger()
        e = _make_executor(ledger=ledger)
        with patch.object(e, "_focus_window", return_value="focused"):
            e.execute(_make_request(action_type="focus_window"))
        assert ledger.log.call_count == 2

    def test_postcommit_hash_is_sha256_of_entry(self):
        ledger = _make_mock_ledger()
        e = _make_executor(ledger=ledger)
        with patch.object(e, "_focus_window", return_value="focused"):
            result = e.execute(_make_request(action_type="focus_window"))
        # The hash should be the SHA-256 of the fake entry (without sig)
        assert result.ledger_entry_hash == _fake_entry_hash()
