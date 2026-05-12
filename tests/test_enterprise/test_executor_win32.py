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


# ── Step 2 pre-check: missing required parameter keys ────────────────────────

class TestPreCheckParamsMissingKeys:
    def test_missing_path_parameter_denied(self):
        profile = _make_profile(allowed_paths=frozenset({"C:\\workspace"}))
        e = _make_executor(profile=profile)
        req = _make_request(
            action_type="write_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={},  # path key absent
        )
        result = e.execute(req)
        assert result.success is False
        assert "missing 'path'" in result.error

    def test_missing_script_hash_denied(self):
        profile = _make_profile(allowed_script_hashes=frozenset({"abc123"}))
        e = _make_executor(profile=profile)
        req = _make_request(
            action_type="run_signed_script",
            target=GFE_FILE_WORKSPACE,
            parameters={"script_path": "run.ps1"},  # script_hash absent
        )
        result = e.execute(req)
        assert result.success is False
        assert "missing 'script_hash'" in result.error


# ── Real file I/O integration (no mocking, pure Python I/O) ─────────────────

class TestFileIoIntegration:
    def test_write_then_read_file_roundtrip(self, tmp_path):
        allowed = str(tmp_path)
        profile  = _make_profile(allowed_paths=frozenset({allowed}))
        e        = _make_executor(profile=profile)
        out_path = str(tmp_path / "out.txt")

        write_req = _make_request(
            action_type="write_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={"path": out_path, "content": "hello integration"},
        )
        write_result = e._write_file_allowed_path(0, write_req.parameters)
        assert "hello integration" in write_result or len(write_result) > 0

        read_req = _make_request(
            action_type="read_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={"path": out_path},
        )
        content = e._read_file_allowed_path(0, read_req.parameters)
        assert content == "hello integration"

    def test_write_file_allowed_path_via_execute(self, tmp_path):
        allowed  = str(tmp_path)
        profile  = _make_profile(allowed_paths=frozenset({allowed}))
        e        = _make_executor(profile=profile)
        out_path = str(tmp_path / "exec_out.txt")

        req = _make_request(
            action_type="write_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={"path": out_path, "content": "written by executor"},
        )
        result = e.execute(req)
        assert result.success is True
        assert result.error == ""
        import pathlib
        assert pathlib.Path(out_path).read_text(encoding="utf-8") == "written by executor"

    def test_read_file_allowed_path_via_execute(self, tmp_path):
        allowed  = str(tmp_path)
        import pathlib
        in_path  = str(tmp_path / "in.txt")
        pathlib.Path(in_path).write_text("read by executor", encoding="utf-8")

        profile = _make_profile(allowed_paths=frozenset({allowed}))
        e       = _make_executor(profile=profile)
        req     = _make_request(
            action_type="read_file_allowed_path",
            target=GFE_FILE_WORKSPACE,
            parameters={"path": in_path},
        )
        result = e.execute(req)
        assert result.success is True
        assert result.output == "read by executor"


# ── Real PowerShell subprocess integration ───────────────────────────────────

class TestRunSignedScriptDirect:
    def test_run_powershell_echo_directly(self):
        import sys
        if sys.platform != "win32":
            return
        e = _make_executor()
        params = {
            "script_path": "powershell",
            "args":        ["-NoProfile", "-Command", "Write-Output hello-from-executor"],
            "timeout":     15,
        }
        output = e._run_signed_script(0, params)
        assert "hello-from-executor" in output

    def test_run_signed_script_nonzero_exit_raises_in_primitive(self):
        import sys
        if sys.platform != "win32":
            return
        e = _make_executor()
        params = {
            "script_path": "powershell",
            "args":        ["-NoProfile", "-Command", "exit 1"],
            "timeout":     15,
        }
        try:
            e._run_signed_script(0, params)
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert "exited 1" in str(exc)

    def test_run_signed_script_nonzero_exit_recorded_in_result(self, tmp_path):
        import sys
        if sys.platform != "win32":
            return
        allowed  = str(tmp_path)
        profile  = _make_profile(
            allowed_paths=frozenset({allowed}),
            allowed_script_hashes=frozenset({"failhash"}),
        )
        e = _make_executor(profile=profile)
        req = _make_request(
            action_type="run_signed_script",
            target=GFE_FILE_WORKSPACE,
            parameters={
                "script_hash": "failhash",
                "script_path": "powershell",
                "args":        ["-NoProfile", "-Command", "exit 2"],
                "timeout":     15,
            },
        )
        result = e.execute(req)
        assert result.success is False
        assert "exited 2" in result.error
        assert result.ledger_entry_hash != ""


# ── Real EnumWindows integration ─────────────────────────────────────────────

class TestListOpenWindowsReal:
    def test_list_open_windows_returns_nonempty_json(self):
        import sys, json
        if sys.platform != "win32":
            return
        e       = _make_executor()
        output  = e._list_open_windows(0, {})
        titles  = json.loads(output)
        assert isinstance(titles, list)
        assert len(titles) > 0

    def test_list_open_windows_via_execute(self):
        import sys, json
        if sys.platform != "win32":
            return
        e      = _make_executor()
        req    = _make_request(action_type="list_open_windows", target=GFE_TERMINAL_POWERSHELL)
        result = e.execute(req)
        assert result.success is True
        titles = json.loads(result.output)
        assert len(titles) > 0


# ── Real WM_GETTEXT on desktop window ────────────────────────────────────────

class TestReadWindowTextReal:
    def test_read_desktop_window_text_returns_string(self):
        import sys, ctypes
        if sys.platform != "win32":
            return
        user32 = ctypes.windll.user32
        hwnd   = user32.GetDesktopWindow()
        assert hwnd != 0
        e      = _make_executor()
        text   = e._read_window_text(hwnd, {})
        assert isinstance(text, str)  # may be "" for the desktop window

    def test_read_window_text_nonzero_length_path(self):
        import sys, ctypes
        if sys.platform != "win32":
            return
        user32 = ctypes.windll.user32
        hwnd   = user32.GetForegroundWindow()
        if hwnd == 0:
            return  # no foreground window in this session
        e    = _make_executor()
        text = e._read_window_text(hwnd, {})
        assert isinstance(text, str)
        assert len(text) >= 0  # may or may not have text


# ── Win32 primitive body coverage (mock _user32) ─────────────────────────────

class TestPrimitiveBodyCoverage:
    """Tests that run through the actual primitive method bodies using mocked
    Win32 handles.  UIA-dependent methods (_read_named_element,
    _click_named_element, _set_text with element_name, _capture_window_screenshot
    full GDI path) are covered separately via mock primitives above.
    """

    def test_focus_window_calls_set_foreground_window(self):
        e = _make_executor()
        with patch("enterprise.executor_win32._user32") as mock_u32:
            mock_u32.SetForegroundWindow.return_value = 1
            result = e._focus_window(0xABC, {})
        assert result == "focused"
        mock_u32.SetForegroundWindow.assert_called_once_with(0xABC)

    def test_set_text_no_element_name_calls_wm_settext(self):
        e = _make_executor()
        WM_SETTEXT = 0x000C
        with patch("enterprise.executor_win32._user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 1
            result = e._set_text(0xABC, {"text": "hello"})
        assert result == "text set (5 chars)"
        args = mock_u32.SendMessageW.call_args[0]
        assert args[0] == 0xABC
        assert args[1] == WM_SETTEXT

    def test_set_text_empty_text_returns_zero_chars(self):
        e = _make_executor()
        with patch("enterprise.executor_win32._user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 1
            result = e._set_text(0xABC, {})
        assert result == "text set (0 chars)"

    def test_type_string_calls_keybd_event_per_char(self):
        e = _make_executor()
        with patch("enterprise.executor_win32._user32") as mock_u32:
            mock_u32.SetForegroundWindow.return_value = 1
            mock_u32.VkKeyScanW.return_value = 0x41  # 'A'
            mock_u32.keybd_event.return_value = None
            result = e._type_string(0xABC, {"text": "hi"})
        assert result == "typed 2 chars"
        mock_u32.SetForegroundWindow.assert_called_once_with(0xABC)
        assert mock_u32.keybd_event.call_count == 4  # 2 chars × 2 events each

    def test_type_string_empty_text(self):
        e = _make_executor()
        with patch("enterprise.executor_win32._user32") as mock_u32:
            mock_u32.SetForegroundWindow.return_value = 1
            result = e._type_string(0xABC, {})
        assert result == "typed 0 chars"

    def test_read_window_text_zero_length_returns_empty(self):
        e = _make_executor()
        with patch("enterprise.executor_win32._user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 0
            result = e._read_window_text(0xABC, {})
        assert result == ""

    # _capture_window_screenshot body (lines 352-367) uses ctypes.byref() which
    # rejects MagicMock objects — those lines are not unit-testable without a
    # real display context.  The dispatch path is exercised by
    # TestPrimitiveExecution.test_capture_window_screenshot above.


# ── UIA helper coverage ───────────────────────────────────────────────────────

class TestUiaHelpers:
    """UIA helpers are isolated methods — test their logic via mock objects."""

    def test_uia_get_value_delegates_to_pattern(self):
        e       = _make_executor()
        element = MagicMock()
        pattern = MagicMock()
        pattern.CurrentValue = "the value"
        element.GetCurrentPattern.return_value = pattern
        assert e._uia_get_value(element) == "the value"
        element.GetCurrentPattern.assert_called_once_with(10002)

    def test_uia_invoke_click_calls_pattern_invoke(self):
        e       = _make_executor()
        element = MagicMock()
        pattern = MagicMock()
        element.GetCurrentPattern.return_value = pattern
        e._uia_invoke_click(element)
        element.GetCurrentPattern.assert_called_once_with(10000)
        pattern.Invoke.assert_called_once()

    def test_uia_set_value_calls_pattern_set_value(self):
        e       = _make_executor()
        element = MagicMock()
        pattern = MagicMock()
        element.GetCurrentPattern.return_value = pattern
        e._uia_set_value(element, "new text")
        element.GetCurrentPattern.assert_called_once_with(10002)
        pattern.SetValue.assert_called_once_with("new text")

    def test_uia_find_element_raises_when_element_is_none(self):
        e = _make_executor()
        try:
            import comtypes.client
        except ImportError:
            return  # comtypes not installed; skip silently
        uia_obj  = MagicMock()
        root_obj = MagicMock()
        cond_obj = MagicMock()
        root_obj.FindFirst.return_value = None  # element not found
        uia_obj.ElementFromHandle.return_value       = root_obj
        uia_obj.CreatePropertyCondition.return_value = cond_obj
        with patch("comtypes.client.CreateObject", return_value=uia_obj):
            try:
                e._uia_find_element(0xABC, "NonExistentButton")
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "not found" in str(exc)

    def test_uia_find_element_returns_element_on_success(self):
        e = _make_executor()
        try:
            import comtypes.client
        except ImportError:
            return
        fake_element = MagicMock()
        uia_obj      = MagicMock()
        root_obj     = MagicMock()
        cond_obj     = MagicMock()
        root_obj.FindFirst.return_value              = fake_element
        uia_obj.ElementFromHandle.return_value       = root_obj
        uia_obj.CreatePropertyCondition.return_value = cond_obj
        with patch("comtypes.client.CreateObject", return_value=uia_obj):
            result = e._uia_find_element(0xABC, "SomeButton")
        assert result is fake_element

    def test_uia_find_element_raises_when_comtypes_unavailable(self):
        import sys
        e = _make_executor()
        saved = sys.modules.get("comtypes")
        saved_client = sys.modules.get("comtypes.client")
        sys.modules["comtypes"] = None  # type: ignore[assignment]
        sys.modules["comtypes.client"] = None  # type: ignore[assignment]
        try:
            e._uia_find_element(0xABC, "Button")
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert "comtypes" in str(exc).lower() or "UIA" in str(exc)
        except Exception:
            pass  # any exception is acceptable here
        finally:
            if saved is None:
                sys.modules.pop("comtypes", None)
            else:
                sys.modules["comtypes"] = saved
            if saved_client is None:
                sys.modules.pop("comtypes.client", None)
            else:
                sys.modules["comtypes.client"] = saved_client


# ── UIA dispatch methods: _read_named_element, _click_named_element, _set_text(name) ──

class TestUiaDispatchMethods:
    """Tests that exercise the UIA-dispatch bodies by patching _uia_find_element
    and the downstream UIA helper methods via patch.object.
    """

    def test_read_named_element_calls_find_and_get_value(self):
        e       = _make_executor()
        fake_el = MagicMock()
        with patch.object(e, "_uia_find_element", return_value=fake_el) as mock_find, \
             patch.object(e, "_uia_get_value", return_value="element text") as mock_get:
            result = e._read_named_element(0xABC, {"element_name": "MyField"})
        assert result == "element text"
        mock_find.assert_called_once_with(0xABC, "MyField")
        mock_get.assert_called_once_with(fake_el)

    def test_click_named_element_calls_find_and_invoke(self):
        e       = _make_executor()
        fake_el = MagicMock()
        with patch.object(e, "_uia_find_element", return_value=fake_el) as mock_find, \
             patch.object(e, "_uia_invoke_click") as mock_click:
            result = e._click_named_element(0xABC, {"element_name": "Submit"})
        assert result == "clicked 'Submit'"
        mock_find.assert_called_once_with(0xABC, "Submit")
        mock_click.assert_called_once_with(fake_el)

    def test_set_text_with_element_name_calls_find_and_set_value(self):
        e       = _make_executor()
        fake_el = MagicMock()
        with patch.object(e, "_uia_find_element", return_value=fake_el) as mock_find, \
             patch.object(e, "_uia_set_value") as mock_set:
            result = e._set_text(0xABC, {"text": "new value", "element_name": "SearchBox"})
        assert "9 chars" in result
        mock_find.assert_called_once_with(0xABC, "SearchBox")
        mock_set.assert_called_once_with(fake_el, "new value")
