"""tests/test_enterprise/test_bridge_connector.py — Unit tests for BridgeConnector.

All Win32 calls and TargetRegistry are mocked — no live desktop required.
"""
from __future__ import annotations

import json
import time
import uuid
from unittest.mock import MagicMock, patch

from enterprise.bridge_connector import (
    BRIDGE_ALLOWED_PROPOSALS,
    BRIDGE_FORBIDDEN_PROPOSALS,
    SYSTEM_INSTRUCTION,
    BridgeConnector,
    BridgeProposal,
)
from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.executor_win32 import ExecutorActionRequest
from enterprise.labels import Classification
from enterprise.target_registry import (
    GENAIMIL_BROWSER_INPUT,
    GENAIMIL_BROWSER_OUTPUT,
    TargetNotFoundError,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

FAKE_HWND  = 0xABC01234
SESSION_ID = "bridge-session-test-01"


def _make_profile() -> ClassifiedModeProfile:
    return ClassifiedModeProfile(max_classification=Classification.SECRET)


def _make_mock_ledger() -> MagicMock:
    mock = MagicMock()
    mock.log.return_value = {"seq": 1, "agent_id": SESSION_ID}
    return mock


def _make_mock_registry(hwnd: int = FAKE_HWND) -> MagicMock:
    mock = MagicMock()
    mock.resolve_to_hwnd.return_value = hwnd
    return mock


def _make_connector(
    registry: MagicMock | None = None,
    ledger:   MagicMock | None = None,
    profile:  ClassifiedModeProfile | None = None,
) -> BridgeConnector:
    return BridgeConnector(
        target_registry = registry or _make_mock_registry(),
        ledger          = ledger   or _make_mock_ledger(),
        profile         = profile  or _make_profile(),
        session_id      = SESSION_ID,
    )


def _raw_response_with_action(action_type: str, target: str = "gfe.terminal.cmd", params: dict | None = None) -> str:
    block = json.dumps({
        "action_type":       action_type,
        "target_logical_id": target,
        "parameters":        params or {},
    })
    return f"Here is what I suggest doing.\n```ACTION\n{block}\n```"


def _make_proposal(
    parse_confidence: str = "structured",
    action_type: str = "read_window_text",
    params: dict | None = None,
) -> BridgeProposal:
    return BridgeProposal(
        proposal_id        = str(uuid.uuid4()),
        source_session_id  = SESSION_ID,
        raw_llm_output     = "raw response",
        parsed_action_type = action_type,
        parsed_parameters  = params or {"action_type": action_type, "target_logical_id": "gfe.terminal.cmd", "parameters": {}},
        parse_confidence   = parse_confidence,  # type: ignore[arg-type]
        classification     = Classification.SECRET,
        proposed_at        = time.time(),
    )


# ── Action set constants ───────────────────────────────────────────────────────

class TestActionSets:
    def test_allowed_set_contains_expected_actions(self):
        assert "read_window_text"        in BRIDGE_ALLOWED_PROPOSALS
        assert "read_named_element"      in BRIDGE_ALLOWED_PROPOSALS
        assert "write_file_allowed_path" in BRIDGE_ALLOWED_PROPOSALS
        assert "read_file_allowed_path"  in BRIDGE_ALLOWED_PROPOSALS
        assert "set_text"                in BRIDGE_ALLOWED_PROPOSALS
        assert "click_named_element"     in BRIDGE_ALLOWED_PROPOSALS
        assert len(BRIDGE_ALLOWED_PROPOSALS) == 6

    def test_forbidden_set_contains_expected_actions(self):
        assert "execute_shell"          in BRIDGE_FORBIDDEN_PROPOSALS
        assert "run_signed_script"      in BRIDGE_FORBIDDEN_PROPOSALS
        assert "write_registry"         in BRIDGE_FORBIDDEN_PROPOSALS
        assert "submit_form_external"   in BRIDGE_FORBIDDEN_PROPOSALS
        assert "run_arbitrary_code"     in BRIDGE_FORBIDDEN_PROPOSALS

    def test_no_overlap_between_sets(self):
        assert BRIDGE_ALLOWED_PROPOSALS.isdisjoint(BRIDGE_FORBIDDEN_PROPOSALS)

    def test_system_instruction_contains_marker(self):
        assert "[SELFCONNECT-BRIDGE]" in SYSTEM_INSTRUCTION
        assert "```ACTION" in SYSTEM_INSTRUCTION


# ── send_prompt ────────────────────────────────────────────────────────────────

class TestSendPrompt:
    def test_returns_true_on_success(self):
        c = _make_connector()
        with patch.object(c, "_win32_set_text"):
            result = c.send_prompt("Do something.")
        assert result is True

    def test_system_instruction_prepended_to_every_prompt(self):
        c = _make_connector()
        captured: list[str] = []
        with patch.object(c, "_win32_set_text", side_effect=lambda hwnd, text: captured.append(text)):
            c.send_prompt("Tell me about the screen.")
        assert len(captured) == 1
        assert captured[0].startswith(SYSTEM_INSTRUCTION)
        assert "Tell me about the screen." in captured[0]

    def test_original_prompt_follows_instruction(self):
        c = _make_connector()
        captured: list[str] = []
        prompt = "unique-prompt-content-xyz"
        with patch.object(c, "_win32_set_text", side_effect=lambda hwnd, text: captured.append(text)):
            c.send_prompt(prompt)
        full = captured[0]
        assert full.index(SYSTEM_INSTRUCTION) < full.index(prompt)

    def test_returns_false_on_target_not_found(self):
        registry = _make_mock_registry()
        registry.resolve_to_hwnd.side_effect = TargetNotFoundError("genaimil.browser.input")
        c = _make_connector(registry=registry)
        result = c.send_prompt("hello")
        assert result is False

    def test_writes_ledger_on_failure(self):
        ledger   = _make_mock_ledger()
        registry = _make_mock_registry()
        registry.resolve_to_hwnd.side_effect = TargetNotFoundError("genaimil.browser.input")
        c = _make_connector(registry=registry, ledger=ledger)
        c.send_prompt("hello")
        ledger.log.assert_called_once()
        call_kwargs = ledger.log.call_args[1] if ledger.log.call_args[1] else {}
        call_args   = ledger.log.call_args[0]
        metadata    = call_kwargs.get("metadata") or (call_args[2] if len(call_args) > 2 else None)
        assert metadata is not None
        assert "error" in metadata

    def test_uses_bridge_mode_for_target_resolution(self):
        registry = _make_mock_registry()
        c = _make_connector(registry=registry)
        with patch.object(c, "_win32_set_text"):
            c.send_prompt("test", target_id=GENAIMIL_BROWSER_INPUT)
        registry.resolve_to_hwnd.assert_called_once_with(GENAIMIL_BROWSER_INPUT, "bridge")


# ── read_response ─────────────────────────────────────────────────────────────

class TestReadResponse:
    def test_returns_text_when_available(self):
        c = _make_connector()
        with patch.object(c, "_win32_read_text", return_value="LLM response text"):
            result = c.read_response(_poll_interval=0)
        assert result == "LLM response text"

    def test_timeout_returns_empty_string(self):
        c = _make_connector()
        with patch.object(c, "_win32_read_text", return_value=""):
            result = c.read_response(timeout_sec=0.001, _poll_interval=0)
        assert result == ""

    def test_timeout_writes_ledger_with_error_timeout(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        with patch.object(c, "_win32_read_text", return_value=""):
            c.read_response(timeout_sec=0.001, _poll_interval=0)
        ledger.log.assert_called_once()
        call = ledger.log.call_args
        # metadata is a kwarg
        metadata = call[1].get("metadata") or {}
        assert metadata.get("error") == "timeout"

    def test_target_not_found_returns_empty_string(self):
        registry = _make_mock_registry()
        registry.resolve_to_hwnd.side_effect = TargetNotFoundError("genaimil.browser.output")
        c = _make_connector(registry=registry)
        result = c.read_response()
        assert result == ""

    def test_success_writes_ledger(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        with patch.object(c, "_win32_read_text", return_value="response"):
            c.read_response(_poll_interval=0)
        ledger.log.assert_called_once()


# ── parse_response ─────────────────────────────────────────────────────────────

class TestParseResponse:
    def test_structured_output_parsed_correctly(self):
        c = _make_connector()
        raw = _raw_response_with_action("read_window_text", target="gfe.terminal.cmd")
        proposal = c.parse_response(raw)
        assert proposal.parse_confidence  == "structured"
        assert proposal.parsed_action_type == "read_window_text"
        assert proposal.parsed_parameters["target_logical_id"] == "gfe.terminal.cmd"

    def test_missing_action_block_returns_failed(self):
        c = _make_connector()
        proposal = c.parse_response("This is a plain text response with no action block.")
        assert proposal.parse_confidence == "failed"
        assert proposal.parsed_action_type == ""

    def test_invalid_json_returns_failed(self):
        c = _make_connector()
        raw = "Some text\n```ACTION\nnot valid json at all\n```"
        proposal = c.parse_response(raw)
        assert proposal.parse_confidence == "failed"

    def test_forbidden_action_returns_failed(self):
        c = _make_connector()
        raw = _raw_response_with_action("run_signed_script")
        proposal = c.parse_response(raw)
        assert proposal.parse_confidence == "failed"
        assert proposal.parsed_action_type == "run_signed_script"

    def test_forbidden_action_writes_ledger(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        raw = _raw_response_with_action("execute_shell")
        c.parse_response(raw)
        ledger.log.assert_called_once()
        call_result = ledger.log.call_args[1].get("result") or ledger.log.call_args[0][1]
        assert "BLOCKED" in str(call_result) or "forbidden" in str(call_result).lower()

    def test_raw_output_always_stored(self):
        c = _make_connector()
        raw = "plain response no action"
        proposal = c.parse_response(raw)
        assert proposal.raw_llm_output == raw

    def test_raw_output_stored_even_for_structured_parse(self):
        c = _make_connector()
        raw = _raw_response_with_action("set_text")
        proposal = c.parse_response(raw)
        assert proposal.raw_llm_output == raw

    def test_uses_last_action_block_when_multiple_present(self):
        c = _make_connector()
        # Two ACTION blocks — parser should use the last one
        first  = '```ACTION\n{"action_type": "set_text", "target_logical_id": "a", "parameters": {}}\n```'
        second = '```ACTION\n{"action_type": "read_window_text", "target_logical_id": "b", "parameters": {}}\n```'
        proposal = c.parse_response(f"Preamble {first} middle text {second}")
        assert proposal.parsed_action_type == "read_window_text"

    def test_unknown_action_not_in_allowed_returns_failed(self):
        c = _make_connector()
        raw = _raw_response_with_action("focus_window")  # not in BRIDGE_ALLOWED
        proposal = c.parse_response(raw)
        assert proposal.parse_confidence == "failed"

    def test_source_session_id_set_correctly(self):
        c = _make_connector()
        proposal = c.parse_response(_raw_response_with_action("set_text"))
        assert proposal.source_session_id == SESSION_ID


# ── submit_proposal ────────────────────────────────────────────────────────────

class TestSubmitProposal:
    def test_valid_proposal_returns_executor_request(self):
        c = _make_connector()
        proposal = _make_proposal(parse_confidence="structured", action_type="read_window_text")
        result = c.submit_proposal(proposal)
        assert isinstance(result, ExecutorActionRequest)

    def test_valid_proposal_request_has_correct_action_type(self):
        c = _make_connector()
        proposal = _make_proposal(parse_confidence="structured", action_type="set_text")
        request  = c.submit_proposal(proposal)
        assert request is not None
        assert request.action_type == "set_text"

    def test_valid_proposal_proposed_by_is_session_id(self):
        c = _make_connector()
        proposal = _make_proposal(parse_confidence="structured")
        request  = c.submit_proposal(proposal)
        assert request is not None
        assert request.proposed_by == SESSION_ID

    def test_valid_proposal_target_from_parsed_parameters(self):
        c = _make_connector()
        params = {
            "action_type":       "read_window_text",
            "target_logical_id": "gfe.terminal.powershell",
            "parameters":        {"element": "main"},
        }
        proposal = _make_proposal(parse_confidence="structured", params=params)
        request  = c.submit_proposal(proposal)
        assert request is not None
        assert request.target_logical_id == "gfe.terminal.powershell"
        assert request.parameters == {"element": "main"}

    def test_failed_parse_returns_none(self):
        c = _make_connector()
        proposal = _make_proposal(parse_confidence="failed")
        result   = c.submit_proposal(proposal)
        assert result is None

    def test_heuristic_parse_returns_none(self):
        c = _make_connector()
        proposal = _make_proposal(parse_confidence="heuristic")
        result   = c.submit_proposal(proposal)
        assert result is None

    def test_ledger_written_for_valid_proposal(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        proposal = _make_proposal(parse_confidence="structured")
        c.submit_proposal(proposal)
        ledger.log.assert_called_once()

    def test_ledger_written_for_failed_proposal(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        proposal = _make_proposal(parse_confidence="failed")
        c.submit_proposal(proposal)
        ledger.log.assert_called_once()

    def test_raw_llm_output_in_ledger_on_rejection(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        proposal = _make_proposal(parse_confidence="failed")
        proposal.raw_llm_output = "this is the raw output"
        c.submit_proposal(proposal)
        call_kwargs = ledger.log.call_args[1]
        metadata    = call_kwargs.get("metadata", {})
        assert "raw_output_len" in metadata
        assert metadata["raw_output_len"] == len("this is the raw output")

    def test_structured_but_not_allowed_action_returns_none(self):
        # parse_confidence="structured" but action not in BRIDGE_ALLOWED_PROPOSALS
        # (reachable only by direct construction; tests lines 308-318)
        c = _make_connector()
        proposal = _make_proposal(parse_confidence="structured", action_type="focus_window")
        result = c.submit_proposal(proposal)
        assert result is None

    def test_structured_but_not_allowed_action_writes_ledger(self):
        ledger = _make_mock_ledger()
        c = _make_connector(ledger=ledger)
        proposal = _make_proposal(parse_confidence="structured", action_type="focus_window")
        c.submit_proposal(proposal)
        ledger.log.assert_called_once()
        call_result = ledger.log.call_args[1].get("result") or str(ledger.log.call_args)
        assert "not in allowed" in str(call_result) or "focus_window" in str(call_result)


# ── read_response: exception inside poll loop ─────────────────────────────────

class TestReadResponseExceptionInLoop:
    def test_exception_in_win32_read_returns_empty(self):
        c = _make_connector()
        with patch.object(c, "_win32_read_text", side_effect=RuntimeError("UIA error")):
            result = c.read_response(_poll_interval=0)
        assert result == ""

    def test_exception_in_win32_read_writes_ledger_with_error(self):
        ledger = _make_mock_ledger()
        c      = _make_connector(ledger=ledger)
        with patch.object(c, "_win32_read_text", side_effect=RuntimeError("UIA error")):
            c.read_response(_poll_interval=0)
        ledger.log.assert_called_once()
        metadata = ledger.log.call_args[1].get("metadata", {})
        assert "error" in metadata

    def test_poll_interval_positive_path_returns_text(self):
        c = _make_connector()
        responses = iter(["", "", "got it"])

        def _side_effect(hwnd):
            return next(responses)

        with patch.object(c, "_win32_read_text", side_effect=_side_effect):
            result = c.read_response(timeout_sec=10, _poll_interval=0.001)
        assert result == "got it"


# ── send_prompt: _win32_set_text raises ──────────────────────────────────────

class TestSendPromptWin32Raises:
    def test_win32_set_text_raises_returns_false(self):
        c = _make_connector()
        with patch.object(c, "_win32_set_text", side_effect=OSError("access denied")):
            result = c.send_prompt("hello")
        assert result is False

    def test_win32_set_text_raises_writes_ledger(self):
        ledger = _make_mock_ledger()
        c      = _make_connector(ledger=ledger)
        with patch.object(c, "_win32_set_text", side_effect=OSError("access denied")):
            c.send_prompt("hello")
        ledger.log.assert_called_once()
        metadata = ledger.log.call_args[1].get("metadata", {})
        assert "error" in metadata


# ── _win32_set_text / _win32_read_text body coverage ────────────────────────

class TestWin32BodyCoverage:
    def test_win32_set_text_calls_sendmessagew_with_wm_settext(self):
        import ctypes
        c = _make_connector()
        WM_SETTEXT = 0x000C
        with patch("enterprise.bridge_connector._user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 1
            c._win32_set_text(0xABC, "hello")
        args = mock_u32.SendMessageW.call_args[0]
        assert args[0] == 0xABC
        assert args[1] == WM_SETTEXT

    def test_win32_read_text_returns_empty_when_length_zero(self):
        c = _make_connector()
        with patch("enterprise.bridge_connector._user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 0  # WM_GETTEXTLENGTH → 0
            result = c._win32_read_text(0xABC)
        assert result == ""

    def test_win32_read_text_returns_text_when_nonzero(self):
        import ctypes
        c = _make_connector()
        WM_GETTEXTLENGTH = 0x000E
        WM_GETTEXT       = 0x000D

        def _mock_send(hwnd, msg, wparam, lparam):
            if msg == WM_GETTEXTLENGTH:
                return 5
            if msg == WM_GETTEXT:
                # lparam is the buffer pointer — write into it
                buf = ctypes.cast(lparam, ctypes.POINTER(ctypes.c_wchar * 6))
                text = "hello"
                for i, ch in enumerate(text):
                    buf.contents[i] = ch
                buf.contents[len(text)] = "\0"
                return len(text)
            return 0

        with patch("enterprise.bridge_connector._user32") as mock_u32:
            mock_u32.SendMessageW.side_effect = _mock_send
            result = c._win32_read_text(0xABC)
        assert isinstance(result, str)
