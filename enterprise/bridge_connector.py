"""enterprise/bridge_connector.py — GenAI.mil / browser-hosted LLM connector.

Registers as participant_mode="bridge".  Has no execution capability: it reads
LLM output from a browser window, parses it into a structured action proposal,
and produces an ExecutorActionRequest for the caller (MeshOrchestrator) to
dispatch.  The bridge never calls Win32Executor.execute() — the executor acts;
the bridge only proposes.

I/O lifecycle per prompt roundtrip:
    1. send_prompt()  — prepend system instruction, write text to browser input
    2. read_response() — poll browser output window until text appears or timeout
    3. parse_response() — extract and validate the ACTION block
    4. submit_proposal() — produce ExecutorActionRequest (or None on bad parse)

All Win32 interactions are isolated in _win32_set_text / _win32_read_text for
clean patch.object() mocking in tests.  Target resolution always goes through
TargetRegistry.resolve_to_hwnd(target_id, "bridge") — no raw HWNDs hard-coded.

Version: 1.0.0-enterprise  Session 21
"""
from __future__ import annotations

import ctypes
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal, Optional

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.executor_win32 import ExecutorActionRequest
from enterprise.labels import Classification
from enterprise.ledger import AgentLedger
from enterprise.target_registry import (
    GENAIMIL_BROWSER_INPUT,
    GENAIMIL_BROWSER_OUTPUT,
    TargetRegistry,
)

# ── Win32 handles ─────────────────────────────────────────────────────────────
_user32 = ctypes.windll.user32

WM_GETTEXT       = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_SETTEXT       = 0x000C

# ── Action sets ───────────────────────────────────────────────────────────────

BRIDGE_ALLOWED_PROPOSALS: frozenset[str] = frozenset({
    "read_window_text",
    "read_named_element",
    "write_file_allowed_path",
    "read_file_allowed_path",
    "set_text",
    "click_named_element",
})

BRIDGE_FORBIDDEN_PROPOSALS: frozenset[str] = frozenset({
    "execute_shell",
    "run_signed_script",
    "write_registry",
    "submit_form_external",
    "run_arbitrary_code",
})

# ── System instruction block (prepended to every prompt) ──────────────────────

SYSTEM_INSTRUCTION: str = (
    "[SELFCONNECT-BRIDGE] Your response must end with an action block in this "
    "exact format if an action is needed. "
    "If no action is needed, omit the block entirely.\n"
    "```ACTION\n"
    '{"action_type": "<action>", "target_logical_id": "<target>", "parameters": {}}\n'
    "```"
)

# Regex to extract the last ```ACTION...``` block (DOTALL so . matches newlines)
_ACTION_BLOCK_RE = re.compile(r"```ACTION\s*(.*?)```", re.DOTALL)


# ── BridgeProposal ────────────────────────────────────────────────────────────

@dataclass
class BridgeProposal:
    """Structured proposal produced by parsing an LLM response."""
    proposal_id:        str
    source_session_id:  str
    raw_llm_output:     str
    parsed_action_type: str
    parsed_parameters:  dict
    parse_confidence:   Literal["structured", "heuristic", "failed"]
    classification:     Classification
    proposed_at:        float


# ── BridgeConnector ───────────────────────────────────────────────────────────

class BridgeConnector:
    """GenAI.mil browser LLM connector with no execution capability.

    Produces ExecutorActionRequest objects; never calls Win32Executor.execute().
    Every send_prompt(), read_response(), and submit_proposal() call is logged
    to the ledger.  parse_response() also logs forbidden-action attempts.
    """

    def __init__(
        self,
        target_registry: TargetRegistry,
        ledger:          AgentLedger,
        profile:         ClassifiedModeProfile,
        session_id:      str,
    ) -> None:
        self._target_registry = target_registry
        self._ledger          = ledger
        self._profile         = profile
        self._session_id      = session_id

    # ── Public API ────────────────────────────────────────────────────────────

    def send_prompt(
        self,
        prompt:    str,
        target_id: str = GENAIMIL_BROWSER_INPUT,
    ) -> bool:
        """Prepend system instruction and send prompt to browser input target.

        Returns True on success, False if target resolution or Win32 write fails.
        Always writes a ledger entry.
        """
        full_prompt = SYSTEM_INSTRUCTION + "\n\n" + prompt
        try:
            hwnd = self._target_registry.resolve_to_hwnd(target_id, "bridge")
            self._win32_set_text(hwnd, full_prompt)
            self._ledger.log(
                action="bridge.send_prompt",
                result=f"sent {len(full_prompt)} chars to {target_id!r}",
                metadata={
                    "session_id": self._session_id,
                    "target":     target_id,
                    "prompt_len": len(full_prompt),
                },
            )
            return True
        except Exception as exc:
            self._ledger.log(
                action="bridge.send_prompt",
                result=f"FAILED: {exc}",
                metadata={
                    "session_id": self._session_id,
                    "target":     target_id,
                    "error":      str(exc),
                },
            )
            return False

    def read_response(
        self,
        target_id:      str   = GENAIMIL_BROWSER_OUTPUT,
        timeout_sec:    float = 60.0,
        *,
        _poll_interval: float = 0.5,
    ) -> str:
        """Poll browser output target until text appears or timeout_sec elapses.

        Returns the raw text on success, "" on timeout or error.
        Always writes a ledger entry.

        _poll_interval: seconds between polls (keyword-only; use 0 in tests for
                        instant timeout without sleeping).
        """
        try:
            hwnd = self._target_registry.resolve_to_hwnd(target_id, "bridge")
        except Exception as exc:
            self._ledger.log(
                action="bridge.read_response",
                result=f"FAILED: {exc}",
                metadata={
                    "session_id": self._session_id,
                    "target":     target_id,
                    "error":      str(exc),
                },
            )
            return ""

        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                text = self._win32_read_text(hwnd)
            except Exception as exc:
                self._ledger.log(
                    action="bridge.read_response",
                    result=f"FAILED: {exc}",
                    metadata={
                        "session_id": self._session_id,
                        "target":     target_id,
                        "error":      str(exc),
                    },
                )
                return ""
            if text:
                self._ledger.log(
                    action="bridge.read_response",
                    result=f"received {len(text)} chars from {target_id!r}",
                    metadata={
                        "session_id": self._session_id,
                        "target":     target_id,
                        "output_len": len(text),
                    },
                )
                return text
            if _poll_interval > 0:
                time.sleep(_poll_interval)

        self._ledger.log(
            action="bridge.read_response",
            result="FAILED: timeout",
            metadata={
                "session_id": self._session_id,
                "target":     target_id,
                "error":      "timeout",
            },
        )
        return ""

    def parse_response(self, raw_response: str) -> BridgeProposal:
        """Parse raw LLM output and extract an ACTION block if present.

        parse_confidence values:
            "structured" — valid JSON, action_type in BRIDGE_ALLOWED_PROPOSALS
            "failed"     — missing block, invalid JSON, or forbidden action_type
        """
        now = time.time()

        def _failed(action_type: str = "", params: dict | None = None) -> BridgeProposal:
            return BridgeProposal(
                proposal_id        = str(uuid.uuid4()),
                source_session_id  = self._session_id,
                raw_llm_output     = raw_response,
                parsed_action_type = action_type,
                parsed_parameters  = params or {},
                parse_confidence   = "failed",
                classification     = self._profile.max_classification,
                proposed_at        = now,
            )

        # Extract the last ```ACTION...``` block
        matches = _ACTION_BLOCK_RE.findall(raw_response)
        if not matches:
            return _failed()

        block = matches[-1].strip()
        try:
            data = json.loads(block)
        except json.JSONDecodeError:
            return _failed()

        action_type = data.get("action_type", "")

        if action_type in BRIDGE_FORBIDDEN_PROPOSALS:
            self._ledger.log(
                action="bridge.parse_response.forbidden_action",
                result=f"BLOCKED: forbidden action_type={action_type!r}",
                metadata={
                    "session_id":    self._session_id,
                    "action_type":   action_type,
                    "raw_output_len": len(raw_response),
                },
            )
            return _failed(action_type=action_type, params=data)

        if action_type not in BRIDGE_ALLOWED_PROPOSALS:
            return _failed(action_type=action_type, params=data)

        return BridgeProposal(
            proposal_id        = str(uuid.uuid4()),
            source_session_id  = self._session_id,
            raw_llm_output     = raw_response,
            parsed_action_type = action_type,
            parsed_parameters  = data,
            parse_confidence   = "structured",
            classification     = self._profile.max_classification,
            proposed_at        = now,
        )

    def submit_proposal(
        self,
        proposal: BridgeProposal,
    ) -> Optional[ExecutorActionRequest]:
        """Convert a structured BridgeProposal into an ExecutorActionRequest.

        Returns None if parse_confidence != "structured" or action_type is not
        in BRIDGE_ALLOWED_PROPOSALS.  Always writes a ledger entry.
        """
        if proposal.parse_confidence != "structured":
            self._ledger.log(
                action="bridge.submit_proposal.rejected",
                result=f"parse_confidence={proposal.parse_confidence!r}",
                metadata={
                    "session_id":    self._session_id,
                    "proposal_id":   proposal.proposal_id,
                    "raw_output_len": len(proposal.raw_llm_output),
                    "parse_confidence": proposal.parse_confidence,
                },
            )
            return None

        if proposal.parsed_action_type not in BRIDGE_ALLOWED_PROPOSALS:
            self._ledger.log(
                action="bridge.submit_proposal.rejected",
                result=f"action_type={proposal.parsed_action_type!r} not in allowed proposals",
                metadata={
                    "session_id":  self._session_id,
                    "proposal_id": proposal.proposal_id,
                    "action_type": proposal.parsed_action_type,
                },
            )
            return None

        params = proposal.parsed_parameters
        request = ExecutorActionRequest(
            request_id        = str(uuid.uuid4()),
            action_type       = proposal.parsed_action_type,
            target_logical_id = params.get("target_logical_id", ""),
            parameters        = params.get("parameters", {}),
            proposed_by       = self._session_id,
            classification    = proposal.classification,
            timestamp         = time.time(),
        )
        self._ledger.log(
            action="bridge.submit_proposal.accepted",
            result=f"action_type={proposal.parsed_action_type!r} → request {request.request_id}",
            metadata={
                "session_id":  self._session_id,
                "proposal_id": proposal.proposal_id,
                "request_id":  request.request_id,
                "action_type": proposal.parsed_action_type,
            },
        )
        return request

    # ── Win32 I/O helpers (isolated for patch.object mocking) ─────────────────

    def _win32_set_text(self, hwnd: int, text: str) -> None:
        """Write text to a window via WM_SETTEXT."""
        buf = ctypes.create_unicode_buffer(text)
        _user32.SendMessageW(hwnd, WM_SETTEXT, 0, buf)

    def _win32_read_text(self, hwnd: int) -> str:
        """Read window text via WM_GETTEXT.  Returns '' if window is empty."""
        length = _user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        if length == 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        _user32.SendMessageW(hwnd, WM_GETTEXT, length + 1, buf)
        return buf.value


__all__ = [
    "BridgeProposal",
    "BridgeConnector",
    "BRIDGE_ALLOWED_PROPOSALS",
    "BRIDGE_FORBIDDEN_PROPOSALS",
    "SYSTEM_INSTRUCTION",
]
