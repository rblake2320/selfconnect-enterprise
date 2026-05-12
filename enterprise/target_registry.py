"""enterprise/target_registry.py — Logical target naming layer.

Decouples the Win32 executor from raw HWNDs by providing stable logical IDs
(e.g. "gfe.terminal.powershell") that are resolved to live HWNDs at execution
time.  Classification ceilings and actor-mode restrictions are enforced before
any HWND lookup is performed.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass

# ── Win32 handle ──────────────────────────────────────────────────────────────
_user32 = ctypes.windll.user32


# ── Exceptions ────────────────────────────────────────────────────────────────

class TargetNotFoundError(Exception):
    """Raised when a logical_id is not registered, or no live window exists for it."""
    def __init__(self, logical_id: str) -> None:
        super().__init__(f"logical target {logical_id!r} not found or no live window")
        self.logical_id = logical_id


class TargetAccessDeniedError(Exception):
    """Raised when actor_mode is not in the target's allowed_actor_modes."""
    def __init__(self, logical_id: str, actor_mode: str) -> None:
        super().__init__(
            f"actor_mode={actor_mode!r} is not permitted for target {logical_id!r}"
        )
        self.logical_id = logical_id
        self.actor_mode = actor_mode


# ── LogicalTarget ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LogicalTarget:
    """Stable logical identifier for an automation target.

    classification_ceiling: max classification this target may process —
        metadata for the policy layer, not enforced here.
    allowed_actor_modes: set of participant_mode values that may drive this
        target; enforced in resolve_to_hwnd() before any Win32 call.
    window_class: Win32 window class name for FindWindowW lookup.
        Empty string for non-window targets (e.g. file workspace).
    window_title_pattern: informational regex hint; currently stored for
        future narrowed resolution — not evaluated in resolve_to_hwnd().
    """
    logical_id:             str
    display_name:           str
    classification_ceiling: str
    allowed_actor_modes:    frozenset[str]
    window_class:           str = ""
    window_title_pattern:   str = ""


# ── Built-in target ID constants ──────────────────────────────────────────────

GFE_TERMINAL_POWERSHELL = "gfe.terminal.powershell"
GFE_TERMINAL_CMD        = "gfe.terminal.cmd"
GENAIMIL_BROWSER_INPUT  = "genaimil.browser.input"
GENAIMIL_BROWSER_OUTPUT = "genaimil.browser.output"
GFE_FILE_WORKSPACE      = "gfe.file.workspace"

_BUILT_IN_TARGETS: list[LogicalTarget] = [
    LogicalTarget(
        logical_id=GFE_TERMINAL_POWERSHELL,
        display_name="GFE PowerShell Terminal",
        classification_ceiling="SECRET",
        allowed_actor_modes=frozenset({"agent", "executor"}),
        window_class="ConsoleWindowClass",
        window_title_pattern=r"(?i)powershell",
    ),
    LogicalTarget(
        logical_id=GFE_TERMINAL_CMD,
        display_name="GFE Command Prompt",
        classification_ceiling="SECRET",
        allowed_actor_modes=frozenset({"agent", "executor"}),
        window_class="ConsoleWindowClass",
        window_title_pattern=r"(?i)cmd|command prompt",
    ),
    LogicalTarget(
        logical_id=GENAIMIL_BROWSER_INPUT,
        display_name="GenAI.mil Browser Input",
        classification_ceiling="SECRET",
        allowed_actor_modes=frozenset({"agent", "bridge"}),
        window_class="Chrome_WidgetWin_1",
        window_title_pattern=r"(?i)genai\.mil",
    ),
    LogicalTarget(
        logical_id=GENAIMIL_BROWSER_OUTPUT,
        display_name="GenAI.mil Browser Output",
        classification_ceiling="SECRET",
        allowed_actor_modes=frozenset({"agent", "bridge", "observer"}),
        window_class="Chrome_WidgetWin_1",
        window_title_pattern=r"(?i)genai\.mil",
    ),
    LogicalTarget(
        logical_id=GFE_FILE_WORKSPACE,
        display_name="GFE File Workspace",
        classification_ceiling="SECRET",
        allowed_actor_modes=frozenset({"agent", "executor"}),
        window_class="",   # filesystem target — no HWND
        window_title_pattern="",
    ),
]


# ── TargetRegistry ────────────────────────────────────────────────────────────

class TargetRegistry:
    """Registry of logical automation targets.

    Built-in targets are registered at construction.  Additional targets can be
    registered via register().  resolve_to_hwnd() enforces actor-mode access
    control before performing the live Win32 HWND lookup.

    Access control order in resolve_to_hwnd():
        1. Target must be registered         → TargetNotFoundError
        2. actor_mode in allowed_actor_modes → TargetAccessDeniedError
        3. Win32 FindWindowW lookup
        4. No live window found              → TargetNotFoundError
    """

    def __init__(self) -> None:
        self._targets: dict[str, LogicalTarget] = {}
        for t in _BUILT_IN_TARGETS:
            self._targets[t.logical_id] = t

    def register(self, target: LogicalTarget) -> None:
        """Register or overwrite a logical target."""
        self._targets[target.logical_id] = target

    def get(self, logical_id: str) -> LogicalTarget:
        """Return the LogicalTarget for logical_id.

        Raises TargetNotFoundError if not registered.
        """
        try:
            return self._targets[logical_id]
        except KeyError:
            raise TargetNotFoundError(logical_id)

    def list_targets(self) -> list[LogicalTarget]:
        """Return all registered targets sorted by logical_id."""
        return sorted(self._targets.values(), key=lambda t: t.logical_id)

    def resolve_to_hwnd(self, logical_id: str, actor_mode: str) -> int:
        """Resolve a logical target to a live Win32 HWND.

        Access control is enforced before any Win32 call (see class docstring).
        Returns 0 for non-window targets (window_class == "").
        """
        target = self.get(logical_id)  # raises TargetNotFoundError if absent

        if actor_mode not in target.allowed_actor_modes:
            raise TargetAccessDeniedError(logical_id, actor_mode)

        if not target.window_class:
            return 0  # file / non-window target

        hwnd: int = _user32.FindWindowW(target.window_class, None)
        if hwnd == 0:
            raise TargetNotFoundError(logical_id)
        return hwnd


__all__ = [
    "LogicalTarget",
    "TargetRegistry",
    "TargetNotFoundError",
    "TargetAccessDeniedError",
    "GFE_TERMINAL_POWERSHELL",
    "GFE_TERMINAL_CMD",
    "GENAIMIL_BROWSER_INPUT",
    "GENAIMIL_BROWSER_OUTPUT",
    "GFE_FILE_WORKSPACE",
]
