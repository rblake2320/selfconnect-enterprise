"""tests/test_enterprise/test_target_registry.py — Unit tests for target_registry.

All Win32 calls are mocked — no live desktop required.
"""
from __future__ import annotations

from unittest.mock import patch

from enterprise.target_registry import (
    GFE_FILE_WORKSPACE,
    GFE_TERMINAL_CMD,
    GFE_TERMINAL_POWERSHELL,
    GENAIMIL_BROWSER_INPUT,
    GENAIMIL_BROWSER_OUTPUT,
    LogicalTarget,
    TargetAccessDeniedError,
    TargetNotFoundError,
    TargetRegistry,
)

FAKE_HWND = 0xABC01234


# ── LogicalTarget ──────────────────────────────────────────────────────────────

class TestLogicalTarget:
    def test_frozen_immutable(self):
        t = LogicalTarget(
            logical_id="test.target",
            display_name="Test",
            classification_ceiling="SECRET",
            allowed_actor_modes=frozenset({"agent"}),
        )
        raised = False
        try:
            t.logical_id = "other"  # type: ignore[misc]
        except (AttributeError, TypeError):
            raised = True
        assert raised, "frozen dataclass should reject attribute assignment"

    def test_defaults(self):
        t = LogicalTarget(
            logical_id="t",
            display_name="T",
            classification_ceiling="UNCLASSIFIED",
            allowed_actor_modes=frozenset({"agent"}),
        )
        assert t.window_class == ""
        assert t.window_title_pattern == ""

    def test_fields_preserved(self):
        t = LogicalTarget(
            logical_id="gfe.terminal.powershell",
            display_name="GFE PS",
            classification_ceiling="SECRET",
            allowed_actor_modes=frozenset({"agent", "executor"}),
            window_class="ConsoleWindowClass",
            window_title_pattern=r"(?i)powershell",
        )
        assert t.logical_id == "gfe.terminal.powershell"
        assert "executor" in t.allowed_actor_modes
        assert t.window_class == "ConsoleWindowClass"


# ── Built-in target catalogue ─────────────────────────────────────────────────

class TestTargetRegistryBuiltins:
    def test_all_five_builtins_registered(self):
        r = TargetRegistry()
        ids = {t.logical_id for t in r.list_targets()}
        assert GFE_TERMINAL_POWERSHELL in ids
        assert GFE_TERMINAL_CMD in ids
        assert GENAIMIL_BROWSER_INPUT in ids
        assert GENAIMIL_BROWSER_OUTPUT in ids
        assert GFE_FILE_WORKSPACE in ids
        assert len(ids) == 5

    def test_builtin_get_returns_correct_target(self):
        r = TargetRegistry()
        t = r.get(GFE_TERMINAL_POWERSHELL)
        assert t.logical_id == GFE_TERMINAL_POWERSHELL
        assert t.window_class == "ConsoleWindowClass"

    def test_executor_allowed_on_terminals(self):
        r = TargetRegistry()
        assert "executor" in r.get(GFE_TERMINAL_POWERSHELL).allowed_actor_modes
        assert "executor" in r.get(GFE_TERMINAL_CMD).allowed_actor_modes

    def test_executor_allowed_on_file_workspace(self):
        r = TargetRegistry()
        assert "executor" in r.get(GFE_FILE_WORKSPACE).allowed_actor_modes

    def test_observer_not_allowed_on_terminals(self):
        r = TargetRegistry()
        assert "observer" not in r.get(GFE_TERMINAL_POWERSHELL).allowed_actor_modes
        assert "observer" not in r.get(GFE_TERMINAL_CMD).allowed_actor_modes

    def test_observer_allowed_on_browser_output(self):
        r = TargetRegistry()
        assert "observer" in r.get(GENAIMIL_BROWSER_OUTPUT).allowed_actor_modes

    def test_bridge_allowed_on_browser_targets(self):
        r = TargetRegistry()
        assert "bridge" in r.get(GENAIMIL_BROWSER_INPUT).allowed_actor_modes
        assert "bridge" in r.get(GENAIMIL_BROWSER_OUTPUT).allowed_actor_modes

    def test_bridge_not_allowed_on_terminals(self):
        r = TargetRegistry()
        assert "bridge" not in r.get(GFE_TERMINAL_POWERSHELL).allowed_actor_modes

    def test_file_workspace_has_no_window_class(self):
        r = TargetRegistry()
        assert r.get(GFE_FILE_WORKSPACE).window_class == ""

    def test_list_targets_sorted(self):
        r = TargetRegistry()
        ids = [t.logical_id for t in r.list_targets()]
        assert ids == sorted(ids)


# ── Registry CRUD ─────────────────────────────────────────────────────────────

class TestTargetRegistryCRUD:
    def test_register_custom_target(self):
        r = TargetRegistry()
        custom = LogicalTarget(
            logical_id="custom.target",
            display_name="Custom",
            classification_ceiling="UNCLASSIFIED",
            allowed_actor_modes=frozenset({"agent"}),
        )
        r.register(custom)
        assert r.get("custom.target") is custom

    def test_get_unknown_raises_target_not_found(self):
        r = TargetRegistry()
        raised = False
        try:
            r.get("no.such.target")
        except TargetNotFoundError as exc:
            raised = True
            assert exc.logical_id == "no.such.target"
        assert raised

    def test_register_overwrites_builtin(self):
        r = TargetRegistry()
        replacement = LogicalTarget(
            logical_id=GFE_TERMINAL_CMD,
            display_name="Overridden",
            classification_ceiling="UNCLASSIFIED",
            allowed_actor_modes=frozenset({"agent"}),
        )
        r.register(replacement)
        assert r.get(GFE_TERMINAL_CMD).display_name == "Overridden"

    def test_custom_target_appears_in_list(self):
        r = TargetRegistry()
        r.register(LogicalTarget(
            logical_id="zzz.last",
            display_name="Last",
            classification_ceiling="UNCLASSIFIED",
            allowed_actor_modes=frozenset({"agent"}),
        ))
        ids = [t.logical_id for t in r.list_targets()]
        assert "zzz.last" in ids
        assert ids == sorted(ids)


# ── resolve_to_hwnd ────────────────────────────────────────────────────────────

class TestResolveToHwnd:
    def test_file_workspace_returns_zero_no_win32(self):
        r = TargetRegistry()
        with patch("enterprise.target_registry._user32") as mock_u32:
            hwnd = r.resolve_to_hwnd(GFE_FILE_WORKSPACE, actor_mode="executor")
            mock_u32.FindWindowW.assert_not_called()
        assert hwnd == 0

    def test_window_target_returns_hwnd(self):
        r = TargetRegistry()
        with patch("enterprise.target_registry._user32") as mock_u32:
            mock_u32.FindWindowW.return_value = FAKE_HWND
            hwnd = r.resolve_to_hwnd(GFE_TERMINAL_POWERSHELL, actor_mode="executor")
        assert hwnd == FAKE_HWND

    def test_access_denied_wrong_mode(self):
        r = TargetRegistry()
        raised = False
        try:
            r.resolve_to_hwnd(GFE_TERMINAL_POWERSHELL, actor_mode="observer")
        except TargetAccessDeniedError as exc:
            raised = True
            assert exc.logical_id == GFE_TERMINAL_POWERSHELL
            assert exc.actor_mode == "observer"
        assert raised

    def test_access_check_before_win32(self):
        r = TargetRegistry()
        with patch("enterprise.target_registry._user32") as mock_u32:
            mock_u32.FindWindowW.return_value = FAKE_HWND
            try:
                r.resolve_to_hwnd(GFE_TERMINAL_POWERSHELL, actor_mode="observer")
            except TargetAccessDeniedError:
                pass
            mock_u32.FindWindowW.assert_not_called()

    def test_not_found_when_no_live_window(self):
        r = TargetRegistry()
        raised = False
        with patch("enterprise.target_registry._user32") as mock_u32:
            mock_u32.FindWindowW.return_value = 0
            try:
                r.resolve_to_hwnd(GFE_TERMINAL_POWERSHELL, actor_mode="executor")
            except TargetNotFoundError as exc:
                raised = True
                assert exc.logical_id == GFE_TERMINAL_POWERSHELL
        assert raised

    def test_unknown_logical_id_raises_not_found(self):
        r = TargetRegistry()
        raised = False
        try:
            r.resolve_to_hwnd("no.such.target", actor_mode="executor")
        except TargetNotFoundError as exc:
            raised = True
            assert exc.logical_id == "no.such.target"
        assert raised

    def test_bridge_resolves_browser_input(self):
        r = TargetRegistry()
        with patch("enterprise.target_registry._user32") as mock_u32:
            mock_u32.FindWindowW.return_value = FAKE_HWND
            hwnd = r.resolve_to_hwnd(GENAIMIL_BROWSER_INPUT, actor_mode="bridge")
        assert hwnd == FAKE_HWND

    def test_executor_denied_on_browser_input(self):
        r = TargetRegistry()
        raised = False
        try:
            r.resolve_to_hwnd(GENAIMIL_BROWSER_INPUT, actor_mode="executor")
        except TargetAccessDeniedError as exc:
            raised = True
            assert exc.actor_mode == "executor"
        assert raised
