from __future__ import annotations

import hashlib

import pytest

from enterprise.logical_targets import (
    LogicalTargetError,
    LogicalTargetResolver,
    LogicalTargetSpec,
)


PATH = (
    r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_test"
    r"\WindowsTerminal.exe"
)
TITLE = "Governed Terminal"
TITLE_HASH = hashlib.sha256(TITLE.encode()).hexdigest()


def spec(**changes) -> LogicalTargetSpec:
    values = {
        "logical_id": "ops.terminal.primary",
        "expected_exe_path": PATH,
        "expected_class": "CASCADIA_HOSTING_WINDOW_CLASS",
        "expected_title_sha256": TITLE_HASH,
        "allowed_roles": frozenset({"sender", "receiver"}),
    }
    values.update(changes)
    return LogicalTargetSpec(**values)


def report(hwnd: int, *, ok: bool = True, **changes):
    value = {
        "hwnd": hwnd,
        "valid": True,
        "ok": ok,
        "reasons": [] if ok else ["not the configured target"],
        "pid": 4242,
        "exe": "WindowsTerminal.exe",
        "exe_path": PATH,
        "class": "CASCADIA_HOSTING_WINDOW_CLASS",
        "title": TITLE,
        "is_terminal": True,
        "is_self": False,
    }
    value.update(changes)
    return value


class TestLogicalTargetSpec:
    @pytest.mark.parametrize(
        "field,value",
        [
            ("logical_id", "UPPER"),
            ("logical_id", ""),
            ("expected_exe_path", "relative.exe"),
            ("expected_exe_path", r"\Windows\System32\cmd.exe"),
            ("expected_exe_path", "C:\\bad\x00path"),
            ("expected_class", ""),
            ("expected_title_sha256", "A" * 64),
            ("expected_title_sha256", "0" * 63),
            ("allowed_roles", frozenset()),
            ("allowed_roles", frozenset({"admin"})),
        ],
    )
    def test_strict_validation(self, field, value):
        with pytest.raises(ValueError):
            spec(**{field: value})

    def test_defensively_freezes_roles(self):
        roles = {"sender"}
        item = spec(allowed_roles=roles)
        roles.add("observer")
        assert item.allowed_roles == frozenset({"sender"})
        with pytest.raises(Exception):
            item.logical_id = "changed"  # type: ignore[misc]


class TestLogicalTargetResolver:
    def test_duplicate_aliases_rejected(self):
        with pytest.raises(ValueError, match="duplicate"):
            LogicalTargetResolver([spec(), spec()])

    def test_requires_exact_spec_type(self):
        class Child(LogicalTargetSpec):
            pass

        with pytest.raises(TypeError, match="exact"):
            LogicalTargetResolver([Child(**spec().__dict__)])

    def test_unknown_alias_and_role_deny_before_enumeration(self):
        calls = []
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: calls.append(1))
        with pytest.raises(LogicalTargetError, match="not configured"):
            resolver.resolve("missing.target", role="sender", target_verifier=report)
        with pytest.raises(LogicalTargetError, match="not authorized"):
            resolver.resolve("ops.terminal.primary", role="observer", target_verifier=report)
        assert calls == []

    def test_requires_exactly_one_safe_match_and_checks_every_candidate(self):
        calls = []

        def verifier(hwnd, **kwargs):
            calls.append((hwnd, kwargs))
            return report(hwnd, ok=hwnd in {11, 22})

        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: [11, 22, 33])
        with pytest.raises(LogicalTargetError, match="ambiguous"):
            resolver.resolve("ops.terminal.primary", role="sender", target_verifier=verifier)
        assert [hwnd for hwnd, _ in calls] == [11, 22, 33]
        for _, kwargs in calls:
            assert kwargs == {
                "expect_exe_path": PATH,
                "expect_class": "CASCADIA_HOSTING_WINDOW_CLASS",
                "expect_title_sha256": TITLE_HASH,
                "require_terminal": True,
            }

    def test_zero_matches_denied(self):
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: [11])
        with pytest.raises(LogicalTargetError, match="no safe live match"):
            resolver.resolve(
                "ops.terminal.primary",
                role="sender",
                target_verifier=lambda hwnd, **kwargs: report(hwnd, ok=False),
            )

    @pytest.mark.parametrize("candidates", [[1, 1], [0], [0xFFFFFFFF], [True]])
    def test_malformed_enumeration_denied(self, candidates):
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: candidates)
        with pytest.raises(LogicalTargetError):
            resolver.resolve("ops.terminal.primary", role="sender", target_verifier=report)

    def test_candidate_enumeration_is_bounded_while_iterating(self):
        resolver = LogicalTargetResolver(
            [spec()], enumerate_windows=lambda: iter(range(1, 5000))
        )
        with pytest.raises(LogicalTargetError, match="exceeded"):
            resolver.resolve(
                "ops.terminal.primary",
                role="sender",
                target_verifier=lambda hwnd, **kwargs: report(hwnd, ok=False),
            )

    def test_verifier_exception_or_incomplete_success_denies(self):
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: [11])
        with pytest.raises(LogicalTargetError, match="verification failed"):
            resolver.resolve(
                "ops.terminal.primary",
                role="sender",
                target_verifier=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
            )
        with pytest.raises(LogicalTargetError, match="incomplete"):
            resolver.resolve(
                "ops.terminal.primary",
                role="sender",
                target_verifier=lambda hwnd, **kwargs: report(hwnd, exe=""),
            )

    @pytest.mark.parametrize(
        "change",
        [
            {"hwnd": 99},
            {"valid": "yes"},
            {"is_terminal": False},
            {"is_self": True},
            {"reasons": ()},
            {"reasons": ["contradictory"]},
            {"ok": "yes"},
        ],
    )
    def test_noncanonical_success_shape_cannot_match(self, change):
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: [11])
        with pytest.raises(LogicalTargetError):
            resolver.resolve(
                "ops.terminal.primary",
                role="sender",
                target_verifier=lambda hwnd, **kwargs: report(hwnd, **change),
            )

    @pytest.mark.parametrize(
        "change",
        [
            {"exe_path": r"C:\\Users\\Public\\WindowsTerminal.exe"},
            {"exe": "not-the-path-basename.exe"},
            {"class": "FakeClass"},
            {"title": "Changed"},
        ],
    )
    def test_successful_but_mismatched_report_denied(self, change):
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: [11])
        with pytest.raises(LogicalTargetError, match="mismatched"):
            resolver.resolve(
                "ops.terminal.primary",
                role="sender",
                target_verifier=lambda hwnd, **kwargs: report(hwnd, **change),
            )

    def test_returns_frozen_identity_snapshot(self):
        resolver = LogicalTargetResolver([spec()], enumerate_windows=lambda: [11])
        resolved = resolver.resolve(
            "ops.terminal.primary", role="sender", target_verifier=report
        )
        assert resolved.logical_id == "ops.terminal.primary"
        assert resolved.hwnd == 11
        assert resolved.title_sha256 == TITLE_HASH
        with pytest.raises(Exception):
            resolved.hwnd = 22  # type: ignore[misc]

    def test_no_product_specific_builtins(self):
        resolver = LogicalTargetResolver([], enumerate_windows=lambda: ())
        assert resolver.logical_ids() == ()
