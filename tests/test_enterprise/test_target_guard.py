"""Focused contract tests for the canonical Win32 target guard."""
from __future__ import annotations

import hashlib
from unittest.mock import patch

from experiments.win32_probe.target_guard import verify_target


def _verify_title(expected_hash: str) -> dict:
    with (
        patch("experiments.win32_probe.target_guard.user32.IsWindow", return_value=1),
        patch("experiments.win32_probe.target_guard.user32.IsWindowVisible", return_value=1),
        patch("experiments.win32_probe.target_guard._pid", return_value=4242),
        patch("experiments.win32_probe.target_guard._class_name", return_value="TestClass"),
        patch("experiments.win32_probe.target_guard._title", return_value="Bound Terminal"),
        patch(
            "experiments.win32_probe.target_guard._exe_path",
            return_value=r"C:\Program Files\Test\terminal.exe",
        ),
        patch("experiments.win32_probe.target_guard._session", return_value=1),
    ):
        return verify_target(
            1234,
            expect_title_sha256=expected_hash,
            require_terminal=False,
            own_pid=1,
        )


def test_exact_title_hash_is_part_of_target_binding() -> None:
    expected = hashlib.sha256(b"Bound Terminal").hexdigest()
    assert _verify_title(expected)["ok"] is True


def test_changed_title_hash_fails_closed() -> None:
    report = _verify_title("0" * 64)
    assert report["ok"] is False
    assert "title hash" in report["reasons"][0]
