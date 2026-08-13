"""Fail-closed UI Automation text reader for governed terminal output."""
from __future__ import annotations

from typing import Any


class UIAOutputError(RuntimeError):
    """The target did not expose a readable UIA TextPattern document."""


def read_terminal_text(hwnd: int) -> str:
    """Return the full UIA TextPattern buffer for *hwnd*.

    The reusable Win32 probe deliberately selects the descendant with the
    largest TextPattern document. Windows Terminal's top-level window does not
    itself expose the terminal scrollback. An empty or unavailable document is
    an error here: governed callers must never interpret an unreadable target
    as a successful read containing no output.
    """
    try:
        from enterprise_experiments.win32_probe.uia_textpattern import (
            get_uia,
            read_text,
            text_element,
        )

        uia, uia_types = get_uia()
        element: Any = text_element(uia, uia_types, int(hwnd))
        if element is None:
            raise UIAOutputError("target exposes no readable UIA TextPattern element")
        text = read_text(uia, uia_types, element)
    except UIAOutputError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise UIAOutputError(f"UIA TextPattern read failed: {exc}") from exc

    if not isinstance(text, str):
        raise UIAOutputError("UIA TextPattern reader returned a non-text value")
    return text


__all__ = ["UIAOutputError", "read_terminal_text"]
