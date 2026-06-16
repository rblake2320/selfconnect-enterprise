"""POC item 5: UIA TextChanged LIVE-FIRE proof on a terminal (the real read target).

Finding from the Notepad attempt: RichEditD2DPT does NOT raise UIA TextChanged on
ValuePattern.SetValue. The production read target is the terminal TermControl — the
single text surface that updates as the console buffer changes — which DOES raise
TextChanged on output.

This spawns its OWN console (via conhost.exe, bypassing Windows Terminal tab-routing so
we get a standalone window to pin), streams lines into it, registers a TextChanged handler
on that window's text element, pumps the COM loop, and reports whether the callback fired
on real output. Targets only the window THIS process spawned (pinned by hwnd set-diff).

Run:  python experiments/win32_probe/uia_textchanged_fire.py
Exit: 0 = PASS (fired on live output), 1 = registered but did not fire, 3 = refused
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import pythoncom
import win32gui

from uia_textpattern import (
    UIA_Text_TextChangedEventId,
    compute_delta,
    get_uia,
    read_text,
    register_textchanged,
    text_element,
)

CREATE_NEW_CONSOLE = 0x00000010
TERM_CLASSES = {"ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS"}


def _term_hwnds() -> set[int]:
    out: set[int] = set()

    def cb(h, _):
        try:
            if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) in TERM_CLASSES:
                out.add(h)
        except Exception:  # noqa: BLE001
            pass
        return True

    win32gui.EnumWindows(cb, None)
    return out


def main() -> int:
    before = _term_hwnds()
    # conhost.exe hosts a classic console regardless of the default-terminal setting,
    # giving a standalone top-level window we can pin (no Windows Terminal tab routing).
    loop = "for /l %i in (1,1,15) do @(echo CLAUDE1-FIRE %i & ping -n 2 127.0.0.1 >nul)"
    proc = subprocess.Popen(  # noqa: F841
        ["conhost.exe", "cmd", "/c", loop], creationflags=CREATE_NEW_CONSOLE
    )
    mine = None
    for _ in range(25):
        time.sleep(0.4)
        new = _term_hwnds() - before
        if len(new) >= 1:
            mine = sorted(new)[0]
            break
    if not mine:
        print("REFUSED: no new console/terminal window appeared to pin.")
        return 3

    uia, UIA = get_uia()
    el = text_element(uia, UIA, mine)
    if el is None:
        print(f"PARTIAL: no TextPattern element on spawned hwnd={mine}.")
        return 1

    fired = {"n": 0, "last": None}
    last_text = [read_text(uia, UIA, el)]

    def on_change(_sender):
        fired["n"] += 1
        try:
            now = read_text(uia, UIA, el)
            fired["last"] = compute_delta(last_text[0], now)
            last_text[0] = now
        except Exception:  # noqa: BLE001
            pass

    handler = register_textchanged(uia, UIA, el, on_change)

    # Pump the COM loop while the console streams output (~8s window).
    deadline = time.time() + 8.0
    while time.time() < deadline and fired["n"] < 2:
        pythoncom.PumpWaitingMessages()
        time.sleep(0.05)

    try:
        uia.RemoveAutomationEventHandler(UIA_Text_TextChangedEventId, el, handler)
    except Exception:  # noqa: BLE001
        pass

    if fired["n"] > 0:
        print(f"PASS: TextChanged FIRED {fired['n']}x on live terminal output; "
              f"last_delta={str(fired['last'])[:80]!r}")
        return 0
    print("PARTIAL: TextChanged did not fire within 8s on the spawned console "
          "(conhost UIA may not raise it; Windows Terminal TermControl is the next target).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
