"""Mesh comms helper — talk to peer agent terminals via the SelfConnect SDK.

Targets are chosen EXPLICITLY by hwnd (never by broad title match) after `list`,
so we only ever touch the intended peer windows.

  python mesh_talk.py list
  python mesh_talk.py send <hwnd> <message...>
  python mesh_talk.py read <hwnd>
"""
from __future__ import annotations

import sys
import time

sys.path.insert(0, "sdk")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

from self_connect import (  # noqa: E402
    get_own_terminal_pid,
    get_text_uia,
    list_windows,
    send_string,
    submit_claude_input,
)
from experiments.win32_probe.target_guard import assert_safe_target  # noqa: E402


def cmd_list() -> None:
    own = get_own_terminal_pid()
    for w in list_windows():
        t = w.title.lower()
        if w.exe_name.lower() == "windowsterminal.exe" or any(
            k in t for k in ("claude", "codex", "migration", "selfconnect")
        ):
            mark = "  <-- SELF (exclude)" if w.pid == own else ""
            print(f"{w.hwnd}\t{w.pid}\t{w.exe_name}\t{w.title!r}{mark}")


def cmd_send(hwnd: int, msg: str) -> None:
    w = next((x for x in list_windows() if x.hwnd == hwnd), None)
    if not w:
        print(f"FAIL: no window with hwnd {hwnd}")
        return
    own = get_own_terminal_pid()
    if w.pid == own:
        print("REFUSED: that hwnd is my own terminal.")
        return
    try:
        assert_safe_target(hwnd, expect_exe="WindowsTerminal.exe", require_terminal=True)
    except PermissionError as exc:
        print(f"REFUSED: {exc}")
        return
    # Type the message (single line, no embedded Enter), then submit.
    send_string(w, msg)
    time.sleep(0.4)
    ok = submit_claude_input(hwnd)
    print(f"SENT -> hwnd={hwnd} title={w.title!r} submit_posted={bool(ok)}")


def cmd_read(hwnd: int) -> None:
    txt = get_text_uia(hwnd) or ""
    print(f"--- hwnd {hwnd} ({len(txt)} chars) ---")
    print(txt[-3000:] if txt else "(no text extracted)")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "list":
        cmd_list()
    elif args[0] == "send" and len(args) >= 3:
        cmd_send(int(args[1]), " ".join(args[2:]))
    elif args[0] == "read" and len(args) == 2:
        cmd_read(int(args[1]))
    else:
        print(__doc__)
