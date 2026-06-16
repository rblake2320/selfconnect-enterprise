"""POC: SAFE structured WRITE channel — only ever touches a window THIS process spawned.

Rewrite after the 2026-06-16 incident, where an earlier version matched windows by
title substring and overwrote unrelated Notepad windows. This version is ownership-bound:

  1. snapshot the set of existing Notepad top-level HWNDs
  2. spawn exactly one notepad.exe
  3. wait for exactly ONE new Notepad HWND to appear (refuse if 0 or >1 — never guess)
  4. pin that HWND; verify the UIA element's native handle matches the pin
  5. write ONLY to the pinned window (UIA ValuePattern.SetValue)
  6. read back via TextPattern from the same pinned window and verify the loop

It never targets, reads, or writes any window it did not create.

Run:  python experiments/win32_probe/uia_write.py "text to type"
Exit: 0 = PASS (wrote+verified own window), 1 = wrote but unverified, 3 = refused (unsafe)
"""
from __future__ import annotations

import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import comtypes
import comtypes.client
import win32gui

CLSID_CUIAutomation = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}"
UIA_ValuePatternId = 10002
UIA_TextPatternId = 10014
UIA_IsValuePatternAvailablePropertyId = 30043
UIA_IsTextPatternAvailablePropertyId = 30040
TreeScope_Descendants = 4


def _notepad_hwnds() -> set[int]:
    out: set[int] = set()

    def cb(h, _):
        try:
            if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "Notepad":
                out.add(h)
        except Exception:  # noqa: BLE001
            pass
        return True

    win32gui.EnumWindows(cb, None)
    return out


def _read_back(el, uia, UIA) -> str:
    """Longest TextPattern string among the element's descendants (the document body)."""
    bodies: list[str] = []
    try:
        cond = uia.CreatePropertyCondition(UIA_IsTextPatternAvailablePropertyId, True)
        found = el.FindAll(TreeScope_Descendants, cond)
        for i in range(found.Length):
            try:
                tp = found.GetElement(i).GetCurrentPattern(UIA_TextPatternId).QueryInterface(
                    UIA.IUIAutomationTextPattern
                )
                t = tp.DocumentRange.GetText(400) or ""
                if t.strip():
                    bodies.append(t)
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return max(bodies, key=len) if bodies else ""


def main() -> int:
    text = sys.argv[1] if len(sys.argv) > 1 else (
        "[CLAUDE-1 safe write] this is my own spawned window — nothing else was touched."
    )

    before = _notepad_hwnds()
    proc = subprocess.Popen(["notepad.exe"])  # noqa: F841 — handoff may reparent; we pin by HWND
    mine = None
    for _ in range(20):
        time.sleep(0.4)
        new = _notepad_hwnds() - before
        if len(new) == 1:
            mine = next(iter(new))
            break
        if len(new) > 1:
            print(f"REFUSED: {len(new)} new Notepad windows appeared; cannot disambiguate. No write.")
            return 3
    if not mine:
        print("REFUSED: no single new Notepad window appeared (opened as a tab?). No write.")
        return 3

    comtypes.client.GetModule("UIAutomationCore.dll")
    from comtypes.gen import UIAutomationClient as UIA  # type: ignore

    uia = comtypes.client.CreateObject(CLSID_CUIAutomation, interface=UIA.IUIAutomation)
    el = uia.ElementFromHandle(mine)

    # Defense in depth: confirm the UIA element really is the window we pinned.
    if int(el.CurrentNativeWindowHandle or 0) != mine:
        print(f"REFUSED: UIA element handle != pinned hwnd {mine}. No write.")
        return 3

    val_cond = uia.CreatePropertyCondition(UIA_IsValuePatternAvailablePropertyId, True)
    ve = el.FindFirst(TreeScope_Descendants, val_cond)
    if not ve:
        print(f"PARTIAL: pinned hwnd={mine} exposes no ValuePattern element; not writing.")
        return 1
    vp = ve.GetCurrentPattern(UIA_ValuePatternId).QueryInterface(UIA.IUIAutomationValuePattern)
    vp.SetValue(text)
    time.sleep(0.4)

    back = _read_back(el, uia, UIA)
    ok = bool(back) and text[:24] in back
    print(f"{'PASS' if ok else 'PARTIAL'}: wrote to MY pinned hwnd={mine} ONLY; "
          f"read-back verified={ok}; back={back[:90]!r}")
    print("(window left open for inspection — it is the only window this process touched)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
