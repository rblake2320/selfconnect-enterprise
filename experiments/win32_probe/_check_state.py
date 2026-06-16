"""READ-ONLY: report the current document text of every Notepad window.

No writes. Used to verify whether a prior write clobbered real content.
For each Notepad window, finds every descendant exposing TextPattern and prints
the longest non-empty text (that's the document body).
"""
from __future__ import annotations

import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import comtypes
import comtypes.client

CLSID = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}"
UIA_TextPatternId = 10014
UIA_IsTextPatternAvailablePropertyId = 30040
TreeScope_Children = 2
TreeScope_Descendants = 4

comtypes.client.GetModule("UIAutomationCore.dll")
from comtypes.gen import UIAutomationClient as UIA  # type: ignore  # noqa: E402

uia = comtypes.client.CreateObject(CLSID, interface=UIA.IUIAutomation)
root = uia.GetRootElement()
true_cond = uia.CreateTrueCondition()
text_cond = uia.CreatePropertyCondition(UIA_IsTextPatternAvailablePropertyId, True)


def read_el(el) -> str:
    try:
        unk = el.GetCurrentPattern(UIA_TextPatternId)
        if not unk:
            return ""
        tp = unk.QueryInterface(UIA.IUIAutomationTextPattern)
        return tp.DocumentRange.GetText(2000) or ""
    except Exception:  # noqa: BLE001
        return ""


kids = root.FindAll(TreeScope_Children, true_cond)
for i in range(kids.Length):
    el = kids.GetElement(i)
    try:
        name = el.CurrentName or ""
        cls = el.CurrentClassName or ""
    except Exception:  # noqa: BLE001
        continue
    if cls != "Notepad" and "notepad" not in name.lower():
        continue
    # collect all TextPattern descendants, pick the longest body
    bodies = []
    try:
        found = el.FindAll(TreeScope_Descendants, text_cond)
        for j in range(found.Length):
            t = read_el(found.GetElement(j))
            if t.strip():
                bodies.append(t)
    except Exception:  # noqa: BLE001
        pass
    body = max(bodies, key=len) if bodies else ""
    print(f"\n=== {name!r} (class={cls}) ===")
    print(f"    body_len={len(body)}  preview={body[:160]!r}")
