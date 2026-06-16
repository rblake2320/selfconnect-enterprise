"""Reusable UIA TextPattern read + TextChanged subscription.

The read-channel path proven in uia_read.py, extracted for chained_channel.py (RMC).

KEY GOTCHA (this cost me a bad result earlier):
  The terminal's TOP-LEVEL window (CASCADIA_HOSTING_WINDOW_CLASS) does NOT expose
  TextPattern. You MUST descend to the "Text Area" descendant. Locate it by
  IsTextPatternAvailable over TreeScope_Descendants, then pick the descendant whose
  DocumentRange has the LONGEST text (the scrollback). The FIRST match is usually a
  header/title element — calling TextPattern there returns the tab title, not output.

  We use IUIAutomationTextPattern (v1). TextPattern2 is NOT required for delta reads —
  diff successive DocumentRange.GetText() snapshots instead (compute_delta below).

Importable API:
  uia, UIA      = get_uia()
  text_el       = text_element(uia, UIA, hwnd)          # the Text Area, or None
  s             = read_text(uia, UIA, text_el)          # full scrollback string
  handler       = register_textchanged(uia, UIA, text_el, on_change)  # push events
  delta         = compute_delta(old_s, new_s)           # appended text since last read

Demo:  python uia_textpattern.py <hwnd>
"""
from __future__ import annotations

import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import comtypes
import comtypes.client

CLSID_CUIAutomation = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}"
UIA_TextPatternId = 10014
UIA_IsTextPatternAvailablePropertyId = 30040
UIA_Text_TextChangedEventId = 20015
TreeScope_Descendants = 4
TreeScope_Subtree = 7


def get_uia():
    """Create the IUIAutomation root object (binds UIAutomationCore.dll via comtypes)."""
    comtypes.client.GetModule("UIAutomationCore.dll")
    from comtypes.gen import UIAutomationClient as UIA  # type: ignore

    uia = comtypes.client.CreateObject(CLSID_CUIAutomation, interface=UIA.IUIAutomation)
    return uia, UIA


def text_element(uia, UIA, hwnd: int):
    """Return the descendant element exposing TextPattern with the MOST text.

    For Windows Terminal that's the Text Area (scrollback). Returns None if the
    window exposes no readable TextPattern element.
    """
    el = uia.ElementFromHandle(hwnd)
    cond = uia.CreatePropertyCondition(UIA_IsTextPatternAvailablePropertyId, True)
    found = el.FindAll(TreeScope_Descendants, cond)
    best = None
    best_len = -1
    for i in range(found.Length):
        cand = found.GetElement(i)
        try:
            tp = cand.GetCurrentPattern(UIA_TextPatternId).QueryInterface(
                UIA.IUIAutomationTextPattern
            )
            n = len(tp.DocumentRange.GetText(-1) or "")
        except Exception:  # noqa: BLE001
            continue
        if n > best_len:
            best_len = n
            best = cand
    return best


def read_text(uia, UIA, element, limit: int = -1) -> str:
    """Full text of an element's DocumentRange (limit=-1 = entire buffer)."""
    tp = element.GetCurrentPattern(UIA_TextPatternId).QueryInterface(
        UIA.IUIAutomationTextPattern
    )
    return tp.DocumentRange.GetText(limit) or ""


def register_textchanged(uia, UIA, element, on_change):
    """Subscribe to TextChanged on `element`. `on_change(sender)` fires on change.

    The caller MUST run a COM message pump (e.g. pythoncom.PumpWaitingMessages() in a
    loop) to actually receive callbacks. Keep the returned handler referenced; remove
    with uia.RemoveAutomationEventHandler(UIA_Text_TextChangedEventId, element, handler).
    """
    class _Handler(comtypes.COMObject):
        _com_interfaces_ = [UIA.IUIAutomationEventHandler]

        def IUIAutomationEventHandler_HandleAutomationEvent(self, sender, event_id):
            try:
                on_change(sender)
            except Exception:  # noqa: BLE001
                pass
            return 0

    handler = _Handler()
    uia.AddAutomationEventHandler(
        UIA_Text_TextChangedEventId, element, TreeScope_Subtree, None, handler
    )
    return handler


def compute_delta(old: str, new: str) -> str:
    """Appended text if `new` extends `old`; otherwise the full `new` (buffer rolled)."""
    return new[len(old):] if new.startswith(old) else new


_CTRL_TYPES = {
    50004: "Edit", 50020: "Text", 50033: "Pane", 50036: "Document", 50032: "Window",
}

if __name__ == "__main__":
    hwnd = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    uia, UIA = get_uia()
    el = text_element(uia, UIA, hwnd) if hwnd else None
    if not el:
        print("no TextPattern element found")
    else:
        ct = el.CurrentControlType
        print(f"element: ControlType={_CTRL_TYPES.get(ct, ct)}({ct}) "
              f"Name={el.CurrentName!r} Class={el.CurrentClassName!r} "
              f"AutomationId={el.CurrentAutomationId!r}")
        txt = read_text(uia, UIA, el)
        print(f"text_len={len(txt)} tail={txt[-200:]!r}")
