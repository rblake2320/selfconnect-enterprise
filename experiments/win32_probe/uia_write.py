"""POC: structured WRITE/inject channel — the other half of the SelfConnect loop.

Finds Notepad windows and types text into them, trying methods in order:
  1. UIA ValuePattern.SetValue   (structured write — the alternate-embodiment inject)
  2. WM_SETTEXT to an edit child  (classic Win32)
  3. WM_CHAR PostMessage loop     (the original SelfConnect SDK injection method)
Then reads the text back via TextPattern to verify — closing the read+write loop
on the same window.

Run:  python experiments/win32_probe/uia_write.py "text to type"
"""
from __future__ import annotations

import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import comtypes
import comtypes.client
import win32api
import win32con
import win32gui

CLSID_CUIAutomation = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}"
UIA_ValuePatternId = 10002
UIA_TextPatternId = 10014
UIA_IsValuePatternAvailablePropertyId = 30043
TreeScope_Children = 2
TreeScope_Descendants = 4


def _load_uia():
    comtypes.client.GetModule("UIAutomationCore.dll")
    from comtypes.gen import UIAutomationClient as UIA  # type: ignore

    uia = comtypes.client.CreateObject(CLSID_CUIAutomation, interface=UIA.IUIAutomation)
    return uia, UIA


def _read_back(el, UIA) -> str | None:
    try:
        unk = el.GetCurrentPattern(UIA_TextPatternId)
        if unk:
            tp = unk.QueryInterface(UIA.IUIAutomationTextPattern)
            txt = tp.DocumentRange.GetText(400)
            return txt
    except Exception:  # noqa: BLE001
        pass
    # descend to first TextPattern element
    try:
        return None
    except Exception:  # noqa: BLE001
        return None


def _child_classes(hwnd: int) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []

    def cb(h, _):
        try:
            out.append((h, win32gui.GetClassName(h)))
        except Exception:  # noqa: BLE001
            pass
        return True

    try:
        win32gui.EnumChildWindows(hwnd, cb, None)
    except Exception:  # noqa: BLE001
        pass
    return out


def _wm_char_inject(hwnd: int, text: str) -> None:
    for ch in text:
        win32api.PostMessage(hwnd, win32con.WM_CHAR, ord(ch), 0)
        time.sleep(0.005)


def main() -> int:
    text = sys.argv[1] if len(sys.argv) > 1 else (
        "[SelfConnect inject test] typed via UIA/WM_CHAR — not the keyboard."
    )
    uia, UIA = _load_uia()
    root = uia.GetRootElement()
    true_cond = uia.CreateTrueCondition()
    val_cond = uia.CreatePropertyCondition(UIA_IsValuePatternAvailablePropertyId, True)

    kids = root.FindAll(TreeScope_Children, true_cond)
    targets = []
    for i in range(kids.Length):
        el = kids.GetElement(i)
        try:
            name = el.CurrentName or ""
            cls = el.CurrentClassName or ""
            hwnd = int(el.CurrentNativeWindowHandle or 0)
        except Exception:  # noqa: BLE001
            continue
        nl = name.lower()
        if "notepad" in nl or "untitled" in nl or cls in ("Notepad", "ApplicationFrameWindow"):
            targets.append((el, name, cls, hwnd))

    if not targets:
        print("No Notepad windows found via UIA. Open one and retry.")
        return 1

    print(f"Found {len(targets)} Notepad window(s):")
    for idx, (el, name, cls, hwnd) in enumerate(targets):
        print(f"\n--- window #{idx}: {name!r} class={cls!r} hwnd={hwnd} ---")
        children = _child_classes(hwnd)
        if children:
            print(f"    child controls: {[c for _, c in children][:8]}")

        wrote_via = None

        # Method 1: UIA ValuePattern.SetValue on a descendant that supports it
        try:
            ve = el.FindFirst(TreeScope_Descendants, val_cond)
            if ve:
                vp = ve.GetCurrentPattern(UIA_ValuePatternId).QueryInterface(
                    UIA.IUIAutomationValuePattern
                )
                vp.SetValue(text)
                wrote_via = "UIA ValuePattern.SetValue"
        except Exception as e:  # noqa: BLE001
            print(f"    ValuePattern write failed: {type(e).__name__}: {e}")

        # Method 2: WM_SETTEXT to an edit-like child
        if not wrote_via:
            for h, c in children:
                if any(k in c for k in ("Edit", "RichEdit", "RICHEDIT")):
                    try:
                        win32api.SendMessage(h, win32con.WM_SETTEXT, 0, text)
                        wrote_via = f"WM_SETTEXT -> {c}"
                        break
                    except Exception:  # noqa: BLE001
                        continue

        # Method 3: WM_CHAR injection (original SelfConnect SDK method)
        if not wrote_via:
            edit_h = next(
                (h for h, c in children if any(k in c for k in ("Edit", "RichEdit", "RICHEDIT"))),
                hwnd,
            )
            try:
                _wm_char_inject(edit_h, text)
                wrote_via = f"WM_CHAR loop -> hwnd {edit_h}"
            except Exception as e:  # noqa: BLE001
                print(f"    WM_CHAR inject failed: {e}")

        time.sleep(0.4)
        back = _read_back(el, UIA)
        ok = bool(back and text.split("]")[0] in back) if back else False
        print(f"    wrote via: {wrote_via}")
        print(f"    read-back via TextPattern: {(back or '')[:120]!r}")
        print(f"    VERIFIED loop: {ok}")

    return 0


if __name__ == "__main__":
    # QUARANTINED 2026-06-16. This version selected target windows by TITLE SUBSTRING
    # ("Untitled"/"Notepad") and called ValuePattern.SetValue on EVERY match, which
    # overwrote the in-memory contents of unrelated user Notepad windows. Nothing was
    # saved to disk, but this must not run again until rewritten to pin a SINGLE window
    # by the spawned process PID/HWND and refuse to write to any window it didn't create.
    # See NEXT_STEPS.md, item 1.
    print(
        "QUARANTINED: uia_write.py is disabled pending the PID/HWND-pin rewrite. "
        "See experiments/win32_probe/NEXT_STEPS.md."
    )
    sys.exit(2)
    # sys.exit(main())  # re-enable ONLY after the safe-targeting rewrite
