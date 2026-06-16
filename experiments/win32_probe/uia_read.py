"""POC: structured read channel via UI Automation (UIA) — the alternate to PrintWindow.

The shipped read channel is PrintWindow() -> bitmap -> pixel parse. This probe proves
the semantic alternative: enumerate top-level windows through UIA (a structured session
registry, no fragile FindWindow), read a window's *text content as a string* via
TextPattern (no screenshot, no OCR), and register a UIA automation-event handler
(the basis for push-based "reply is ready" detection instead of a polling/screenshot loop).

Patent relevance
----------------
A distinct read-channel embodiment: injection + *semantic structured read* replaces
injection + *visual scrape*. Worth documenting as an alternate embodiment in the IP.

Uses comtypes to bind UIAutomationCore.dll (already installed; no new dependency).

Run:  python experiments/win32_probe/uia_read.py
Exit: 0 = PASS (enumerated + read structured text + registered event),
      1 = partial, 3 = FAIL (UIA unavailable)
"""
from __future__ import annotations

import subprocess
import sys
import time

# Window/terminal text can contain glyphs the legacy console codepage can't encode.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

try:
    import comtypes
    import comtypes.client
except Exception as e:  # noqa: BLE001
    print(f"FAIL: comtypes unavailable: {e}")
    sys.exit(3)

CLSID_CUIAutomation = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}"
UIA_TextPatternId = 10014
UIA_IsTextPatternAvailablePropertyId = 30040
TreeScope_Children = 2
TreeScope_Descendants = 4

CONSOLE_CLASSES = {
    "ConsoleWindowClass",             # conhost / classic console
    "CASCADIA_HOSTING_WINDOW_CLASS",  # Windows Terminal
    "PseudoConsoleWindow",
    "mintty",
}


def _load_uia():
    comtypes.client.GetModule("UIAutomationCore.dll")
    from comtypes.gen import UIAutomationClient as UIA  # type: ignore

    uia = comtypes.client.CreateObject(CLSID_CUIAutomation, interface=UIA.IUIAutomation)
    return uia, UIA


def _read_text(el, UIA, limit: int = 240) -> str | None:
    """Read up to `limit` chars from an element's own TextPattern, or None."""
    try:
        unk = el.GetCurrentPattern(UIA_TextPatternId)
        if not unk:
            return None
        tp = unk.QueryInterface(UIA.IUIAutomationTextPattern)
        txt = tp.DocumentRange.GetText(limit)
        return txt if txt and txt.strip() else None
    except Exception:  # noqa: BLE001
        return None


def _deep_read(el, uia, UIA) -> str | None:
    """Read text from `el`, descending to the first descendant exposing TextPattern."""
    direct = _read_text(el, UIA)
    if direct:
        return direct
    try:
        cond = uia.CreatePropertyCondition(UIA_IsTextPatternAvailablePropertyId, True)
        target = el.FindFirst(TreeScope_Descendants, cond)
        if target:
            return _read_text(target, UIA)
    except Exception:  # noqa: BLE001
        return None
    return None


def main() -> int:
    try:
        uia, UIA = _load_uia()
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: could not initialize UI Automation: {e}")
        return 3

    root = uia.GetRootElement()
    true_cond = uia.CreateTrueCondition()
    kids = root.FindAll(TreeScope_Children, true_cond)
    n = kids.Length
    print(f"UIA enumerated {n} top-level windows (structured registry, no FindWindow):")

    consoles = []  # (class, name, element)
    for i in range(n):
        el = kids.GetElement(i)
        try:
            name = el.CurrentName or ""
            cls = el.CurrentClassName or ""
        except Exception:  # noqa: BLE001
            continue
        if cls in CONSOLE_CLASSES or any(
            k in name.lower() for k in ("powershell", "terminal", "cmd", "command prompt")
        ):
            consoles.append((cls, name, el))

    print(f"  terminal/console windows visible to UIA: {len(consoles)}")

    readable = 0
    samples: list[str] = []
    for cls, name, el in consoles[:4]:
        txt = _deep_read(el, uia, UIA)
        status = "READ" if txt else "no-text"
        print(f"    [{status}] {cls} :: {name[:48]!r}")
        if txt:
            readable += 1
            if len(samples) < 3:
                flat = " ".join(txt.split())
                samples.append(f"        -> {flat[:90]!r}")

    # Controlled demonstration: launch Notepad, read its document text via TextPattern.
    np_text = None
    proc = None
    try:
        proc = subprocess.Popen(["notepad.exe"])
        time.sleep(1.2)
        np = None
        for _ in range(12):
            kk = root.FindAll(TreeScope_Children, true_cond)
            for i in range(kk.Length):
                el = kk.GetElement(i)
                try:
                    nm = (el.CurrentName or "").lower()
                    cl = el.CurrentClassName or ""
                except Exception:  # noqa: BLE001
                    continue
                if "notepad" in nm or "untitled" in nm or cl == "Notepad":
                    np = el
                    break
            if np:
                break
            time.sleep(0.3)
        if np is not None:
            np_text = _deep_read(np, uia, UIA)
            print(f"  Notepad found via UIA; structured read returned: {(np_text or '')[:60]!r}")
        else:
            print("  (Notepad window not located via UIA)")
    except Exception as e:  # noqa: BLE001
        print(f"  (notepad demonstration skipped: {e})")
    finally:
        if proc is not None:
            proc.terminate()

    # Event subscription path (push-based reply detection). Register + immediately
    # remove a focus-changed handler to prove the API works without blocking on delivery.
    event_ok = False
    try:
        class _Handler(comtypes.COMObject):
            _com_interfaces_ = [UIA.IUIAutomationFocusChangedEventHandler]

            def IUIAutomationFocusChangedEventHandler_HandleFocusChangedEvent(self, sender):
                return 0

        handler = _Handler()
        uia.AddFocusChangedEventHandler(None, handler)
        uia.RemoveFocusChangedEventHandler(handler)
        event_ok = True
        print("  UIA event handler registered + removed OK (push-notification path available).")
    except Exception as e:  # noqa: BLE001
        print(f"  (event-handler registration failed: {e})")

    total_readable = readable + (1 if np_text else 0)
    if total_readable:
        print(
            f"PASS: structured enumeration ({n} windows), structured text read "
            f"({total_readable} targets read via TextPattern, no pixels), event API: {event_ok}."
        )
        for s in samples:
            print(s)
        return 0
    print(f"PARTIAL: enumerated {n} windows but no TextPattern read succeeded. event API: {event_ok}.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
