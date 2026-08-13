"""Enterprise target guard for safe window injection.

Lesson from the 2026-06-16 Notepad overwrite: an allow-flag answers "may I write?" but
NOT "am I writing to the RIGHT window?". This verifies the live target first.

Drop into send_text / MCP send paths:
    rpt = verify_target(hwnd, expect_pid=..., expect_exe="WindowsTerminal.exe",
                        expect_title_substr="codex 1")
    if not rpt["ok"]:
        return refuse(rpt["reasons"])
    # ... safe to inject ...

Key gate: WM_CHAR injection is only valid for ConPTY terminals, so a non-terminal class
is refused — that alone would have blocked the Notepad incident.

Demo / proof:  python target_guard.py <hwnd> [<hwnd> ...]
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import os

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ConPTY / terminal classes where background WM_CHAR injection is valid and meaningful.
TERMINAL_CLASSES = {
    "CASCADIA_HOSTING_WINDOW_CLASS",  # Windows Terminal
    "ConsoleWindowClass",             # conhost / classic console
    "PseudoConsoleWindow",
    "mintty",
}

# OS-reported executable image required for spoofable class names.
# Any process can call RegisterClassExW with any name, so GetClassNameW alone
# is NOT a security gate.  QueryFullProcessImageNameW returns the kernel's
# image path. This resists a class-name/basename spoof from a user-writable
# directory; it is not cryptographic process identity and does not cover a
# compromised trusted binary, protected directory, administrator, or kernel.
# Enforcement: when require_terminal=True and the class appears in this map,
# the owning exe MUST match (case-insensitive) — no exceptions.
TERMINAL_CLASS_TO_EXE: dict[str, frozenset[str]] = {
    "CASCADIA_HOSTING_WINDOW_CLASS": frozenset({"WindowsTerminal.exe"}),
    "ConsoleWindowClass": frozenset({"cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe"}),
}


def _class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def _title(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    if not n:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def _pid(hwnd: int) -> int:
    p = wt.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
    return p.value


def _exe_path(pid: int) -> str:
    h = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(512)
        sz = wt.DWORD(512)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(sz)):
            return buf.value
        return ""
    finally:
        kernel32.CloseHandle(h)


def _exe(pid: int) -> str:
    return os.path.basename(_exe_path(pid))


def _trusted_terminal_image(window_class: str, exe_path: str) -> bool:
    """Validate terminal images against protected installation roots."""
    if not exe_path:
        return False
    normalized = os.path.normcase(os.path.abspath(exe_path))
    name = os.path.basename(normalized)
    allowed_names = {item.lower() for item in TERMINAL_CLASS_TO_EXE.get(window_class, ())}
    if name.lower() not in allowed_names:
        return False

    windir = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
    program_files = os.path.normcase(os.environ.get("ProgramFiles", r"C:\Program Files"))
    if window_class == "CASCADIA_HOSTING_WINDOW_CLASS":
        windows_apps = os.path.normcase(os.path.join(program_files, "WindowsApps") + os.sep)
        relative = normalized[len(windows_apps):] if normalized.startswith(windows_apps) else ""
        package = relative.split(os.sep, 1)[0].lower()
        return package.startswith(("microsoft.windowsterminal_", "microsoft.windowsterminalpreview_"))

    trusted_console_images = {
        os.path.normcase(os.path.join(windir, "System32", "cmd.exe")),
        os.path.normcase(os.path.join(windir, "System32", "conhost.exe")),
        os.path.normcase(
            os.path.join(windir, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        ),
    }
    powershell_root = os.path.normcase(os.path.join(program_files, "PowerShell") + os.sep)
    return normalized in trusted_console_images or (
        name.lower() == "pwsh.exe" and normalized.startswith(powershell_root)
    )


def _session(pid: int) -> int:
    sid = wt.DWORD(0)
    return sid.value if kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)) else -1


def _own_pid() -> int:
    return kernel32.GetCurrentProcessId()


def verify_target(
    hwnd: int,
    *,
    expect_pid: int | None = None,
    expect_exe: str | None = None,
    expect_exe_path: str | None = None,
    expect_class: str | None = None,
    expect_title_substr: str | None = None,
    expect_title_sha256: str | None = None,
    allow_classes: set[str] = TERMINAL_CLASSES,
    require_terminal: bool = True,
    own_pid: int | None = None,
) -> dict:
    """Return a report dict. `ok` is True only if every applicable gate passes.

    Report fields: hwnd, valid, visible, pid, exe, class, title, session_id, own_pid,
    is_self, is_terminal, ok, reasons (list of refusal strings).

    Gates (any failure -> ok=False, reason recorded):
      - valid            window must exist (IsWindow)
      - not is_self      never inject into our own console
      - is_terminal      class must be a ConPTY terminal (unless require_terminal=False)
      - expect_*         if the caller asserts pid/exe/class/title, the LIVE window must
                         still match (defeats stale-hwnd reuse after a tab closed/reopened)
    """
    hwnd = int(hwnd)
    own_pid = own_pid if own_pid is not None else _own_pid()
    valid = bool(user32.IsWindow(hwnd))
    rpt: dict = {"hwnd": hwnd, "valid": valid, "ok": False, "reasons": []}
    if not valid:
        rpt["reasons"].append("hwnd is not a live window")
        return rpt

    pid = _pid(hwnd)
    cls = _class_name(hwnd)
    title = _title(hwnd)
    exe_path = _exe_path(pid)
    exe = os.path.basename(exe_path)
    rpt.update({
        "visible": bool(user32.IsWindowVisible(hwnd)),
        "pid": pid, "exe": exe, "exe_path": exe_path, "class": cls, "title": title,
        "session_id": _session(pid), "own_pid": own_pid,
        "is_self": pid == own_pid,
        "is_terminal": cls in allow_classes,
    })

    r = rpt["reasons"]
    if rpt["is_self"]:
        r.append("target is my own console (refuse self-injection)")
    if require_terminal and not rpt["is_terminal"]:
        r.append(f"class {cls!r} is not a ConPTY terminal (WM_CHAR inject unsafe here)")
    if require_terminal and rpt["is_terminal"]:
        if cls not in TERMINAL_CLASS_TO_EXE:
            r.append(
                f"class {cls!r} has no protected executable-path policy — refused"
            )
        elif not _trusted_terminal_image(cls, exe_path):
            required_exe = sorted(TERMINAL_CLASS_TO_EXE[cls])
            r.append(
                f"class {cls!r} requires a protected path for one of {required_exe!r} but "
                f"owning image is {exe_path!r} — possible class-name spoof (WRAITH-001)"
            )
    if expect_pid is not None and pid != expect_pid:
        r.append(f"pid {pid} != expected {expect_pid} (stale hwnd?)")
    if expect_exe is not None and exe.lower() != expect_exe.lower():
        r.append(f"exe {exe!r} != expected {expect_exe!r}")
    if expect_exe_path is not None:
        actual_path = os.path.normcase(os.path.abspath(exe_path)) if exe_path else ""
        expected_path = os.path.normcase(os.path.abspath(expect_exe_path))
        if actual_path != expected_path:
            r.append(f"exe_path {exe_path!r} != expected {expect_exe_path!r}")
    if expect_class is not None and cls != expect_class:
        r.append(f"class {cls!r} != expected {expect_class!r}")
    if expect_title_substr is not None and expect_title_substr.lower() not in title.lower():
        r.append(f"title {title!r} missing expected substring {expect_title_substr!r}")
    if expect_title_sha256 is not None:
        title_sha256 = hashlib.sha256(title.encode("utf-8")).hexdigest()
        if title_sha256 != expect_title_sha256:
            r.append("title hash does not match the expected target binding")

    rpt["ok"] = not r
    return rpt


def assert_safe_target(hwnd: int, **kw) -> dict:
    """Raise PermissionError unless the target passes every gate; else return the report."""
    rpt = verify_target(hwnd, **kw)
    if not rpt["ok"]:
        raise PermissionError(f"unsafe target hwnd={hwnd}: {'; '.join(rpt['reasons'])}")
    return rpt


if __name__ == "__main__":
    import json
    import sys

    for a in sys.argv[1:]:
        print(json.dumps(verify_target(int(a, 0)), indent=2, default=str))
