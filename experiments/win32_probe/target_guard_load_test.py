"""target_guard_load_test.py — CRUCIBLE rapid-fire load test for target_guard.py

Tests:
  0. _own_pid() returns the correct non-zero PID (WRAITH-002 guard-bypass fix)
  1. Enumerate all live windows via EnumWindows
  2. Call verify_target() on every HWND — expect no exceptions, only ok/not-ok
  3. Run the full window list 3 times and verify deterministic results
  4. Verify no access violations or exceptions on any valid HWND
  5. Graceful refusal for invalid HWNDs: 0, 1, 999999999
  6. WRAITH-001: class-name spoof detection — terminal class owned by a
     non-matching exe must be refused; legitimate owner must pass.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import sys
import time
import traceback
import unittest.mock

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
if __package__:
    from . import target_guard
    from .target_guard import _own_pid, verify_target
else:  # Direct-script compatibility.
    import target_guard
    from target_guard import _own_pid, verify_target  # noqa: E402  (same directory)

user32 = ctypes.windll.user32

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)


def enum_windows() -> list[int]:
    """Return a list of all top-level HWNDs from EnumWindows."""
    hwnds: list[int] = []

    def _cb(hwnd: int, _lparam: int) -> bool:
        hwnds.append(hwnd)
        return True  # keep enumerating

    cb = EnumWindowsProc(_cb)
    if not user32.EnumWindows(cb, 0):
        err = ctypes.GetLastError()
        # EnumWindows sets last-error only on hard failure; callback returning
        # False will also set it (but we always return True above).  A non-zero
        # code here is a genuine Win32 error.
        if err:
            raise OSError(f"EnumWindows failed with error {err}")
    return hwnds


# ---------------------------------------------------------------------------
# Test primitives
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

results: list[dict] = []


def record(name: str, verdict: str, detail: str = "") -> None:
    results.append({"name": name, "verdict": verdict, "detail": detail})
    marker = "  [PASS]" if verdict == PASS else ("  [SKIP]" if verdict == SKIP else "  [FAIL]")
    line = f"{marker} {name}"
    if detail:
        line += f" — {detail}"
    print(line)


# ---------------------------------------------------------------------------
# Test 1 + 2: enumerate live windows, call verify_target on each
# ---------------------------------------------------------------------------

def _run_once(hwnds: list[int]) -> dict[int, dict]:
    """Call verify_target on every HWND; return {hwnd: report}. Never raises."""
    reports: dict[int, dict] = {}
    for hwnd in hwnds:
        try:
            rpt = verify_target(hwnd)
            # Structural contract: report must have these keys
            required = {"hwnd", "valid", "ok", "reasons"}
            missing = required - rpt.keys()
            if missing:
                raise AssertionError(f"report missing keys {missing}")
            reports[hwnd] = rpt
        except Exception:
            reports[hwnd] = {"hwnd": hwnd, "_exception": traceback.format_exc()}
    return reports


def test_own_pid_non_console() -> None:
    """Test 0 (WRAITH-002): _own_pid() must never return 0.

    GetConsoleWindow() returns NULL for pythonw.exe, pytest workers, background
    services, and any process that has called FreeConsole().  Before the fix,
    _own_pid() returned 0 in those cases, silently disabling the self-injection
    guard.  After the fix it uses GetCurrentProcessId(), which always returns
    the real PID regardless of console attachment.
    """
    pid = _own_pid()
    expected = os.getpid()
    if pid == 0:
        record(
            "own_pid_non_zero",
            FAIL,
            "_own_pid() returned 0 — guard-bypass regression (WRAITH-002)",
        )
    elif pid != expected:
        record(
            "own_pid_matches_os_getpid",
            FAIL,
            f"_own_pid()={pid} != os.getpid()={expected}",
        )
    else:
        record(
            "own_pid_non_zero",
            PASS,
            f"_own_pid()={pid} == os.getpid()={expected} (guard active for all process types)",
        )


def test_enumerate_and_call() -> tuple[list[int], dict[int, dict]]:
    """Test 1 & 2: EnumWindows + verify_target on every HWND."""
    try:
        hwnds = enum_windows()
    except Exception as exc:
        record("EnumWindows", FAIL, str(exc))
        return [], {}

    record("EnumWindows", PASS, f"found {len(hwnds)} top-level windows")

    if not hwnds:
        record("verify_target_all_hwnds", SKIP, "no windows to test")
        return [], {}

    exceptions: list[str] = []
    run1 = _run_once(hwnds)

    for hwnd, rpt in run1.items():
        if "_exception" in rpt:
            exceptions.append(f"hwnd={hwnd}: {rpt['_exception']}")

    if exceptions:
        record(
            "verify_target_all_hwnds",
            FAIL,
            f"{len(exceptions)} exception(s) — first: {exceptions[0][:120]}",
        )
    else:
        record(
            "verify_target_all_hwnds",
            PASS,
            f"all {len(hwnds)} HWNDs handled without exception",
        )

    return hwnds, run1


# ---------------------------------------------------------------------------
# Test 3 + 4: determinism — run 3 times, compare verdicts
# ---------------------------------------------------------------------------

def test_determinism(hwnds: list[int], run1: dict[int, dict]) -> None:
    """Test 3 & 4: same HWND always gives same ok verdict across 3 runs."""
    if not hwnds:
        record("determinism_3_runs", SKIP, "no windows enumerated")
        return

    runs = [run1]
    for i in range(2, 4):
        runs.append(_run_once(hwnds))

    mismatches: list[str] = []
    for hwnd in hwnds:
        verdicts = []
        for run in runs:
            rpt = run.get(hwnd, {})
            if "_exception" in rpt:
                verdicts.append("EXCEPTION")
            else:
                verdicts.append(rpt.get("ok"))
        if len(set(str(v) for v in verdicts)) > 1:
            mismatches.append(f"hwnd={hwnd} verdicts={verdicts}")

    if mismatches:
        record(
            "determinism_3_runs",
            FAIL,
            f"{len(mismatches)} non-deterministic HWND(s) — e.g. {mismatches[0]}",
        )
    else:
        record(
            "determinism_3_runs",
            PASS,
            f"all {len(hwnds)} HWNDs gave identical ok verdict across 3 runs",
        )

    # No access violations / exceptions on any run
    all_exc: list[str] = []
    for run in runs[1:]:
        for hwnd, rpt in run.items():
            if "_exception" in rpt:
                all_exc.append(f"hwnd={hwnd}")

    if all_exc:
        record(
            "no_exceptions_all_runs",
            FAIL,
            f"{len(all_exc)} exception(s) in runs 2+3 — e.g. {all_exc[0]}",
        )
    else:
        record("no_exceptions_all_runs", PASS, "zero exceptions across all 3 runs")


# ---------------------------------------------------------------------------
# Test 5: graceful refusal for bad HWNDs
# ---------------------------------------------------------------------------

INVALID_HWNDS = [0, 1, 999_999_999]


def test_invalid_hwnds() -> None:
    """Test 5: HWND 0, 1, 999999999 must not raise and must return ok=False."""
    failures: list[str] = []
    for hwnd in INVALID_HWNDS:
        try:
            rpt = verify_target(hwnd)
            if rpt.get("ok") is not False:
                failures.append(
                    f"hwnd={hwnd} returned ok={rpt.get('ok')!r} (expected False)"
                )
            elif not rpt.get("reasons"):
                failures.append(
                    f"hwnd={hwnd} returned ok=False but reasons list is empty"
                )
            else:
                record(
                    f"graceful_refusal_hwnd_{hwnd}",
                    PASS,
                    f"ok=False, reasons={rpt['reasons']}",
                )
        except Exception as exc:
            failures.append(f"hwnd={hwnd} raised {type(exc).__name__}: {exc}")

    for fail in failures:
        record("graceful_refusal_invalid_hwnds", FAIL, fail)

    if not failures:
        record(
            "graceful_refusal_summary",
            PASS,
            f"all {len(INVALID_HWNDS)} invalid HWNDs refused cleanly",
        )


# ---------------------------------------------------------------------------
# Test 6: WRAITH-001 — class-name spoof detection
# ---------------------------------------------------------------------------

def test_class_name_spoof_detection() -> None:
    """Test 6 (WRAITH-001): spoofed CASCADIA / ConsoleWindowClass must be refused.

    Any process can register a class with RegisterClassExW using a terminal
    class name.  GetClassNameW returns that user-controlled string verbatim.
    The fix adds TERMINAL_CLASS_TO_EXE enforcement: when require_terminal=True
    and the class is in the map, the owning exe must match the kernel-verified
    binary from QueryFullProcessImageNameW.

    This test patches target_guard._exe_path (the kernel path resolver) and
    target_guard._pid / Win32 APIs so verify_target sees a live-looking window
    owned by an attacker process (e.g. python.exe) carrying a terminal class
    name.  The gate must fire: ok=False with a WRAITH-001 reason.
    """
    # Minimal HWND value that IsWindow() will accept — we mock it to return 1.
    FAKE_HWND = 0x1234

    spoof_cases = [
        (
            "CASCADIA_HOSTING_WINDOW_CLASS",
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe",
            r"C:\Users\Public\WindowsTerminal.exe",
        ),
        (
            "ConsoleWindowClass",
            r"C:\Windows\System32\cmd.exe",
            r"C:\Users\Public\cmd.exe",
        ),
    ]

    failures: list[str] = []

    for cls_name, required_exe, attacker_exe in spoof_cases:
        with (
            unittest.mock.patch.object(target_guard.user32, "IsWindow", return_value=1),
            unittest.mock.patch.object(target_guard.user32, "IsWindowVisible", return_value=1),
            unittest.mock.patch("target_guard._pid", return_value=9999),
            unittest.mock.patch("target_guard._class_name", return_value=cls_name),
            unittest.mock.patch("target_guard._title", return_value="Fake Terminal"),
            unittest.mock.patch("target_guard._exe_path", return_value=attacker_exe),
            unittest.mock.patch("target_guard._session", return_value=1),
            unittest.mock.patch("target_guard._own_pid", return_value=1),
        ):
            rpt = verify_target(FAKE_HWND)

        if rpt.get("ok") is not False:
            failures.append(
                f"cls={cls_name!r} owned by {attacker_exe!r}: expected ok=False,"
                f" got ok={rpt.get('ok')!r}"
            )
            continue

        wraith_reasons = [r for r in rpt.get("reasons", []) if "WRAITH-001" in r]
        if not wraith_reasons:
            failures.append(
                f"cls={cls_name!r} owned by {attacker_exe!r}: ok=False but no"
                f" WRAITH-001 reason — reasons={rpt.get('reasons')}"
            )
            continue

        record(
            f"spoof_refused_{cls_name}",
            PASS,
            f"ok=False, exe {attacker_exe!r} != required {required_exe!r},"
            f" reason recorded",
        )

    # Also verify that a legitimately-owned terminal class passes the exe gate.
    for cls_name, required_exe, _attacker_exe in spoof_cases:
        with (
            unittest.mock.patch.object(target_guard.user32, "IsWindow", return_value=1),
            unittest.mock.patch.object(target_guard.user32, "IsWindowVisible", return_value=1),
            unittest.mock.patch("target_guard._pid", return_value=9998),
            unittest.mock.patch("target_guard._class_name", return_value=cls_name),
            unittest.mock.patch("target_guard._title", return_value="Real Terminal"),
            unittest.mock.patch("target_guard._exe_path", return_value=required_exe),
            unittest.mock.patch("target_guard._session", return_value=1),
            unittest.mock.patch("target_guard._own_pid", return_value=1),
        ):
            rpt = verify_target(FAKE_HWND)

        wraith_reasons = [r for r in rpt.get("reasons", []) if "WRAITH-001" in r]
        if wraith_reasons:
            failures.append(
                f"cls={cls_name!r} legitimately owned by {required_exe!r} was"
                f" wrongly refused: {wraith_reasons}"
            )
        else:
            record(
                f"legitimate_terminal_passes_{cls_name}",
                PASS,
                f"exe={required_exe!r} accepted for class {cls_name!r}",
            )

    for fail in failures:
        record("wraith_001_spoof_detection", FAIL, fail)

    if not failures:
        record(
            "wraith_001_summary",
            PASS,
            "all spoof cases refused; all legitimate cases accepted",
        )


# ---------------------------------------------------------------------------
# Throughput / timing
# ---------------------------------------------------------------------------

def test_throughput(hwnds: list[int]) -> None:
    """Sanity check: 3 full passes finish in < 30 s on a modern system."""
    if not hwnds:
        record("throughput", SKIP, "no windows")
        return
    t0 = time.perf_counter()
    for _ in range(3):
        _run_once(hwnds)
    elapsed = time.perf_counter() - t0
    per_window = elapsed / (3 * len(hwnds)) * 1000  # ms

    verdict = PASS if elapsed < 30 else FAIL
    record(
        "throughput",
        verdict,
        f"3 × {len(hwnds)} windows in {elapsed:.2f}s ({per_window:.2f} ms/call)",
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 70)
    print("CRUCIBLE — target_guard.py load test")
    print("=" * 70)

    test_own_pid_non_console()
    hwnds, run1 = test_enumerate_and_call()
    test_determinism(hwnds, run1)
    test_invalid_hwnds()
    test_class_name_spoof_detection()
    test_throughput(hwnds)

    print()
    print("=" * 70)
    passed = sum(1 for r in results if r["verdict"] == PASS)
    failed = sum(1 for r in results if r["verdict"] == FAIL)
    skipped = sum(1 for r in results if r["verdict"] == SKIP)
    print(f"RESULTS  passed={passed}  failed={failed}  skipped={skipped}")
    print("=" * 70)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
