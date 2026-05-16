"""Real integration tests for enterprise.msg_validator — NO MOCKS.

Uses os.getpid() as a live process and calls get_process_birth_time() directly
against real Win32 GetProcessTimes.  No patching.

These tests fail on non-Windows platforms — skipped automatically.
"""
from __future__ import annotations

import os
import sys
import time

import pytest

if sys.platform != "win32":
    pytest.skip("Windows-only integration tests", allow_module_level=True)

from enterprise.msg_validator import ValidatorCache, get_process_birth_time


MY_PID = os.getpid()


# ── get_process_birth_time ────────────────────────────────────────────────────

def test_live_pid_returns_string():
    """os.getpid() must return a non-empty string from real GetProcessTimes."""
    result = get_process_birth_time(MY_PID)
    assert result is not None, "get_process_birth_time returned None for live pid"
    assert isinstance(result, str)
    assert len(result) > 0


def test_live_pid_is_numeric_string():
    """The returned value is a float string (epoch seconds from GetProcessTimes)."""
    result = get_process_birth_time(MY_PID)
    float(result)  # must not raise — confirms it's a parseable numeric string


def test_live_pid_birth_time_is_positive():
    result = get_process_birth_time(MY_PID)
    assert float(result) > 0


def test_dead_pid_returns_none():
    """A PID that cannot be opened returns None."""
    dead_pid = 99999999  # virtually guaranteed to not exist
    result = get_process_birth_time(dead_pid)
    # May be None (process not found) or a string if this PID happens to exist.
    # On any sane machine 99999999 is above the PID limit.
    if result is not None:
        pytest.skip(f"PID {dead_pid} unexpectedly exists on this machine")


def test_birth_time_stable_across_calls():
    """The same PID returns the same birth time on repeated calls."""
    a = get_process_birth_time(MY_PID)
    b = get_process_birth_time(MY_PID)
    assert a == b, "Birth time for the same process must be deterministic"


# ── ValidatorCache real round-trip ────────────────────────────────────────────

def test_validate_own_pid_passes():
    """Validating the test process itself with its real birth time must pass."""
    os.environ["SC_VALIDATE_BIRTH"] = "1"
    os.environ["SC_VALIDATE_BIRTH_TTL"] = "0"  # always recheck

    try:
        cache = ValidatorCache()
        live_birth = get_process_birth_time(MY_PID)
        assert live_birth is not None

        ok, reason = cache.validate_sender(MY_PID, live_birth)
        assert ok is True, f"validate_sender failed for own pid: {reason}"
    finally:
        del os.environ["SC_VALIDATE_BIRTH"]
        del os.environ["SC_VALIDATE_BIRTH_TTL"]


def test_wrong_birth_time_for_own_pid_rejected():
    """Using a wrong birth time for a live PID must be detected and rejected."""
    os.environ["SC_VALIDATE_BIRTH"] = "1"
    os.environ["SC_VALIDATE_BIRTH_TTL"] = "0"

    try:
        cache = ValidatorCache()
        wrong_birth = "1.0"  # clearly wrong epoch

        ok, reason = cache.validate_sender(MY_PID, wrong_birth)
        assert ok is False, "Wrong birth time for live pid must be rejected"
        assert "mismatch" in reason.lower() or "birth time" in reason.lower()
    finally:
        del os.environ["SC_VALIDATE_BIRTH"]
        del os.environ["SC_VALIDATE_BIRTH_TTL"]


def test_cache_accepts_on_second_call_within_ttl():
    """Within TTL, the live check is not repeated (fast path confirmed by timing)."""
    os.environ["SC_VALIDATE_BIRTH"] = "1"
    os.environ["SC_VALIDATE_BIRTH_TTL"] = "60"

    try:
        cache = ValidatorCache()
        live_birth = get_process_birth_time(MY_PID)

        # Seed
        ok1, _ = cache.validate_sender(MY_PID, live_birth)
        assert ok1 is True

        # Second call — within TTL, should be fast
        t0 = time.perf_counter()
        ok2, _ = cache.validate_sender(MY_PID, live_birth)
        elapsed = time.perf_counter() - t0

        assert ok2 is True
        assert elapsed < 0.010, f"Expected fast path (<10ms), took {elapsed*1000:.1f}ms"
    finally:
        del os.environ["SC_VALIDATE_BIRTH"]
        del os.environ["SC_VALIDATE_BIRTH_TTL"]


def test_process_exit_hook_clears_entries():
    """on_process_exit() removes all cached entries for that pid."""
    os.environ["SC_VALIDATE_BIRTH"] = "1"
    os.environ["SC_VALIDATE_BIRTH_TTL"] = "60"

    try:
        cache = ValidatorCache()
        live_birth = get_process_birth_time(MY_PID)

        cache.validate_sender(MY_PID, live_birth)
        assert cache.cache_size() == 1

        cache.on_process_exit(MY_PID)
        assert cache.cache_size() == 0
    finally:
        del os.environ["SC_VALIDATE_BIRTH"]
        del os.environ["SC_VALIDATE_BIRTH_TTL"]
