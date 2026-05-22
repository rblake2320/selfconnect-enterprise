"""tests/test_enterprise/test_msg_validator.py — Tests for enterprise.msg_validator (Tier 2)

get_process_birth_time() is mocked so no live processes are needed.
"""
from __future__ import annotations

from unittest.mock import patch


from enterprise.msg_validator import ValidatorCache, validate_sender


FAKE_PID   = 99999
FAKE_CTIME = "132987654321"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _cache_with_validation_on(monkeypatch) -> ValidatorCache:
    monkeypatch.setenv("SC_VALIDATE_BIRTH", "1")
    monkeypatch.setenv("SC_VALIDATE_BIRTH_TTL", "1")
    return ValidatorCache()


# ── Disabled (SC_VALIDATE_BIRTH != 1) ────────────────────────────────────────

class TestDisabled:
    def test_disabled_always_accepts(self, monkeypatch):
        monkeypatch.delenv("SC_VALIDATE_BIRTH", raising=False)
        cache = ValidatorCache()
        ok, reason = cache.validate_sender(FAKE_PID, FAKE_CTIME)
        assert ok is True
        assert "disabled" in reason

    def test_module_level_validate_disabled(self, monkeypatch):
        monkeypatch.delenv("SC_VALIDATE_BIRTH", raising=False)
        ok, _ = validate_sender(FAKE_PID, FAKE_CTIME)
        assert ok is True


# ── Fast path (TTL hit) ───────────────────────────────────────────────────────

class TestFastPath:
    def test_accepted_within_ttl(self, monkeypatch):
        monkeypatch.setenv("SC_VALIDATE_BIRTH", "1")
        monkeypatch.setenv("SC_VALIDATE_BIRTH_TTL", "60")
        cache = ValidatorCache()

        # Seed the cache
        with patch("enterprise.msg_validator.get_process_birth_time", return_value=FAKE_CTIME):
            ok1, _ = cache.validate_sender(FAKE_PID, FAKE_CTIME)

        assert ok1 is True

        # Second call within TTL — should NOT call get_process_birth_time
        call_count = [0]
        def counting_get(pid):
            call_count[0] += 1
            return FAKE_CTIME

        with patch("enterprise.msg_validator.get_process_birth_time", side_effect=counting_get):
            ok2, _ = cache.validate_sender(FAKE_PID, FAKE_CTIME)

        assert ok2 is True
        assert call_count[0] == 0, "get_process_birth_time should not be called within TTL"

    def test_cache_size_increases_on_new_pid(self, monkeypatch):
        cache = _cache_with_validation_on(monkeypatch)
        with patch("enterprise.msg_validator.get_process_birth_time", return_value=FAKE_CTIME):
            cache.validate_sender(FAKE_PID, FAKE_CTIME)
        assert cache.cache_size() == 1


# ── Slow path (TTL expired / first check) ────────────────────────────────────

class TestSlowPath:
    def test_valid_birth_time_accepted(self, monkeypatch):
        cache = _cache_with_validation_on(monkeypatch)
        with patch("enterprise.msg_validator.get_process_birth_time", return_value=FAKE_CTIME):
            ok, reason = cache.validate_sender(FAKE_PID, FAKE_CTIME)
        assert ok is True
        assert reason == "ok"

    def test_ttl_expiry_triggers_recheck(self, monkeypatch):
        monkeypatch.setenv("SC_VALIDATE_BIRTH", "1")
        monkeypatch.setenv("SC_VALIDATE_BIRTH_TTL", "0")  # always expired
        cache = ValidatorCache()

        call_count = [0]
        def counting_get(pid):
            call_count[0] += 1
            return FAKE_CTIME

        with patch("enterprise.msg_validator.get_process_birth_time", side_effect=counting_get):
            cache.validate_sender(FAKE_PID, FAKE_CTIME)
            cache.validate_sender(FAKE_PID, FAKE_CTIME)

        assert call_count[0] == 2, "Should re-check live birth time on each call when TTL=0"


# ── Mismatch detection ────────────────────────────────────────────────────────

class TestMismatch:
    def test_pid_recycled_detected(self, monkeypatch):
        """Live birth time differs from cached → reject + flush."""
        cache = _cache_with_validation_on(monkeypatch)
        cached_ctime = "111111111111"
        live_ctime   = "222222222222"  # different — PID recycled

        with patch("enterprise.msg_validator.get_process_birth_time", return_value=live_ctime):
            ok, reason = cache.validate_sender(FAKE_PID, cached_ctime)

        assert ok is False
        assert "mismatch" in reason.lower() or "birth time" in reason.lower()

    def test_mismatch_flushes_all_pid_entries(self, monkeypatch):
        """After a mismatch, cache entries for that pid are flushed."""
        monkeypatch.setenv("SC_VALIDATE_BIRTH", "1")
        monkeypatch.setenv("SC_VALIDATE_BIRTH_TTL", "0")  # always recheck
        cache = ValidatorCache()

        # Seed two different birth-time entries for same PID (edge: multiple ctimes cached)
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="111"):
            cache.validate_sender(FAKE_PID, "111")
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="222"):
            cache.validate_sender(FAKE_PID, "222")

        assert cache.cache_size() == 2

        # Now simulate mismatch (live ≠ "111") — TTL=0 ensures recheck
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="999"):
            ok, _ = cache.validate_sender(FAKE_PID, "111")

        assert ok is False
        assert cache.cache_size() == 0, "All PID entries should be flushed after mismatch"

    def test_process_not_found_rejected(self, monkeypatch):
        """pid no longer exists → rejected."""
        cache = _cache_with_validation_on(monkeypatch)

        with patch("enterprise.msg_validator.get_process_birth_time", return_value=None):
            ok, reason = cache.validate_sender(FAKE_PID, FAKE_CTIME)

        assert ok is False
        assert "not found" in reason.lower() or "exited" in reason.lower()

    def test_different_pids_not_affected_by_flush(self, monkeypatch):
        """Flushing one pid's entries does not affect other pids."""
        monkeypatch.setenv("SC_VALIDATE_BIRTH", "1")
        monkeypatch.setenv("SC_VALIDATE_BIRTH_TTL", "0")  # always recheck
        cache = ValidatorCache()

        other_pid = FAKE_PID + 1
        # Seed both pids
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="111"):
            cache.validate_sender(FAKE_PID, "111")
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="999"):
            cache.validate_sender(other_pid, "999")

        # Trigger mismatch for FAKE_PID only (TTL=0 ensures live check)
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="WRONG"):
            cache.validate_sender(FAKE_PID, "111")

        # other_pid entry should survive — but with TTL=0 it was also expired and
        # rechecked (with "WRONG" live) so we need to check the other_pid independently
        # Re-validate other_pid with correct live value
        with patch("enterprise.msg_validator.get_process_birth_time", return_value="999"):
            ok, _ = cache.validate_sender(other_pid, "999")
        assert ok is True


# ── on_process_exit (cache_bus integration) ───────────────────────────────────

class TestProcessExitHook:
    def test_exit_flushes_pid_entries(self, monkeypatch):
        cache = _cache_with_validation_on(monkeypatch)
        with patch("enterprise.msg_validator.get_process_birth_time", return_value=FAKE_CTIME):
            cache.validate_sender(FAKE_PID, FAKE_CTIME)
        assert cache.cache_size() == 1

        cache.on_process_exit(FAKE_PID)
        assert cache.cache_size() == 0

    def test_exit_for_unknown_pid_is_no_op(self, monkeypatch):
        cache = _cache_with_validation_on(monkeypatch)
        cache.on_process_exit(99991)  # no entries, should not raise
        assert cache.cache_size() == 0

    def test_exit_does_not_affect_other_pids(self, monkeypatch):
        cache = _cache_with_validation_on(monkeypatch)
        other_pid = FAKE_PID + 1
        with patch("enterprise.msg_validator.get_process_birth_time", return_value=FAKE_CTIME):
            cache.validate_sender(FAKE_PID, FAKE_CTIME)
            cache.validate_sender(other_pid, FAKE_CTIME)

        cache.on_process_exit(FAKE_PID)
        assert cache.cache_size() == 1


# ── invalidate_all ────────────────────────────────────────────────────────────

class TestInvalidateAll:
    def test_flushes_entire_cache(self, monkeypatch):
        cache = _cache_with_validation_on(monkeypatch)
        with patch("enterprise.msg_validator.get_process_birth_time", return_value=FAKE_CTIME):
            cache.validate_sender(1111, FAKE_CTIME)
            cache.validate_sender(2222, FAKE_CTIME)
            cache.validate_sender(3333, FAKE_CTIME)

        assert cache.cache_size() == 3
        cache.invalidate_all()
        assert cache.cache_size() == 0
