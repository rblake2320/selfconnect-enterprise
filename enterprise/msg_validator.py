"""enterprise/msg_validator.py — Per-Message Birth-Time Validation (Tier 2)

On every cross-agent message, verifies that the sender process's current OS
birth time matches the value cached when the sender was discovered.  A mismatch
means the PID was recycled by a different process — the cached identity is
stale and must be flushed.

Gated on SC_VALIDATE_BIRTH=1 (default: off).

Design
------
    Cache key:   (pid, birth_time_str)  — both required to distinguish recycled PIDs
    TTL:         SC_VALIDATE_BIRTH_TTL seconds (default: 1s) for happy-path caching
    Invalidation: immediate on any mismatch; also via cache_bus process-exit hook

Flow (per message):
    1. Caller has a message from sender (pid, birth_time_str).
    2. validate_sender(pid, cached_birth_time_str) is called.
    3. If (pid, cached_birth_time_str) in cache and TTL not expired → accept (fast path).
    4. Otherwise: read live OS birth time for pid via GetProcessTimes.
    5. Compare live vs cached_birth_time_str.
    6. Match: update cache, accept.
    7. Mismatch: flush ALL entries for this pid, emit warning, reject.

Integration with cache_bus (Tier 1e):
    Register on startup:
        from enterprise.cache_bus import register_exit_callback
        from enterprise.msg_validator import ValidatorCache
        validator = ValidatorCache()
        register_exit_callback(validator.on_process_exit)

    When a process exits, the cache bus fires on_process_exit(pid) immediately,
    clearing stale entries before the next message check.

Flags:
    SC_VALIDATE_BIRTH=1              — enable validation (default: off)
    SC_VALIDATE_BIRTH_TTL=1          — cache TTL in seconds (default: 1)

Version: 1.0.0-enterprise  Tier 2
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Optional

_log = logging.getLogger(__name__)

# ── Env config ────────────────────────────────────────────────────────────────

def _validate_enabled() -> bool:
    return os.environ.get("SC_VALIDATE_BIRTH", "").strip() == "1"


def _cache_ttl() -> float:
    return float(os.environ.get("SC_VALIDATE_BIRTH_TTL", "1"))


# ── Live birth-time reader ────────────────────────────────────────────────────

def get_process_birth_time(pid: int) -> Optional[str]:
    """Return the OS process creation time for pid as a string, or None on error.

    Uses GetProcessTimes (same source as stamp_birth_tag SCCTIME).
    Returns None if the process no longer exists or access is denied.
    """
    try:
        from enterprise.registry import get_process_creation_time
        ct = get_process_creation_time(pid)
        return str(ct) if ct is not None else None
    except Exception:
        return None


# ── Cache ─────────────────────────────────────────────────────────────────────

class ValidatorCache:
    """Thread-safe cache mapping (pid, birth_time_str) → last_verified_epoch.

    On TTL expiry the live OS birth time is re-checked.
    On mismatch all entries for that pid are flushed and the message is rejected.
    """

    def __init__(self) -> None:
        self._lock:  threading.Lock = threading.Lock()
        # key: (pid, birth_time_str) → last_verified epoch
        self._cache: dict[tuple[int, str], float] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def validate_sender(self, pid: int, cached_birth_time: str) -> tuple[bool, str]:
        """Validate that pid's live OS birth time matches cached_birth_time.

        Args:
            pid:               Sender process ID from the message header.
            cached_birth_time: Birth time string from the sender's birth tag
                               (SCCTIME property value).

        Returns:
            (True, "ok") if accepted.
            (False, reason) if rejected.
        """
        if not _validate_enabled():
            return True, "validation disabled"

        key = (pid, cached_birth_time)

        with self._lock:
            last = self._cache.get(key)
            if last is not None and (time.time() - last) < _cache_ttl():
                return True, "ok"  # fast path — within TTL

        # Slow path: re-read live birth time
        live_birth_time = get_process_birth_time(pid)

        if live_birth_time is None:
            # Process no longer exists — reject and flush
            self._flush_pid(pid)
            _log.warning(
                "birth_time_validation_failed pid=%d — process not found (may have exited)",
                pid,
            )
            return False, f"pid {pid} not found — process may have exited"

        if live_birth_time != cached_birth_time:
            # PID recycled — stale identity
            self._flush_pid(pid)
            _log.warning(
                "birth_time_mismatch_detected pid=%d cached=%s live=%s — PID recycled",
                pid, cached_birth_time[:12], live_birth_time[:12],
            )
            return False, (
                f"birth time mismatch for pid {pid}: "
                f"cached={cached_birth_time!r} live={live_birth_time!r}"
            )

        # Match — update cache
        with self._lock:
            self._cache[key] = time.time()

        return True, "ok"

    def on_process_exit(self, pid: int) -> None:
        """Cache-bus callback: immediately flush all entries for exited pid.

        Called by enterprise.cache_bus when a process-exit event fires.
        """
        count = self._flush_pid(pid)
        if count:
            _log.debug("msg_validator: flushed %d cache entries for exited pid=%d", count, pid)

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def invalidate_all(self) -> None:
        """Flush the entire cache (e.g., after a key rotation or mesh reset)."""
        with self._lock:
            self._cache.clear()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _flush_pid(self, pid: int) -> int:
        """Remove all cache entries for pid.  Returns count removed."""
        with self._lock:
            keys = [k for k in self._cache if k[0] == pid]
            for k in keys:
                del self._cache[k]
        return len(keys)


# ── Module-level singleton ────────────────────────────────────────────────────
# Callers may use this singleton or create their own ValidatorCache instance.

_default_cache = ValidatorCache()


def validate_sender(pid: int, cached_birth_time: str) -> tuple[bool, str]:
    """Module-level shortcut using the default ValidatorCache singleton."""
    return _default_cache.validate_sender(pid, cached_birth_time)
