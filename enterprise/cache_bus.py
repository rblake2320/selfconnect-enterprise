"""enterprise/cache_bus.py — Process-exit event bus for SelfConnect Enterprise.

Provides a single registration point that Tier 3 plugins use to push cache
invalidation events into core without either layer importing the other's internals.

Usage (plugin side — Tier 3):
    from enterprise.cache_bus import register_exit_callback

    def my_invalidation_handler(pid: int) -> None:
        # flush whatever cache this plugin manages
        birth_time_cache.pop(pid, None)

    register_exit_callback(my_invalidation_handler)

Usage (core side — Tier 2 msg_validator, etc.):
    from enterprise.cache_bus import notify_process_exit

    # called when a process-death is detected (WMI, ETW, or TOCTOU mismatch)
    notify_process_exit(dead_pid)

Thread safety: all operations are protected by a single lock. Callbacks are
invoked holding no lock — a slow or crashing callback cannot block other callbacks
or the notification caller.

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

_log = logging.getLogger(__name__)

# Type alias for callbacks
ProcessExitCallback = Callable[[int], None]

_lock: threading.Lock = threading.Lock()
_callbacks: list[ProcessExitCallback] = []


def register_exit_callback(fn: ProcessExitCallback) -> None:
    """Register a callback to be invoked when a process exit is detected.

    Args:
        fn: Callable that receives the dead process PID as its only argument.
            Must not raise — exceptions are caught and logged.
    """
    with _lock:
        if fn not in _callbacks:
            _callbacks.append(fn)
            _log.debug("cache_bus: registered callback %s (total=%d)", fn.__qualname__, len(_callbacks))


def unregister_exit_callback(fn: ProcessExitCallback) -> None:
    """Unregister a previously registered callback. Safe to call if not registered."""
    with _lock:
        try:
            _callbacks.remove(fn)
            _log.debug("cache_bus: unregistered callback %s", fn.__qualname__)
        except ValueError:
            pass


def notify_process_exit(pid: int) -> None:
    """Notify all registered callbacks that a process has exited.

    Called by Tier 2 (msg_validator, registry) when process death is detected
    via birth-time mismatch, WM_COPYDATA failure, or signature rejection.
    Also called by Tier 3 plugins (WMI watcher, ETW invalidator) on OS-level events.

    Args:
        pid: The PID of the process that exited.
    """
    with _lock:
        current = list(_callbacks)  # snapshot — iterate outside lock

    _log.debug("cache_bus: notifying %d callbacks of pid=%d exit", len(current), pid)
    for fn in current:
        try:
            fn(pid)
        except Exception:
            _log.exception("cache_bus: callback %s raised on pid=%d", fn.__qualname__, pid)


def callback_count() -> int:
    """Return the number of registered callbacks. Used in tests."""
    with _lock:
        return len(_callbacks)


def clear_all_callbacks() -> None:
    """Remove all registered callbacks. Use only in tests."""
    with _lock:
        _callbacks.clear()
