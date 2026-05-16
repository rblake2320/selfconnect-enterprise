"""Tests for enterprise/cache_bus.py — process-exit event bus."""
import pytest
from enterprise import cache_bus


@pytest.fixture(autouse=True)
def _clean():
    """Ensure no registered callbacks leak between tests."""
    cache_bus.clear_all_callbacks()
    yield
    cache_bus.clear_all_callbacks()


def test_register_and_count():
    """Registering a callback increments the count."""
    assert cache_bus.callback_count() == 0

    def handler(pid: int) -> None:
        pass

    cache_bus.register_exit_callback(handler)
    assert cache_bus.callback_count() == 1


def test_no_duplicate_registration():
    """Registering the same callable twice only stores it once."""
    def handler(pid: int) -> None:
        pass

    cache_bus.register_exit_callback(handler)
    cache_bus.register_exit_callback(handler)
    assert cache_bus.callback_count() == 1


def test_unregister():
    """Unregistering removes the callback."""
    def handler(pid: int) -> None:
        pass

    cache_bus.register_exit_callback(handler)
    cache_bus.unregister_exit_callback(handler)
    assert cache_bus.callback_count() == 0


def test_unregister_not_registered_is_safe():
    """Unregistering a callback that was never registered does not raise."""
    def handler(pid: int) -> None:
        pass

    cache_bus.unregister_exit_callback(handler)  # must not raise


def test_notify_calls_all_callbacks():
    """notify_process_exit invokes every registered callback with the pid."""
    received: list[int] = []

    def handler_a(pid: int) -> None:
        received.append(("a", pid))

    def handler_b(pid: int) -> None:
        received.append(("b", pid))

    cache_bus.register_exit_callback(handler_a)
    cache_bus.register_exit_callback(handler_b)
    cache_bus.notify_process_exit(12345)

    assert ("a", 12345) in received
    assert ("b", 12345) in received
    assert len(received) == 2


def test_notify_continues_after_crashing_callback():
    """A callback that raises must not prevent other callbacks from being called."""
    second_called: list[bool] = []

    def bad_handler(pid: int) -> None:
        raise RuntimeError("simulated crash")

    def good_handler(pid: int) -> None:
        second_called.append(True)

    cache_bus.register_exit_callback(bad_handler)
    cache_bus.register_exit_callback(good_handler)
    cache_bus.notify_process_exit(999)  # must not raise

    assert second_called == [True]


def test_notify_with_no_callbacks_is_safe():
    """notify_process_exit with zero callbacks must not raise."""
    cache_bus.notify_process_exit(0)


def test_multiple_distinct_pids():
    """Each pid notified is seen by the callback independently."""
    seen: list[int] = []

    def handler(pid: int) -> None:
        seen.append(pid)

    cache_bus.register_exit_callback(handler)
    cache_bus.notify_process_exit(1001)
    cache_bus.notify_process_exit(1002)
    cache_bus.notify_process_exit(1003)

    assert seen == [1001, 1002, 1003]
