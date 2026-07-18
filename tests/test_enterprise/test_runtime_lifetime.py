from __future__ import annotations

import threading

import pytest

from enterprise.runtime_lifetime import (
    RuntimeClosedError,
    RuntimeCloseReentrantError,
    RuntimeLifetime,
)


def test_close_rejects_new_operations_and_drains_in_flight_before_return():
    lifetime = RuntimeLifetime()
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()

    def operation() -> None:
        with lifetime.operation():
            entered.set()
            assert release.wait(timeout=5)

    worker = threading.Thread(target=operation)
    worker.start()
    assert entered.wait(timeout=2)

    def close() -> None:
        lifetime.close_and_drain()
        closed.set()

    closer = threading.Thread(target=close)
    closer.start()
    assert lifetime._revoked.wait(timeout=2)
    with pytest.raises(RuntimeClosedError, match="runtime is closed"):
        with lifetime.operation():
            pass
    assert not closed.wait(timeout=0.1)
    release.set()
    worker.join(timeout=2)
    closer.join(timeout=2)
    assert closed.is_set()


def test_close_is_idempotent_and_permanently_revokes_lifetime():
    lifetime = RuntimeLifetime()
    lifetime.close_and_drain()
    lifetime.close_and_drain()
    with pytest.raises(RuntimeClosedError, match="runtime is closed"):
        with lifetime.operation():
            pass


def test_close_from_inside_admitted_operation_fails_without_deadlock():
    lifetime = RuntimeLifetime()
    with lifetime.operation():
        with pytest.raises(RuntimeCloseReentrantError, match="in-flight operation"):
            lifetime.close_and_drain()
        with lifetime.operation():
            pass
    lifetime.close_and_drain()


def test_previously_admitted_outer_operation_can_finish_nested_work_during_close():
    lifetime = RuntimeLifetime()
    close_started = threading.Event()
    close_done = threading.Event()

    def close() -> None:
        close_started.set()
        lifetime.close_and_drain()
        close_done.set()

    with lifetime.operation():
        closer = threading.Thread(target=close)
        closer.start()
        assert close_started.wait(timeout=2)
        assert lifetime._revoked.wait(timeout=2)
        with lifetime.operation():
            pass
        assert not close_done.is_set()
    closer.join(timeout=2)
    assert close_done.is_set()
