"""Revocable lifetime barrier for one governed runtime object graph."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Iterator, TypeVar


class RuntimeClosedError(RuntimeError):
    """The governed runtime has closed and cannot authorize more mutation."""


class RuntimeLifetime:
    """Reject new operations and drain in-flight operations before unlock."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._accepting = True
        self._in_flight = 0
        self._revoked = threading.Event()

    @contextmanager
    def operation(self) -> Iterator[None]:
        with self._condition:
            if not self._accepting:
                raise RuntimeClosedError("governed runtime is closed")
            self._in_flight += 1
        try:
            yield
        finally:
            with self._condition:
                self._in_flight -= 1
                if self._in_flight == 0:
                    self._condition.notify_all()

    def close_and_drain(self) -> None:
        with self._condition:
            self._accepting = False
            self._revoked.set()
            while self._in_flight:
                self._condition.wait()


_F = TypeVar("_F", bound=Callable[..., Any])


def governed_operation(method: _F) -> _F:
    """Wrap a component mutation in its optional shared runtime lifetime."""

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        lifetime = getattr(self, "_runtime_lifetime", None)
        if lifetime is None:
            return method(self, *args, **kwargs)
        with lifetime.operation():
            return method(self, *args, **kwargs)

    return wrapped  # type: ignore[return-value]


__all__ = ["RuntimeClosedError", "RuntimeLifetime"]
