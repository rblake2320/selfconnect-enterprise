"""Exclusive local process ownership for governed persistence resources."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import BinaryIO


class RuntimeOwnershipError(RuntimeError):
    """A governed persistence resource is already owned by another runtime."""


def _resource_identities(path: Path) -> tuple[str, ...]:
    resolved = Path(path).resolve(strict=False)
    parent_stat = resolved.parent.stat()
    name = resolved.name.casefold() if os.name == "nt" else resolved.name
    identities = [f"path:{parent_stat.st_dev}:{parent_stat.st_ino}:{name}"]
    if resolved.exists():
        stat = resolved.stat()
        identities.append(f"file:{stat.st_dev}:{stat.st_ino}")
    return tuple(identities)


def _assert_distinct_resources(identity_sets: tuple[set[str], set[str]]) -> None:
    if identity_sets[0] & identity_sets[1]:
        raise RuntimeOwnershipError(
            "approval database and ledger must be distinct persistence resources"
        )


class _ResourceLock:
    def __init__(self, identity: str, lock_dir: Path) -> None:
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        self.path = lock_dir / f"resource-{suffix}.lock"
        self._handle: BinaryIO | None = open(self.path, "a+b")
        try:
            self._acquire()
        except Exception:
            self._handle.close()
            self._handle = None
            raise

    def _acquire(self) -> None:
        assert self._handle is not None
        if os.name == "nt":
            import msvcrt

            if os.fstat(self._handle.fileno()).st_size == 0:
                self._handle.write(b"0")
                self._handle.flush()
            self._handle.seek(0)
            try:
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeOwnershipError(
                    "governed persistence resource already has a writer"
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeOwnershipError(
                    "governed persistence resource already has a writer"
                ) from exc

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


class RuntimeOwnershipLock:
    """Independently lock ledger and approval-store identities on one host.

    Existing files are keyed by OS device/inode identity, so hard-link aliases
    present during acquisition or startup binding cannot create another
    ownership namespace. Future files are keyed by their stable parent directory
    identity and filename, then rebound after the resources are opened. Resource
    directories and path entries must be owner-controlled and immutable to
    untrusted principals for the runtime lifetime. This is not distributed
    consensus and cannot prevent a privileged post-binding rename or replacement.
    """

    def __init__(self, ledger_path: Path, approval_path: Path) -> None:
        lock_dir = Path(tempfile.gettempdir()) / "selfconnect-governed-runtime-locks"
        lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._resource_paths = (Path(ledger_path), Path(approval_path))
        initial_sets = tuple(
            set(_resource_identities(path)) for path in self._resource_paths
        )
        _assert_distinct_resources(initial_sets)
        self.paths: list[Path] = []
        self._locks: list[_ResourceLock] = []
        self._held_identities: set[str] = set()
        try:
            self._acquire_identities(set().union(*initial_sets), lock_dir)
        except Exception:
            self.close()
            raise

    def _acquire_identities(self, identities: set[str], lock_dir: Path) -> None:
        for identity in sorted(identities - self._held_identities):
            lock = _ResourceLock(identity, lock_dir)
            self._locks.append(lock)
            self.paths.append(lock.path)
            self._held_identities.add(identity)

    def bind_opened_resources(self) -> None:
        """Bind actual file identities and reject startup path substitution.

        Call after constructors have opened/created both resources but before
        exposing the runtime. Path locks remain held from initial acquisition.
        """
        lock_dir = Path(tempfile.gettempdir()) / "selfconnect-governed-runtime-locks"
        before = tuple(set(_resource_identities(path)) for path in self._resource_paths)
        _assert_distinct_resources(before)
        self._acquire_identities(set().union(*before), lock_dir)
        after = tuple(set(_resource_identities(path)) for path in self._resource_paths)
        _assert_distinct_resources(after)
        if before != after:
            raise RuntimeOwnershipError(
                "governed persistence resource changed during startup binding"
            )

    def close(self) -> None:
        locks, self._locks = self._locks, []
        self._held_identities.clear()
        for lock in reversed(locks):
            lock.close()

    def __enter__(self) -> "RuntimeOwnershipLock":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


__all__ = ["RuntimeOwnershipError", "RuntimeOwnershipLock"]
