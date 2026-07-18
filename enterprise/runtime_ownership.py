"""Exclusive local process ownership for governed persistence resources."""
from __future__ import annotations

import hashlib
import os
import stat
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


def _is_reparse_point(path_stat: os.stat_result) -> bool:
    attributes = getattr(path_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _validate_secure_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeOwnershipError("runtime lock directory is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or _is_reparse_point(info):
        raise RuntimeOwnershipError("runtime lock directory is not a real directory")
    if os.name != "nt":
        if info.st_uid != os.geteuid():
            raise RuntimeOwnershipError("runtime lock directory has the wrong owner")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeOwnershipError("runtime lock directory permissions are too broad")


def _secure_lock_dir() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise RuntimeOwnershipError("LOCALAPPDATA is required for runtime locks")
        base = Path(local_app_data)
        lock_dir = base / "SelfConnect" / "runtime-locks"
    else:
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
        base = Path(runtime_dir) if runtime_dir else Path.home() / ".local" / "state"
        lock_dir = base / "selfconnect" / "runtime-locks"
    try:
        lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeOwnershipError("cannot create runtime lock directory") from exc
    _validate_secure_directory(lock_dir)
    if os.name == "nt":
        # LocalAppData is the Windows per-user ACL boundary. Refuse junctions or
        # symlinks in the SelfConnect-owned suffix rather than using shared temp.
        _validate_secure_directory(lock_dir.parent)
    return lock_dir


class _ResourceLock:
    def __init__(self, identity: str, lock_dir: Path) -> None:
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        self.path = lock_dir / f"resource-{suffix}.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self._handle: BinaryIO | None = None
        try:
            fd = os.open(self.path, flags, 0o600)
            self._handle = os.fdopen(fd, "r+b", buffering=0)
            self._validate_file()
            self._acquire()
        except Exception as exc:
            if self._handle is not None:
                self._handle.close()
            self._handle = None
            if isinstance(exc, RuntimeOwnershipError):
                raise
            raise RuntimeOwnershipError("cannot securely open runtime lock file") from exc

    def _validate_file(self) -> None:
        assert self._handle is not None
        opened = os.fstat(self._handle.fileno())
        path_info = self.path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or self.path.is_symlink()
            or _is_reparse_point(path_info)
            or (opened.st_dev, opened.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            raise RuntimeOwnershipError("runtime lock file is unsafe or was replaced")
        if os.name != "nt":
            if opened.st_uid != os.geteuid():
                raise RuntimeOwnershipError("runtime lock file has the wrong owner")
            if stat.S_IMODE(opened.st_mode) & 0o077:
                raise RuntimeOwnershipError("runtime lock file permissions are too broad")

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

    def validate_path(self) -> None:
        if self._handle is None:
            raise RuntimeOwnershipError("runtime lock is closed")
        self._validate_file()


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
        lock_dir = _secure_lock_dir()
        self._lock_dir = lock_dir
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
        for lock in self._locks:
            lock.validate_path()
        lock_dir = self._lock_dir
        before = tuple(set(_resource_identities(path)) for path in self._resource_paths)
        _assert_distinct_resources(before)
        self._acquire_identities(set().union(*before), lock_dir)
        after = tuple(set(_resource_identities(path)) for path in self._resource_paths)
        _assert_distinct_resources(after)
        if before != after:
            raise RuntimeOwnershipError(
                "governed persistence resource changed during startup binding"
            )
        for lock in self._locks:
            lock.validate_path()

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
