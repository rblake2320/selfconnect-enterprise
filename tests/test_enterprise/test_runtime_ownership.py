from __future__ import annotations

import os
import subprocess
import sys

import pytest

import enterprise.runtime_ownership as runtime_ownership
from enterprise.runtime_ownership import RuntimeOwnershipError, RuntimeOwnershipLock


def test_second_process_cannot_own_same_ledger_and_approval_pair(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    script = (
        "import sys; from pathlib import Path; "
        "from enterprise.runtime_ownership import RuntimeOwnershipLock; "
        "lock=RuntimeOwnershipLock(Path(sys.argv[1]),Path(sys.argv[2])); "
        "print('READY',flush=True); sys.stdin.readline(); lock.close()"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(ledger), str(approvals)],
        cwd=str(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(__import__("pathlib").Path.cwd())},
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "READY"
        with pytest.raises(RuntimeOwnershipError, match="already has a writer"):
            RuntimeOwnershipLock(ledger, approvals)
    finally:
        assert child.stdin is not None
        child.stdin.write("stop\n")
        child.stdin.flush()
        child.wait(timeout=10)
    with RuntimeOwnershipLock(ledger, approvals):
        pass


def test_same_ledger_cannot_be_recombined_with_another_approval_store(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    approvals_a = tmp_path / "approvals-a.sqlite3"
    approvals_b = tmp_path / "approvals-b.sqlite3"
    with RuntimeOwnershipLock(ledger, approvals_a):
        with pytest.raises(RuntimeOwnershipError, match="resource already has a writer"):
            RuntimeOwnershipLock(ledger, approvals_b)


def test_same_approval_store_cannot_be_recombined_with_another_ledger(tmp_path):
    ledger_a = tmp_path / "ledger-a.jsonl"
    ledger_b = tmp_path / "ledger-b.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    with RuntimeOwnershipLock(ledger_a, approvals):
        with pytest.raises(RuntimeOwnershipError, match="resource already has a writer"):
            RuntimeOwnershipLock(ledger_b, approvals)


def test_hardlink_alias_cannot_create_another_resource_identity(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"existing-ledger")
    alias = tmp_path / "ledger-alias.jsonl"
    try:
        os.link(ledger, alias)
    except OSError as exc:  # pragma: no cover - filesystem capability boundary
        pytest.skip(f"hard links unavailable: {exc}")

    with RuntimeOwnershipLock(ledger, tmp_path / "approvals-a.sqlite3"):
        with pytest.raises(RuntimeOwnershipError, match="resource already has a writer"):
            RuntimeOwnershipLock(alias, tmp_path / "approvals-b.sqlite3")


def test_cross_resource_hardlink_created_after_acquisition_fails_binding(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    with RuntimeOwnershipLock(ledger, approvals) as lock:
        ledger.write_bytes(b"new-ledger")
        try:
            os.link(ledger, approvals)
        except OSError as exc:  # pragma: no cover - filesystem capability boundary
            pytest.skip(f"hard links unavailable: {exc}")
        with pytest.raises(RuntimeOwnershipError, match="distinct persistence resources"):
            lock.bind_opened_resources()


def test_path_substitution_during_startup_binding_fails_closed(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.jsonl"
    approvals = tmp_path / "approvals.sqlite3"
    ledger.write_bytes(b"ledger")
    approvals.write_bytes(b"approvals")
    lock = RuntimeOwnershipLock(ledger, approvals)
    original = runtime_ownership._resource_identities
    calls = [0]

    def unstable(path):
        calls[0] += 1
        identities = original(path)
        if calls[0] == 3:
            return (*identities, "file:substituted-during-binding")
        return identities

    monkeypatch.setattr(runtime_ownership, "_resource_identities", unstable)
    try:
        with pytest.raises(RuntimeOwnershipError, match="changed during startup binding"):
            lock.bind_opened_resources()
    finally:
        lock.close()


def _isolated_lock_root(tmp_path, monkeypatch) -> None:
    if os.name == "nt":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local-app-data"))
    else:
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))


def test_precreated_symlink_lock_directory_is_rejected(tmp_path, monkeypatch):
    _isolated_lock_root(tmp_path, monkeypatch)
    if os.name == "nt":
        # The environment-provided path is untrusted and must be ignored.
        attacker_root = tmp_path / "local-app-data"
        attacker_root.mkdir()
        lock = RuntimeOwnershipLock(tmp_path / "ledger", tmp_path / "approvals")
        try:
            assert all(attacker_root not in path.parents for path in lock.paths)
        finally:
            lock.close()
        return
    else:
        lock_dir = tmp_path / "runtime" / "selfconnect" / "runtime-locks"
    target = tmp_path / "attacker-locks"
    target.mkdir(parents=True)
    lock_dir.parent.mkdir(parents=True)
    try:
        lock_dir.symlink_to(target, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - Windows privilege boundary
        pytest.skip(f"directory symlinks unavailable: {exc}")
    with pytest.raises(RuntimeOwnershipError, match="not a real directory"):
        RuntimeOwnershipLock(tmp_path / "ledger", tmp_path / "approvals")


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode semantics")
def test_permissive_lock_directory_is_rejected(tmp_path, monkeypatch):
    _isolated_lock_root(tmp_path, monkeypatch)
    lock_dir = tmp_path / "runtime" / "selfconnect" / "runtime-locks"
    lock_dir.mkdir(mode=0o777, parents=True)
    lock_dir.chmod(0o777)
    with pytest.raises(RuntimeOwnershipError, match="permissions are too broad"):
        RuntimeOwnershipLock(tmp_path / "ledger", tmp_path / "approvals")


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership semantics")
def test_wrong_owner_lock_directory_is_rejected(tmp_path, monkeypatch):
    _isolated_lock_root(tmp_path, monkeypatch)
    lock_dir = tmp_path / "runtime" / "selfconnect" / "runtime-locks"
    lock_dir.mkdir(mode=0o700, parents=True)
    actual_uid = lock_dir.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: actual_uid + 1)
    with pytest.raises(RuntimeOwnershipError, match="wrong owner"):
        RuntimeOwnershipLock(tmp_path / "ledger", tmp_path / "approvals")


@pytest.mark.skipif(os.name == "nt", reason="POSIX no-follow file-symlink semantics")
def test_precreated_symlink_lock_file_is_rejected(tmp_path, monkeypatch):
    _isolated_lock_root(tmp_path, monkeypatch)
    ledger = tmp_path / "ledger"
    approvals = tmp_path / "approvals"
    first = RuntimeOwnershipLock(ledger, approvals)
    lock_path = first.paths[0]
    first.close()
    lock_path.unlink()
    target = tmp_path / "attacker-file"
    target.write_bytes(b"x")
    try:
        lock_path.symlink_to(target)
    except OSError as exc:  # pragma: no cover - Windows privilege boundary
        pytest.skip(f"file symlinks unavailable: {exc}")
    with pytest.raises(RuntimeOwnershipError, match="securely open|unsafe"):
        RuntimeOwnershipLock(ledger, approvals)


@pytest.mark.skipif(os.name == "nt", reason="Windows denies unlink of locked file")
def test_replaced_lock_file_during_binding_is_rejected(tmp_path, monkeypatch):
    _isolated_lock_root(tmp_path, monkeypatch)
    ledger = tmp_path / "ledger"
    approvals = tmp_path / "approvals"
    lock = RuntimeOwnershipLock(ledger, approvals)
    lock_path = lock.paths[0]
    lock_path.unlink()
    lock_path.write_bytes(b"replacement")
    lock_path.chmod(0o600)
    try:
        with pytest.raises(RuntimeOwnershipError, match="unsafe or was replaced"):
            lock.bind_opened_resources()
    finally:
        lock.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction semantics")
def test_windows_junction_ancestor_is_rejected(tmp_path):
    from enterprise.windows_lock_boundary import (
        WindowsLockBoundaryError,
        _open_directory,
    )

    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:  # pragma: no cover - host policy boundary
        pytest.skip(f"junction creation unavailable: {created.stderr}")
    try:
        with pytest.raises(WindowsLockBoundaryError, match="reparse point"):
            _open_directory(junction)
    finally:
        os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-retarget semantics")
def test_windows_directory_swap_to_junction_during_open_is_rejected(tmp_path):
    from enterprise.windows_lock_boundary import (
        WindowsLockBoundaryError,
        _open_directory,
    )

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    target = tmp_path / "target"
    target.mkdir()

    def swap() -> None:
        os.rmdir(candidate)
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(candidate), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert created.returncode == 0, created.stderr

    try:
        with pytest.raises(WindowsLockBoundaryError, match="reparse point|changed"):
            _open_directory(candidate, _before_open=swap)
    finally:
        if candidate.exists():
            os.rmdir(candidate)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-retarget semantics")
def test_windows_directory_swap_to_second_namespace_is_rejected(tmp_path):
    from enterprise.windows_lock_boundary import (
        WindowsLockBoundaryError,
        _open_directory,
    )

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    replacement = tmp_path / "replacement"
    replacement.mkdir()

    def swap() -> None:
        os.rmdir(candidate)
        replacement.rename(candidate)

    with pytest.raises(WindowsLockBoundaryError, match="changed during open"):
        _open_directory(candidate, _before_open=swap)


@pytest.mark.skipif(os.name != "nt", reason="Windows native-API boundary")
def test_windows_lock_boundary_does_not_execute_from_process_path(
    tmp_path, monkeypatch
):
    import enterprise.windows_lock_boundary as windows_boundary

    local_app_data = tmp_path / "known-local-app-data"
    local_app_data.mkdir()
    monkeypatch.setattr(
        windows_boundary, "_known_local_app_data", lambda: local_app_data
    )
    monkeypatch.setenv("PATH", str(tmp_path / "attacker-bin"))
    boundary = windows_boundary.WindowsLockBoundary()
    try:
        windows_boundary._validate_acl(
            boundary.path, windows_boundary._current_sid()
        )
    finally:
        boundary.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows governed-root semantics")
def test_windows_governed_suffix_junction_is_rejected(tmp_path, monkeypatch):
    import enterprise.windows_lock_boundary as windows_boundary

    local_app_data = tmp_path / "known-local-app-data"
    local_app_data.mkdir()
    target = tmp_path / "attacker-root"
    target.mkdir()
    junction = local_app_data / "SelfConnect"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert created.returncode == 0, created.stderr
    monkeypatch.setattr(
        windows_boundary, "_known_local_app_data", lambda: local_app_data
    )
    try:
        with pytest.raises(
            windows_boundary.WindowsLockBoundaryError, match="reparse point"
        ):
            windows_boundary.WindowsLockBoundary()
    finally:
        os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="Windows lock-file DACL semantics")
def test_windows_fresh_lock_files_have_the_declared_security_policy(tmp_path):
    import enterprise.windows_lock_boundary as windows_boundary
    import win32security

    lock = RuntimeOwnershipLock(tmp_path / "ledger", tmp_path / "approvals")
    try:
        sid = windows_boundary._current_sid()
        for path in lock.paths:
            descriptor = win32security.GetNamedSecurityInfo(
                str(path),
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            windows_boundary._validate_file_descriptor(descriptor, sid)
    finally:
        lock.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows lock-file DACL semantics")
def test_windows_existing_everyone_lock_file_is_precisely_remediated(tmp_path):
    import enterprise.windows_lock_boundary as windows_boundary
    import ntsecuritycon
    import win32security

    ledger = tmp_path / "ledger"
    approvals = tmp_path / "approvals"
    first = RuntimeOwnershipLock(ledger, approvals)
    lock_path = first.paths[0]
    first.close()

    everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid)
    permissive = win32security.ACL()
    permissive.AddAccessAllowedAceEx(
        win32security.ACL_REVISION,
        0,
        ntsecuritycon.FILE_ALL_ACCESS,
        everyone,
    )
    win32security.SetNamedSecurityInfo(
        str(lock_path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        permissive,
        None,
    )

    second = RuntimeOwnershipLock(ledger, approvals)
    try:
        descriptor = win32security.GetNamedSecurityInfo(
            str(lock_path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        windows_boundary._validate_file_descriptor(
            descriptor, windows_boundary._current_sid()
        )
    finally:
        second.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows lock-file DACL semantics")
def test_windows_wrong_owner_security_descriptor_is_rejected():
    import enterprise.windows_lock_boundary as windows_boundary
    import win32security

    descriptor = win32security.SECURITY_DESCRIPTOR()
    wrong_owner = win32security.CreateWellKnownSid(win32security.WinLocalServiceSid)
    descriptor.SetSecurityDescriptorOwner(wrong_owner, False)
    descriptor.SetSecurityDescriptorDacl(1, win32security.ACL(), 0)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
    )
    with pytest.raises(
        windows_boundary.WindowsLockBoundaryError, match="untrusted owner"
    ):
        windows_boundary._validate_file_descriptor(
            descriptor, windows_boundary._current_sid()
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-close semantics")
def test_windows_boundary_retains_handles_that_fail_to_close(monkeypatch):
    import enterprise.windows_lock_boundary as windows_boundary

    boundary = windows_boundary.WindowsLockBoundary.__new__(
        windows_boundary.WindowsLockBoundary
    )
    boundary._handles = [11, 22]
    fail = {22}

    def close(handle):
        if handle in fail:
            raise windows_boundary.WindowsLockBoundaryError("close failed")

    monkeypatch.setattr(windows_boundary, "_close_handle", close)
    with pytest.raises(windows_boundary.WindowsLockBoundaryError, match="close failed"):
        boundary.close()
    assert boundary._handles == [22]
    fail.clear()
    boundary.close()
    assert boundary._handles == []
