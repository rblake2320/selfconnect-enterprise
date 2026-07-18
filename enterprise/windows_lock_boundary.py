"""Windows per-user filesystem boundary for governed runtime locks."""
from __future__ import annotations

import ctypes
import os
import stat
import uuid
from ctypes import wintypes
from pathlib import Path


class WindowsLockBoundaryError(RuntimeError):
    pass


_FILE_SHARE_READ = 1
_FILE_SHARE_WRITE = 2
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
_SE_DACL_PROTECTED = 0x1000


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_uuid(cls, value: uuid.UUID) -> "_GUID":
        raw = value.bytes_le
        return cls.from_buffer_copy(raw)


def _known_local_app_data() -> Path:
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(_GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    folder_id = _GUID.from_uuid(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091"))
    result = wintypes.LPWSTR()
    hr = shell32.SHGetKnownFolderPath(
        ctypes.byref(folder_id), 0, None, ctypes.byref(result)
    )
    if hr != 0:
        raise WindowsLockBoundaryError(f"SHGetKnownFolderPath failed: 0x{hr:08x}")
    try:
        return Path(result.value)
    finally:
        ole32.CoTaskMemFree(result)


def _current_sid() -> str:
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid)
    finally:
        token.Close()


def _protect_acl(path: Path, sid: str) -> None:
    import ntsecuritycon
    import win32security

    owner = win32security.ConvertStringSidToSid(sid)
    system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
    administrators = win32security.CreateWellKnownSid(
        win32security.WinBuiltinAdministratorsSid
    )
    dacl = win32security.ACL()
    flags = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    for principal in (owner, system, administrators):
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION,
            flags,
            ntsecuritycon.FILE_ALL_ACCESS,
            principal,
        )
    try:
        win32security.SetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            None,
            dacl,
            None,
        )
    except OSError as exc:
        raise WindowsLockBoundaryError("cannot establish runtime-lock DACL") from exc


def _validate_acl(path: Path, sid: str) -> None:
    import ntsecuritycon
    import win32security

    trusted = {sid, "S-1-5-18", "S-1-5-32-544"}
    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )
    owner = descriptor.GetSecurityDescriptorOwner()
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if win32security.ConvertSidToStringSid(owner) != sid or not (
        control & _SE_DACL_PROTECTED
    ):
        raise WindowsLockBoundaryError("runtime-lock owner or inheritance is unsafe")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None or dacl.GetAceCount() == 0:
        raise WindowsLockBoundaryError("runtime-lock DACL is absent")
    for index in range(dacl.GetAceCount()):
        header, mask, ace_sid = dacl.GetAce(index)
        if header[0] == win32security.ACCESS_ALLOWED_ACE_TYPE:
            principal = win32security.ConvertSidToStringSid(ace_sid)
            if principal not in trusted or (
                mask & ntsecuritycon.FILE_ALL_ACCESS
            ) != ntsecuritycon.FILE_ALL_ACCESS:
                raise WindowsLockBoundaryError(
                    "runtime-lock DACL grants an untrusted or incomplete ACE"
                )


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def _close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        raise WindowsLockBoundaryError("cannot close runtime-lock ancestor handle")


def _normalized_final_path(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def _handle_path(kernel32, handle: int) -> str:
    size = kernel32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), None, 0, 0
    )
    if not size:
        raise WindowsLockBoundaryError("cannot resolve runtime-lock ancestor handle")
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = kernel32.GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), buffer, len(buffer), 0
    )
    if not written or written >= len(buffer):
        raise WindowsLockBoundaryError("cannot resolve runtime-lock ancestor handle")
    return buffer.value


def _open_directory(path: Path, *, _before_open=None) -> int:
    before = path.lstat()
    attributes = getattr(before, "st_file_attributes", 0)
    if not stat.S_ISDIR(before.st_mode) or attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsLockBoundaryError("runtime-lock ancestor is a reparse point")
    if _before_open is not None:
        _before_open()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    handle = kernel32.CreateFileW(
        str(path),
        0,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise WindowsLockBoundaryError("cannot open runtime-lock ancestor")
    handle_value = int(handle)
    try:
        opened = _BY_HANDLE_FILE_INFORMATION()
        if not kernel32.GetFileInformationByHandle(
            wintypes.HANDLE(handle_value), ctypes.byref(opened)
        ):
            raise WindowsLockBoundaryError("cannot inspect runtime-lock ancestor")
        after = path.lstat()
        if (
            opened.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or getattr(after, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
            or not stat.S_ISDIR(after.st_mode)
        ):
            raise WindowsLockBoundaryError("runtime-lock ancestor is a reparse point")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise WindowsLockBoundaryError("runtime-lock ancestor changed during open")
        final_path = _normalized_final_path(_handle_path(kernel32, handle_value))
        expected = _normalized_final_path(str(path.resolve(strict=True)))
        if final_path != expected:
            raise WindowsLockBoundaryError("runtime-lock ancestor handle was retargeted")
        return handle_value
    except Exception:
        _close_handle(handle_value)
        raise


class WindowsLockBoundary:
    """Hold non-delete-sharing handles across the canonical per-user chain."""

    def __init__(self) -> None:
        base = _known_local_app_data()
        selfconnect_root = base / "SelfConnect"
        governed_root = selfconnect_root / "GovernedRuntimeLocks"
        lock_dir = governed_root / "v1"
        sid = _current_sid()
        self._handles: list[int] = []
        try:
            # Pin each ancestor before creating beneath it. The known-folder and
            # SelfConnect ancestors retain their existing ACL boundary; only the
            # governed suffix is replaced with the explicit owner-only DACL.
            self._handles.append(_open_directory(base))
            selfconnect_root.mkdir(mode=0o700, exist_ok=True)
            self._handles.append(_open_directory(selfconnect_root))
            governed_root.mkdir(mode=0o700, exist_ok=True)
            self._handles.append(_open_directory(governed_root))
            _protect_acl(governed_root, sid)
            _validate_acl(governed_root, sid)
            lock_dir.mkdir(mode=0o700, exist_ok=True)
            self._handles.append(_open_directory(lock_dir))
            _protect_acl(lock_dir, sid)
            _validate_acl(lock_dir, sid)
            self.path = lock_dir.resolve(strict=True)
            canonical_base = base.resolve(strict=True)
            if canonical_base not in self.path.parents:
                raise WindowsLockBoundaryError("runtime-lock path escaped LocalAppData")
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        handles, self._handles = self._handles, []
        first_error: WindowsLockBoundaryError | None = None
        for handle in reversed(handles):
            try:
                _close_handle(handle)
            except WindowsLockBoundaryError as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error


__all__ = ["WindowsLockBoundary", "WindowsLockBoundaryError"]
