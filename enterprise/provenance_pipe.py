"""Windows named-pipe boundary for the dedicated provenance service."""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from enterprise.provenance_ipc import (
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    ProvenanceProtocolError,
    decode_frame,
    encode_frame,
    sign_service_response,
    verify_service_response,
)
from enterprise.provenance_service_core import ProvenanceServiceCore, ProvenanceServiceUnavailable

logger = logging.getLogger(__name__)

PIPE_NAME = r"\\.\pipe\SelfConnectProvenance.v1"
DEFAULT_INSTANCES = 4
DEFAULT_CONNECT_TIMEOUT_MS = 5_000
DEFAULT_REQUEST_TIMEOUT_MS = 5_000

FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002
FILE_WRITE_ATTRIBUTES = 0x0100
SYNCHRONIZE = 0x00100000
PIPE_CLIENT_ACCESS = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
PIPE_INTEGRITY_SID = "S-1-16-8192"
PIPE_INTEGRITY_POLICY = 0x00000001  # SYSTEM_MANDATORY_LABEL_NO_WRITE_UP

try:
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32security
    import winerror

    _WIN32_AVAILABLE = os.name == "nt"
except ImportError:  # pragma: no cover - non-Windows packaging path
    _WIN32_AVAILABLE = False


class ProvenancePipeError(RuntimeError):
    pass


def _require_windows() -> None:
    if not _WIN32_AVAILABLE:
        raise ProvenancePipeError("pywin32 on Windows is required")


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32.GetNamedPipeServerProcessId.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.ULONG),
    ]
    _kernel32.GetNamedPipeServerProcessId.restype = ctypes.wintypes.BOOL
    _kernel32.PeekNamedPipe.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.PeekNamedPipe.restype = ctypes.wintypes.BOOL
    _advapi32.ImpersonateNamedPipeClient.argtypes = [ctypes.wintypes.HANDLE]
    _advapi32.ImpersonateNamedPipeClient.restype = ctypes.wintypes.BOOL
    _advapi32.RevertToSelf.argtypes = []
    _advapi32.RevertToSelf.restype = ctypes.wintypes.BOOL


def resolve_account_sid(account_name: str) -> str:
    _require_windows()
    sid, _domain, _kind = win32security.LookupAccountName("", account_name)
    return win32security.ConvertSidToStringSid(sid)


def _sid(value: str):
    return win32security.ConvertStringSidToSid(value)


def build_pipe_security_attributes(service_sid: str, client_sids: set[str] | frozenset[str]):
    """Create the explicit pipe DACL; no inherited or Everyone ACEs."""
    _require_windows()
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        win32con.GENERIC_ALL,
        _sid(service_sid),
    )
    # Do not grant FILE_GENERIC_WRITE here. For named pipes it contains
    # FILE_APPEND_DATA, which is the same bit as FILE_CREATE_PIPE_INSTANCE and
    # would let an enrolled client create a server-side pipe instance.
    for sid in sorted(client_sids):
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            PIPE_CLIENT_ACCESS,
            _sid(sid),
        )
    sacl = win32security.ACL()
    medium_integrity_sid = win32security.CreateWellKnownSid(
        win32security.WinMediumLabelSid
    )
    sacl.AddMandatoryAce(
        win32security.ACL_REVISION,
        0,
        win32security.SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        medium_integrity_sid,
    )
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    descriptor.SetSecurityDescriptorSacl(True, sacl, False)
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


def pipe_mandatory_label(handle: Any) -> tuple[str, int]:
    """Read the live pipe mandatory label using the server handle's READ_CONTROL."""
    _require_windows()
    descriptor = win32security.GetSecurityInfo(
        handle,
        win32security.SE_KERNEL_OBJECT,
        win32security.LABEL_SECURITY_INFORMATION,
    )
    sacl = descriptor.GetSecurityDescriptorSacl()
    if sacl is None or sacl.GetAceCount() != 1:
        raise ProvenancePipeError("provenance pipe must have exactly one integrity label")
    ace = sacl.GetAce(0)
    if int(ace[0][0]) != 17:  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
        raise ProvenancePipeError("provenance pipe SACL is not a mandatory integrity label")
    return win32security.ConvertSidToStringSid(ace[2]), int(ace[1])


def pipe_client_sid(handle: Any, allowed_sids: frozenset[str]) -> str:
    """Resolve exactly one enrolled SID from the impersonated client token."""
    _require_windows()
    if not _advapi32.ImpersonateNamedPipeClient(int(handle)):
        raise ProvenancePipeError(
            f"ImpersonateNamedPipeClient failed: {ctypes.get_last_error()}"
        )
    try:
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(),
            win32con.TOKEN_QUERY,
            True,
        )
        try:
            token_user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            presented = {win32security.ConvertSidToStringSid(token_user)}
            for sid, _attributes in win32security.GetTokenInformation(
                token,
                win32security.TokenGroups,
            ):
                presented.add(win32security.ConvertSidToStringSid(sid))
            matches = sorted(presented & allowed_sids)
            if len(matches) != 1:
                raise ProvenancePipeError(
                    "client token must present exactly one enrolled OS SID"
                )
            return matches[0]
        finally:
            token.Close()
    finally:
        if not _advapi32.RevertToSelf():
            raise ProvenancePipeError(f"RevertToSelf failed: {ctypes.get_last_error()}")


def pipe_server_sid(handle: Any) -> str:
    """Resolve the server process token SID, not a payload-asserted identity."""
    _require_windows()
    process_id = ctypes.wintypes.ULONG()
    if not _kernel32.GetNamedPipeServerProcessId(int(handle), ctypes.byref(process_id)):
        raise ProvenancePipeError(
            f"GetNamedPipeServerProcessId failed: {ctypes.get_last_error()}"
        )
    process = win32api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id.value)
    try:
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            return win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
    finally:
        process.Close()


def _safe_request_id(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    request_id = value.get("request_id")
    return request_id if isinstance(request_id, str) and len(request_id) <= 64 else None


def _wait_for_message(
    handle: Any,
    *,
    deadline: float,
    stop_event: threading.Event | None = None,
) -> None:
    while time.monotonic() < deadline:
        if stop_event is not None and stop_event.is_set():
            raise ProvenancePipeError("provenance pipe is stopping")
        available = ctypes.wintypes.DWORD()
        if not _kernel32.PeekNamedPipe(
            int(handle),
            None,
            0,
            None,
            ctypes.byref(available),
            None,
        ):
            raise ProvenancePipeError(
                f"PeekNamedPipe failed: {ctypes.get_last_error()}"
            )
        if available.value:
            return
        time.sleep(0.005)
    raise ProvenancePipeError("provenance pipe read deadline expired")


@dataclass(frozen=True)
class ProvenancePipeConfig:
    service_sid: str
    client_sids: frozenset[str]
    pipe_name: str = PIPE_NAME
    instances: int = DEFAULT_INSTANCES
    input_buffer_bytes: int = MAX_FRAME_BYTES
    output_buffer_bytes: int = MAX_FRAME_BYTES
    request_timeout_ms: int = DEFAULT_REQUEST_TIMEOUT_MS

    def __post_init__(self) -> None:
        if not self.pipe_name.startswith("\\\\.\\pipe\\"):
            raise ValueError("pipe_name must be a local named pipe")
        if not 1 <= self.instances <= 64:
            raise ValueError("instances must be between 1 and 64")
        if not 1 <= self.input_buffer_bytes <= MAX_FRAME_BYTES:
            raise ValueError("input_buffer_bytes is out of range")
        if not 1 <= self.output_buffer_bytes <= MAX_FRAME_BYTES:
            raise ValueError("output_buffer_bytes is out of range")
        if not 100 <= self.request_timeout_ms <= 60_000:
            raise ValueError("request_timeout_ms must be between 100 and 60000")


class ProvenancePipeServer:
    def __init__(
        self,
        core: ProvenanceServiceCore,
        config: ProvenancePipeConfig,
    ) -> None:
        _require_windows()
        self.core = core
        self.config = config
        self._security_attributes = build_pipe_security_attributes(
            config.service_sid,
            config.client_sids,
        )
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._fatal = threading.Event()
        self._started = False
        self.integrity_sid: str | None = None
        self.integrity_policy: int | None = None

    def _create_pipe(self, *, first: bool):
        flags = win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_WRITE_THROUGH
        if first:
            flags |= FILE_FLAG_FIRST_PIPE_INSTANCE
        return win32pipe.CreateNamedPipe(
            self.config.pipe_name,
            flags,
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT
            | PIPE_REJECT_REMOTE_CLIENTS,
            self.config.instances,
            self.config.output_buffer_bytes,
            self.config.input_buffer_bytes,
            0,
            self._security_attributes,
        )

    def start(self) -> None:
        if self._started:
            return
        # This creation is synchronous: a squatted pipe name fails startup
        # before the service reports ready.
        first_handle = self._create_pipe(first=True)
        try:
            integrity_sid, integrity_policy = pipe_mandatory_label(first_handle)
            if (
                integrity_sid != PIPE_INTEGRITY_SID
                or integrity_policy != PIPE_INTEGRITY_POLICY
            ):
                raise ProvenancePipeError(
                    "provenance pipe mandatory integrity label is not medium/no-write-up"
                )
        except Exception:
            win32file.CloseHandle(first_handle)
            raise
        self.integrity_sid = integrity_sid
        self.integrity_policy = integrity_policy
        self._started = True
        for index in range(self.config.instances):
            thread = threading.Thread(
                target=self._worker,
                args=(first_handle if index == 0 else None,),
                daemon=True,
                name=f"provenance-pipe-{index}",
            )
            self._threads.append(thread)
            thread.start()

    def _error_response(self, code: str, request_id: str | None = None) -> dict[str, Any]:
        response: dict[str, Any] = {
            "error": code,
            "ok": False,
            "request_id": request_id,
            "server_ts_ms": self.core.now_ms(),
            "status": "denied",
            "version": PROTOCOL_VERSION,
        }
        return sign_service_response(self.core.service_identity, response)

    def _process(self, handle: Any) -> None:
        request: dict[str, Any] | None = None
        try:
            _wait_for_message(
                handle,
                deadline=time.monotonic() + self.config.request_timeout_ms / 1000,
                stop_event=self._stop,
            )
            try:
                _hr, data = win32file.ReadFile(handle, MAX_FRAME_BYTES + 1)
            except pywintypes.error as exc:
                if exc.winerror == winerror.ERROR_MORE_DATA:
                    raise ProvenanceProtocolError(
                        "frame_too_large", "request frame exceeds the limit"
                    ) from exc
                raise
            if len(data) > MAX_FRAME_BYTES:
                raise ProvenanceProtocolError("frame_too_large", "request frame exceeds the limit")
            # Impersonate only after a message has been read. Windows defines
            # ImpersonateNamedPipeClient in terms of the last message read.
            caller_sid = pipe_client_sid(handle, self.config.client_sids)
            request = decode_frame(bytes(data))
            response = self.core.handle_record(request, caller_sid)
        except ProvenanceProtocolError as exc:
            response = self._error_response(exc.code, _safe_request_id(request))
        except ProvenanceServiceUnavailable:
            response = self._error_response("service_unavailable", _safe_request_id(request))
        except Exception:
            logger.exception("Unhandled provenance pipe request failure")
            response = self._error_response("internal_fail_closed", _safe_request_id(request))
        encoded = encode_frame(response)
        win32file.WriteFile(handle, encoded)
        win32file.FlushFileBuffers(handle)

    def _worker(self, initial_handle: Any | None) -> None:
        handle = initial_handle
        while not self._stop.is_set():
            if handle is None:
                try:
                    handle = self._create_pipe(first=False)
                except Exception:
                    if not self._stop.is_set():
                        logger.exception("Could not create provenance pipe instance")
                        self._fatal.set()
                    return
            try:
                try:
                    win32pipe.ConnectNamedPipe(handle, None)
                except pywintypes.error as exc:
                    if exc.winerror != winerror.ERROR_PIPE_CONNECTED:
                        raise
                if not self._stop.is_set():
                    self._process(handle)
            except pywintypes.error as exc:
                if not self._stop.is_set() and exc.winerror not in {
                    winerror.ERROR_BROKEN_PIPE,
                    winerror.ERROR_NO_DATA,
                }:
                    logger.warning("Provenance pipe worker error: %s", exc)
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(handle)
                except Exception:
                    pass
                win32file.CloseHandle(handle)
                handle = None

    def stop(self) -> None:
        if not self._started:
            return
        self._stop.set()
        # Wake blocking ConnectNamedPipe calls. Each connection is local and
        # immediately closed without sending application data.
        for _thread in self._threads:
            try:
                win32pipe.WaitNamedPipe(self.config.pipe_name, 100)
                handle = win32file.CreateFile(
                    self.config.pipe_name,
                    PIPE_CLIENT_ACCESS,
                    0,
                    None,
                    win32con.OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    None,
                )
                win32file.CloseHandle(handle)
            except Exception:
                pass
        for thread in self._threads:
            thread.join(timeout=5)
        self.core.close()
        self._started = False

    @property
    def healthy(self) -> bool:
        return self._started and not self._fatal.is_set() and all(
            thread.is_alive() for thread in self._threads
        )


class ProvenancePipeClient:
    def __init__(
        self,
        *,
        expected_service_sid: str,
        service_agent_id: str,
        service_algorithm: str,
        service_public_key: bytes,
        pipe_name: str = PIPE_NAME,
        timeout_ms: int = DEFAULT_CONNECT_TIMEOUT_MS,
    ) -> None:
        _require_windows()
        self.expected_service_sid = expected_service_sid
        self.service_agent_id = service_agent_id
        self.service_algorithm = service_algorithm
        self.service_public_key = service_public_key
        self.pipe_name = pipe_name
        self.timeout_ms = timeout_ms

    def submit(self, request: dict[str, Any]) -> dict[str, Any]:
        encoded = encode_frame(request)
        deadline = time.monotonic() + self.timeout_ms / 1000
        handle = None
        last_error = None
        while handle is None and time.monotonic() < deadline:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            try:
                win32pipe.WaitNamedPipe(self.pipe_name, remaining_ms)
                handle = win32file.CreateFile(
                    self.pipe_name,
                    PIPE_CLIENT_ACCESS,
                    0,
                    None,
                    win32con.OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    None,
                )
            except pywintypes.error as exc:
                last_error = exc
                if exc.winerror not in {
                    winerror.ERROR_FILE_NOT_FOUND,
                    winerror.ERROR_PIPE_BUSY,
                    winerror.ERROR_SEM_TIMEOUT,
                }:
                    raise ProvenancePipeError("provenance service connection was rejected") from exc
                time.sleep(0.01)
        if handle is None:
            raise ProvenancePipeError(
                "provenance service is unavailable or backpressured"
            ) from last_error
        try:
            actual_sid = pipe_server_sid(handle)
            if actual_sid != self.expected_service_sid:
                raise ProvenancePipeError("named-pipe server SID does not match the pinned service SID")
            win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            win32file.WriteFile(handle, encoded)
            _wait_for_message(handle, deadline=deadline)
            _hr, data = win32file.ReadFile(handle, MAX_FRAME_BYTES + 1)
            response = decode_frame(bytes(data))
            if not verify_service_response(
                response,
                algorithm=self.service_algorithm,
                public_key=self.service_public_key,
                expected_agent_id=self.service_agent_id,
            ):
                raise ProvenancePipeError("provenance service response signature is invalid")
            if response.get("request_id") not in {None, request.get("request_id")}:
                raise ProvenancePipeError("provenance response request_id mismatch")
            return response
        finally:
            win32file.CloseHandle(handle)
