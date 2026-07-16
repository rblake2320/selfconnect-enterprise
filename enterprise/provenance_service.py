"""Dedicated Windows service hosting the authoritative provenance writer."""

from __future__ import annotations

import logging
import json
import os
import secrets
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from enterprise.audit_config import AuditMode as ConfigAuditMode
from enterprise.audit_config import load_audit_config
from enterprise.identity import AgentIdentity
from enterprise.provenance import ProvenanceRecorder, SessionState, verify_log
from enterprise.provenance_ipc import EnrollmentRegistry
from enterprise.provenance_pipe import (
    PIPE_NAME,
    ProvenancePipeConfig,
    ProvenancePipeServer,
    resolve_account_sid,
)
from enterprise.provenance_service_core import ProvenanceRequestStore, ProvenanceServiceCore
from enterprise.service import _validate_env_path
from enterprise.session_index import SessionIndex, SessionIndexError
from enterprise.worm_service import build_provenance_recorder, make_replication_sink

try:
    import servicemanager
    import win32api
    import win32con
    import win32event
    import win32security
    import win32service
    import win32serviceutil

    _WIN32_SERVICE_AVAILABLE = os.name == "nt"
except ImportError:  # pragma: no cover - non-Windows packaging path
    _WIN32_SERVICE_AVAILABLE = False

logger = logging.getLogger(__name__)

SERVICE_NAME = "SelfConnectProvenance"
SERVICE_DISPLAY_NAME = "SelfConnect Provenance Recorder"
SERVICE_ACCOUNT = rf"NT SERVICE\{SERVICE_NAME}"
SERVICE_DESCRIPTION = (
    "Dedicated signed provenance writer with enrolled identity verification, "
    "replay protection, and a service-SID filesystem boundary."
)

_WRITE_MASK = (
    0x00000002  # FILE_WRITE_DATA
    | 0x00000004  # FILE_APPEND_DATA
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x40000000  # GENERIC_WRITE
    | 0x10000000  # GENERIC_ALL
)
_READ_REQUIRED = 0x00000001 | 0x00000008 | 0x00000080 | 0x00020000 | 0x00100000
_WRITE_REQUIRED = 0x00000002 | 0x00000004 | 0x00000010 | 0x00000100
_BROAD_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545"})
_FILESYSTEM_AUTHORITY_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544"})
_PROHIBITED_CLIENT_SIDS = _BROAD_SIDS | frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-19",  # LocalService
        "S-1-5-20",  # NetworkService
    }
)


class ProvenanceServiceConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProvenanceServicePaths:
    root: Path
    config_dir: Path
    enrollment_file: Path
    endpoint_dir: Path
    endpoint_file: Path
    identity_dir: Path
    ledger_dir: Path
    log_file: Path
    request_db: Path
    state_dir: Path

    @classmethod
    def from_env(cls) -> "ProvenanceServicePaths":
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        root = _validate_env_path(
            os.environ.get(
                "SC_PROVENANCE_SERVICE_ROOT",
                str(program_data / "SelfConnect" / "Provenance"),
            ),
            "SC_PROVENANCE_SERVICE_ROOT",
        )
        config_dir = root / "config"
        identity_dir = root / "identity"
        endpoint_dir = root / "endpoint"
        ledger_dir = root / "ledger"
        state_dir = root / "state"
        return cls(
            root=root,
            config_dir=config_dir,
            enrollment_file=config_dir / "enrollments.json",
            endpoint_dir=endpoint_dir,
            endpoint_file=endpoint_dir / "current.json",
            identity_dir=identity_dir,
            ledger_dir=ledger_dir,
            log_file=state_dir / "service.log",
            request_db=state_dir / "requests.sqlite3",
            state_dir=state_dir,
        )


def _path_dacl(path: Path) -> list[tuple[int, int, str]]:
    descriptor = win32security.GetFileSecurity(
        str(path),
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        raise ProvenanceServiceConfigurationError(f"{path} has a null DACL")
    entries = []
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        ace_type = int(ace[0][0])
        mask = int(ace[1])
        sid = win32security.ConvertSidToStringSid(ace[2])
        entries.append((ace_type, mask, sid))
    return entries


def _path_owner(path: Path) -> str:
    descriptor = win32security.GetFileSecurity(
        str(path),
        win32security.OWNER_SECURITY_INFORMATION,
    )
    owner = descriptor.GetSecurityDescriptorOwner()
    return win32security.ConvertSidToStringSid(owner)


def verify_service_path_acl(
    path: Path,
    *,
    service_sid: str,
    client_sids: frozenset[str],
    service_requires_write: bool,
) -> None:
    """Fail startup on broad or client write authority and missing service rights."""
    if not path.exists():
        raise ProvenanceServiceConfigurationError(f"required hardened path is missing: {path}")
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise ProvenanceServiceConfigurationError(f"hardened path is a reparse point: {path}")
    owner = _path_owner(path)
    if owner not in _FILESYSTEM_AUTHORITY_SIDS:
        raise ProvenanceServiceConfigurationError(
            f"hardened path owner is not SYSTEM or Administrators: {path} ({owner})"
        )
    service_rights = 0
    for ace_type, mask, sid in _path_dacl(path):
        if ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
            if sid == service_sid and mask & (_READ_REQUIRED | _WRITE_REQUIRED):
                raise ProvenanceServiceConfigurationError(
                    f"service SID is explicitly denied required authority on {path}"
                )
            continue
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise ProvenanceServiceConfigurationError(
                f"unsupported ACE type {ace_type} on hardened path {path}"
            )
        if sid not in _FILESYSTEM_AUTHORITY_SIDS | {service_sid} | set(client_sids):
            raise ProvenanceServiceConfigurationError(
                f"unexpected allowed SID {sid} on hardened path {path}"
            )
        if sid == service_sid:
            service_rights |= mask
        if sid in _BROAD_SIDS and mask & _WRITE_MASK:
            raise ProvenanceServiceConfigurationError(
                f"broad SID {sid} has write authority on hardened path {path}"
            )
        if sid in client_sids and sid != service_sid and mask & _WRITE_MASK:
            raise ProvenanceServiceConfigurationError(
                f"client SID {sid} has direct write authority on hardened path {path}"
            )
    required = _READ_REQUIRED | (_WRITE_REQUIRED if service_requires_write else 0)
    if service_rights & required != required:
        mode = "write" if service_requires_write else "read"
        raise ProvenanceServiceConfigurationError(
            f"service SID lacks complete required {mode} authority on {path}"
        )


def verify_service_tree_acls(
    root: Path,
    *,
    service_sid: str,
    client_sids: frozenset[str],
    service_requires_write: bool,
) -> None:
    """Verify every existing directory and file without following reparse points."""
    pending = [Path(root)]
    while pending:
        current = pending.pop()
        verify_service_path_acl(
            current,
            service_sid=service_sid,
            client_sids=client_sids,
            service_requires_write=service_requires_write,
        )
        if not current.is_dir():
            continue
        try:
            children = list(os.scandir(current))
        except OSError as exc:
            raise ProvenanceServiceConfigurationError(
                f"cannot enumerate hardened path {current}: {exc}"
            ) from exc
        for child in children:
            child_path = Path(child.path)
            attributes = getattr(child.stat(follow_symlinks=False), "st_file_attributes", 0)
            if child.is_symlink() or attributes & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                raise ProvenanceServiceConfigurationError(
                    f"hardened tree contains a reparse point: {child_path}"
                )
            pending.append(child_path)


def current_process_sid() -> str:
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid)
    finally:
        token.Close()


class ProvenanceRecorderManager:
    def __init__(
        self,
        *,
        audit_config: Any,
        identity: Any,
        ledger_dir: Path,
    ) -> None:
        if audit_config.audit_mode == ConfigAuditMode.CONSUMER:
            raise ProvenanceServiceConfigurationError(
                "dedicated provenance service refuses consumer audit mode"
            )
        self.audit_config = audit_config
        self.identity = identity
        self.ledger_dir = ledger_dir
        self.index = SessionIndex(
            index_dir=ledger_dir,
            identity=identity,
            replication_sink=make_replication_sink(audit_config),
            require_signatures=True,
        )
        self.orchestrator_token = secrets.token_urlsafe(48)
        self._recorders: dict[str, ProvenanceRecorder] = {}
        self._lock = threading.RLock()

    def __call__(self, session_id: str, supervisor_id: str | None) -> ProvenanceRecorder:
        with self._lock:
            existing = self._recorders.get(session_id)
            if existing is not None:
                return existing
            try:
                manifest = self.index.get_session(session_id)
            except SessionIndexError as exc:
                raise ProvenanceServiceConfigurationError(
                    f"session index verification failed: {exc}"
                ) from exc
            resuming = manifest is not None
            if resuming:
                if manifest.session_state == SessionState.SEALED.value:
                    raise ProvenanceServiceConfigurationError("sealed session cannot be resumed")
                try:
                    resume = self.index.verify_for_resume(session_id)
                except SessionIndexError as exc:
                    raise ProvenanceServiceConfigurationError(
                        f"session index verification failed: {exc}"
                    ) from exc
                if not resume.ok:
                    raise ProvenanceServiceConfigurationError(
                        f"session resume verification failed: {resume.message}"
                    )
                signed = verify_log(
                    Path(manifest.log_path),
                    session_id,
                    recorder_public_key=self.identity.public_key_bytes,
                    require_recorder_signatures=True,
                )
                if not signed.ok:
                    raise ProvenanceServiceConfigurationError(
                        f"signed session resume verification failed: {signed.message}"
                    )
            recorder = build_provenance_recorder(
                self.audit_config,
                session_id,
                agent_id=self.identity.agent_id,
                identity=self.identity,
                log_dir=self.ledger_dir,
                orchestrator_token=self.orchestrator_token,
                supervisor_id=supervisor_id,
            )
            recorder.start(resume=resuming)
            if resuming:
                self.index.update_session(
                    session_id,
                    recorder=recorder,
                    state=SessionState.RECONSTRUCTED,
                )
            else:
                self.index.open_session(recorder)
            self._recorders[session_id] = recorder
            return recorder

    def interrupt_all(self, reason: str) -> None:
        with self._lock:
            for session_id, recorder in self._recorders.items():
                if not recorder.is_closed:
                    recorder.interrupt(reason)
                    self.index.update_session(
                        session_id,
                        recorder=recorder,
                        state=SessionState.INTERRUPTED,
                    )

    def note_commit(self, recorder: ProvenanceRecorder) -> None:
        """Advance the signed high-water index after every accepted event."""
        sink = recorder._replication_sink
        remote_receipt = (
            sink.get_latest_receipt(recorder.session_id)
            if sink is not None
            else None
        )
        updated = self.index.update_session(
            recorder.session_id,
            recorder=recorder,
            state=recorder.session_state,
            remote_receipt=remote_receipt,
        )
        if updated is None:
            raise ProvenanceServiceConfigurationError(
                "accepted event has no authoritative session index entry"
            )


class ProvenanceServiceRuntime:
    def __init__(self, paths: ProvenanceServicePaths | None = None) -> None:
        if not _WIN32_SERVICE_AVAILABLE:
            raise ProvenanceServiceConfigurationError("Windows and pywin32 are required")
        self.paths = paths or ProvenanceServicePaths.from_env()
        self.service_sid = resolve_account_sid(SERVICE_ACCOUNT)
        if current_process_sid() != self.service_sid:
            raise ProvenanceServiceConfigurationError(
                "process token is not the dedicated SelfConnectProvenance service SID"
            )
        self.registry = EnrollmentRegistry.load(self.paths.enrollment_file)
        prohibited = self.registry.allowed_sids & (
            _PROHIBITED_CLIENT_SIDS | {self.service_sid}
        )
        if prohibited:
            raise ProvenanceServiceConfigurationError(
                "enrolled client SIDs include a shared or privileged service identity: "
                + ", ".join(sorted(prohibited))
            )
        for path, writable in [
            (self.paths.root, False),
            (self.paths.config_dir, False),
            (self.paths.endpoint_dir, True),
            (self.paths.identity_dir, True),
            (self.paths.ledger_dir, True),
            (self.paths.state_dir, True),
        ]:
            verify_service_tree_acls(
                path,
                service_sid=self.service_sid,
                client_sids=self.registry.allowed_sids,
                service_requires_write=writable,
            )
        identity_name = SERVICE_NAME
        self.identity = (
            AgentIdentity.load(identity_name, data_dir=self.paths.identity_dir)
            if AgentIdentity.exists(identity_name, data_dir=self.paths.identity_dir)
            else AgentIdentity.init(identity_name, data_dir=self.paths.identity_dir)
        )
        self.manager = ProvenanceRecorderManager(
            audit_config=load_audit_config(),
            identity=self.identity,
            ledger_dir=self.paths.ledger_dir,
        )
        self.request_store = ProvenanceRequestStore(self.paths.request_db)
        for path, writable in [
            (self.paths.identity_dir, True),
            (self.paths.endpoint_dir, True),
            (self.paths.ledger_dir, True),
            (self.paths.state_dir, True),
        ]:
            verify_service_tree_acls(
                path,
                service_sid=self.service_sid,
                client_sids=self.registry.allowed_sids,
                service_requires_write=writable,
            )
        self.core = ProvenanceServiceCore(
            registry=self.registry,
            request_store=self.request_store,
            recorder_factory=self.manager,
            service_identity=self.identity,
            on_commit=self.manager.note_commit,
        )
        instances = int(os.environ.get("SC_PROVENANCE_PIPE_INSTANCES", "4"))
        self.pipe_name = f"{PIPE_NAME}.{secrets.token_hex(16)}"
        self.pipe = ProvenancePipeServer(
            self.core,
            ProvenancePipeConfig(
                service_sid=self.service_sid,
                client_sids=self.registry.allowed_sids,
                pipe_name=self.pipe_name,
                instances=instances,
            ),
        )

    def start(self) -> None:
        self.pipe.start()
        try:
            self._publish_endpoint()
        except Exception:
            self.pipe.stop()
            raise

    def stop(self, reason: str = "service_stop") -> None:
        try:
            self.manager.interrupt_all(reason)
        finally:
            try:
                self.pipe.stop()
            finally:
                self._remove_endpoint()

    @property
    def healthy(self) -> bool:
        return self.pipe.healthy and self.paths.endpoint_file.exists()

    def _publish_endpoint(self) -> None:
        value = {
            "pipe_name": self.pipe_name,
            "service_agent_id": self.identity.agent_id,
            "service_sid": self.service_sid,
            "version": "selfconnect.provenance.endpoint.v1",
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        temporary = self.paths.endpoint_file.with_name(
            f".{self.paths.endpoint_file.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.paths.endpoint_file)
        finally:
            temporary.unlink(missing_ok=True)
        verify_service_path_acl(
            self.paths.endpoint_file,
            service_sid=self.service_sid,
            client_sids=self.registry.allowed_sids,
            service_requires_write=True,
        )

    def _remove_endpoint(self) -> None:
        try:
            value = json.loads(self.paths.endpoint_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if value.get("pipe_name") == self.pipe_name:
            self.paths.endpoint_file.unlink(missing_ok=True)


if _WIN32_SERVICE_AVAILABLE:
    class SelfConnectProvenanceService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, True, False, None)
            self._runtime: ProvenanceServiceRuntime | None = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self) -> None:
            try:
                self._runtime = ProvenanceServiceRuntime()
                self._runtime.start()
                servicemanager.LogInfoMsg("SelfConnectProvenance service started")
                while True:
                    result = win32event.WaitForSingleObject(self._stop_event, 1_000)
                    if result == win32event.WAIT_OBJECT_0:
                        break
                    if not self._runtime.healthy:
                        raise ProvenanceServiceConfigurationError(
                            "provenance pipe worker set is not healthy"
                        )
                self._runtime.stop("scm_stop")
                servicemanager.LogInfoMsg("SelfConnectProvenance service stopped")
            except Exception:
                logger.exception("SelfConnectProvenance failed closed")
                servicemanager.LogErrorMsg("SelfConnectProvenance failed closed")
                raise


def main(argv: list[str] | None = None) -> int:
    if not _WIN32_SERVICE_AVAILABLE:
        print("ERROR: Windows and pywin32 are required", file=sys.stderr)
        return 1
    return int(
        win32serviceutil.HandleCommandLine(
            SelfConnectProvenanceService,
            argv=argv,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
