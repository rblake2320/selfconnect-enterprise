"""enterprise/service.py — Windows Service wrapper for the SelfConnect Enterprise control plane."""
from __future__ import annotations

import logging
import os
import pathlib
import sys
import threading

try:
    import win32event
    import win32service
    import win32serviceutil
    import servicemanager
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

logger = logging.getLogger(__name__)

SERVICE_NAME = "SelfConnectEnterprise"
SERVICE_DISPLAY_NAME = "SelfConnect Enterprise Control Plane"
SERVICE_DESCRIPTION = (
    "Governed OS-native AI peer mesh. Provides TPM-backed identity leases, "
    "DACL-guarded pipe transport, fail-closed target verification, and per-action audit receipts."
)

# ---------------------------------------------------------------------------
# Path validation helpers — prevent env-var-driven path traversal
# ---------------------------------------------------------------------------

_SAFE_PATH_BASES: tuple[pathlib.Path, ...] = (
    pathlib.Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")),
    pathlib.Path(os.environ.get("APPDATA", r"C:\Users\Default\AppData\Roaming")),
    pathlib.Path(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local")),
    pathlib.Path.cwd(),
)


def _validate_env_path(raw: str, purpose: str) -> pathlib.Path:
    """Return a resolved, safe Path from *raw*.

    Raises ValueError if the path:
    - contains ``..`` components (traversal attempt)
    - is an absolute UNC path (``\\\\`` prefix)
    - resolves to a known sensitive system directory
    """
    # UNC paths can redirect I/O to attacker-controlled shares.
    if raw.startswith("\\\\") or raw.startswith("//"):
        raise ValueError(
            f"SCENT env path for {purpose} must not be a UNC path: {raw!r}"
        )

    candidate = pathlib.Path(raw)

    # Reject any ``..`` components before resolution to catch obvious traversal.
    if any(part == ".." for part in candidate.parts):
        raise ValueError(
            f"SCENT env path for {purpose} contains '..' traversal: {raw!r}"
        )

    try:
        resolved = candidate.resolve()
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"SCENT env path for {purpose} could not be resolved: {raw!r}"
        ) from exc

    # Block writes into sensitive Windows system directories.
    _BLOCKED = (
        pathlib.Path(os.environ.get("WINDIR", r"C:\Windows")),
        pathlib.Path(os.environ.get("SYSTEMROOT", r"C:\Windows")),
    )
    for blocked in _BLOCKED:
        try:
            resolved.relative_to(blocked.resolve())
            raise ValueError(
                f"SCENT env path for {purpose} targets a protected system directory: {raw!r}"
            )
        except ValueError as exc:
            # relative_to raises ValueError when resolved is NOT under blocked — that is
            # the good case.  Re-raise only when we produced our own message above.
            if "protected system directory" in str(exc):
                raise

    return resolved


def _safe_config_path() -> pathlib.Path:
    raw = os.environ.get("SCENT_CONFIG", "enterprise_config.toml")
    try:
        return _validate_env_path(raw, "SCENT_CONFIG")
    except ValueError:
        logger.error(
            "SCENT_CONFIG value %r failed validation; falling back to default", raw
        )
        return pathlib.Path("enterprise_config.toml").resolve()


def _safe_log_dir_path() -> pathlib.Path:
    raw = os.environ.get("SCENT_LOG_DIR", ".")
    try:
        validated = _validate_env_path(raw, "SCENT_LOG_DIR")
    except ValueError:
        logger.error(
            "SCENT_LOG_DIR value %r failed validation; falling back to cwd", raw
        )
        validated = pathlib.Path(".").resolve()
    return validated / "scent-service.log"


DEFAULT_CONFIG_PATH = _safe_config_path()
DEFAULT_LOG_PATH = _safe_log_dir_path()


def _setup_file_logging(log_path: pathlib.Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)


class ControlPlaneThread(threading.Thread):
    """Worker thread that runs the ControlPlane.

    The *crashed* attribute is set to ``True`` if the thread exits due to an
    unhandled exception.  Callers MUST check this flag and fail the service
    rather than continuing with a dead control plane (silent fail-open).

    Attributes
    ----------
    provenance_recorder:
        The ProvenanceRecorder created for this thread's session.  Set after
        run() successfully initialises it; None if initialisation failed or
        WORM setup was skipped (consumer mode).
    """

    def __init__(self, stop_event: threading.Event) -> None:
        super().__init__(daemon=True, name="scent-control-plane")
        self._stop_signal = stop_event
        self.crashed: bool = False
        self.provenance_recorder = None

    def run(self) -> None:
        recorder = None
        orchestrator_token = None
        try:
            import secrets
            import uuid
            from enterprise.audit_config import AuditMode as CfgAuditMode
            from enterprise.audit_config import WormSinkType, load_audit_config
            from enterprise.worm_service import WormServiceError, build_provenance_recorder

            audit_config = load_audit_config()
            logger.info("Audit config: %s", audit_config.describe())

            # Government mode with no WORM sink — refuse to start (fail-closed).
            if (
                audit_config.fail_closed_without_worm()
                and audit_config.worm_sink == WormSinkType.NONE
            ):
                logger.error(
                    "REFUSING to start ControlPlane: government audit mode requires "
                    "a WORM replication sink (SCENT_WORM_SINK != none)."
                )
                self.crashed = True
                self._stop_signal.set()
                return

            # Enterprise mode with memory sink — no immutable retention proof.
            if (
                audit_config.audit_mode == CfgAuditMode.ENTERPRISE
                and audit_config.worm_sink == WormSinkType.MEMORY
            ):
                logger.warning(
                    "Enterprise mode is configured with InMemoryWitnessSink. "
                    "This is not immutable retention; configure and live-verify "
                    "S3 Object Lock or Cloudflare R2 bucket lock."
                )

            from enterprise.identity import AgentIdentity

            session_id = str(uuid.uuid4())
            identity_name = "scent-service"
            identity = (
                AgentIdentity.load(identity_name)
                if AgentIdentity.exists(identity_name)
                else AgentIdentity.init(identity_name)
            )
            orchestrator_token = secrets.token_urlsafe(32)
            try:
                recorder = build_provenance_recorder(
                    audit_config,
                    session_id,
                    identity=identity,
                    orchestrator_token=orchestrator_token,
                )
                recorder.start()
                self.provenance_recorder = recorder
                logger.info(
                    "ProvenanceRecorder initialised: session=%s mode=%s",
                    session_id, audit_config.audit_mode.value,
                )
            except WormServiceError as exc:
                logger.error("WORM service initialisation failed: %s", exc)
                self.crashed = True
                self._stop_signal.set()
                return

            from enterprise.control import ControlPlane
            cp = ControlPlane(ledger=_ProvenanceLedgerAdapter(recorder))
            logger.info("ControlPlane started")
            while not self._stop_signal.wait(timeout=5.0):
                pass
            cp.shutdown() if hasattr(cp, "shutdown") else None
            recorder.close(
                summary={"reason": "service_stop"},
                orchestrator_token=orchestrator_token,
            )
            logger.info("ControlPlane stopped")
        except Exception:  # noqa: BLE001
            logger.exception("ControlPlane thread crashed — service will stop to avoid fail-open")
            self.crashed = True
            # Signal the service main loop to stop so the SCM can restart it
            # rather than leaving the service alive with no enforcement.
            self._stop_signal.set()
        finally:
            if recorder is not None and recorder.is_started and not recorder.is_closed:
                try:
                    recorder.close(
                        summary={"reason": "service_failure" if self.crashed else "service_stop"},
                        orchestrator_token=orchestrator_token,
                    )
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to seal provenance recorder during shutdown")
                    self.crashed = True
                    self._stop_signal.set()


class _ProvenanceLedgerAdapter:
    """Expose ProvenanceRecorder as the ledger interface used by ControlPlane."""

    def __init__(self, recorder) -> None:
        self._recorder = recorder

    def log(self, action: str, result: str = "", metadata: dict | None = None, **_kwargs):
        from enterprise.provenance import SessionEventType

        return self._recorder.record(
            SessionEventType.TOOL_CALL,
            payload={
                "action": action,
                "result": result,
                "metadata": metadata or {},
            },
        )


if _WIN32_AVAILABLE:
    class SelfConnectEnterpriseService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._thread_stop = threading.Event()
            self._cp_thread: ControlPlaneThread | None = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )
            self._thread_stop.set()
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self) -> None:
            _setup_file_logging(DEFAULT_LOG_PATH)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            logger.info("SelfConnect Enterprise service starting")
            self._cp_thread = ControlPlaneThread(self._thread_stop)
            self._cp_thread.start()

            # Poll for both the OS stop signal (5-second granularity) and a
            # ControlPlane crash.  If the control plane crashes we stop the
            # service immediately — running without enforcement is fail-open.
            _POLL_MS = 5_000
            while True:
                result = win32event.WaitForSingleObject(self._stop_event, _POLL_MS)
                if result == win32event.WAIT_OBJECT_0:
                    # Normal SCM stop request.
                    break
                # WAIT_TIMEOUT — check whether the control-plane thread crashed.
                if self._cp_thread.crashed:
                    logger.error(
                        "ControlPlane thread crashed; stopping service to avoid fail-open"
                    )
                    self.SvcStop()
                    break

            logger.info("SelfConnect Enterprise service stopped")


def main(argv: list[str] | None = None) -> int:
    if not _WIN32_AVAILABLE:
        print("ERROR: pywin32 is required to run as a Windows service.", file=sys.stderr)
        return 1
    win32serviceutil.HandleCommandLine(SelfConnectEnterpriseService, argv=argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
