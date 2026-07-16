"""Fail-closed client adapter for the dedicated provenance service."""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path
from typing import Any

from enterprise.identity import AgentIdentity
from enterprise.provenance import SessionEventType
from enterprise.provenance_ipc import build_record_request
from enterprise.provenance_pipe import PIPE_NAME, ProvenancePipeClient, resolve_account_sid
from enterprise.provenance_service import SERVICE_ACCOUNT
from enterprise.provenance_service_core import ProvenanceServiceUnavailable


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ProvenanceServiceUnavailable(f"{name} is required for hardened provenance")
    return value


class ProvenanceServiceLedgerAdapter:
    """Expose the remote recorder as the ledger contract used by ControlPlane."""

    def __init__(self, *, identity: Any, client: ProvenancePipeClient, session_id: str) -> None:
        self.identity = identity
        self.client = client
        self.session_id = str(uuid.UUID(session_id))
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "ProvenanceServiceLedgerAdapter":
        identity_root_raw = _required_env("SC_PROVENANCE_CLIENT_IDENTITY_DIR")
        if identity_root_raw.startswith(("\\\\", "//")):
            raise ProvenanceServiceUnavailable("provenance client identity path must be local")
        identity_root = Path(identity_root_raw).resolve()
        identity_name = os.environ.get("SC_PROVENANCE_CLIENT_IDENTITY_NAME", "scent-service")
        if not AgentIdentity.exists(identity_name, data_dir=identity_root):
            raise ProvenanceServiceUnavailable("enrolled provenance client identity is unavailable")
        identity = AgentIdentity.load(identity_name, data_dir=identity_root)
        algorithm = os.environ.get("SC_PROVENANCE_SERVICE_ALGORITHM", "ed25519")
        if algorithm not in {"ed25519", "ecdsa-p384-cng"}:
            raise ProvenanceServiceUnavailable("unsupported provenance service identity algorithm")
        try:
            service_public_key = bytes.fromhex(
                _required_env("SC_PROVENANCE_SERVICE_PUBLIC_KEY_HEX")
            )
        except ValueError as exc:
            raise ProvenanceServiceUnavailable(
                "SC_PROVENANCE_SERVICE_PUBLIC_KEY_HEX is not hexadecimal"
            ) from exc
        expected_length = 32 if algorithm == "ed25519" else 96
        if len(service_public_key) != expected_length:
            raise ProvenanceServiceUnavailable("provenance service public key has the wrong length")
        expected_sid = os.environ.get("SC_PROVENANCE_SERVICE_SID", "").strip()
        if not expected_sid:
            expected_sid = resolve_account_sid(SERVICE_ACCOUNT)
        client = ProvenancePipeClient(
            expected_service_sid=expected_sid,
            service_agent_id=_required_env("SC_PROVENANCE_SERVICE_AGENT_ID"),
            service_algorithm=algorithm,
            service_public_key=service_public_key,
            pipe_name=os.environ.get("SC_PROVENANCE_PIPE_NAME", PIPE_NAME),
            timeout_ms=int(os.environ.get("SC_PROVENANCE_CLIENT_TIMEOUT_MS", "5000")),
        )
        return cls(identity=identity, client=client, session_id=str(uuid.uuid4()))

    def log(
        self,
        action: str,
        result: str = "",
        metadata: dict | None = None,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        request = build_record_request(
            self.identity,
            session_id=self.session_id,
            event_type=SessionEventType.TOOL_CALL,
            payload={
                "action": action,
                "metadata": metadata or {},
                "result": result,
            },
        )
        with self._lock:
            response = self.client.submit(request)
        if response.get("ok") is not True or response.get("status") not in {
            "committed",
            "already_committed",
        }:
            raise ProvenanceServiceUnavailable(
                f"provenance service denied evidence commit: {response.get('error', 'unknown')}"
            )
        return response
