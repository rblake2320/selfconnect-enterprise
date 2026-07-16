from __future__ import annotations

import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.provenance_client import ProvenanceServiceLedgerAdapter
from enterprise.provenance_service_core import ProvenanceServiceUnavailable


class FakeIdentity:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.agent_id = "SC-" + hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def submit(self, request):
        self.requests.append(request)
        return dict(self.response)


def test_ledger_adapter_submits_signed_tool_call_and_returns_receipt():
    client = FakeClient({"ok": True, "status": "committed", "receipt": {"seq": 2}})
    adapter = ProvenanceServiceLedgerAdapter(
        identity=FakeIdentity(),
        client=client,
        session_id=str(uuid.uuid4()),
    )
    response = adapter.log("operator_control", result="paused", metadata={"command": "pause"})
    assert response["receipt"]["seq"] == 2
    request = client.requests[0]
    assert request["event_type"] == "tool_call"
    assert request["payload"] == {
        "action": "operator_control",
        "metadata": {"command": "pause"},
        "result": "paused",
    }
    assert isinstance(request["request_signature"], str)


def test_ledger_adapter_denial_is_fail_closed():
    adapter = ProvenanceServiceLedgerAdapter(
        identity=FakeIdentity(),
        client=FakeClient({"error": "service_unavailable", "ok": False, "status": "denied"}),
        session_id=str(uuid.uuid4()),
    )
    with pytest.raises(ProvenanceServiceUnavailable, match="denied evidence commit"):
        adapter.log("operator_control")
