from __future__ import annotations

import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.provenance_client import (
    DiscoveringProvenancePipeClient,
    ProvenanceServiceLedgerAdapter,
)
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


def test_discovering_client_uses_fresh_pinned_endpoint_each_submission(tmp_path, monkeypatch):
    endpoint = tmp_path / "current.json"
    service_key = b"k" * 32
    observed = []

    class CapturingClient:
        def __init__(self, **kwargs):
            observed.append(kwargs)

        def submit(self, request):
            return {"ok": True, "request": request}

    monkeypatch.setattr("enterprise.provenance_client.ProvenancePipeClient", CapturingClient)
    client = DiscoveringProvenancePipeClient(
        endpoint_file=endpoint,
        expected_service_sid="S-1-5-80-123",
        service_agent_id="SC-12345678",
        service_algorithm="ed25519",
        service_public_key=service_key,
        timeout_ms=1000,
    )
    for suffix in ("a" * 32, "b" * 32):
        endpoint.write_text(
            (
                '{"pipe_name":"\\\\\\\\.\\\\pipe\\\\SelfConnectProvenance.v1.'
                + suffix
                + '","service_agent_id":"SC-12345678",'
                '"service_sid":"S-1-5-80-123",'
                '"version":"selfconnect.provenance.endpoint.v1"}'
            ),
            encoding="utf-8",
        )
        assert client.submit({"request_id": suffix})["ok"]
    assert [item["pipe_name"] for item in observed] == [
        rf"\\.\pipe\SelfConnectProvenance.v1.{'a' * 32}",
        rf"\\.\pipe\SelfConnectProvenance.v1.{'b' * 32}",
    ]


def test_discovering_client_rejects_unpinned_endpoint(tmp_path):
    endpoint = tmp_path / "current.json"
    endpoint.write_text(
        '{"pipe_name":"\\\\\\\\.\\\\pipe\\\\Other.x",'
        '"service_agent_id":"SC-12345678","service_sid":"S-1-5-80-123",'
        '"version":"selfconnect.provenance.endpoint.v1"}',
        encoding="utf-8",
    )
    client = DiscoveringProvenancePipeClient(
        endpoint_file=endpoint,
        expected_service_sid="S-1-5-80-123",
        service_agent_id="SC-12345678",
        service_algorithm="ed25519",
        service_public_key=b"k" * 32,
        timeout_ms=1000,
    )
    with pytest.raises(ProvenanceServiceUnavailable, match="pipe name is invalid"):
        client.submit({})
