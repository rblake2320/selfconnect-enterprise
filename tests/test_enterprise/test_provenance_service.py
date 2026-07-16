from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from enterprise.audit_config import AuditConfig, AuditMode as ConfigAuditMode, WormSinkType
from enterprise.provenance import SessionEventType, SessionState, canonical_hash
from enterprise.provenance_service import (
    ProvenanceRecorderManager,
    ProvenanceServiceConfigurationError,
    main,
    verify_service_path_acl,
)
import enterprise.provenance_service as provenance_service


class FakeIdentity:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.agent_id = "SC-" + hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def manager(tmp_path, identity):
    return ProvenanceRecorderManager(
        audit_config=AuditConfig(
            audit_mode=ConfigAuditMode.ENTERPRISE,
            worm_sink=WormSinkType.MEMORY,
        ),
        identity=identity,
        ledger_dir=tmp_path,
    )


def event_types(path):
    return [json.loads(line)["event_type"] for line in path.read_text(encoding="utf-8").splitlines()]


def test_service_identity_bootstrap_requires_service_token_and_uses_enrollment_scope(
    tmp_path, monkeypatch
):
    paths = SimpleNamespace(
        root=tmp_path,
        config_dir=tmp_path / "config",
        enrollment_file=tmp_path / "config" / "enrollments.json",
        identity_dir=tmp_path / "identity",
    )
    paths.config_dir.mkdir()
    paths.identity_dir.mkdir()
    paths.enrollment_file.write_text('{"agents":[],"version":1}\n', encoding="ascii")
    service_sid = "S-1-5-80-123"
    client_sids = frozenset({"S-1-5-21-1-2-3-1001"})
    observed = []
    identity = SimpleNamespace(agent_id="SC-BOOTSTRAP")

    monkeypatch.setattr(provenance_service, "_WIN32_SERVICE_AVAILABLE", True)
    monkeypatch.setattr(provenance_service, "resolve_account_sid", lambda _name: service_sid)
    monkeypatch.setattr(provenance_service, "current_process_sid", lambda: service_sid)
    monkeypatch.setattr(
        provenance_service.EnrollmentRegistry,
        "load",
        lambda _path: SimpleNamespace(allowed_sids=client_sids),
    )
    monkeypatch.setattr(
        provenance_service,
        "verify_service_tree_acls",
        lambda path, **kwargs: observed.append((path, kwargs)),
    )
    monkeypatch.setattr(provenance_service.AgentIdentity, "exists", lambda *_a, **_k: False)
    monkeypatch.setattr(provenance_service.AgentIdentity, "init", lambda *_a, **_k: identity)

    assert provenance_service.bootstrap_service_identity(paths) is identity
    assert [item[0] for item in observed] == [
        paths.root,
        paths.config_dir,
        paths.identity_dir,
    ]
    assert all(item[1]["service_sid"] == service_sid for item in observed)
    assert all(item[1]["client_sids"] == client_sids for item in observed)

    monkeypatch.setattr(provenance_service, "current_process_sid", lambda: "S-1-5-21-OTHER")
    with pytest.raises(ProvenanceServiceConfigurationError, match="bootstrap token"):
        provenance_service.bootstrap_service_identity(paths)


def test_manager_interrupts_and_reconstructs_only_after_signed_chain_verification(tmp_path):
    identity = FakeIdentity()
    session_id = str(uuid.uuid4())
    first_manager = manager(tmp_path, identity)
    first = first_manager(session_id, None)
    first.record(SessionEventType.TOOL_CALL, payload={"action": "one"})
    first_manager.interrupt_all("test_restart")
    assert first.session_state == SessionState.INTERRUPTED
    assert first_manager.index.get_session(session_id).session_state == SessionState.INTERRUPTED.value

    second_manager = manager(tmp_path, identity)
    resumed = second_manager(session_id, None)
    assert resumed.session_state == SessionState.RECONSTRUCTED
    types = event_types(resumed.log_path)
    assert types.count(SessionEventType.SESSION_OPEN.value) == 1
    assert [item for item in types if item != SessionEventType.REPLICATION_ACK.value][-1] == (
        SessionEventType.SESSION_RECONSTRUCTED.value
    )
    assert resumed.verify().ok


def test_manager_refuses_resume_after_record_signature_tamper(tmp_path):
    identity = FakeIdentity()
    session_id = str(uuid.uuid4())
    first_manager = manager(tmp_path, identity)
    recorder = first_manager(session_id, None)
    recorder.record(SessionEventType.TOOL_CALL, payload={"action": "one"})
    first_manager.interrupt_all("test_restart")
    lines = recorder.log_path.read_text(encoding="utf-8").splitlines()
    target = next(
        index
        for index, line in enumerate(lines)
        if json.loads(line).get("event_type") == SessionEventType.TOOL_CALL.value
    )
    record = json.loads(lines[target])
    record["payload"]["action"] = "tampered"
    lines[target] = json.dumps(record, separators=(",", ":"))
    recorder.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ProvenanceServiceConfigurationError, match="resume verification failed"):
        manager(tmp_path, identity)(session_id, None)


def test_manager_refuses_resume_after_valid_tail_records_are_removed(tmp_path):
    identity = FakeIdentity()
    session_id = str(uuid.uuid4())
    first_manager = manager(tmp_path, identity)
    recorder = first_manager(session_id, None)
    recorder.record(SessionEventType.TOOL_CALL, payload={"action": "one"})
    first_manager.note_commit(recorder)
    high_water = first_manager.index.get_session(session_id).last_known_seq
    assert high_water == recorder.event_count

    lines = recorder.log_path.read_text(encoding="utf-8").splitlines()
    while lines and json.loads(lines[-1]).get("event_type") == SessionEventType.REPLICATION_ACK.value:
        lines.pop()
    removed = json.loads(lines.pop())
    assert removed["event_type"] == SessionEventType.TOOL_CALL.value
    recorder.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ProvenanceServiceConfigurationError, match="rollback suspected"):
        manager(tmp_path, identity)(session_id, None)


def test_manager_refuses_rewritten_signed_high_water_index(tmp_path):
    identity = FakeIdentity()
    session_id = str(uuid.uuid4())
    first_manager = manager(tmp_path, identity)
    recorder = first_manager(session_id, None)
    recorder.record(SessionEventType.TOOL_CALL, payload={"action": "one"})
    first_manager.note_commit(recorder)
    first_manager.interrupt_all("test_restart")

    index_path = tmp_path / "session_index.jsonl"
    lines = index_path.read_text(encoding="utf-8").splitlines()
    rewritten = json.loads(lines[-1])
    rewritten["last_known_seq"] = 1
    rewritten["remote_receipt"] = None
    rewritten.pop("entry_hash")
    rewritten["entry_hash"] = canonical_hash(rewritten)
    lines[-1] = json.dumps(rewritten, sort_keys=True, separators=(",", ":"))
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ProvenanceServiceConfigurationError, match="session index"):
        manager(tmp_path, identity)(session_id, None)


def test_manager_rejects_consumer_mode(tmp_path):
    with pytest.raises(ProvenanceServiceConfigurationError, match="consumer"):
        ProvenanceRecorderManager(
            audit_config=AuditConfig(audit_mode=ConfigAuditMode.CONSUMER),
            identity=FakeIdentity(),
            ledger_dir=tmp_path,
        )


def test_manager_configures_the_session_index_for_remote_receipt_comparison(tmp_path):
    value = manager(tmp_path, FakeIdentity())
    assert value.index._replication_sink is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL contract")
def test_path_acl_accepts_service_only_write_and_rejects_client_write(tmp_path):
    import win32api
    import win32con
    import win32security

    path = tmp_path / "ledger"
    path.mkdir()
    service_sid_obj, _domain, _kind = win32security.LookupAccountName("", win32api.GetUserNameEx(2))
    service_sid = win32security.ConvertSidToStringSid(service_sid_obj)
    client_sid = "S-1-5-21-1-2-3-1001"

    def set_dacl(client_read=False, client_write=False):
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_ALL,
            service_sid_obj,
        )
        if client_read or client_write:
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_WRITE if client_write else win32con.GENERIC_READ,
                win32security.ConvertStringSidToSid(client_sid),
            )
        descriptor = win32security.SECURITY_DESCRIPTOR()
        descriptor.SetSecurityDescriptorOwner(
            win32security.ConvertStringSidToSid("S-1-5-32-544"),
            False,
        )
        descriptor.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
            descriptor,
        )

    set_dacl(client_read=True)
    verify_service_path_acl(
        path,
        service_sid=service_sid,
        client_sids=frozenset({client_sid}),
        service_requires_write=True,
    )
    set_dacl(client_write=True)
    with pytest.raises(ProvenanceServiceConfigurationError, match="direct write authority"):
        verify_service_path_acl(
            path,
            service_sid=service_sid,
            client_sids=frozenset({client_sid}),
            service_requires_write=True,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows owner contract")
def test_path_acl_allows_exact_service_owner_only_for_runtime_descendants(tmp_path):
    import win32api
    import win32con
    import win32security

    path = tmp_path / "runtime-created.jsonl"
    path.write_text("{}\n", encoding="ascii")
    service_sid_obj, _domain, _kind = win32security.LookupAccountName(
        "", win32api.GetUserNameEx(2)
    )
    service_sid = win32security.ConvertSidToStringSid(service_sid_obj)
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, service_sid_obj)
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(service_sid_obj, False)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(
        str(path),
        win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
        descriptor,
    )
    with pytest.raises(ProvenanceServiceConfigurationError, match="permitted dedicated"):
        verify_service_path_acl(
            path,
            service_sid=service_sid,
            client_sids=frozenset(),
            service_requires_write=True,
        )
    verify_service_path_acl(
        path,
        service_sid=service_sid,
        client_sids=frozenset(),
        service_requires_write=True,
        allow_service_owner=True,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows service command contract")
def test_service_command_propagates_pywin32_failure_exit(monkeypatch):
    monkeypatch.setattr(
        "enterprise.provenance_service.win32serviceutil.HandleCommandLine",
        lambda *_args, **_kwargs: 37,
    )
    assert main(["provenance_service", "install"]) == 37


@pytest.mark.skipif(os.name != "nt", reason="Windows service command contract")
def test_service_install_uses_exact_python_module_host():
    from enterprise.provenance_service import SelfConnectProvenanceService

    assert SelfConnectProvenanceService._exe_name_ == sys.executable
    assert SelfConnectProvenanceService._exe_args_ == "-m enterprise.provenance_service"


@pytest.mark.skipif(os.name != "nt", reason="Windows service command contract")
def test_service_process_registers_dispatcher_without_cli_args(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "enterprise.provenance_service.servicemanager.Initialize",
        lambda: calls.append("initialize"),
    )
    monkeypatch.setattr(
        "enterprise.provenance_service.servicemanager.PrepareToHostSingle",
        lambda service_class: calls.append(("prepare", service_class._svc_name_)),
    )
    monkeypatch.setattr(
        "enterprise.provenance_service.servicemanager.StartServiceCtrlDispatcher",
        lambda: calls.append("dispatch"),
    )
    assert main(["provenance_service"]) == 0
    assert calls == [
        "initialize",
        ("prepare", "SelfConnectProvenance"),
        "dispatch",
    ]
