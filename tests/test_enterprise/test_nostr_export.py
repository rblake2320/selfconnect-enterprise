"""NIP-01 export-only adapter tests."""
from __future__ import annotations

import hashlib
import json
from unittest.mock import patch

import pytest

from enterprise.identity import AgentIdentity
from enterprise.ledger import AgentLedger
from enterprise.nostr_export import export_from_verified_observer, export_verified_record
from enterprise.observer import LedgerObserver


class _Signer:
    public_key_xonly = bytes(range(32))

    def __init__(self) -> None:
        self.signed: list[bytes] = []

    def sign_schnorr(self, event_id: bytes) -> bytes:
        self.signed.append(event_id)
        return event_id + event_id


def test_verified_record_exports_exact_nip01_shape():
    signer = _Signer()
    event = export_verified_record(
        {"seq": 7, "action": "sc_inject_text", "decision": "allow"},
        source_verifier=lambda record: record["decision"] == "allow",
        signer=signer,
        created_at=1_700_000_000,
        kind=8_901,
        tags=[["classification", "CUI"]],
    )
    assert set(event) == {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    expected = hashlib.sha256(serialized).digest()
    assert event["id"] == expected.hex()
    assert signer.signed == [expected]
    assert event["sig"] == (expected + expected).hex()


def test_unverified_source_fails_before_signing():
    signer = _Signer()
    with pytest.raises(PermissionError, match="source record verification failed"):
        export_verified_record(
            {"decision": "deny"},
            source_verifier=lambda _record: False,
            signer=signer,
            created_at=1,
            kind=8_901,
        )
    assert signer.signed == []


@pytest.mark.parametrize("created_at,kind", [(-1, 8_901), (True, 8_901), (1, -1), (1, 65_536)])
def test_invalid_time_or_kind_rejected(created_at, kind):
    with pytest.raises(ValueError):
        export_verified_record(
            {}, source_verifier=lambda _record: True, signer=_Signer(), created_at=created_at, kind=kind
        )


def test_non_nostr_key_is_not_relabelled():
    signer = _Signer()
    signer.public_key_xonly = b"short"
    with pytest.raises(ValueError, match="32-byte x-only"):
        export_verified_record(
            {}, source_verifier=lambda _record: True, signer=signer, created_at=1, kind=8_901
        )


def test_non_schnorr_length_signature_is_rejected():
    signer = _Signer()
    signer.sign_schnorr = lambda _event_id: b"not-a-signature"
    with pytest.raises(ValueError, match="64-byte Schnorr"):
        export_verified_record(
            {}, source_verifier=lambda _record: True, signer=signer, created_at=1, kind=8_901
        )


def test_caller_cannot_override_authoritative_export_tags():
    with pytest.raises(ValueError, match="reserved export tags"):
        export_verified_record(
            {},
            source_verifier=lambda _record: True,
            signer=_Signer(),
            created_at=1,
            kind=8_901,
            tags=[["source-sha256", "forged"]],
        )


def test_verified_observer_path_checks_ledger_before_export(tmp_path):
    with patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value):
        identity = AgentIdentity.init("nostr-observer", data_dir=tmp_path / "identities")
    ledger = AgentLedger(identity, log_path=tmp_path / "verified.jsonl")
    ledger.log(
        "sc_inject_text",
        result="allowed",
        metadata={
            "decision": "allow",
            "approval_mode": "human_approved",
            "classification": "CUI",
            "policy_id": "policy-1",
        },
    )
    observer = LedgerObserver(ledger.log_path, verifier=ledger, context_window=0)
    events = export_from_verified_observer(observer, signer=_Signer(), kind=8_901)
    assert len(events) == 1
    assert ["source-seq", "1"] in events[0]["tags"]
    assert ["classification", "CUI"] in events[0]["tags"]


def test_unsafe_observer_cannot_use_production_export_path(tmp_path):
    observer = LedgerObserver(tmp_path / "raw.jsonl", unsafe_unverified=True)
    with pytest.raises(PermissionError, match="verifier-bound observer"):
        export_from_verified_observer(observer, signer=_Signer(), kind=8_901)


def test_tampered_ledger_fails_before_nostr_signing(tmp_path):
    with patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value):
        identity = AgentIdentity.init("nostr-tamper", data_dir=tmp_path / "identities")
    ledger = AgentLedger(identity, log_path=tmp_path / "tampered.jsonl")
    ledger.log(
        "sc_inject_text",
        result="allowed",
        metadata={"decision": "allow", "approval_mode": "autonomous"},
    )
    entry = json.loads(ledger.log_path.read_text(encoding="utf-8"))
    entry["result"] = "altered"
    ledger.log_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    signer = _Signer()
    observer = LedgerObserver(ledger.log_path, verifier=ledger)
    with pytest.raises(RuntimeError, match="Ledger integrity check failed"):
        export_from_verified_observer(observer, signer=signer, kind=8_901)
    assert signer.signed == []


def test_wrong_ledger_verifier_fails_before_nostr_signing(tmp_path):
    with patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value):
        identity = AgentIdentity.init("nostr-path", data_dir=tmp_path / "identities")
    first = AgentLedger(identity, log_path=tmp_path / "first.jsonl")
    second = AgentLedger(identity, log_path=tmp_path / "second.jsonl")
    first.log("first", metadata={"decision": "allow", "approval_mode": "autonomous"})
    second.log("second", metadata={"decision": "allow", "approval_mode": "autonomous"})
    signer = _Signer()
    observer = LedgerObserver(first.log_path, verifier=second)
    with pytest.raises(ValueError, match="Verifier is bound"):
        export_from_verified_observer(observer, signer=signer, kind=8_901)
    assert signer.signed == []
