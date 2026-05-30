"""tests/test_enterprise/test_identity_cng.py — Integration tests for CngIdentity and CngLedger

Tests call real Windows CNG (NCrypt software KSP) — no mocking needed.
Keys are created with unique names and deleted in teardown.
"""
from __future__ import annotations

import json
import uuid

import pytest
from enterprise.crypto import CNG_BACKEND_AVAILABLE

from enterprise.crypto import ALGO_ID, P384_SIG_BYTES, SHA384_BYTES, cng_delete_key, cng_sha384
from enterprise.identity_cng import GENESIS_HASH_CNG, CngIdentity, CngLedger


pytestmark = pytest.mark.skipif(
    not CNG_BACKEND_AVAILABLE,
    reason='No ECDSA-P384 signing backend available (CNG or portable)'
)


AGENT_NAME_PREFIX = "sc-test-id-"


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def agent_name():
    """Unique agent name — NCrypt key auto-deleted after test."""
    name = f"{AGENT_NAME_PREFIX}{uuid.uuid4().hex[:10]}"
    yield name
    # cleanup NCrypt key regardless of test outcome
    cng_delete_key(f"SelfConnect.{name}")


@pytest.fixture
def identity(tmp_path, agent_name):
    """Fresh CngIdentity in a tmp directory."""
    ident = CngIdentity.init(agent_name, data_dir=tmp_path)
    yield ident
    ident.close()


@pytest.fixture
def ledger(tmp_path, identity):
    """CngLedger backed by the test identity."""
    return CngLedger(identity, log_path=tmp_path / "test_ledger_cng.jsonl")


# ── CngIdentity.init ───────────────────────────────────────────────────────────

class TestInit:
    def test_creates_pub_file(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path):
            pub_path = tmp_path / agent_name / "identity_cng.pub"
            assert pub_path.exists()

    def test_creates_algo_file(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path):
            algo_path = tmp_path / agent_name / "identity_cng.algo"
            assert algo_path.exists()
            assert algo_path.read_text() == ALGO_ID

    def test_agent_id_format(self, identity):
        assert identity.agent_id.startswith("SC-")
        assert len(identity.agent_id) == 11  # "SC-" + 8 hex chars

    def test_agent_id_derived_from_sha384_of_public_key(self, identity):
        expected = "SC-" + cng_sha384(identity.public_key_bytes).hex()[:8].upper()
        assert identity.agent_id == expected

    def test_public_key_bytes_length(self, identity):
        assert len(identity.public_key_bytes) == 96  # P-384 raw X || Y

    def test_pub_file_hex_matches_public_key(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path) as ident:
            pub_hex = (tmp_path / agent_name / "identity_cng.pub").read_text()
            assert bytes.fromhex(pub_hex) == ident.public_key_bytes

    def test_raises_if_already_exists(self, tmp_path, agent_name):
        CngIdentity.init(agent_name, data_dir=tmp_path).close()
        with pytest.raises(FileExistsError):
            CngIdentity.init(agent_name, data_dir=tmp_path)

    def test_overwrite_replaces_key(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path) as id1:
            pub1 = id1.public_key_bytes
        with CngIdentity.init(agent_name, data_dir=tmp_path, overwrite=True) as id2:
            pub2 = id2.public_key_bytes
        assert len(pub2) == 96
        assert pub1 != pub2  # new key pair

    def test_algo_id_property(self, identity):
        assert identity.algo_id == ALGO_ID
        assert "P384" in identity.algo_id


# ── CngIdentity.load ───────────────────────────────────────────────────────────

class TestLoad:
    def test_load_restores_same_agent_id(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path) as id1:
            agent_id_original = id1.agent_id

        with CngIdentity.load(agent_name, data_dir=tmp_path) as id2:
            assert id2.agent_id == agent_id_original

    def test_load_restores_same_public_key(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path) as id1:
            pub1 = id1.public_key_bytes
        with CngIdentity.load(agent_name, data_dir=tmp_path) as id2:
            assert id2.public_key_bytes == pub1

    def test_load_raises_if_not_found(self, tmp_path, agent_name):
        with pytest.raises(FileNotFoundError):
            CngIdentity.load(agent_name, data_dir=tmp_path)

    def test_signatures_match_across_load(self, tmp_path, agent_name):
        with CngIdentity.init(agent_name, data_dir=tmp_path) as id1:
            sig = id1.sign(b"hello world")
            pub = id1.public_key_bytes

        with CngIdentity.load(agent_name, data_dir=tmp_path) as id2:
            assert CngIdentity.verify(b"hello world", sig, id2.public_key_bytes)
            # id1 pubkey and id2 pubkey are the same key
            assert id2.public_key_bytes == pub


# ── CngIdentity.exists ─────────────────────────────────────────────────────────

class TestExists:
    def test_false_before_init(self, tmp_path, agent_name):
        assert CngIdentity.exists(agent_name, data_dir=tmp_path) is False

    def test_true_after_init(self, tmp_path, agent_name):
        CngIdentity.init(agent_name, data_dir=tmp_path).close()
        assert CngIdentity.exists(agent_name, data_dir=tmp_path) is True


# ── Sign and verify ────────────────────────────────────────────────────────────

class TestSignVerify:
    def test_sign_returns_96_bytes(self, identity):
        sig = identity.sign(b"payload")
        assert len(sig) == P384_SIG_BYTES

    def test_valid_signature_verifies(self, identity):
        data = b"agent executed task X"
        sig  = identity.sign(data)
        assert CngIdentity.verify(data, sig, identity.public_key_bytes) is True

    def test_wrong_data_fails_verify(self, identity):
        sig = identity.sign(b"original")
        assert CngIdentity.verify(b"tampered", sig, identity.public_key_bytes) is False

    def test_wrong_key_fails_verify(self, tmp_path, identity, agent_name):
        other_name = agent_name + "-other"
        try:
            with CngIdentity.init(other_name, data_dir=tmp_path) as other:
                sig = identity.sign(b"data")
                assert CngIdentity.verify(b"data", sig, other.public_key_bytes) is False
        finally:
            cng_delete_key(f"SelfConnect.{other_name}")

    def test_garbage_signature_fails(self, identity):
        assert CngIdentity.verify(b"data", b"\x00" * P384_SIG_BYTES, identity.public_key_bytes) is False

    def test_verify_never_raises(self):
        assert CngIdentity.verify(b"", b"", b"") is False
        assert CngIdentity.verify(b"x", b"\xde\xad" * 48, b"\xbe\xef" * 48) is False

    def test_different_messages_produce_different_sigs(self, identity):
        sig1 = identity.sign(b"message one")
        sig2 = identity.sign(b"message two")
        assert sig1 != sig2


# ── CngLedger.log() ────────────────────────────────────────────────────────────

class TestCngLedgerLog:
    def test_creates_log_file(self, ledger):
        ledger.log("booted", result="ok")
        assert ledger.log_path.exists()

    def test_entry_has_required_fields(self, ledger):
        entry = ledger.log("action", result="done")
        for field in ("seq", "agent_id", "algo", "action", "result", "ts", "prev_hash", "sig"):
            assert field in entry, f"missing field: {field}"

    def test_algo_field_is_correct(self, ledger):
        entry = ledger.log("action")
        assert entry["algo"] == ALGO_ID

    def test_seq_increments(self, ledger):
        e1 = ledger.log("first")
        e2 = ledger.log("second")
        e3 = ledger.log("third")
        assert e1["seq"] == 1
        assert e2["seq"] == 2
        assert e3["seq"] == 3

    def test_first_entry_uses_genesis_hash(self, ledger):
        entry = ledger.log("boot")
        assert entry["prev_hash"] == GENESIS_HASH_CNG

    def test_genesis_hash_is_96_zeros(self):
        assert len(GENESIS_HASH_CNG) == 96
        assert all(c == "0" for c in GENESIS_HASH_CNG)

    def test_second_entry_prev_hash_matches_first(self, ledger):
        e1 = ledger.log("first")
        e2 = ledger.log("second")
        e1_copy = dict(e1)
        e1_copy.pop("sig")
        e1_bytes  = json.dumps(e1_copy, sort_keys=True, separators=(",", ":")).encode()
        expected  = cng_sha384(e1_bytes).hex()
        assert e2["prev_hash"] == expected

    def test_agent_id_matches_identity(self, ledger, identity):
        entry = ledger.log("action")
        assert entry["agent_id"] == identity.agent_id

    def test_sig_is_96_byte_hex_string(self, ledger):
        entry = ledger.log("action")
        sig_bytes = bytes.fromhex(entry["sig"])
        assert len(sig_bytes) == P384_SIG_BYTES

    def test_metadata_merged_into_entry(self, ledger):
        entry = ledger.log("act", metadata={"target_hwnd": 0xABC})
        assert entry["target_hwnd"] == 0xABC

    def test_appends_to_file(self, ledger):
        for i in range(5):
            ledger.log(f"action-{i}")
        lines = [ln for ln in ledger.log_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 5


# ── CngLedger.verify() ─────────────────────────────────────────────────────────

class TestCngLedgerVerify:
    def test_empty_ledger_is_valid(self, ledger):
        valid, count, _msg = ledger.verify()
        assert valid is True
        assert count == 0

    def test_single_entry_is_valid(self, ledger):
        ledger.log("boot")
        valid, count, _msg = ledger.verify()
        assert valid is True
        assert count == 1

    def test_many_entries_all_valid(self, ledger):
        for i in range(10):
            ledger.log(f"action-{i}", result=str(i))
        valid, count, _msg = ledger.verify()
        assert valid is True
        assert count == 10

    def test_tampered_entry_detected(self, ledger):
        ledger.log("legit action", result="ok")
        ledger.log("second action", result="ok")

        lines = ledger.log_path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["action"] = "TAMPERED"
        lines[0] = json.dumps(entry)
        ledger.log_path.write_text("\n".join(lines) + "\n")

        valid, _count, msg = ledger.verify()
        assert valid is False
        assert "signature invalid" in msg or "chain broken" in msg

    def test_deleted_entry_detected(self, ledger):
        ledger.log("entry-1")
        ledger.log("entry-2")
        ledger.log("entry-3")

        lines = [ln for ln in ledger.log_path.read_text().splitlines() if ln.strip()]
        lines.pop(1)  # delete entry-2 — breaks chain for entry-3
        ledger.log_path.write_text("\n".join(lines) + "\n")

        valid, _, _ = ledger.verify()
        assert valid is False

    def test_sig_field_tampered_detected(self, ledger):
        ledger.log("action")

        lines = ledger.log_path.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["sig"] = "00" * P384_SIG_BYTES
        lines[0] = json.dumps(entry)
        ledger.log_path.write_text("\n".join(lines) + "\n")

        valid, _, msg = ledger.verify()
        assert valid is False
        assert "signature invalid" in msg


# ── Continuity across instances ────────────────────────────────────────────────

class TestCngLedgerContinuity:
    def test_new_instance_continues_chain(self, tmp_path, agent_name):
        log_path = tmp_path / "chain_cng.jsonl"
        with CngIdentity.init(agent_name, data_dir=tmp_path) as identity:
            l1 = CngLedger(identity, log_path=log_path)
            l1.log("session-1-boot")
            l1.log("session-1-action")

            l2 = CngLedger(identity, log_path=log_path)
            l2.log("session-2-boot")
            l2.log("session-2-action")

            valid, count, _msg = l2.verify()
            assert valid is True
            assert count == 4

    def test_seq_continues_from_last(self, tmp_path, agent_name):
        log_path = tmp_path / "seq_cng.jsonl"
        with CngIdentity.init(agent_name, data_dir=tmp_path) as identity:
            l1 = CngLedger(identity, log_path=log_path)
            l1.log("a")
            l1.log("b")  # seq=2

            l2 = CngLedger(identity, log_path=log_path)
            entry = l2.log("c")  # should be seq=3
            assert entry["seq"] == 3


# ── Hash chain uses SHA-384 not SHA-256 ───────────────────────────────────────

class TestHashChainAlgorithm:
    def test_prev_hash_is_96_hex_chars(self, ledger):
        ledger.log("first")
        e2 = ledger.log("second")
        assert len(e2["prev_hash"]) == SHA384_BYTES * 2  # 96 hex chars

    def test_prev_hash_is_not_sha256(self, ledger):
        """SHA-256 would produce 64-char hex; SHA-384 produces 96-char hex."""
        ledger.log("first")
        e2 = ledger.log("second")
        assert len(e2["prev_hash"]) != 64  # not SHA-256
