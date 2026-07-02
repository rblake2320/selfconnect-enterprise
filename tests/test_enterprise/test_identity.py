"""tests/test_enterprise/test_identity.py — Unit tests for enterprise.identity

DPAPI (CryptProtectData / CryptUnprotectData) is mocked — no Windows Vault needed.
ed25519 operations use real cryptography — no mock.
"""
from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest

from enterprise.identity import AgentIdentity

AGENT_NAME = "test-agent"


# ── DPAPI mock helpers ─────────────────────────────────────────────────────────

def _mock_dpapi():
    """Patch DPAPI to be a simple passthrough (identity encryption)."""
    return (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda b: b"ENC:" + b),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda b: b[4:]),  # strip "ENC:"
    )


# ── AgentIdentity.init ─────────────────────────────────────────────────────────

class TestInit:
    def test_creates_files(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        dpapi = tmp_path / AGENT_NAME / "identity.dpapi"
        pub   = tmp_path / AGENT_NAME / "identity.pub"
        assert dpapi.exists()
        assert pub.exists()

    def test_agent_id_format(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            identity = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        assert identity.agent_id.startswith("SC-")
        assert len(identity.agent_id) == 11  # "SC-" + 8 hex chars

    def test_agent_id_derived_from_public_key(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            identity = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        expected = "SC-" + hashlib.sha256(identity.public_key_bytes).hexdigest()[:8].upper()
        assert identity.agent_id == expected

    def test_public_key_bytes_length(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            identity = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        assert len(identity.public_key_bytes) == 32  # ed25519 raw pubkey is 32 bytes

    def test_raises_if_already_exists(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        enc2, dec2 = _mock_dpapi()
        with enc2, dec2:
            with pytest.raises(FileExistsError):
                AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)

    def test_overwrite_replaces_key(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        enc2, dec2 = _mock_dpapi()
        with enc2, dec2:
            id2 = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path, overwrite=True)
        assert isinstance(id2, AgentIdentity)

    def test_pub_file_contains_hex(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            identity = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        pub_hex = (tmp_path / AGENT_NAME / "identity.pub").read_text()
        assert bytes.fromhex(pub_hex) == identity.public_key_bytes

    def test_dpapi_blob_structure(self, tmp_path):
        """DPAPI blob must be non-empty, start with mock ENC: prefix, and contain
        actual key material. This verifies the encrypt path is called and produces
        a real blob, not a no-op that writes empty bytes."""
        enc, dec = _mock_dpapi()
        with enc, dec:
            identity = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        blob = (tmp_path / AGENT_NAME / "identity.dpapi").read_bytes()
        # Mock encrypt prepends b"ENC:" — verify the blob structure
        assert blob.startswith(b"ENC:"), (
            f"DPAPI blob should start with mock ENC: prefix, got: {blob[:16]!r}"
        )
        # After stripping the 4-byte prefix, payload should be >= 32 bytes of key material
        payload = blob[4:]
        assert len(payload) >= 32, (
            f"DPAPI blob payload too short ({len(payload)} bytes); expected >= 32 bytes of key material"
        )
        # The public key must be 32 bytes (ed25519)
        assert len(identity.public_key_bytes) == 32


# ── AgentIdentity.load ────────────────────────────────────────────────────────

class TestLoad:
    def test_load_restores_same_agent_id(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            id1 = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)

        enc2, dec2 = _mock_dpapi()
        with enc2, dec2:
            id2 = AgentIdentity.load(AGENT_NAME, data_dir=tmp_path)

        assert id1.agent_id == id2.agent_id

    def test_load_restores_same_public_key(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            id1 = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        enc2, dec2 = _mock_dpapi()
        with enc2, dec2:
            id2 = AgentIdentity.load(AGENT_NAME, data_dir=tmp_path)
        assert id1.public_key_bytes == id2.public_key_bytes

    def test_load_raises_if_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            AgentIdentity.load("nonexistent", data_dir=tmp_path)

    def test_signatures_match_across_load(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            id1 = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
            sig = id1.sign(b"hello world")

        enc2, dec2 = _mock_dpapi()
        with enc2, dec2:
            id2 = AgentIdentity.load(AGENT_NAME, data_dir=tmp_path)

        # Signature from id1 verifiable with id2's pubkey
        assert AgentIdentity.verify(b"hello world", sig, id2.public_key_bytes)


# ── AgentIdentity.exists ──────────────────────────────────────────────────────

class TestExists:
    def test_false_before_init(self, tmp_path):
        assert AgentIdentity.exists(AGENT_NAME, data_dir=tmp_path) is False

    def test_true_after_init(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        assert AgentIdentity.exists(AGENT_NAME, data_dir=tmp_path) is True


# ── Signing and verification ──────────────────────────────────────────────────

class TestSignVerify:
    def _make_identity(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            return AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)

    def test_sign_returns_64_bytes(self, tmp_path):
        identity = self._make_identity(tmp_path)
        sig = identity.sign(b"data")
        assert len(sig) == 64

    def test_valid_signature_verifies(self, tmp_path):
        identity = self._make_identity(tmp_path)
        data = b"agent executed task X"
        sig  = identity.sign(data)
        assert AgentIdentity.verify(data, sig, identity.public_key_bytes) is True

    def test_wrong_data_fails_verify(self, tmp_path):
        identity = self._make_identity(tmp_path)
        sig = identity.sign(b"original")
        assert AgentIdentity.verify(b"tampered", sig, identity.public_key_bytes) is False

    def test_wrong_key_fails_verify(self, tmp_path):
        id1 = self._make_identity(tmp_path)
        enc, dec = _mock_dpapi()
        with enc, dec:
            id2 = AgentIdentity.init("other-agent", data_dir=tmp_path)
        sig = id1.sign(b"data")
        assert AgentIdentity.verify(b"data", sig, id2.public_key_bytes) is False

    def test_truncated_signature_fails(self, tmp_path):
        identity = self._make_identity(tmp_path)
        sig = identity.sign(b"data")[:32]  # truncate
        assert AgentIdentity.verify(b"data", sig, identity.public_key_bytes) is False

    def test_garbage_signature_fails(self, tmp_path):
        identity = self._make_identity(tmp_path)
        assert AgentIdentity.verify(b"data", b"\x00" * 64, identity.public_key_bytes) is False

    def test_verify_never_raises(self, tmp_path):
        # Even with completely garbage input, verify() must return False, not raise
        assert AgentIdentity.verify(b"", b"not-64-bytes", b"not-32-bytes") is False

    def test_different_messages_produce_different_sigs(self, tmp_path):
        identity = self._make_identity(tmp_path)
        sig1 = identity.sign(b"message one")
        sig2 = identity.sign(b"message two")
        assert sig1 != sig2


# ── repr ───────────────────────────────────────────────────────────────────────

class TestRepr:
    def test_repr_contains_agent_id(self, tmp_path):
        enc, dec = _mock_dpapi()
        with enc, dec:
            identity = AgentIdentity.init(AGENT_NAME, data_dir=tmp_path)
        r = repr(identity)
        assert identity.agent_id in r
        assert AGENT_NAME in r
