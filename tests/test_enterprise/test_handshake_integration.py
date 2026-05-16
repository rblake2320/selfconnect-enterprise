"""Real integration tests for enterprise.handshake — NO CRYPTO MOCKS.

Uses real AgentIdentity with real Windows DPAPI (CryptProtectData /
CryptUnprotectData).  The sign+verify cycle is exercised with no patching
of the cryptographic path.

Win32 property reads (get_agent_prop, set_agent_prop) are still mocked
because they require real window handles which integration tests cannot
create portably.  The handshake network path (send_data / WM_COPYDATA)
is also mocked — the live WM_COPYDATA path is covered by transport tests.

The goal: confirm that real DPAPI + real ed25519 + real nonce + real
canonical bytes all round-trip correctly through HandshakeResponder and
HandshakeInitiator without any cryptographic shortcuts.

Skipped automatically on non-Windows (DPAPI unavailable).
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

if sys.platform != "win32":
    pytest.skip("Windows DPAPI required", allow_module_level=True)

from enterprise.identity import AgentIdentity
from enterprise.handshake import (
    DTYPE_CHALLENGE,
    DTYPE_RESPONSE,
    HandshakeInitiator,
    HandshakeResponder,
    PeerBackoff,
    _signed_bytes,
    handshake_v2_enabled,
)


FAKE_MY_HWND   = 0xAAAA1111
FAKE_PEER_HWND = 0xBBBB2222


# ── Full sign→verify round-trip with real DPAPI ───────────────────────────────

class TestRealCryptoRoundTrip:
    """Real DPAPI + ed25519 — no crypto mocks."""

    def test_responder_signature_verifies_with_real_key(self, tmp_path):
        """HandshakeResponder signs with real DPAPI key; initiator verifies."""
        identity = AgentIdentity.init("hs-integ-responder", data_dir=tmp_path)
        nonce = "cafebabe12345678abcd1234abcd5678"
        initiator_hwnd = FAKE_MY_HWND

        signed_data = _signed_bytes(nonce, initiator_hwnd)
        sig_bytes   = identity.sign(signed_data)

        # Verify with the same key — no mock
        ok = AgentIdentity.verify(signed_data, sig_bytes, identity.public_key_bytes)
        assert ok is True

    def test_signature_is_128_hex_chars(self, tmp_path):
        """ed25519 signature is 64 bytes = 128 hex chars."""
        identity = AgentIdentity.init("hs-integ-siglen", data_dir=tmp_path)
        signed_data = _signed_bytes("00112233445566778899aabbccddeeff", FAKE_MY_HWND)
        sig_bytes = identity.sign(signed_data)
        assert len(sig_bytes) == 64
        assert len(sig_bytes.hex()) == 128

    def test_pubkey_is_32_bytes(self, tmp_path):
        """ed25519 public key is 32 bytes."""
        identity = AgentIdentity.init("hs-integ-publen", data_dir=tmp_path)
        assert len(identity.public_key_bytes) == 32

    def test_tampered_nonce_fails_verify(self, tmp_path):
        """Changing the nonce after signing causes verification to fail."""
        identity = AgentIdentity.init("hs-integ-tamper", data_dir=tmp_path)
        nonce = "aabbccddeeff00112233445566778899"
        sig = identity.sign(_signed_bytes(nonce, FAKE_MY_HWND))

        # Different nonce → different canonical bytes → verification fails
        ok = AgentIdentity.verify(
            _signed_bytes("WRONG_NONCE_HERE0123456789abcdef", FAKE_MY_HWND),
            sig,
            identity.public_key_bytes,
        )
        assert ok is False

    def test_different_keys_sign_independently(self, tmp_path):
        """Signature from key A does not verify with key B."""
        id_a = AgentIdentity.init("hs-integ-a", data_dir=tmp_path / "a")
        id_b = AgentIdentity.init("hs-integ-b", data_dir=tmp_path / "b")

        data = _signed_bytes("testnonce12345678901234567890ab", FAKE_MY_HWND)
        sig_a = id_a.sign(data)

        ok = AgentIdentity.verify(data, sig_a, id_b.public_key_bytes)
        assert ok is False

    def test_responder_to_initiator_full_cycle(self, tmp_path):
        """Full responder→initiator handshake cycle with real DPAPI keys.

        Responder signs challenge; initiator verifies signature and nonce.
        Win32 send_data is mocked (transport layer); crypto is entirely real.
        """
        peer_identity = AgentIdentity.init("hs-integ-peer-full", data_dir=tmp_path)
        nonce = "deadbeef1234567890abcdef12345678"

        initiator = HandshakeInitiator(
            my_hwnd=FAKE_MY_HWND,
            my_agent_id="agent-initiator-real",
        )

        def fake_send_data(hwnd, payload, data_type=0):
            if data_type == DTYPE_CHALLENGE:
                # Responder path: real signing with real DPAPI key
                cn = payload["nonce"]
                ih = payload["initiator_hwnd"]
                sig_bytes = peer_identity.sign(_signed_bytes(cn, ih))
                response = {
                    "type":       "response",
                    "nonce":      cn,
                    "signature":  sig_bytes.hex(),
                    "public_key": peer_identity.public_key_bytes.hex(),
                    "agent_id":   peer_identity.agent_id,
                }
                initiator.handle_response(FAKE_PEER_HWND, response)
            return True

        def fake_get_prop(hwnd, key):
            return ""  # no SCID_SIG — v1 peer path

        from enterprise.registry import BirthTag
        peer = BirthTag(
            hwnd=FAKE_PEER_HWND,
            agent_id=peer_identity.agent_id,
            agent_type="claude_code",
            born=time.time(),
            parent=0,
            model="test-model",
            heartbeat=time.time(),
            pid=12345,
            os_create_time=132987654321,
            session="",
        )

        with patch("enterprise.registry.send_data", side_effect=fake_send_data), \
             patch("enterprise.registry.get_agent_prop", side_effect=fake_get_prop):
            result = initiator.run(peer, timeout_sec=1.0)

        assert result.ok is True, f"Handshake failed: {result.reason}"
        assert result.peer is not None
        assert result.peer.public_key_hex == peer_identity.public_key_bytes.hex()


# ── PeerBackoff with real time ────────────────────────────────────────────────

class TestPeerBackoffRealTime:
    """PeerBackoff uses real time.time() — no mocks."""

    def test_fresh_failure_blocks(self, monkeypatch):
        monkeypatch.setenv("SC_HANDSHAKE_BACKOFF_SEC", "60")
        b = PeerBackoff()
        b.record_failure("agent-real-x")
        assert b.is_blocked("agent-real-x") is True
        b.clear("agent-real-x")

    def test_clear_unblocks_immediately(self, monkeypatch):
        monkeypatch.setenv("SC_HANDSHAKE_BACKOFF_SEC", "60")
        b = PeerBackoff()
        b.record_failure("agent-real-y")
        b.clear("agent-real-y")
        assert b.is_blocked("agent-real-y") is False

    def test_unknown_agent_not_blocked(self):
        b = PeerBackoff()
        assert b.is_blocked("agent-never-seen") is False


# ── handshake_v2_enabled checked at call time ─────────────────────────────────

def test_v2_enabled_reads_env_at_call_time():
    """SC_HANDSHAKE is read at call time, not import time."""
    original = os.environ.pop("SC_HANDSHAKE", None)
    try:
        assert handshake_v2_enabled() is False
        os.environ["SC_HANDSHAKE"] = "v2"
        assert handshake_v2_enabled() is True
    finally:
        if original is None:
            os.environ.pop("SC_HANDSHAKE", None)
        else:
            os.environ["SC_HANDSHAKE"] = original


import os
