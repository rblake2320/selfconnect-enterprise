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
import time
from unittest.mock import patch

import pytest

if sys.platform != "win32":
    pytest.skip("Windows DPAPI required", allow_module_level=True)

from enterprise.identity import AgentIdentity
from enterprise.handshake import (
    DTYPE_CHALLENGE,
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
                    "ed25519_sig":  sig_bytes.hex(),
                    "ed25519_pubkey": peer_identity.public_key_bytes.hex(),
                    "agent_id":   peer_identity.agent_id,
                }
                initiator.handle_response(FAKE_PEER_HWND, response)
            return True

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

        from enterprise.birth_tag_v2 import _build_payload
        btag_ts = time.time()
        btag_sig = peer_identity.sign(
            _build_payload(
                peer.agent_id,
                peer.pid,
                str(peer.os_create_time),
                peer.born,
                btag_ts,
            )
        ).hex()
        prop_store = {
            "SCID_SIG": btag_sig,
            "SCID_STS": str(btag_ts),
            "SCID": peer.agent_id,
            "SCPID": str(peer.pid),
            "SCCTIME": str(peer.os_create_time),
            "SCBORN": str(peer.born),
        }

        def fake_get_prop(hwnd, key):
            return prop_store.get(key, "")

        with patch("enterprise.registry.send_data", side_effect=fake_send_data), \
             patch("enterprise.registry.get_agent_prop", side_effect=fake_get_prop):
            result = initiator.run(peer, timeout_sec=1.0)

        assert result.ok is True, f"Handshake failed: {result.reason}"
        assert result.peer is not None
        assert result.peer.public_key_hex == peer_identity.public_key_bytes.hex()


# ── Gap C binding tests — real Software KSP (ECDSA P-384 / SHA-384) ──────────

class TestGapCBinding:
    """Verify the nonce-bound key binding that closes Gap C.

    Provider used: Microsoft Software Key Storage Provider (NCrypt, ECDSA P-384).
    No crypto mocks.  All signatures are real.
    """

    def test_verify_peer_passes_with_valid_binding(self, tmp_path):
        """verify_peer() accepts a packet with correct P-384 binding and ed25519 sig."""
        from enterprise.identity_cng import CngIdentity
        from enterprise.handshake import verify_peer, _cng_binding_bytes, _signed_bytes

        ed_identity  = AgentIdentity.init("gap-c-ed25519", data_dir=tmp_path / "ed")
        cng_identity = CngIdentity.init("gap-c-cng", data_dir=tmp_path / "cng", overwrite=True)

        nonce          = "aabbccddeeff00112233445566778899"
        initiator_hwnd = FAKE_MY_HWND

        ed25519_pub = ed_identity.public_key_bytes
        ed_sig      = ed_identity.sign(_signed_bytes(nonce, initiator_hwnd))
        cng_sig     = cng_identity.sign(_cng_binding_bytes(nonce, ed25519_pub))

        from enterprise.crypto import cng_sha384
        packet = {
            "agent_id":            "SC-" + cng_sha384(cng_identity.public_key_bytes).hex()[:8].upper(),
            "ed25519_pubkey":      ed25519_pub.hex(),
            "ed25519_sig":         ed_sig.hex(),
            "platform_ksp_pubkey": cng_identity.public_key_bytes.hex(),
            "platform_ksp_sig":    cng_sig.hex(),
        }

        gap_c_closed = verify_peer(packet, nonce, initiator_hwnd)
        assert gap_c_closed is True

    def test_attacker_with_stolen_ed25519_and_own_cng_rejected(self, tmp_path):
        """Attacker has victim's ed25519 key but their own P-384 key.

        They claim victim's agent_id but provide their own platform_ksp_pubkey.
        verify_peer() must reject: agent_id fingerprint does not match
        the attacker's platform_ksp_pubkey.
        """
        from enterprise.identity_cng import CngIdentity
        from enterprise.handshake import verify_peer, _cng_binding_bytes, _signed_bytes, PeerVerificationError

        victim_ed      = AgentIdentity.init("victim-ed25519", data_dir=tmp_path / "v-ed")
        victim_cng     = CngIdentity.init("victim-cng",      data_dir=tmp_path / "v-cng", overwrite=True)
        attacker_cng   = CngIdentity.init("attacker-cng",    data_dir=tmp_path / "a-cng", overwrite=True)

        nonce          = "deadbeef12345678cafebabe90abcdef"
        initiator_hwnd = FAKE_MY_HWND

        from enterprise.crypto import cng_sha384
        # Attacker claims victim's agent_id (derived from victim's P-384 pubkey)
        victim_agent_id = "SC-" + cng_sha384(victim_cng.public_key_bytes).hex()[:8].upper()

        # But provides their own platform_ksp_pubkey
        victim_ed_pub = victim_ed.public_key_bytes
        ed_sig        = victim_ed.sign(_signed_bytes(nonce, initiator_hwnd))
        # Attacker signs with their own CNG key
        cng_sig       = attacker_cng.sign(_cng_binding_bytes(nonce, victim_ed_pub))

        fake_packet = {
            "agent_id":            victim_agent_id,               # claims victim
            "ed25519_pubkey":      victim_ed_pub.hex(),           # stolen key
            "ed25519_sig":         ed_sig.hex(),                   # valid ed25519 sig
            "platform_ksp_pubkey": attacker_cng.public_key_bytes.hex(),  # attacker's key
            "platform_ksp_sig":    cng_sig.hex(),                  # attacker's sig
        }

        with pytest.raises(PeerVerificationError) as exc_info:
            verify_peer(fake_packet, nonce, initiator_hwnd)

        assert "agent_id" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()

    def test_attacker_cannot_forge_cng_sig_for_victim_pubkey(self, tmp_path):
        """Attacker knows victim's P-384 pubkey but not the private key.

        They provide victim's platform_ksp_pubkey and correct agent_id,
        but must forge platform_ksp_sig — which requires the P-384 private key.
        verify_peer() must reject at step 2 (cng_verify fails).
        """
        from enterprise.identity_cng import CngIdentity
        from enterprise.handshake import verify_peer, _signed_bytes, PeerVerificationError
        from enterprise.crypto import cng_sha384

        victim_cng = CngIdentity.init("victim-cng-forge", data_dir=tmp_path / "v-cng", overwrite=True)
        victim_ed  = AgentIdentity.init("victim-ed-forge",  data_dir=tmp_path / "v-ed")

        nonce          = "1122334455667788aabbccddeeff0011"
        initiator_hwnd = FAKE_MY_HWND

        victim_ed_pub = victim_ed.public_key_bytes
        victim_agent_id = "SC-" + cng_sha384(victim_cng.public_key_bytes).hex()[:8].upper()

        ed_sig = victim_ed.sign(_signed_bytes(nonce, initiator_hwnd))

        # Attacker forges a random P-384 sig (garbage bytes)
        forged_cng_sig = bytes(96)  # 96 zero bytes — invalid ECDSA P-384

        fake_packet = {
            "agent_id":            victim_agent_id,
            "ed25519_pubkey":      victim_ed_pub.hex(),
            "ed25519_sig":         ed_sig.hex(),
            "platform_ksp_pubkey": victim_cng.public_key_bytes.hex(),
            "platform_ksp_sig":    forged_cng_sig.hex(),
        }

        with pytest.raises(PeerVerificationError) as exc_info:
            verify_peer(fake_packet, nonce, initiator_hwnd)

        assert "platform_ksp_sig" in str(exc_info.value) or "binding" in str(exc_info.value).lower()

    def test_responder_produces_verifiable_binding(self, tmp_path):
        """HandshakeResponder with real CngIdentity produces a packet verify_peer accepts."""
        from enterprise.identity_cng import CngIdentity
        from enterprise.handshake import verify_peer

        ed_identity  = AgentIdentity.init("resp-binding-ed",  data_dir=tmp_path / "ed")
        cng_identity = CngIdentity.init("resp-binding-cng", data_dir=tmp_path / "cng", overwrite=True)

        captured = {}

        def fake_send_data(hwnd, payload, data_type=0):
            captured["payload"] = payload
            return True

        responder = HandshakeResponder(
            my_hwnd=FAKE_MY_HWND,
            identity=ed_identity,
            cng_identity=cng_identity,
        )

        nonce          = "fedcba0987654321fedcba0987654321"
        initiator_hwnd = FAKE_PEER_HWND

        challenge = {
            "type":           "challenge",
            "nonce":          nonce,
            "initiator_hwnd": initiator_hwnd,
            "initiator_id":   "agent-initiator",
        }

        with patch("enterprise.registry.send_data", side_effect=fake_send_data):
            responder.handle_challenge(initiator_hwnd, challenge)

        assert "payload" in captured, "Responder should have sent a response"
        packet = captured["payload"]

        # platform_ksp fields must be present
        assert "platform_ksp_pubkey" in packet
        assert "platform_ksp_sig" in packet

        # verify_peer must accept it — real crypto, no mocks
        gap_c_closed = verify_peer(packet, nonce, initiator_hwnd)
        assert gap_c_closed is True, "verify_peer must confirm Gap C closed"


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
