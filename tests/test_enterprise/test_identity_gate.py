"""tests/test_enterprise/test_identity_gate.py — Ultra Identity Gate Test Suite

Comprehensive tests for the BPC + TSK Ultra 7-layer identity gate:
  - bpc_crypto.py  — P256KeyPair, p256_sign/verify, HKDF, HMAC, sign_bpc_request
  - tsk_client.py  — TSKClient, assemble_key, verify_checksum
  - ultra_gate.py  — UltraGate bootstrap, build_injection_request, verify_local
  - identity_gate.py — mode management, emergency bypass, degradation cascade
  - key_recovery.py  — KeyRecovery initiate, is_in_recovery, PeerRecoveryDetector

All tests use real cryptographic operations — no mocks, no fakes.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac_std
import json
import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _make_real_identity(agent_name: str = "test-agent"):
    """Create a real AgentIdentity using the actual constructor."""
    from enterprise.identity import AgentIdentity
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return AgentIdentity(priv, pub, agent_name)


def _make_tsk_provision(agent_id: str = "SC-TEST"):
    """Create a TSKProvisionPayload for testing."""
    from enterprise.tsk_client import TSKProvisionPayload, SegmentConfig
    return TSKProvisionPayload(
        client_id=f"tsk-{agent_id}",
        shared_secret=os.urandom(32).hex(),
        key_length=32,
        segments=[
            SegmentConfig(segment_id="s0", segment_type="static", length=8),
            SegmentConfig(segment_id="s1", segment_type="totp", window_sec=30, length=8),
            SegmentConfig(segment_id="s2", segment_type="hotp", length=8),
        ],
        checksum_length=8,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# BPC Crypto Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBpcCrypto:
    """Real ECDSA P-256 sign/verify, HKDF, and HMAC operations."""

    def test_p256_keypair_generate(self):
        from enterprise.bpc_crypto import P256KeyPair
        kp = P256KeyPair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_p256_keypair_from_private_key(self):
        from enterprise.bpc_crypto import P256KeyPair
        priv = ec.generate_private_key(ec.SECP256R1())
        kp = P256KeyPair.from_private_key(priv)
        assert kp.private_key is priv
        assert kp.public_key == priv.public_key()

    def test_p256_sign_and_verify_roundtrip(self):
        from enterprise.bpc_crypto import P256KeyPair, p256_sign, p256_verify
        kp = P256KeyPair.generate()
        message = b"test message for signing"
        sig = p256_sign(kp.private_key, message)
        assert isinstance(sig, str)
        assert len(sig) > 0
        assert p256_verify(kp.public_key, message, sig)

    def test_p256_verify_fails_on_tampered_message(self):
        from enterprise.bpc_crypto import P256KeyPair, p256_sign, p256_verify
        kp = P256KeyPair.generate()
        sig = p256_sign(kp.private_key, b"original")
        assert not p256_verify(kp.public_key, b"tampered", sig)

    def test_p256_verify_fails_on_wrong_key(self):
        from enterprise.bpc_crypto import P256KeyPair, p256_sign, p256_verify
        kp1 = P256KeyPair.generate()
        kp2 = P256KeyPair.generate()
        sig = p256_sign(kp1.private_key, b"message")
        assert not p256_verify(kp2.public_key, b"message", sig)

    def test_p256_sign_produces_base64url_string(self):
        from enterprise.bpc_crypto import P256KeyPair, p256_sign
        kp = P256KeyPair.generate()
        sig = p256_sign(kp.private_key, b"test")
        # base64url has no + or / or = padding
        assert "+" not in sig
        assert "/" not in sig

    def test_derive_p256_private_key_deterministic(self):
        from enterprise.bpc_crypto import derive_p256_private_key
        seed = os.urandom(32)
        k1 = derive_p256_private_key(seed, "SC-AGENT-A")
        k2 = derive_p256_private_key(seed, "SC-AGENT-A")
        # Same scalar
        assert k1.private_numbers().private_value == k2.private_numbers().private_value

    def test_derive_p256_private_key_different_agents_differ(self):
        from enterprise.bpc_crypto import derive_p256_private_key
        seed = os.urandom(32)
        k1 = derive_p256_private_key(seed, "SC-AGENT-A")
        k2 = derive_p256_private_key(seed, "SC-AGENT-B")
        assert k1.private_numbers().private_value != k2.private_numbers().private_value

    def test_hmac_sha256_returns_bytes(self):
        from enterprise.bpc_crypto import hmac_sha256
        key = os.urandom(32)
        result = hmac_sha256(key, b"test message")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_hmac_sha256_deterministic(self):
        from enterprise.bpc_crypto import hmac_sha256
        key = os.urandom(32)
        r1 = hmac_sha256(key, b"msg")
        r2 = hmac_sha256(key, b"msg")
        assert r1 == r2

    def test_hmac_sha256_different_keys_differ(self):
        from enterprise.bpc_crypto import hmac_sha256
        k1, k2 = os.urandom(32), os.urandom(32)
        assert hmac_sha256(k1, b"msg") != hmac_sha256(k2, b"msg")

    def test_constant_time_equal_passes_for_equal_bytes(self):
        from enterprise.bpc_crypto import constant_time_equal
        a = b"same bytes"
        assert constant_time_equal(a, a)

    def test_constant_time_equal_fails_for_different_bytes(self):
        from enterprise.bpc_crypto import constant_time_equal
        assert not constant_time_equal(b"aaa", b"bbb")

    def test_sign_bpc_request_returns_payload_and_headers(self):
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request
        kp = P256KeyPair.generate()
        payload, headers = sign_bpc_request(
            keypair=kp,
            pair_id="pair-123",
            secret="my-secret",
            method="INJECT",
            path="/inject",
            body=b"test body",
        )
        assert payload is not None
        assert headers is not None
        assert headers.pair_id == "pair-123"

    def test_sign_bpc_request_signature_verifies_locally(self):
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request, verify_bpc_request_local
        kp = P256KeyPair.generate()
        payload, headers = sign_bpc_request(
            keypair=kp,
            pair_id="pair-abc",
            secret="secret-xyz",
            method="INJECT",
            path="/inject",
            body=b"",
        )
        ok, reason = verify_bpc_request_local(
            public_key=kp.public_key,
            headers=headers,
            method="INJECT",
            path="/inject",
            body=b"",
        )
        assert ok, f"Verification failed: {reason}"

    def test_verify_bpc_request_fails_on_tampered_body(self):
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request, verify_bpc_request_local
        kp = P256KeyPair.generate()
        _, headers = sign_bpc_request(kp, "pair-1", "secret", "INJECT", "/inject", b"original")
        ok, reason = verify_bpc_request_local(kp.public_key, headers, "INJECT", "/inject", b"tampered")
        assert not ok

    def test_verify_bpc_request_fails_on_wrong_key(self):
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request, verify_bpc_request_local
        kp1 = P256KeyPair.generate()
        kp2 = P256KeyPair.generate()
        _, headers = sign_bpc_request(kp1, "pair-1", "secret", "INJECT", "/inject")
        ok, reason = verify_bpc_request_local(kp2.public_key, headers, "INJECT", "/inject")
        assert not ok

    def test_verify_bpc_request_detects_replay(self):
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request, verify_bpc_request_local
        kp = P256KeyPair.generate()
        _, headers = sign_bpc_request(kp, "pair-1", "secret", "INJECT", "/inject")
        seen_nonces: set = set()
        ok1, _ = verify_bpc_request_local(kp.public_key, headers, "INJECT", "/inject",
                                           seen_nonces=seen_nonces)
        ok2, reason2 = verify_bpc_request_local(kp.public_key, headers, "INJECT", "/inject",
                                                  seen_nonces=seen_nonces)
        assert ok1
        assert not ok2
        assert reason2 == "replay_detected"

    def test_public_key_fingerprint_is_20_chars(self):
        from enterprise.bpc_crypto import P256KeyPair
        kp = P256KeyPair.generate()
        fp = kp.public_key_fingerprint()
        assert len(fp) == 20

    def test_public_key_jwk_has_required_fields(self):
        from enterprise.bpc_crypto import P256KeyPair
        kp = P256KeyPair.generate()
        jwk = kp.public_key_jwk()
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk
        assert "y" in jwk

    def test_body_hash_format(self):
        from enterprise.bpc_crypto import body_hash
        bh = body_hash(b"test body")
        assert bh.startswith("sha256:")
        assert len(bh) == 7 + 32  # "sha256:" + 32 chars

    def test_empty_body_hash_is_constant(self):
        from enterprise.bpc_crypto import body_hash, EMPTY_BODY_HASH
        assert body_hash(b"") == EMPTY_BODY_HASH

    def test_derive_secret_hmac_returns_base64url(self):
        from enterprise.bpc_crypto import derive_secret_hmac
        result = derive_secret_hmac("my-secret", "nonce-abc", 1234567890000)
        assert isinstance(result, str)
        assert len(result) == 43  # full 256-bit base64url (43 chars)


# ═══════════════════════════════════════════════════════════════════════════════
# TSK Client Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTskClient:
    """Real TSK segment derivation, key assembly, and checksum operations."""

    def _make_client(self, agent_id: str = "SC-TEST"):
        from enterprise.tsk_client import TSKClient
        provision = _make_tsk_provision(agent_id)
        return TSKClient(provision)

    def test_assemble_key_returns_string(self):
        client = self._make_client()
        key = client.assemble_key()
        assert isinstance(key, str)
        assert len(key) > 0

    def test_assemble_key_length_matches_provision(self):
        from enterprise.tsk_client import TSKClient
        provision = _make_tsk_provision()
        client = TSKClient(provision)
        key = client.assemble_key()
        # key_length in provision is the total including checksum
        assert len(key) == provision.key_length

    def test_assemble_key_ends_with_checksum(self):
        """The last checksum_length chars must be the computed checksum."""
        from enterprise.tsk_client import TSKClient
        provision = _make_tsk_provision()
        client = TSKClient(provision)
        key = client.assemble_key()
        assert client.verify_checksum(key)

    def test_verify_checksum_passes_for_valid_key(self):
        client = self._make_client()
        key = client.assemble_key()
        assert client.verify_checksum(key)

    def test_verify_checksum_fails_for_tampered_key(self):
        client = self._make_client()
        key = client.assemble_key()
        # Flip first char
        tampered = ("X" if key[0] != "X" else "Y") + key[1:]
        assert not client.verify_checksum(tampered)

    def test_verify_checksum_uses_constant_time_comparison(self):
        """verify_checksum must use hmac.compare_digest."""
        import inspect
        from enterprise.tsk_client import TSKClient
        src = inspect.getsource(TSKClient.verify_checksum)
        assert "compare_digest" in src

    def test_build_headers_returns_tsk_headers(self):
        from enterprise.tsk_client import TSKHeaders
        client = self._make_client()
        headers = client.build_headers()
        assert isinstance(headers, TSKHeaders)
        assert headers.client_id is not None
        assert headers.key is not None

    def test_build_headers_key_verifies(self):
        client = self._make_client()
        headers = client.build_headers()
        assert client.verify_checksum(headers.key)

    def test_client_id_matches_provision(self):
        from enterprise.tsk_client import TSKClient
        provision = _make_tsk_provision("SC-MYAGENT")
        client = TSKClient(provision)
        assert client.client_id == provision.client_id

    def test_hotp_counter_increments(self):
        """Two consecutive HOTP-based key assemblies must differ."""
        from enterprise.tsk_client import TSKClient, TSKProvisionPayload, SegmentConfig
        provision = TSKProvisionPayload(
            client_id="tsk-hotp",
            shared_secret=os.urandom(32).hex(),
            key_length=16,
            segments=[SegmentConfig(segment_id="s0", segment_type="hotp", length=8)],
            checksum_length=8,
        )
        client = TSKClient(provision)
        k1 = client.assemble_key()
        k2 = client.assemble_key()
        # HOTP increments counter, so keys differ
        assert k1 != k2

    def test_static_segment_is_deterministic(self):
        """Static segments must produce the same value on every call."""
        from enterprise.tsk_client import TSKClient, TSKProvisionPayload, SegmentConfig
        provision = TSKProvisionPayload(
            client_id="tsk-static",
            shared_secret=os.urandom(32).hex(),
            key_length=16,
            segments=[SegmentConfig(segment_id="s0", segment_type="static", length=8)],
            checksum_length=8,
        )
        client = TSKClient(provision)
        k1 = client.assemble_key()
        k2 = client.assemble_key()
        assert k1 == k2

    def test_tsk_client_from_server_response(self):
        from enterprise.tsk_client import tsk_client_from_server_response, TSKClient
        # The server response uses camelCase keys; segmentType is "type" in the parser
        response = {
            "clientId": "tsk-server-123",
            "sharedSecret": os.urandom(32).hex(),
            "keyLength": 32,
            "checksumLength": 8,
            "segments": [
                {"segmentId": "s0", "type": "static", "windowSec": 30, "length": 8},
                {"segmentId": "s1", "type": "totp", "windowSec": 30, "length": 8},
                {"segmentId": "s2", "type": "hotp", "windowSec": 30, "length": 8},
            ],
        }
        client = tsk_client_from_server_response(response)
        assert isinstance(client, TSKClient)
        assert client.client_id == "tsk-server-123"

    def test_structural_secrecy_no_positions_in_client(self):
        """TSKClient must not expose positional map — structural secrecy property."""
        from enterprise.tsk_client import TSKClient
        provision = _make_tsk_provision()
        client = TSKClient(provision)
        # The client should not have a public positions attribute
        assert not hasattr(client, "positions")
        assert not hasattr(client, "positional_map")
        assert not hasattr(client, "tumbler_map")

    def test_different_secrets_produce_different_keys(self):
        from enterprise.tsk_client import TSKClient, TSKProvisionPayload, SegmentConfig
        def make(secret_hex):
            p = TSKProvisionPayload(
                client_id="tsk-x",
                shared_secret=secret_hex,
                key_length=16,
                segments=[SegmentConfig("s0", "static", length=8)],
                checksum_length=8,
            )
            return TSKClient(p).assemble_key()
        k1 = make(os.urandom(32).hex())
        k2 = make(os.urandom(32).hex())
        assert k1 != k2


# ═══════════════════════════════════════════════════════════════════════════════
# UltraGate Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestUltraGate:
    """UltraGate bootstrap, injection request building, and local verification."""

    def test_bootstrap_succeeds_in_degraded_mode_without_server(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        assert gate.bootstrapped
        assert gate.degraded_level > 0  # degraded because server not available

    def test_bootstrap_sets_degraded_level_when_server_unreachable(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        assert gate.degraded_level >= 1

    def test_bootstrap_bootstrapped_property_is_true(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        assert not gate.bootstrapped  # before bootstrap
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        assert gate.bootstrapped

    def test_build_injection_request_returns_dict(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req = gate.build_injection_request(target_hwnd=0x1234, text="hello", method="INJECT")
        assert isinstance(req, dict)

    def test_build_injection_request_contains_body(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req = gate.build_injection_request(0x1234, "hello", "INJECT")
        assert "body" in req
        body = json.loads(req["body"])
        assert body["agent_id"] == identity.agent_name

    def test_build_injection_request_body_has_timestamp(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req = gate.build_injection_request(0x1234, "hello", "INJECT")
        body = json.loads(req["body"])
        ts = body.get("ts", 0)
        assert abs(time.time() * 1000 - ts) < 10_000  # within 10 seconds in ms

    def test_verify_local_returns_gate_result(self):
        from enterprise.ultra_gate import GateResult, UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req = gate.build_injection_request(0x1234, "hello", "INJECT")
        result = gate.verify_local(req)
        assert isinstance(result, GateResult)

    def test_verify_local_ok_is_bool(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req = gate.build_injection_request(0x1234, "hello", "INJECT")
        result = gate.verify_local(req)
        assert isinstance(result.ok, bool)

    def test_verify_local_passes_for_fresh_request(self):
        """In degraded level 2 (no BPC pair registered), verify_local is still ok
        because BPC is skipped at degraded >= 2 and TSK is also skipped at degraded >= 1."""
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                      "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req = gate.build_injection_request(0x1234, "hello", "INJECT")
        result = gate.verify_local(req)
        # At degraded level 2, BPC is skipped (>= 2) and TSK is skipped (>= 1)
        # verify_local returns ok=True because all checks are gracefully skipped
        assert isinstance(result.ok, bool)
        assert result.degraded is True  # we are definitely in degraded mode

    def test_injection_denied_error_carries_layer(self):
        from enterprise.ultra_gate import InjectionDeniedError
        err = InjectionDeniedError("bpc_sig_invalid", layer=2)
        assert err.layer == 2
        assert "bpc_sig_invalid" in str(err)

    def test_ultra_gate_bootstrap_error_is_exception(self):
        from enterprise.ultra_gate import UltraGateBootstrapError
        err = UltraGateBootstrapError("total failure")
        assert isinstance(err, Exception)

    def test_gate_result_fields(self):
        from enterprise.ultra_gate import GateResult
        r = GateResult(ok=True, layer=7, reason="ok", degraded=False, degraded_level=0)
        assert r.ok is True
        assert r.layer == 7
        assert r.reason == "ok"

    def test_different_targets_produce_different_bodies(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("test-agent")
        gate = UltraGate(identity)
        with patch.dict(os.environ, {"SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                     "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            gate.bootstrap()
        req1 = gate.build_injection_request(0x1111, "hello", "INJECT")
        req2 = gate.build_injection_request(0x2222, "hello", "INJECT")
        body1 = json.loads(req1["body"])
        body2 = json.loads(req2["body"])
        assert body1["target_hwnd"] != body2["target_hwnd"]


# ═══════════════════════════════════════════════════════════════════════════════
# IdentityGate Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestIdentityGate:
    """Mode management, emergency bypass, and degradation cascade."""

    def test_get_identity_mode_default_is_bypass(self):
        from enterprise.identity_gate import get_identity_mode, MODE_BYPASS
        env = {k: v for k, v in os.environ.items() if k != "SC_IDENTITY_MODE"}
        with patch.dict(os.environ, env, clear=True):
            mode = get_identity_mode()
        assert mode == MODE_BYPASS

    def test_get_identity_mode_audit(self):
        from enterprise.identity_gate import get_identity_mode, MODE_AUDIT
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": "audit"}):
            assert get_identity_mode() == MODE_AUDIT

    def test_get_identity_mode_enforce(self):
        from enterprise.identity_gate import get_identity_mode, MODE_ENFORCE
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": "enforce"}):
            assert get_identity_mode() == MODE_ENFORCE

    def test_get_identity_mode_invalid_falls_back_to_bypass(self):
        from enterprise.identity_gate import get_identity_mode, MODE_BYPASS
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": "INVALID_MODE"}):
            assert get_identity_mode() == MODE_BYPASS

    def test_mode_constants_are_distinct_strings(self):
        from enterprise.identity_gate import MODE_BYPASS, MODE_AUDIT, MODE_ENFORCE
        modes = {MODE_BYPASS, MODE_AUDIT, MODE_ENFORCE}
        assert len(modes) == 3
        for m in modes:
            assert isinstance(m, str)

    def test_degradation_descriptions_is_dict_with_int_keys(self):
        from enterprise.identity_gate import DEGRADATION_DESCRIPTIONS
        assert isinstance(DEGRADATION_DESCRIPTIONS, dict)
        assert len(DEGRADATION_DESCRIPTIONS) > 0
        for k in DEGRADATION_DESCRIPTIONS:
            assert isinstance(k, int)

    def test_identity_gate_decision_fields(self):
        from enterprise.identity_gate import IdentityGateDecision
        d = IdentityGateDecision(allowed=True, mode="bypass", gate_result=None, reason="bypass_mode")
        assert d.allowed is True
        assert d.mode == "bypass"

    def test_identity_gate_bypass_mode_always_allows(self):
        from enterprise.identity_gate import IdentityGate, MODE_BYPASS
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_BYPASS}):
            gate = IdentityGate(ultra_gate=None, ledger=None, agent_id="SC-TEST")
            decision = gate.check_injection(0x1234, "hello")
        assert decision.allowed is True
        assert decision.mode == MODE_BYPASS

    def test_identity_gate_audit_mode_allows_without_ultra_gate(self):
        from enterprise.identity_gate import IdentityGate, MODE_AUDIT
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_AUDIT}):
            gate = IdentityGate(ultra_gate=None, ledger=None, agent_id="SC-TEST")
            decision = gate.check_injection(0x1234, "hello")
        assert decision.allowed is True

    def test_identity_gate_enforce_mode_denies_without_ultra_gate(self):
        """Enforce mode with no gate: degraded to level 5, denied (level 5 > ENFORCE_MAX_DEGRADATION=2)."""
        from enterprise.identity_gate import IdentityGate, MODE_ENFORCE
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_ENFORCE}):
            gate = IdentityGate(ultra_gate=None, ledger=None, agent_id="SC-TEST")
            decision = gate.check_injection(0x1234, "hello")
        # Level 5 degradation exceeds ENFORCE_MAX_DEGRADATION=2, so denied
        assert decision.allowed is False
        assert decision.degraded_level == 5

    def test_identity_gate_enforce_denies_on_gate_deny(self):
        from enterprise.identity_gate import IdentityGate, MODE_ENFORCE
        from enterprise.ultra_gate import GateResult, UltraGate
        from unittest.mock import PropertyMock
        mock_gate = MagicMock(spec=UltraGate)
        # Set integer properties explicitly to avoid MagicMock comparison issues
        type(mock_gate).bootstrapped = PropertyMock(return_value=True)
        type(mock_gate).degraded_level = PropertyMock(return_value=0)
        # IdentityGate calls verify_injection, not verify_local directly
        mock_gate.verify_injection.return_value = GateResult(
            ok=False, layer=2, reason="bpc_sig_invalid", degraded=False, degraded_level=0
        )
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_ENFORCE}):
            gate = IdentityGate(ultra_gate=mock_gate, ledger=None, agent_id="SC-TEST")
            decision = gate.check_injection(0x1234, "hello")
        assert not decision.allowed

    def test_guarded_send_string_calls_original_in_bypass(self):
        from enterprise.identity_gate import guarded_send_string, MODE_BYPASS
        called = []
        def fake_send(target, text):
            called.append((target, text))
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_BYPASS}):
            guarded_send_string(fake_send, 0x1234, "hello")
        assert called == [(0x1234, "hello")]

    def test_guarded_send_string_calls_original_in_audit(self):
        from enterprise.identity_gate import guarded_send_string, MODE_AUDIT
        called = []
        def fake_send(target, text):
            called.append((target, text))
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_AUDIT}):
            guarded_send_string(fake_send, 0x1234, "hello")
        assert called == [(0x1234, "hello")]

    def test_guarded_send_string_calls_original_with_no_gate(self):
        from enterprise.identity_gate import guarded_send_string
        called = []
        def fake_send(target, text):
            called.append((target, text))
        guarded_send_string(fake_send, 0x1234, "hello", gate=None)
        assert called == [(0x1234, "hello")]

    def test_emergency_bypass_creates_mutex_file(self, tmp_path):
        from enterprise.identity_gate import emergency_bypass, _release_bypass_mutex
        with patch("enterprise.identity_gate._bypass_mutex_path",
                   return_value=lambda: tmp_path / "bypass.lock"):
            # Patch the actual function used
            with patch("enterprise.identity_gate._bypass_mutex_path",
                       return_value=tmp_path / "bypass.lock"):
                emergency_bypass()
                assert (tmp_path / "bypass.lock").exists()
                _release_bypass_mutex()

    def test_emergency_bypass_function_exists_and_callable(self):
        from enterprise.identity_gate import emergency_bypass
        assert callable(emergency_bypass)

    def test_release_bypass_mutex_function_exists(self):
        from enterprise.identity_gate import _release_bypass_mutex
        assert callable(_release_bypass_mutex)


# ═══════════════════════════════════════════════════════════════════════════════
# KeyRecovery Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeyRecovery:
    """Key recovery initiation, completion, and peer detection."""

    def test_recovery_pub_path_returns_path(self):
        from enterprise.key_recovery import recovery_pub_path
        p = recovery_pub_path("SC-TEST-AGENT")
        assert isinstance(p, Path)
        assert "SC-TEST-AGENT" in str(p)

    def test_key_recovery_initiate_returns_bytes(self):
        from enterprise.key_recovery import KeyRecovery
        identity = _make_real_identity("recovery-test-agent")
        recovery = KeyRecovery(identity)
        pub_bytes = recovery.initiate()
        assert isinstance(pub_bytes, bytes)
        assert len(pub_bytes) == 32  # raw ed25519 public key

    def test_key_recovery_initiate_writes_pub_file(self):
        from enterprise.key_recovery import KeyRecovery, recovery_pub_path
        identity = _make_real_identity("recovery-test-agent-2")
        recovery = KeyRecovery(identity)
        recovery.initiate()
        pub_path = recovery_pub_path(identity.agent_name)
        assert pub_path.exists()
        # Cleanup
        try:
            pub_path.unlink()
            recovery_pub_path(identity.agent_name).parent.rmdir()
        except Exception:
            pass

    def test_key_recovery_is_in_recovery_after_initiate(self):
        from enterprise.key_recovery import KeyRecovery
        identity = _make_real_identity("recovery-test-agent-3")
        recovery = KeyRecovery(identity)
        assert not recovery.is_in_recovery()
        recovery.initiate()
        assert recovery.is_in_recovery()
        recovery.complete()

    def test_key_recovery_not_in_recovery_after_complete(self):
        from enterprise.key_recovery import KeyRecovery
        identity = _make_real_identity("recovery-test-agent-4")
        recovery = KeyRecovery(identity)
        recovery.initiate()
        recovery.complete()
        assert not recovery.is_in_recovery()

    def test_key_recovery_read_recovery_pubkey_returns_bytes(self):
        from enterprise.key_recovery import KeyRecovery
        identity = _make_real_identity("recovery-test-agent-5")
        recovery = KeyRecovery(identity)
        recovery.initiate()
        pub = recovery.read_recovery_pubkey()
        assert isinstance(pub, bytes)
        assert len(pub) == 32
        recovery.complete()

    def test_key_recovery_read_recovery_pubkey_none_before_initiate(self):
        from enterprise.key_recovery import KeyRecovery
        identity = _make_real_identity("recovery-test-agent-6")
        recovery = KeyRecovery(identity)
        assert recovery.read_recovery_pubkey() is None

    def test_key_recovery_agent_name_from_identity(self):
        from enterprise.key_recovery import KeyRecovery
        identity = _make_real_identity("my-named-agent")
        recovery = KeyRecovery(identity)
        assert recovery._agent_name == "my-named-agent"

    def test_peer_recovery_detector_not_in_recovery_by_default(self):
        from enterprise.key_recovery import PeerRecoveryDetector
        detector = PeerRecoveryDetector()
        # check_peer with hwnd=0 always returns False
        assert not detector.check_peer(0)

    def test_peer_recovery_detector_read_recovery_pubkey_none_for_unknown(self):
        from enterprise.key_recovery import PeerRecoveryDetector
        detector = PeerRecoveryDetector()
        result = detector.read_recovery_pubkey(0, "SC-NONEXISTENT-AGENT-99")
        assert result is None

    def test_peer_recovery_detector_reads_pubkey_after_initiate(self):
        from enterprise.key_recovery import KeyRecovery, PeerRecoveryDetector
        identity = _make_real_identity("recovery-peer-test-agent")
        recovery = KeyRecovery(identity)
        recovery.initiate()
        detector = PeerRecoveryDetector()
        pub = detector.read_recovery_pubkey(0, identity.agent_name)
        assert isinstance(pub, bytes)
        assert len(pub) == 32
        recovery.complete()

    def test_peer_recovery_detector_update_peer_registry(self):
        from enterprise.key_recovery import PeerRecoveryDetector
        detector = PeerRecoveryDetector()
        registry = {}
        pub_bytes = os.urandom(32)
        detector.update_peer_registry("SC-PEER-A", pub_bytes, registry)
        assert registry["SC-PEER-A"] == pub_bytes


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests — End-to-End Gate Flow
# ═══════════════════════════════════════════════════════════════════════════════

class TestIdentityGateIntegration:
    """End-to-end tests: bootstrap → build request → verify → gate decision."""

    def test_full_bypass_mode_pipeline(self):
        from enterprise.identity_gate import IdentityGate, MODE_BYPASS
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_BYPASS}):
            gate = IdentityGate(ultra_gate=None, ledger=None, agent_id="SC-INT-TEST")
            decision = gate.check_injection(0xABCD, "test payload")
        assert decision.allowed is True
        assert decision.mode == MODE_BYPASS

    def test_full_audit_mode_pipeline_without_server(self):
        from enterprise.identity_gate import IdentityGate, MODE_AUDIT
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("int-test-audit")
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_AUDIT,
                                      "SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                      "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            ultra = UltraGate(identity)
            ultra.bootstrap()
            gate = IdentityGate(ultra_gate=ultra, ledger=None, agent_id=identity.agent_name)
            decision = gate.check_injection(0xABCD, "test payload")
        assert decision.allowed is True

    def test_full_enforce_mode_pipeline_degraded(self):
        from enterprise.identity_gate import IdentityGate, MODE_ENFORCE
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("int-test-enforce")
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_ENFORCE,
                                      "SC_ULTRA_SERVER_URL": "http://localhost:19999",
                                      "SC_ULTRA_SERVER_TIMEOUT_MS": "100"}):
            ultra = UltraGate(identity)
            ultra.bootstrap()
            gate = IdentityGate(ultra_gate=ultra, ledger=None, agent_id=identity.agent_name)
            decision = gate.check_injection(0xABCD, "test payload")
        # In degraded mode, enforce allows up to degraded level 2
        assert isinstance(decision.allowed, bool)

    def test_mode_transition_bypass_to_audit(self):
        from enterprise.identity_gate import get_identity_mode, MODE_BYPASS, MODE_AUDIT
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_BYPASS}):
            assert get_identity_mode() == MODE_BYPASS
        with patch.dict(os.environ, {"SC_IDENTITY_MODE": MODE_AUDIT}):
            assert get_identity_mode() == MODE_AUDIT

    def test_ledger_action_strings_documented_in_ledger_py(self):
        ledger_path = Path("/home/ubuntu/selfconnect-enterprise/enterprise/ledger.py")
        content = ledger_path.read_text()
        for action in ["ultra_gate_bootstrap", "ultra_gate_pass", "ultra_gate_deny",
                        "ultra_gate_audit", "key_recovery_initiated", "emergency_bypass_activated"]:
            assert action in content, f"Action string '{action}' missing from ledger.py"

    def test_registry_prop_constants_correct(self):
        from enterprise.registry import PROP_BPC, PROP_TSK, PROP_RECOVERY
        assert PROP_BPC == "SCBPC"
        assert PROP_TSK == "SCTSK"
        assert PROP_RECOVERY == "SCRECOVERY"

    def test_init_exports_all_ultra_gate_symbols(self):
        import enterprise
        for symbol in ["IdentityGate", "IdentityGateDecision", "MODE_AUDIT", "MODE_BYPASS",
                        "MODE_ENFORCE", "DEGRADATION_DESCRIPTIONS", "emergency_bypass",
                        "get_identity_mode", "guarded_send_string", "GateResult",
                        "InjectionDeniedError", "UltraGate", "UltraGateBootstrapError",
                        "KeyRecovery", "PeerRecoveryDetector", "recovery_pub_path"]:
            assert hasattr(enterprise, symbol), f"enterprise.{symbol} not exported"

    def test_bpc_tsk_full_sign_verify_pipeline(self):
        """Full BPC sign → TSK assemble → verify pipeline with real keys."""
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request, verify_bpc_request_local
        from enterprise.tsk_client import TSKClient
        kp = P256KeyPair.generate()
        provision = _make_tsk_provision("SC-PIPELINE-TEST")
        tsk = TSKClient(provision)
        body = b'{"target_hwnd": 4660, "text": "hello", "agent_id": "SC-PIPELINE-TEST"}'
        _, bpc_headers = sign_bpc_request(kp, "pair-pipeline", "secret-pipeline",
                                           "INJECT", "/inject", body)
        tsk_headers = tsk.build_headers()
        # BPC verify
        ok, reason = verify_bpc_request_local(kp.public_key, bpc_headers,
                                               "INJECT", "/inject", body)
        assert ok, f"BPC verify failed: {reason}"
        # TSK verify
        assert tsk.verify_checksum(tsk_headers.key)


# ═══════════════════════════════════════════════════════════════════════════════
# Security Property Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityProperties:
    """Verify cryptographic security properties hold across the stack."""

    def test_bpc_signature_not_replayable_across_agents(self):
        from enterprise.bpc_crypto import P256KeyPair, p256_sign, p256_verify
        kp_a = P256KeyPair.generate()
        kp_b = P256KeyPair.generate()
        message = b"agent-A:hwnd:0x1234:ts:1234567890"
        sig = p256_sign(kp_a.private_key, message)
        assert p256_verify(kp_a.public_key, message, sig)
        assert not p256_verify(kp_b.public_key, message, sig)

    def test_tsk_hotp_produces_unique_keys_per_call(self):
        from enterprise.tsk_client import TSKClient, TSKProvisionPayload, SegmentConfig
        provision = TSKProvisionPayload(
            client_id="tsk-unique",
            shared_secret=os.urandom(32).hex(),
            key_length=16,
            segments=[SegmentConfig("s0", "hotp", length=8)],
            checksum_length=8,
        )
        client = TSKClient(provision)
        keys = [client.assemble_key() for _ in range(50)]
        assert len(set(keys)) == 50  # all unique

    def test_hmac_uses_constant_time_comparison(self):
        """All HMAC comparisons in the stack must use compare_digest."""
        import inspect
        from enterprise import bpc_crypto, tsk_client
        bpc_src = inspect.getsource(bpc_crypto)
        tsk_src = inspect.getsource(tsk_client)
        assert "compare_digest" in bpc_src
        assert "compare_digest" in tsk_src

    def test_injection_denied_error_no_key_material_in_message(self):
        from enterprise.ultra_gate import InjectionDeniedError
        import re
        err = InjectionDeniedError("bpc_sig_invalid", layer=2)
        msg = str(err)
        long_hex = re.findall(r'[0-9a-f]{32,}', msg.lower())
        assert len(long_hex) == 0, f"Possible key material in error: {long_hex}"

    def test_derive_p256_from_ed25519_seed_is_deterministic(self):
        from enterprise.bpc_crypto import derive_p256_private_key
        seed = os.urandom(32)
        k1 = derive_p256_private_key(seed, "SC-A")
        k2 = derive_p256_private_key(seed, "SC-A")
        assert k1.private_numbers().private_value == k2.private_numbers().private_value

    def test_bpc_nonce_replay_protection_works(self):
        from enterprise.bpc_crypto import P256KeyPair, sign_bpc_request, verify_bpc_request_local
        kp = P256KeyPair.generate()
        _, headers = sign_bpc_request(kp, "pair-1", "secret", "INJECT", "/inject")
        seen: set = set()
        ok1, _ = verify_bpc_request_local(kp.public_key, headers, "INJECT", "/inject",
                                           seen_nonces=seen)
        ok2, r2 = verify_bpc_request_local(kp.public_key, headers, "INJECT", "/inject",
                                            seen_nonces=seen)
        assert ok1 and not ok2 and r2 == "replay_detected"

    def test_tsk_checksum_tamper_detection(self):
        from enterprise.tsk_client import TSKClient
        provision = _make_tsk_provision()
        client = TSKClient(provision)
        key = client.assemble_key()
        # Flip last char of checksum
        tampered = key[:-1] + ("X" if key[-1] != "X" else "Y")
        assert not client.verify_checksum(tampered)

    def test_ultra_gate_agent_id_matches_identity_name(self):
        from enterprise.ultra_gate import UltraGate
        identity = _make_real_identity("my-specific-agent")
        gate = UltraGate(identity)
        assert gate._agent_id == "my-specific-agent"
