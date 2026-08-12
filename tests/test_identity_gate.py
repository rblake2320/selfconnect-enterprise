"""tests/test_identity_gate.py — Identity gate unit tests.

Tests:
  1. Mode switching: bypass / audit / enforce via SC_IDENTITY_MODE env var.
  2. Emergency bypass Named Mutex: create, effect, release.
  3. BPC crypto: sign/verify round-trip, canonicalization, body hash.
  4. TSK client: segment derivation, key assembly, checksum.
  5. UltraGate: self-verify pipeline, InjectionDeniedError on failure.
  6. Degradation cascade: each level mock.
  7. Key recovery: recovery.pub write/read, peer detection.

All tests are pure Python — no live Win32 calls, no Ultra Server required.
Uses monkeypatching to simulate enterprise dependencies.

Run: python -m pytest tests/test_identity_gate.py -v
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from unittest import mock

import pytest




# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_fake_identity(agent_id: str = "SC-TESTTEST"):
    """Create a fake AgentIdentity-like object with a real ed25519 key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    fake = mock.MagicMock()
    fake.agent_id = agent_id
    fake._private_key = private_key
    fake.public_key_bytes = private_key.public_key().public_bytes_raw()
    return fake


# ═════════════════════════════════════════════════════════════════════════════
# 1. BPC Crypto Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestBPCCrypto:
    def test_b64url_roundtrip(self):
        from enterprise.bpc_crypto import b64url, b64url_decode
        data = b"hello world \x00\xff"
        assert b64url_decode(b64url(data)) == data

    def test_canonicalize_sorted_keys(self):
        from enterprise.bpc_crypto import canonicalize
        result = canonicalize({"z": 1, "a": 2, "m": 3})
        parsed = json.loads(result)
        assert list(parsed.keys()) == ["a", "m", "z"]

    def test_canonicalize_rejects_nested(self):
        from enterprise.bpc_crypto import canonicalize
        with pytest.raises(TypeError, match="nested"):
            canonicalize({"key": {"nested": "val"}})

    def test_canonicalize_rejects_forbidden_key(self):
        from enterprise.bpc_crypto import canonicalize
        with pytest.raises(TypeError, match="forbidden"):
            canonicalize({"__proto__": "evil"})

    def test_body_hash_deterministic(self):
        from enterprise.bpc_crypto import body_hash
        h1 = body_hash("hello")
        h2 = body_hash("hello")
        h3 = body_hash("world")
        assert h1 == h2
        assert h1 != h3

    def test_hash_secret_produces_b64url(self):
        from enterprise.bpc_crypto import hash_secret, b64url_decode
        result = hash_secret("Mesh-Secret-Test-2026!!")
        decoded = b64url_decode(result)
        assert len(decoded) == 32  # 256 bits

    def test_hmac_derive_deterministic(self):
        from enterprise.bpc_crypto import hash_secret, hmac_derive
        key = hash_secret("Mesh-Secret-Test-2026!!")
        h1 = hmac_derive(key, "nonce123456")
        h2 = hmac_derive(key, "nonce123456")
        assert h1 == h2

    def test_sign_verify_roundtrip(self):
        from enterprise.bpc_crypto import (
            derive_p256_from_ed25519, sign_payload, verify_payload_with_jwk,
            p256_public_key_to_jwk,
        )
        identity = _make_fake_identity()
        p256_key = derive_p256_from_ed25519(identity._private_key, identity.agent_id)
        pub_jwk = p256_public_key_to_jwk(p256_key)
        payload = {"a": "hello", "b": 42, "c": None}
        sig = sign_payload(p256_key, payload)
        assert verify_payload_with_jwk(pub_jwk, payload, sig)

    def test_sign_verify_tampered_payload(self):
        from enterprise.bpc_crypto import (
            derive_p256_from_ed25519, sign_payload, verify_payload_with_jwk,
            p256_public_key_to_jwk,
        )
        identity = _make_fake_identity()
        p256_key = derive_p256_from_ed25519(identity._private_key, identity.agent_id)
        pub_jwk = p256_public_key_to_jwk(p256_key)
        payload = {"action": "inject", "target": "hwnd_0x1234"}
        sig = sign_payload(p256_key, payload)
        tampered = dict(payload)
        tampered["target"] = "hwnd_0x9999"
        assert not verify_payload_with_jwk(pub_jwk, tampered, sig)

    def test_p256_derivation_is_deterministic(self):
        """Same ed25519 key must always produce the same P-256 key."""
        from enterprise.bpc_crypto import derive_p256_from_ed25519, p256_public_key_to_jwk
        identity = _make_fake_identity()
        key1 = derive_p256_from_ed25519(identity._private_key, identity.agent_id)
        key2 = derive_p256_from_ed25519(identity._private_key, identity.agent_id)
        jwk1 = p256_public_key_to_jwk(key1)
        jwk2 = p256_public_key_to_jwk(key2)
        assert jwk1["x"] == jwk2["x"]
        assert jwk1["y"] == jwk2["y"]

    def test_different_agents_get_different_keys(self):
        """Different agent_ids → different P-256 keys from same ed25519."""
        from enterprise.bpc_crypto import derive_p256_from_ed25519, p256_public_key_to_jwk
        identity = _make_fake_identity()
        key1 = derive_p256_from_ed25519(identity._private_key, "SC-AGENT01")
        key2 = derive_p256_from_ed25519(identity._private_key, "SC-AGENT02")
        assert p256_public_key_to_jwk(key1)["x"] != p256_public_key_to_jwk(key2)["x"]

    def test_constant_time_equal(self):
        from enterprise.bpc_crypto import constant_time_equal
        assert constant_time_equal("abc", "abc")
        assert not constant_time_equal("abc", "xyz")
        assert not constant_time_equal("abc", "ab")


# ═════════════════════════════════════════════════════════════════════════════
# 2. TSK Client Tests
# ═════════════════════════════════════════════════════════════════════════════

_TEST_SECRET = "a" * 64  # 64 hex chars = 256 bits

class TestTSKClient:
    def _make_state(self):  # -> TSKClientState (imported lazily inside)
        from enterprise.tsk_client import TSKClientState, SegmentConfig
        segs = [
            SegmentConfig(segment_id="seg_001", type="static", seg_len=8),
            SegmentConfig(segment_id="seg_002", type="totp", seg_len=10, window_sec=60),
            SegmentConfig(segment_id="seg_003", type="hotp", seg_len=6, counter=0),
        ]
        return TSKClientState(client_id="tsk_test", shared_secret=_TEST_SECRET, segments=segs)

    def test_validate_hex_secret_valid(self):
        from enterprise.tsk_client import validate_hex_secret
        validate_hex_secret(_TEST_SECRET)  # Should not raise

    def test_validate_hex_secret_too_short(self):
        from enterprise.tsk_client import validate_hex_secret
        with pytest.raises(ValueError, match="64 hex chars"):
            validate_hex_secret("abc")

    def test_validate_hex_secret_non_hex(self):
        from enterprise.tsk_client import validate_hex_secret
        with pytest.raises(ValueError, match="non-hex"):
            validate_hex_secret("g" * 64)

    def test_derive_static_deterministic(self):
        from enterprise.tsk_client import derive_segment_value, SegmentConfig
        seg = SegmentConfig(segment_id="s1", type="static", seg_len=8)
        secret_bytes = bytes.fromhex(_TEST_SECRET)
        v1 = derive_segment_value(secret_bytes, seg)
        v2 = derive_segment_value(secret_bytes, seg, now_ms=99999999)
        assert v1 == v2  # static segments never change

    def test_derive_totp_changes_with_window(self):
        from enterprise.tsk_client import derive_segment_value, SegmentConfig
        seg = SegmentConfig(segment_id="s2", type="totp", seg_len=10, window_sec=60)
        secret_bytes = bytes.fromhex(_TEST_SECRET)
        t0 = int(time.time() * 1000)
        t1 = t0 + 61_000  # next TOTP window
        v0 = derive_segment_value(secret_bytes, seg, now_ms=t0)
        v1 = derive_segment_value(secret_bytes, seg, now_ms=t1)
        assert v0 != v1  # different windows → different values

    def test_derive_hotp_uses_counter(self):
        from enterprise.tsk_client import derive_segment_value, SegmentConfig
        seg = SegmentConfig(segment_id="s3", type="hotp", seg_len=6, counter=0)
        secret_bytes = bytes.fromhex(_TEST_SECRET)
        v0 = derive_segment_value(secret_bytes, seg, hotp_counter=0)
        v1 = derive_segment_value(secret_bytes, seg, hotp_counter=1)
        assert v0 != v1  # different counters → different values

    def test_segment_length_enforced(self):
        from enterprise.tsk_client import derive_segment_value, SegmentConfig
        for length in [4, 8, 12, 20, 43]:
            seg = SegmentConfig(segment_id=f"s{length}", type="static", seg_len=length)
            secret_bytes = bytes.fromhex(_TEST_SECRET)
            val = derive_segment_value(secret_bytes, seg)
            assert len(val) == length, f"Expected length {length}, got {len(val)}"

    def test_generate_tsk_key_has_checksum(self):
        from enterprise.tsk_client import generate_tsk_key, compute_checksum, CHECKSUM_LENGTH
        state = self._make_state()
        key = generate_tsk_key(state)
        assert len(key) > CHECKSUM_LENGTH
        body = key[:-CHECKSUM_LENGTH]
        expected_cksum = compute_checksum(_TEST_SECRET, body)
        assert key[-CHECKSUM_LENGTH:] == expected_cksum

    def test_generate_tsk_key_deterministic_same_window(self):
        """Same time window → same key (static + TOTP stay constant within window)."""
        from enterprise.tsk_client import generate_tsk_key
        state = self._make_state()
        now_ms = int(time.time() * 1000)
        k1 = generate_tsk_key(state, now_ms=now_ms)
        k2 = generate_tsk_key(state, now_ms=now_ms)
        assert k1 == k2

    def test_parse_provision_payload(self):
        from enterprise.tsk_client import parse_provision_payload
        payload = {
            "clientSegments": [
                {"segmentId": "seg_a", "type": "static", "length": 8},
                {"segmentId": "seg_b", "type": "totp", "length": 10, "windowSec": 30},
                {"segmentId": "seg_c", "type": "hotp", "length": 6, "counter": 0},
            ]
        }
        state = parse_provision_payload("tsk_test", _TEST_SECRET, payload)
        assert len(state.segments) == 3
        assert state.segments[0].segment_id == "seg_a"
        assert state.segments[1].window_sec == 30


# ═════════════════════════════════════════════════════════════════════════════
# 3. UltraGate Tests (no live server)
# ═════════════════════════════════════════════════════════════════════════════

class TestUltraGate:
    def _make_gate(self):  # -> UltraGate (imported lazily inside)
        from enterprise.ultra_gate import UltraGate
        from enterprise.tsk_client import TSKClientState, SegmentConfig
        identity = _make_fake_identity()
        gate = UltraGate(identity, mesh_secret="Mesh-Secret-Test-2026!!-32-bytes")

        # Manually bootstrap without a server
        segs = [SegmentConfig(segment_id="seg_x", type="static", seg_len=10)]
        gate.pair_id = "pair_test_abc123"
        gate.tsk_state = TSKClientState(
            client_id="tsk_test",
            shared_secret=_TEST_SECRET,
            segments=segs,
        )
        gate._bootstrapped = True
        return gate

    @staticmethod
    def _register_self_binding(gate):
        assert gate.tsk_state is not None
        gate.register_peer_binding(
            gate.pair_id,
            gate._pub_jwk,
            gate.tsk_state.client_id,
            gate.tsk_state,
        )

    def test_build_injection_request_structure(self):
        gate = self._make_gate()
        headers = gate.build_injection_request(0x00AB025A, "hello world\r")
        assert "X-BPC-Pair-ID" in headers
        assert "X-BPC-Signed-Data" in headers
        assert "X-BPC-Signature" in headers
        assert "X-TSK-Client-ID" in headers
        assert "X-TSK-Key" in headers
        assert headers["X-BPC-Pair-ID"] == "pair_test_abc123"

    def test_self_verify_passes(self):
        gate = self._make_gate()
        text = "hello gate test\r"
        headers = gate.build_injection_request(0x1234, text)
        ok, reason = gate._self_verify(headers, text)
        assert ok, f"Self-verify failed: {reason}"

    def test_verify_local_accepts_fresh_fully_bound_request(self):
        """The local fast path accepts a fresh request only after peer registration."""
        from enterprise.tsk_client import CHECKSUM_LENGTH

        assert CHECKSUM_LENGTH == 12
        gate = self._make_gate()
        text = "hello local verify\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert ok, f"Local verify failed with valid {CHECKSUM_LENGTH}-char checksum: {reason}"

    def test_verify_local_rejects_missing_peer_public_key(self):
        gate = self._make_gate()
        text = "missing peer key\r"
        headers = gate.build_injection_request(0x1234, text)

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert not ok
        assert "no complete cached binding" in reason

    def test_verify_local_rejects_missing_tsk_state(self):
        gate = self._make_gate()
        text = "missing TSK state\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)
        gate._peer_bindings[gate.pair_id] = mock.MagicMock(
            pub_jwk=gate._pub_jwk,
            tsk_client_id=gate.tsk_state.client_id,
            tsk_state=None,
        )

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert not ok
        assert reason == "peer TSK state unavailable"

    def test_verify_local_rejects_missing_tsk_client_id(self):
        gate = self._make_gate()
        text = "missing TSK client ID\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)
        del headers["X-TSK-Client-ID"]

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert not ok
        assert reason == "missing required headers"

    def test_verify_local_rejects_tsk_client_id_mismatch(self):
        gate = self._make_gate()
        text = "mismatched TSK client ID\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)
        headers["X-TSK-Client-ID"] = "tsk_attacker"

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert not ok
        assert "TSK client_id mismatch" in reason

    def test_verify_local_rejects_header_pair_not_bound_in_signed_payload(self):
        gate = self._make_gate()
        text = "signed pair binding\r"
        headers = gate.build_injection_request(0x1234, text)
        original_pair_id = gate.pair_id
        alternate_pair_id = "pair_alternate"
        assert gate.tsk_state is not None
        gate.register_peer_binding(
            alternate_pair_id,
            gate._pub_jwk,
            gate.tsk_state.client_id,
            gate.tsk_state,
        )
        headers["X-BPC-Pair-ID"] = alternate_pair_id

        ok, reason = gate.verify_local(headers, text, alternate_pair_id)

        assert original_pair_id != alternate_pair_id
        assert not ok
        assert reason == "signed pair_id mismatch"

    def test_verify_local_rejects_truncated_tsk_key(self):
        gate = self._make_gate()
        text = "truncated TSK key\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)
        headers["X-TSK-Key"] = headers["X-TSK-Key"][:-1]

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert not ok
        assert "TSK key length mismatch" in reason

    def test_verify_local_rejects_malformed_tsk_key(self):
        gate = self._make_gate()
        text = "malformed TSK key\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)
        key = headers["X-TSK-Key"]
        headers["X-TSK-Key"] = ("A" if key[0] != "A" else "B") + key[1:]

        ok, reason = gate.verify_local(headers, text, gate.pair_id)

        assert not ok
        assert reason == "TSK checksum mismatch"

    def test_verify_local_invalid_signature_does_not_consume_nonce(self):
        gate = self._make_gate()
        text = "signature race\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)
        forged = dict(headers)
        forged["X-BPC-Signature"] = "AAAA"

        forged_ok, forged_reason = gate.verify_local(forged, text, gate.pair_id)
        valid_ok, valid_reason = gate.verify_local(headers, text, gate.pair_id)

        assert not forged_ok
        assert forged_reason == "ECDSA signature invalid"
        assert valid_ok, valid_reason

    def test_verify_local_cross_peer_uses_registered_peer_tsk_state(self):
        sender = self._make_gate()
        receiver = self._make_gate()
        text = "cross-peer local verification\r"
        headers = sender.build_injection_request(0x1234, text)
        assert sender.tsk_state is not None
        receiver.register_peer_binding(
            sender.pair_id,
            sender._pub_jwk,
            sender.tsk_state.client_id,
            sender.tsk_state,
        )

        ok, reason = receiver.verify_local(headers, text, sender.pair_id)

        assert ok, reason

    def test_verify_local_cross_peer_rejects_wrong_registered_tsk_identity(self):
        from enterprise.tsk_client import TSKClientState

        sender = self._make_gate()
        receiver = self._make_gate()
        text = "cross-peer wrong TSK identity\r"
        headers = sender.build_injection_request(0x1234, text)
        assert sender.tsk_state is not None
        wrong_state = TSKClientState(
            client_id="tsk_wrong_peer",
            shared_secret=sender.tsk_state.shared_secret,
            segments=sender.tsk_state.segments,
        )
        receiver.register_peer_binding(
            sender.pair_id,
            sender._pub_jwk,
            wrong_state.client_id,
            wrong_state,
        )

        ok, reason = receiver.verify_local(headers, text, sender.pair_id)

        assert not ok
        assert "TSK client_id mismatch" in reason

    def test_register_peer_binding_rejects_state_identity_mismatch(self):
        gate = self._make_gate()
        assert gate.tsk_state is not None

        with pytest.raises(ValueError, match="does not match expected binding"):
            gate.register_peer_binding(
                gate.pair_id,
                gate._pub_jwk,
                "tsk_expected_other",
                gate.tsk_state,
            )

    def test_register_peer_binding_rejects_conflicting_rebind(self):
        gate = self._make_gate()
        other = self._make_gate()
        self._register_self_binding(gate)
        assert gate.tsk_state is not None

        with pytest.raises(ValueError, match="binding conflict"):
            gate.register_peer_binding(
                gate.pair_id,
                other._pub_jwk,
                gate.tsk_state.client_id,
                gate.tsk_state,
            )

    def test_register_peer_binding_snapshots_and_rejects_secret_rebind(self):
        from enterprise.tsk_client import TSKClientState

        gate = self._make_gate()
        assert gate.tsk_state is not None
        original_secret = gate.tsk_state.shared_secret
        self._register_self_binding(gate)
        gate.tsk_state.shared_secret = "b" * 64

        cached = gate._peer_bindings[gate.pair_id]
        assert cached.tsk_state.shared_secret == original_secret
        replacement = TSKClientState(
            client_id=cached.tsk_client_id,
            shared_secret="b" * 64,
            segments=cached.tsk_state.segments,
        )
        with pytest.raises(ValueError, match="binding conflict"):
            gate.register_peer_binding(
                gate.pair_id,
                gate._pub_jwk,
                replacement.client_id,
                replacement,
            )

    def test_self_verify_fails_on_tampered_text(self):
        gate = self._make_gate()
        text = "original text\r"
        headers = gate.build_injection_request(0x1234, text)
        ok, reason = gate._self_verify(headers, "tampered text\r")
        assert not ok
        assert "body_hash" in reason

    def test_authorize_injection_success(self):
        gate = self._make_gate()
        with mock.patch.object(gate, "verify_server", return_value=(True, "")) as verify:
            gate.authorize_injection(0x1234, "test injection\r")
        verify.assert_called_once()

    def test_authorize_injection_denies_server_rejection(self):
        from enterprise.ultra_gate import InjectionDeniedError

        gate = self._make_gate()
        with mock.patch.object(
            gate,
            "verify_server",
            return_value=(False, "TSK verification failed"),
        ):
            with pytest.raises(InjectionDeniedError, match="TSK verification failed"):
                gate.authorize_injection(0x1234, "test injection\r")

    def test_authorize_injection_surfaces_server_unavailability(self):
        from enterprise.ultra_gate import UltraGateServerUnavailableError

        gate = self._make_gate()
        with mock.patch.object(
            gate,
            "verify_server",
            return_value=(False, "server unavailable: connection refused"),
        ):
            with pytest.raises(UltraGateServerUnavailableError):
                gate.authorize_injection(0x1234, "test injection\r")

    def test_verify_local_consumes_duplicate_nonce_atomically(self):
        from concurrent.futures import ThreadPoolExecutor

        gate = self._make_gate()
        text = "concurrent replay\r"
        headers = gate.build_injection_request(0x1234, text)
        self._register_self_binding(gate)

        with ThreadPoolExecutor(max_workers=32) as pool:
            results = list(
                pool.map(
                    lambda _index: gate.verify_local(headers, text, gate.pair_id),
                    range(64),
                )
            )

        assert sum(1 for ok, _reason in results if ok) == 1
        assert sum(1 for ok, reason in results if not ok and reason == "nonce replay detected") == 63

    def test_not_bootstrapped_raises(self):
        from enterprise.ultra_gate import UltraGate, UltraGateNotBootstrappedError
        identity = _make_fake_identity()
        gate = UltraGate(identity, mesh_secret="Mesh-Secret-Test-2026!!-32-bytes")
        with pytest.raises(UltraGateNotBootstrappedError):
            gate.build_injection_request(0x1234, "text")

    def test_high_assurance_rejects_known_development_mesh_secret(self, monkeypatch):
        from enterprise.ultra_gate import DEFAULT_MESH_SECRET, UltraGate

        monkeypatch.setenv("SC_REQUIRE_ULTRA_SERVER", "1")
        identity = _make_fake_identity()
        with mock.patch.object(
            UltraGate,
            "_load_mesh_secret",
            return_value=DEFAULT_MESH_SECRET,
        ):
            with pytest.raises(ValueError, match="explicit mesh secret"):
                UltraGate(identity)

    def test_high_assurance_rejects_short_explicit_mesh_secret(self, monkeypatch):
        from enterprise.ultra_gate import UltraGate

        monkeypatch.setenv("SC_IDENTITY_MODE", "enforce")
        with pytest.raises(ValueError, match="at least 32 bytes"):
            UltraGate(_make_fake_identity(), mesh_secret="too-short")

    def test_status_dict(self):
        gate = self._make_gate()
        status = gate.status()
        assert status["bootstrapped"] is True
        assert status["pair_id"] == "pair_test_abc123"
        assert status["tsk_client_id"] == "tsk_test"


# ═════════════════════════════════════════════════════════════════════════════
# 4. Identity Gate Mode Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestIdentityGateMode:
    def test_default_mode_is_audit(self, monkeypatch):
        # WRAITH-003: default must be audit, not bypass
        monkeypatch.delenv("SC_IDENTITY_MODE", raising=False)
        monkeypatch.delenv("SC_IDENTITY_BYPASS_CONFIRMED", raising=False)
        from enterprise.identity_gate import get_current_mode, MODE_AUDIT
        assert get_current_mode() == MODE_AUDIT

    def test_audit_mode(self, monkeypatch):
        monkeypatch.setenv("SC_IDENTITY_MODE", "audit")
        from enterprise.identity_gate import get_current_mode, MODE_AUDIT
        assert get_current_mode() == MODE_AUDIT

    def test_enforce_mode(self, monkeypatch):
        monkeypatch.setenv("SC_IDENTITY_MODE", "enforce")
        from enterprise.identity_gate import get_current_mode, MODE_ENFORCE
        with mock.patch("enterprise.identity_gate._emergency_mutex_active", return_value=False):
            assert get_current_mode() == MODE_ENFORCE

    def test_invalid_mode_raises_configuration_error(self, monkeypatch):
        # WRAITH-003: unrecognised value must raise, not silently fall back to bypass
        monkeypatch.setenv("SC_IDENTITY_MODE", "invalid_mode")
        from enterprise.identity_gate import get_current_mode, IdentityGateError
        with pytest.raises(IdentityGateError, match="not a recognised mode"):
            get_current_mode()

    def test_bypass_without_confirmation_raises(self, monkeypatch):
        # WRAITH-003: bypass requires SC_IDENTITY_BYPASS_CONFIRMED=1
        monkeypatch.setenv("SC_IDENTITY_MODE", "bypass")
        monkeypatch.delenv("SC_IDENTITY_BYPASS_CONFIRMED", raising=False)
        from enterprise.identity_gate import get_current_mode, IdentityGateError
        with pytest.raises(IdentityGateError, match="SC_IDENTITY_BYPASS_CONFIRMED"):
            get_current_mode()

    def test_bypass_with_confirmation_succeeds(self, monkeypatch):
        # WRAITH-003: bypass is allowed when both env vars are set
        monkeypatch.setenv("SC_IDENTITY_MODE", "bypass")
        monkeypatch.setenv("SC_IDENTITY_BYPASS_CONFIRMED", "1")
        from enterprise.identity_gate import get_current_mode, MODE_BYPASS
        assert get_current_mode() == MODE_BYPASS

    def test_mutex_downgrades_enforce_to_audit(self, monkeypatch):
        monkeypatch.setenv("SC_IDENTITY_MODE", "enforce")
        from enterprise import identity_gate
        with mock.patch.object(identity_gate, "_emergency_mutex_active", return_value=True):
            mode = identity_gate.get_current_mode()
        assert mode == identity_gate.MODE_AUDIT

    def test_bypass_mode_skips_gate(self, monkeypatch):
        """In bypass mode (with confirmation), gated_send_string() calls original without gate check."""
        monkeypatch.delenv("SC_REQUIRE_ULTRA_SERVER", raising=False)
        monkeypatch.setenv("SC_IDENTITY_MODE", "bypass")
        monkeypatch.setenv("SC_IDENTITY_BYPASS_CONFIRMED", "1")
        from enterprise.identity_gate import gated_send_string
        calls = []
        def fake_send(target, text, *args, **kwargs):
            calls.append((target, text))
        fake_target = mock.MagicMock()
        fake_target.hwnd = 0x1234
        gated_send_string(fake_target, "hello", gate=None, _original_send_string=fake_send)
        assert len(calls) == 1
        assert calls[0][1] == "hello"

    def test_enforce_mode_blocks_when_gate_fails(self, monkeypatch):
        monkeypatch.setenv("SC_IDENTITY_MODE", "enforce")
        from enterprise.identity_gate import gated_send_string, InjectionDeniedError
        with mock.patch("enterprise.identity_gate._emergency_mutex_active", return_value=False):
            with mock.patch("enterprise.identity_gate.DegradationCascade.verify",
                            return_value=(False, "all verification failed", 2)):
                fake_target = mock.MagicMock()
                fake_target.hwnd = 0x1234
                with pytest.raises((InjectionDeniedError, Exception)):
                    gated_send_string(
                        fake_target, "text", gate=None,
                        _original_send_string=lambda *a, **kw: None,
                    )

    def test_audit_mode_proceeds_on_failure(self, monkeypatch):
        """In audit mode, injection proceeds even when verification fails."""
        monkeypatch.delenv("SC_REQUIRE_ULTRA_SERVER", raising=False)
        monkeypatch.setenv("SC_IDENTITY_MODE", "audit")
        from enterprise.identity_gate import gated_send_string
        calls = []
        with mock.patch("enterprise.identity_gate.DegradationCascade.verify",
                        return_value=(False, "signature invalid", 0)):
            fake_target = mock.MagicMock()
            fake_target.hwnd = 0x1234
            gated_send_string(
                fake_target, "text", gate=None,
                _original_send_string=lambda t, txt, *a, **kw: calls.append(txt),
            )
        assert calls == ["text"]  # Injection proceeded despite failure


# ═════════════════════════════════════════════════════════════════════════════
# 5. Degradation Cascade Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestDegradationCascade:
    def _make_cascade(self, mode: str, gate=None):
        from enterprise.identity_gate import DegradationCascade
        return DegradationCascade(gate=gate, mode=mode)

    def test_no_gate_skips_level0(self):
        cascade = self._make_cascade("audit", gate=None)
        # Without a gate, should go to Level 2 directly
        with mock.patch.object(cascade, "_level2_enterprise", return_value=(True, "")):
            ok, reason, level = cascade.verify(0x1234, "text")
        assert ok
        assert level == 2

    def test_enforce_stops_at_level2(self):
        """In enforce mode, cascade must not go below Level 2."""
        cascade = self._make_cascade("enforce", gate=None)
        with mock.patch.object(cascade, "_level2_enterprise", return_value=(False, "no birth tag")):
            ok, reason, level = cascade.verify(0x1234, "text")
        assert not ok
        assert level == 2  # stopped at Level 2, did not go to 3 or 4

    def test_audit_can_go_to_level4(self):
        """In audit mode, cascade can reach Level 4 (pass-through)."""
        cascade = self._make_cascade("audit", gate=None)
        with mock.patch.object(cascade, "_level2_enterprise", return_value=(False, "no birth tag")):
            ok, reason, level = cascade.verify(0x1234, "text")
        assert ok  # audit mode: pass even at Level 4
        assert level == 4

    def test_strict_enforce_defaults_to_level0_fail_closed(self, monkeypatch):
        monkeypatch.delenv("SC_STRICT_ENFORCE", raising=False)
        gate = mock.MagicMock()
        gate._bootstrapped = True
        cascade = self._make_cascade("enforce", gate=gate)
        with mock.patch.object(cascade, "_level0_full", return_value=(False, "TSK rejected")), \
             mock.patch.object(cascade, "_level1_bpc_only", return_value=(True, "")) as level1:
            ok, reason, level = cascade.verify(0x1234, "text")
        assert not ok
        assert level == 0
        assert "strict_enforce" in reason
        level1.assert_not_called()

    def test_operator_can_explicitly_allow_bounded_degradation(self, monkeypatch):
        monkeypatch.setenv("SC_STRICT_ENFORCE", "0")
        gate = mock.MagicMock()
        gate._bootstrapped = True
        cascade = self._make_cascade("enforce", gate=gate)
        with mock.patch.object(cascade, "_level0_full", return_value=(False, "TSK rejected")), \
             mock.patch.object(cascade, "_level1_bpc_only", return_value=(True, "")):
            ok, reason, level = cascade.verify(0x1234, "text")
        assert ok
        assert reason == ""
        assert level == 1

    # ── WRAITH-001 regression tests ───────────────────────────────────────────

    def test_level2_no_trusted_key_fails_closed(self):
        """WRAITH-001: Level 2 must fail closed when no trusted public key is registered
        for the target HWND — not raise TypeError or silently pass."""
        from enterprise.identity_gate import DegradationCascade
        cascade = DegradationCascade(gate=None, mode="enforce")
        # No peer_public_keys registered → must fail, not TypeError
        with mock.patch("enterprise.registry.read_birth_tag") as mock_rbt:
            mock_rbt.return_value = mock.MagicMock()  # tag present
            ok, reason = cascade._level2_enterprise(0xDEAD)
        assert not ok
        assert "no trusted public key" in reason

    def test_level2_passes_trusted_key_to_verify(self):
        """WRAITH-001: Level 2 must call verify_signed_birth_tag with (hwnd, pub_key_bytes)
        — not a single-argument call that always raises TypeError."""
        from enterprise.identity_gate import DegradationCascade
        trusted_key = b"\xab" * 32
        cascade = DegradationCascade(
            gate=None, mode="enforce",
            peer_public_keys={0x1234: trusted_key},
        )
        with mock.patch("enterprise.registry.read_birth_tag") as mock_rbt, \
             mock.patch("enterprise.birth_tag_v2.verify_signed_birth_tag",
                        return_value=(True, "ok")) as mock_vsbt:
            mock_rbt.return_value = mock.MagicMock()  # tag present
            ok, reason = cascade._level2_enterprise(0x1234)
        assert ok
        # Verify it was called with both required positional args
        mock_vsbt.assert_called_once_with(0x1234, trusted_key)

    def test_level2_propagates_verify_failure_reason(self):
        """WRAITH-001: Level 2 must propagate the reason string from
        verify_signed_birth_tag on failure, not swallow it."""
        from enterprise.identity_gate import DegradationCascade
        trusted_key = b"\xcd" * 32
        cascade = DegradationCascade(
            gate=None, mode="enforce",
            peer_public_keys={0xBEEF: trusted_key},
        )
        with mock.patch("enterprise.registry.read_birth_tag") as mock_rbt, \
             mock.patch("enterprise.birth_tag_v2.verify_signed_birth_tag",
                        return_value=(False, "signature mismatch")) as mock_vsbt:
            mock_rbt.return_value = mock.MagicMock()
            ok, reason = cascade._level2_enterprise(0xBEEF)
        assert not ok
        assert reason == "signature mismatch"
        mock_vsbt.assert_called_once_with(0xBEEF, trusted_key)


# ═════════════════════════════════════════════════════════════════════════════
# 6. Key Recovery Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestKeyRecovery:
    def test_recovery_pub_write_read(self, tmp_path, monkeypatch):
        """RecoveryManager writes recovery.pub + recovery.token and check_peer_recovery reads it.

        Gap 2 fix: check_peer_recovery now requires a server-signed recovery.token alongside
        recovery.pub. This test uses the live Ultra Server on localhost:7777 to obtain a real
        HMAC-signed token, then verifies that check_peer_recovery returns the correct key.

        If the Ultra Server is not available, the test is skipped.
        """
        import json
        import urllib.request
        import urllib.error
        monkeypatch.setenv("APPDATA", str(tmp_path))
        from enterprise.key_recovery import check_peer_recovery

        # Skip if Ultra Server is not running
        server_url = "http://127.0.0.1:7777"
        try:
            urllib.request.urlopen(f"{server_url}/health", timeout=2)
        except Exception:
            pytest.skip("Ultra Server not available on localhost:7777")

        admin_token = os.environ.get("ULTRA_ADMIN_TOKEN", "")
        if not admin_token:
            if os.environ.get("SC_REQUIRE_ULTRA_SERVER") == "1":
                pytest.fail("ULTRA_ADMIN_TOKEN is required by the live Ultra conformance run")
            pytest.skip("ULTRA_ADMIN_TOKEN is not configured")

        from enterprise.identity import AgentIdentity
        from enterprise.lifecycle_auth import lifecycle_auth_headers

        agent_name = "test-agent-gap2"
        identity = AgentIdentity.init(agent_name, data_dir=tmp_path / "identity")
        pubkey_hex = identity.public_key_bytes.hex()

        # Get a real server-signed token from the Ultra Server
        payload = json.dumps({
            "agentName": agent_name,
            "agentId": identity.agent_id,
            "newPubHex": pubkey_hex,
            "challengeHash": hashlib.sha256(b"gap2-live-recovery").hexdigest(),
        }, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(
            f"{server_url}/confirm-recovery",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {admin_token}",
                **lifecycle_auth_headers(
                    identity, payload, method="POST", path="/confirm-recovery"
                ),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
        assert token_data.get("ok") is True, f"confirm-recovery failed: {token_data}"
        token = token_data["token"]

        # Write recovery.pub and recovery.token
        pub_path = tmp_path / "SelfConnect" / agent_name
        pub_path.mkdir(parents=True, exist_ok=True)
        (pub_path / "recovery.pub").write_text(pubkey_hex + "\n", encoding="utf-8")
        (pub_path / "recovery.token").write_text(
            json.dumps(token), encoding="utf-8"
        )

        result = check_peer_recovery(0x1234, agent_name, server_url=server_url)
        assert result is not None, "check_peer_recovery returned None despite valid token"
        assert result.hex() == pubkey_hex

    def test_recovery_pub_without_token_is_rejected(self, tmp_path, monkeypatch):
        """Gap 2: recovery.pub without recovery.token MUST be rejected.

        An attacker who can write recovery.pub (e.g., via a compromised file system)
        cannot cause peers to accept their rogue key without also obtaining a
        server-signed token from the Ultra Server.
        """
        monkeypatch.setenv("APPDATA", str(tmp_path))
        from enterprise.key_recovery import check_peer_recovery

        agent_name = "test-agent-no-token"
        pub_path = tmp_path / "SelfConnect" / agent_name
        pub_path.mkdir(parents=True, exist_ok=True)
        fake_pubkey_hex = "cd" * 32
        (pub_path / "recovery.pub").write_text(fake_pubkey_hex + "\n", encoding="utf-8")
        # Deliberately do NOT write recovery.token

        result = check_peer_recovery(0x1234, agent_name)
        assert result is None, "Gap 2 VIOLATED: key accepted without server token"

    def test_recovery_pub_expired(self, tmp_path, monkeypatch):
        """Expired recovery files (> RECOVERY_WINDOW_SEC old) are ignored."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        from enterprise.key_recovery import check_peer_recovery

        agent_name = "test-agent"
        pub_path = tmp_path / "SelfConnect" / agent_name
        pub_path.mkdir(parents=True, exist_ok=True)
        recovery_file = pub_path / "recovery.pub"
        recovery_file.write_text("cd" * 32 + "\n", encoding="utf-8")

        # Backdate the file by 120 seconds
        old_mtime = time.time() - 120
        os.utime(recovery_file, (old_mtime, old_mtime))

        result = check_peer_recovery(0x1234, agent_name)
        assert result is None

    def test_recovery_pub_no_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        from enterprise.key_recovery import check_peer_recovery
        result = check_peer_recovery(0x1234, "nonexistent-agent")
        assert result is None


# ═════════════════════════════════════════════════════════════════════════════
# 7. SC_REQUIRE_ULTRA Integration Test
# ═════════════════════════════════════════════════════════════════════════════

class TestSCRequireUltra:
    def test_require_ultra_without_gate_raises(self, monkeypatch):
        """The real send wrapper must reject any non-Level-0 result."""
        from enterprise.identity_gate import InjectionDeniedError, gated_send_string

        monkeypatch.setenv("SC_REQUIRE_ULTRA_SERVER", "1")
        monkeypatch.setenv("SC_IDENTITY_MODE", "audit")
        target = mock.MagicMock(hwnd=0x1234)
        sent: list[str] = []
        with mock.patch(
            "enterprise.identity_gate.DegradationCascade.verify",
            return_value=(True, "", 2),
        ):
            with pytest.raises(InjectionDeniedError, match="requires Level 0"):
                gated_send_string(
                    target,
                    "text",
                    gate=None,
                    _original_send_string=lambda _target, text: sent.append(text),
                )
        assert sent == []

    def test_require_ultra_with_gate_passes(self, monkeypatch):
        """The real send wrapper permits a verified Level-0 result."""
        from enterprise.identity_gate import gated_send_string

        monkeypatch.setenv("SC_REQUIRE_ULTRA_SERVER", "1")
        monkeypatch.setenv("SC_IDENTITY_MODE", "audit")
        target = mock.MagicMock(hwnd=0x1234)
        sent: list[str] = []
        with mock.patch(
            "enterprise.identity_gate.DegradationCascade.verify",
            return_value=(True, "", 0),
        ):
            gated_send_string(
                target,
                "text",
                gate=mock.MagicMock(),
                _original_send_string=lambda _target, text: sent.append(text),
            )
        assert sent == ["text"]

    def test_require_ultra_rejects_bypass_mode(self, monkeypatch):
        from enterprise.identity_gate import InjectionDeniedError, gated_send_string

        monkeypatch.setenv("SC_REQUIRE_ULTRA_SERVER", "1")
        monkeypatch.setenv("SC_IDENTITY_MODE", "bypass")
        monkeypatch.setenv("SC_IDENTITY_BYPASS_CONFIRMED", "1")
        with pytest.raises(InjectionDeniedError, match="incompatible with bypass"):
            gated_send_string(
                mock.MagicMock(hwnd=0x1234),
                "text",
                gate=None,
                _original_send_string=lambda *_args, **_kwargs: None,
            )
