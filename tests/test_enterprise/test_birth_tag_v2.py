"""Tests for enterprise/birth_tag_v2.py — Signed Birth Tag Stamping (Tier 1).

No live Win32 HWNDs needed — set_agent_prop / get_agent_prop are mocked so
the full sign → stamp → verify cycle runs on any OS without a real window.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from enterprise.identity import AgentIdentity
from enterprise.birth_tag_v2 import (
    PROP_SIG,
    PROP_STS,
    _build_payload,
    stamp_signed_birth_tag,
    verify_signed_birth_tag,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _mock_dpapi():
    return (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda b: b"ENC:" + b),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda b: b[4:]),
    )


def make_identity(tmp_path: Path, name: str = "btagv2-test-agent") -> AgentIdentity:
    enc, dec = _mock_dpapi()
    with enc, dec:
        return AgentIdentity.init(name, data_dir=tmp_path)


FAKE_HWND  = 0xDEADBEEF
FAKE_AGENT = "agent-test-btagv2"
FAKE_PID   = 12345
FAKE_CTIME = "132987654321000000"
FAKE_BORN  = 1716000000.0


# ── _build_payload ─────────────────────────────────────────────────────────────

def test_build_payload_is_deterministic():
    """Same inputs always produce the same bytes."""
    ts = 1716100000.0
    a = _build_payload(FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN, ts)
    b = _build_payload(FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN, ts)
    assert a == b


def test_build_payload_contains_all_fields():
    """All five signed fields appear in the canonical payload."""
    ts = 1716100000.0
    payload = json.loads(_build_payload(FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN, ts))
    assert payload["scid"]    == FAKE_AGENT
    assert payload["scpid"]   == str(FAKE_PID)
    assert payload["scctime"] == FAKE_CTIME
    assert payload["scborn"]  == str(FAKE_BORN)
    assert payload["ts"]      == str(ts)


def test_build_payload_different_ts():
    """Different ts produces different payload bytes (anti-replay anchor)."""
    p1 = _build_payload(FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN, 1.0)
    p2 = _build_payload(FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN, 2.0)
    assert p1 != p2


# ── stamp_signed_birth_tag ─────────────────────────────────────────────────────

class FakePropStore:
    """Simulates SetPropW / GetPropW for a single fake HWND."""
    def __init__(self):
        self.props: dict[str, str] = {}

    def set(self, hwnd: int, key: str, value: str) -> bool:
        self.props[key] = value
        return True

    def get(self, hwnd: int, key: str) -> str:
        return self.props.get(key, "")


def _run_stamp(identity, store, ts=None):
    """Stamp with mocked Win32 prop calls."""
    # Pre-populate the unsigned properties (normally done by stamp_birth_tag)
    store.props["SCID"]    = FAKE_AGENT
    store.props["SCPID"]   = str(FAKE_PID)
    store.props["SCCTIME"] = FAKE_CTIME
    store.props["SCBORN"]  = str(FAKE_BORN)

    with patch("enterprise.registry.set_agent_prop", side_effect=store.set), \
         patch("enterprise.registry.get_agent_prop", side_effect=store.get):
        return stamp_signed_birth_tag(
            FAKE_HWND, identity,
            FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN,
            ts=ts,
        )


def test_stamp_returns_hex_sig(tmp_path):
    """stamp_signed_birth_tag returns a non-empty hex string."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    sig = _run_stamp(identity, store, ts=time.time())
    assert isinstance(sig, str)
    assert len(sig) > 0
    # ed25519 signature is 64 bytes = 128 hex chars
    assert len(sig) == 128


def test_stamp_writes_scid_sig_and_sts(tmp_path):
    """Both SCID_SIG and SCID_STS are written to the property store."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    ts = 1716100000.0
    sig = _run_stamp(identity, store, ts=ts)
    assert store.props[PROP_SIG] == sig
    assert store.props[PROP_STS] == str(ts)


# ── verify_signed_birth_tag ────────────────────────────────────────────────────

def _run_verify(store, pub_key_bytes, max_age=0.0):
    """Run verify_signed_birth_tag with mocked Win32 prop calls."""
    with patch("enterprise.registry.get_agent_prop", side_effect=store.get), \
         patch("enterprise.registry.set_agent_prop", side_effect=store.set):
        return verify_signed_birth_tag(FAKE_HWND, pub_key_bytes, max_age_seconds=max_age)


def test_sign_then_verify_ok(tmp_path):
    """Full round-trip: stamp then verify returns (True, 'ok')."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    ts = time.time()
    _run_stamp(identity, store, ts=ts)

    ok, reason = _run_verify(store, identity.public_key_bytes, max_age=0.0)
    assert ok is True
    assert reason == "ok"


def test_verify_fails_on_missing_sig(tmp_path):
    """Missing SCID_SIG → verify returns False."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    ts = time.time()
    _run_stamp(identity, store, ts=ts)
    del store.props[PROP_SIG]

    ok, reason = _run_verify(store, identity.public_key_bytes)
    assert ok is False
    assert "SCID_SIG" in reason


def test_verify_fails_on_corrupted_sig(tmp_path):
    """Corrupted SCID_SIG → signature verification fails."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    _run_stamp(identity, store, ts=time.time())
    # Flip one byte in the signature
    store.props[PROP_SIG] = "00" * 64

    ok, reason = _run_verify(store, identity.public_key_bytes)
    assert ok is False
    assert "signature" in reason.lower()


def test_verify_fails_with_wrong_key(tmp_path):
    """Signature valid for key A → verification with key B returns False."""
    identity_a = make_identity(tmp_path / "a", name="agent-a")
    identity_b = make_identity(tmp_path / "b", name="agent-b")

    store = FakePropStore()
    _run_stamp(identity_a, store, ts=time.time())

    ok, reason = _run_verify(store, identity_b.public_key_bytes)
    assert ok is False


def test_verify_fails_on_expired_ts(tmp_path):
    """Timestamp older than max_age_seconds → verify returns False (anti-replay)."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    old_ts = time.time() - 120.0  # 2 minutes in the past
    _run_stamp(identity, store, ts=old_ts)

    ok, reason = _run_verify(store, identity.public_key_bytes, max_age=60.0)
    assert ok is False
    assert "expired" in reason


def test_verify_passes_before_expiry(tmp_path):
    """Fresh timestamp within max_age_seconds → verify passes."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    fresh_ts = time.time() - 10.0  # 10 seconds ago
    _run_stamp(identity, store, ts=fresh_ts)

    ok, reason = _run_verify(store, identity.public_key_bytes, max_age=60.0)
    assert ok is True, reason


def test_verify_fails_if_scid_tampered(tmp_path):
    """Tampering with the unsigned SCID after signing breaks signature."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    _run_stamp(identity, store, ts=time.time())
    # Tamper with the SCID (normally SetPropW-protected, but sim a scenario)
    store.props["SCID"] = "impersonated-agent"

    ok, reason = _run_verify(store, identity.public_key_bytes)
    assert ok is False


def test_verify_fails_on_missing_sts(tmp_path):
    """Missing SCID_STS → verify returns False."""
    identity = make_identity(tmp_path)
    store = FakePropStore()
    _run_stamp(identity, store, ts=time.time())
    del store.props[PROP_STS]

    ok, reason = _run_verify(store, identity.public_key_bytes)
    assert ok is False
    assert "SCID_STS" in reason


# ── Integration test: real DPAPI (no mocks) ────────────────────────────────────

def test_sign_verify_real_dpapi(tmp_path):
    """Integration: stamp + verify using real Windows DPAPI — no key storage mocks.

    This test exercises the full stack end-to-end:
      - AgentIdentity.init() calls real CryptProtectData to store the private key
      - sign() decrypts the key with CryptUnprotectData and runs real ed25519
      - verify() runs real ed25519 public-key verification

    Win32 SetPropW / GetPropW are still mocked (no live window needed).

    Skipped automatically on non-Windows platforms where DPAPI is unavailable.
    """
    import sys
    if sys.platform != "win32":
        pytest.skip("Windows DPAPI not available on this platform")

    # Real identity — no DPAPI mock
    identity = AgentIdentity.init("btagv2-integration-real", data_dir=tmp_path)

    store = FakePropStore()
    store.props["SCID"]    = FAKE_AGENT
    store.props["SCPID"]   = str(FAKE_PID)
    store.props["SCCTIME"] = FAKE_CTIME
    store.props["SCBORN"]  = str(FAKE_BORN)

    ts = time.time()
    with patch("enterprise.registry.set_agent_prop", side_effect=store.set), \
         patch("enterprise.registry.get_agent_prop", side_effect=store.get):
        sig = stamp_signed_birth_tag(
            FAKE_HWND, identity, FAKE_AGENT, FAKE_PID, FAKE_CTIME, FAKE_BORN, ts=ts
        )

    assert len(sig) == 128, "ed25519 signature must be 128 hex chars (64 bytes)"

    with patch("enterprise.registry.get_agent_prop", side_effect=store.get), \
         patch("enterprise.registry.set_agent_prop", side_effect=store.set):
        ok, reason = verify_signed_birth_tag(
            FAKE_HWND, identity.public_key_bytes, max_age_seconds=0.0
        )

    assert ok is True, f"verify failed with real DPAPI: {reason}"
