"""tests/test_enterprise/test_version_gate.py — Tests for enterprise.version_gate (Tier 2)

All Win32 calls are mocked.  Time is controlled via the `now` parameter.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


from enterprise.version_gate import VersionGate


FAKE_HWND  = 0xDEAD0001
PAST_DATE  = datetime(2025, 1, 1, tzinfo=timezone.utc)   # always in the past
FAR_FUTURE = datetime(2099, 1, 1, tzinfo=timezone.utc)   # always in the future
NOW        = datetime(2026, 6, 1, tzinfo=timezone.utc)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_dpapi():
    return (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda b: b"ENC:" + b),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda b: b[4:]),
    )


def _make_identity(tmp_path: Path, name: str):
    from enterprise.identity import AgentIdentity
    enc, dec = _make_dpapi()
    with enc, dec:
        return AgentIdentity.init(name, data_dir=tmp_path)


class FakePropStore:
    def __init__(self, props: dict = None):
        self.props = props or {}

    def get(self, hwnd, key):
        return self.props.get(key, "")

    def set(self, hwnd, key, value):
        self.props[key] = value
        return True


def _stamp_peer(identity, store, agent_id="agent-test", born=None, ts=None):
    """Stamp a valid SCID_SIG into a FakePropStore."""
    from enterprise.birth_tag_v2 import stamp_signed_birth_tag
    born = born or time.time()
    ts   = ts   or time.time()
    store.props["SCID"]    = agent_id
    store.props["SCPID"]   = "12345"
    store.props["SCCTIME"] = "132987654321"
    store.props["SCBORN"]  = str(born)

    with patch("enterprise.registry.set_agent_prop", side_effect=store.set), \
         patch("enterprise.registry.get_agent_prop", side_effect=store.get):
        stamp_signed_birth_tag(FAKE_HWND, identity, agent_id, 12345, "132987654321", born, ts=ts)


# ── Phase 0: no flag ───────────────────────────────────────────────────────────

class TestPhaseNone:
    def test_no_flag_rejects_unsigned_peer(self, monkeypatch):
        monkeypatch.delenv("SC_SUNSET_V1", raising=False)
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)
        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", return_value=""):
            result = gate.check_peer(FAKE_HWND, None, now=NOW)

        assert result.ok is False
        assert result.phase == "enforced"

    def test_no_flag_phase_is_enforced(self, monkeypatch):
        monkeypatch.delenv("SC_SUNSET_V1", raising=False)
        assert VersionGate.current_phase(now=NOW) == "enforced"


# ── Phase 1: grace period ──────────────────────────────────────────────────────

class TestGracePeriod:
    def test_unsigned_peer_rejected_in_grace(self, monkeypatch):
        monkeypatch.setenv("SC_SUNSET_V1", "2099-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)
        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", return_value=""):
            result = gate.check_peer(FAKE_HWND, None, now=NOW)

        assert result.ok is False
        assert result.phase == "grace"
        assert "required" in result.reason.lower()

    def test_signed_valid_peer_accepted_in_grace(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SC_SUNSET_V1", "2099-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)

        identity = _make_identity(tmp_path, "gate-grace-test")
        store = FakePropStore()
        _stamp_peer(identity, store, ts=time.time())

        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", side_effect=store.get), \
             patch("enterprise.registry.set_agent_prop", side_effect=store.set):
            result = gate.check_peer(
                FAKE_HWND, identity.public_key_bytes, now=NOW, max_sig_age_seconds=60.0
            )

        assert result.ok is True
        assert result.phase == "grace"

    def test_signed_invalid_peer_rejected_in_grace(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SC_SUNSET_V1", "2099-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)

        identity = _make_identity(tmp_path, "gate-grace-invalid")
        store = FakePropStore()
        _stamp_peer(identity, store, ts=time.time())
        # Corrupt the signature
        store.props["SCID_SIG"] = "00" * 64

        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", side_effect=store.get), \
             patch("enterprise.registry.set_agent_prop", side_effect=store.set):
            result = gate.check_peer(
                FAKE_HWND, identity.public_key_bytes, now=NOW, max_sig_age_seconds=60.0
            )

        assert result.ok is False
        assert "verification failed" in result.reason

    def test_phase_is_grace_before_sunset(self, monkeypatch):
        monkeypatch.setenv("SC_SUNSET_V1", "2099-01-01")
        assert VersionGate.current_phase(now=NOW) == "grace"


# ── Phase 2: after sunset ─────────────────────────────────────────────────────

class TestAfterSunset:
    def test_unsigned_peer_rejected_after_sunset(self, monkeypatch):
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)
        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", return_value=""):
            result = gate.check_peer(FAKE_HWND, None, now=NOW)

        assert result.ok is False
        assert result.phase == "sunset"
        assert "rejected" in result.reason.lower()

    def test_signed_valid_peer_accepted_after_sunset(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)

        identity = _make_identity(tmp_path, "gate-sunset-valid")
        store = FakePropStore()
        _stamp_peer(identity, store, ts=time.time())

        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", side_effect=store.get), \
             patch("enterprise.registry.set_agent_prop", side_effect=store.set):
            result = gate.check_peer(
                FAKE_HWND, identity.public_key_bytes, now=NOW, max_sig_age_seconds=60.0
            )

        assert result.ok is True
        assert result.phase == "sunset"

    def test_expired_sig_rejected_after_sunset(self, monkeypatch, tmp_path):
        """SCID_SIG older than max_sig_age_seconds is rejected even if otherwise valid."""
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)

        identity = _make_identity(tmp_path, "gate-expired-sig")
        store = FakePropStore()
        old_ts = time.time() - 120.0  # 2 minutes ago
        _stamp_peer(identity, store, ts=old_ts)

        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", side_effect=store.get), \
             patch("enterprise.registry.set_agent_prop", side_effect=store.set):
            result = gate.check_peer(
                FAKE_HWND, identity.public_key_bytes, now=NOW, max_sig_age_seconds=60.0
            )

        assert result.ok is False
        assert "expired" in result.reason.lower() or "verification failed" in result.reason.lower()

    def test_phase_is_sunset_after_date(self, monkeypatch):
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")
        assert VersionGate.current_phase(now=NOW) == "sunset"

    def test_no_pubkey_with_sig_present_rejected(self, monkeypatch):
        """SCID_SIG present but no pubkey_bytes supplied — cannot verify, reject."""
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)
        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", return_value="aabbccdd" * 16):
            result = gate.check_peer(FAKE_HWND, None, now=NOW)

        assert result.ok is False
        assert "public_key_bytes" in result.reason


# ── Emergency override ────────────────────────────────────────────────────────

class TestEmergencyOverride:
    def test_override_cannot_accept_unsigned_peer(self, monkeypatch):
        monkeypatch.setenv("SC_DISABLE_SIG_VERIFY", "1")
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")  # past sunset
        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", return_value=""):
            result = gate.check_peer(FAKE_HWND, None, now=NOW)

        assert result.ok is False
        assert result.phase == "sunset"

    def test_override_does_not_change_phase(self, monkeypatch):
        monkeypatch.setenv("SC_DISABLE_SIG_VERIFY", "1")
        monkeypatch.setenv("SC_SUNSET_V1", "2025-01-01")
        assert VersionGate.current_phase(now=NOW) == "sunset"


# ── Bad SC_SUNSET_V1 format ───────────────────────────────────────────────────

class TestBadSunsetFormat:
    def test_invalid_date_still_rejects_unsigned_peer(self, monkeypatch):
        monkeypatch.setenv("SC_SUNSET_V1", "not-a-date")
        monkeypatch.delenv("SC_DISABLE_SIG_VERIFY", raising=False)
        gate = VersionGate()

        with patch("enterprise.registry.get_agent_prop", return_value=""):
            result = gate.check_peer(FAKE_HWND, None, now=NOW)

        assert result.ok is False
        assert result.phase == "enforced"
