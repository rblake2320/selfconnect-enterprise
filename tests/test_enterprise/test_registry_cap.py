"""Tests for discover_mesh() cap enforcement, PID stamp volume guard,
and stamp_birth_tag() SCID_SIG wiring.

These are separate from test_registry.py to keep them focused on the new
Tier 1 security additions: cap enforcement and per-PID stamp volume guard.
All Win32 calls are mocked. No live desktop required.
"""
from __future__ import annotations

import logging
import time
from unittest.mock import MagicMock, patch

import pytest

from enterprise.birth_tag_v2 import PROP_SIG, PROP_STS
from enterprise.discovery_config import MAX_CANDIDATES_PER_CYCLE, MAX_STAMPS_PER_PID
from enterprise.registry import BirthTag, discover_mesh, stamp_birth_tag


# -- Helpers -------------------------------------------------------------------

def _make_tag(hwnd: int, pid: int = 12345, agent_id: str = "") -> BirthTag:
    agent_id = agent_id or f"agent-{hwnd:#010x}"
    return BirthTag(
        hwnd=hwnd,
        agent_id=agent_id,
        agent_type="claude_code",
        born=time.time(),
        parent=0,
        model="test-model",
        heartbeat=time.time(),
        pid=pid,
        os_create_time=132987654321,
        session="",
    )


def _fake_enum_windows_factory(tags_by_hwnd: dict[int, BirthTag]):
    """Return a side_effect callable for user32.EnumWindows.

    Simulates EnumWindows calling the callback once per HWND in order.
    Stops if the callback returns False (matching real EnumWindows behavior).
    """
    def fake_enum_windows(callback, lparam):
        for hwnd in tags_by_hwnd:
            result = callback(hwnd, lparam)
            if not result:
                break
        return 1
    return fake_enum_windows


def _build_tags(count: int, pid: int = 99999) -> dict[int, BirthTag]:
    """Build `count` unique tags with sequential fake HWNDs.

    Use small positive HWNDs (1001+) to avoid ctypes.c_int sign-extension.
    WINFUNCTYPE typed args as c_int, so HWNDs must fit in signed 32-bit range.
    """
    return {
        1001 + i: _make_tag(1001 + i, pid=pid + i)
        for i in range(count)
    }


# -- Discovery candidate cap ---------------------------------------------------

class TestDiscoveryCap:
    def test_cap_stops_at_max(self):
        """discover_mesh returns at most MAX_CANDIDATES_PER_CYCLE candidates."""
        count = MAX_CANDIDATES_PER_CYCLE + 10
        tags = _build_tags(count)

        def fake_read(hwnd):
            return tags.get(hwnd)

        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            result = discover_mesh()

        assert len(result) == MAX_CANDIDATES_PER_CYCLE

    def test_cap_emits_log_warning(self, caplog):
        """When cap is hit, a discovery_candidate_capped warning is logged."""
        count = MAX_CANDIDATES_PER_CYCLE + 5
        tags = _build_tags(count)

        def fake_read(hwnd):
            return tags.get(hwnd)

        with caplog.at_level(logging.WARNING, logger="enterprise.registry"), \
             patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            discover_mesh()

        assert any("discovery_candidate_capped" in r.message for r in caplog.records), \
            f"Expected 'discovery_candidate_capped'. Got: {[r.message for r in caplog.records]}"

    def test_below_cap_returns_all(self):
        """When total windows < cap, all candidates are returned."""
        count = MAX_CANDIDATES_PER_CYCLE - 5
        tags = _build_tags(count)

        def fake_read(hwnd):
            return tags.get(hwnd)

        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            result = discover_mesh()

        assert len(result) == count

    def test_exactly_at_cap_no_warning(self, caplog):
        """Exactly MAX_CANDIDATES_PER_CYCLE windows: no cap warning emitted."""
        count = MAX_CANDIDATES_PER_CYCLE
        tags = _build_tags(count)

        def fake_read(hwnd):
            return tags.get(hwnd)

        with caplog.at_level(logging.WARNING, logger="enterprise.registry"), \
             patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            result = discover_mesh()

        assert len(result) == MAX_CANDIDATES_PER_CYCLE
        assert not any("discovery_candidate_capped" in r.message for r in caplog.records)


# -- Per-PID stamp volume guard ------------------------------------------------

class TestPidStampVolumeGuard:
    def test_excess_stamps_from_same_pid_excluded(self):
        """More than MAX_STAMPS_PER_PID tags from one PID: extras excluded."""
        shared_pid = 55555
        count = MAX_STAMPS_PER_PID + 3
        tags = {
            2001 + i: _make_tag(2001 + i, pid=shared_pid)
            for i in range(count)
        }

        def fake_read(hwnd):
            return tags.get(hwnd)

        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            result = discover_mesh()

        assert len(result) == MAX_STAMPS_PER_PID

    def test_pid_volume_emits_log_warning(self, caplog):
        """Excess stamps from same PID emit suspicious_pid_stamp_volume warning."""
        shared_pid = 66666
        count = MAX_STAMPS_PER_PID + 2
        tags = {
            3001 + i: _make_tag(3001 + i, pid=shared_pid)
            for i in range(count)
        }

        def fake_read(hwnd):
            return tags.get(hwnd)

        with caplog.at_level(logging.WARNING, logger="enterprise.registry"), \
             patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            discover_mesh()

        assert any("suspicious_pid_stamp_volume" in r.message for r in caplog.records), \
            f"Expected 'suspicious_pid_stamp_volume'. Got: {[r.message for r in caplog.records]}"

    def test_different_pids_each_allowed_up_to_limit(self):
        """Multiple PIDs each at the limit: all included."""
        count_per_pid = MAX_STAMPS_PER_PID
        pid_a, pid_b = 11111, 22222
        tags: dict[int, BirthTag] = {}
        for i in range(count_per_pid):
            tags[4001 + i] = _make_tag(4001 + i, pid=pid_a)
        for i in range(count_per_pid):
            tags[5001 + i] = _make_tag(5001 + i, pid=pid_b)

        def fake_read(hwnd):
            return tags.get(hwnd)

        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            result = discover_mesh()

        assert len(result) == count_per_pid * 2

    def test_exactly_at_pid_limit_no_warning(self, caplog):
        """Exactly MAX_STAMPS_PER_PID tags from one PID: no warning."""
        shared_pid = 77777
        count = MAX_STAMPS_PER_PID
        tags = {
            6001 + i: _make_tag(6001 + i, pid=shared_pid)
            for i in range(count)
        }

        def fake_read(hwnd):
            return tags.get(hwnd)

        with caplog.at_level(logging.WARNING, logger="enterprise.registry"), \
             patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.read_birth_tag", side_effect=fake_read):
            mock_u32.EnumWindows.side_effect = _fake_enum_windows_factory(tags)
            result = discover_mesh()

        assert len(result) == MAX_STAMPS_PER_PID
        assert not any("suspicious_pid_stamp_volume" in r.message for r in caplog.records)


# -- stamp_birth_tag SCID_SIG wiring -------------------------------------------

class TestStampBirthTagSignedWiring:
    """Confirm stamp_birth_tag() calls stamp_signed_birth_tag() when identity provided."""

    def _make_identity_mock(self):
        identity = MagicMock()
        identity.sign.return_value = b"\x00" * 64
        return identity

    def test_scid_sig_stamped_when_identity_provided(self):
        """When identity is passed, SCID_SIG and SCID_STS appear in SetPropW calls."""
        stamped: dict[str, str] = {}

        def fake_set(hwnd, key, value):
            stamped[key] = value
            return True

        identity = self._make_identity_mock()

        with patch("enterprise.registry.user32"), \
             patch("enterprise.registry.kernel32"), \
             patch("enterprise.registry.get_process_creation_time", return_value=132987654321), \
             patch("enterprise.registry.set_agent_prop", side_effect=fake_set):
            stamp_birth_tag(0xABC01234, "agent-x", "claude_code", "model-y", identity=identity)

        assert PROP_SIG in stamped, "SCID_SIG was not stamped when identity provided"
        assert PROP_STS in stamped, "SCID_STS was not stamped when identity provided"
        assert identity.sign.called, "identity.sign() was not called"

    def test_scid_sig_not_stamped_without_identity(self):
        """Without identity, stamp_birth_tag behaves as v1: no SCID_SIG."""
        stamped: dict[str, str] = {}

        def fake_set(hwnd, key, value):
            stamped[key] = value
            return True

        with patch("enterprise.registry.user32"), \
             patch("enterprise.registry.kernel32"), \
             patch("enterprise.registry.get_process_creation_time", return_value=132987654321), \
             patch("enterprise.registry.set_agent_prop", side_effect=fake_set):
            stamp_birth_tag(0xABC01234, "agent-x", "claude_code", "model-y")

        assert PROP_SIG not in stamped, "SCID_SIG should NOT be stamped without identity"
        assert PROP_STS not in stamped, "SCID_STS should NOT be stamped without identity"

    def test_signing_failure_does_not_prevent_unsigned_tag(self):
        """If signing fails, stamp_birth_tag still stamps unsigned tag (v1 fallback)."""
        stamped: dict[str, str] = {}

        def fake_set(hwnd, key, value):
            stamped[key] = value
            return True

        identity = self._make_identity_mock()
        identity.sign.side_effect = RuntimeError("simulated TPM failure")

        with patch("enterprise.registry.user32"), \
             patch("enterprise.registry.kernel32"), \
             patch("enterprise.registry.get_process_creation_time", return_value=132987654321), \
             patch("enterprise.registry.set_agent_prop", side_effect=fake_set):
            tag = stamp_birth_tag(0xABC01234, "agent-x", "claude_code", "model-y", identity=identity)

        assert "SCID" in stamped
        assert "SCPID" in stamped
        assert PROP_SIG not in stamped
        assert tag.agent_id == "agent-x"
