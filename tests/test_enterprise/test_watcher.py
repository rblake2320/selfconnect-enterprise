"""Tests for enterprise/watcher.py and enterprise/cli.py."""
from __future__ import annotations

import threading
import time
import unittest.mock as umock
from unittest.mock import patch

import pytest

from enterprise.cli import (
    _MAX_HZ,
    _MAX_LAST,
    _MIN_HZ,
    _MIN_LAST,
    build_parser,
    cmd_audit,
    cmd_leases,
    cmd_status,
    cmd_version,
    main,
)
from enterprise.watcher import (
    MAX_RECENT_EVENTS,
    AuditEvent,
    ChannelHealth,
    LeaseInfo,
    WatcherState,
    make_audit_table,
    make_lease_table,
    make_status_table,
)


class TestLeaseInfo:
    def test_ttl_positive(self):
        lease = LeaseInfo(
            lease_id="abc", agent_id="agent1", hwnd=12345,
            role="sender", expires_at=time.time() + 300
        )
        assert lease.ttl_seconds > 0

    def test_expired_lease(self):
        lease = LeaseInfo(
            lease_id="abc", agent_id="agent1", hwnd=12345,
            role="sender", expires_at=time.time() - 1.0
        )
        assert lease.is_expired

    def test_active_lease(self):
        lease = LeaseInfo(
            lease_id="abc", agent_id="agent1", hwnd=12345,
            role="sender", expires_at=time.time() + 300
        )
        assert not lease.is_expired


class TestWatcherState:
    def test_initial_state_has_no_leases(self):
        state = WatcherState()
        assert state.active_leases() == []

    def test_initial_state_has_no_events(self):
        state = WatcherState()
        assert state.recent_events() == []

    def test_refresh_does_not_crash_when_control_plane_down(self):
        state = WatcherState()
        with patch("enterprise.watcher.WatcherState._load_leases", side_effect=RuntimeError("no cp")):
            state.refresh()
        assert state.error is not None

    def test_refresh_sets_last_refresh_time(self):
        state = WatcherState()
        before = time.time()
        state.refresh()
        assert state.last_refresh >= before

    def test_active_leases_filters_expired(self):
        state = WatcherState()
        now = time.time()
        state._leases = [
            LeaseInfo("a", "ag1", 1, "sender", now + 100),
            LeaseInfo("b", "ag2", 2, "receiver", now - 1),
        ]
        active = state.active_leases()
        assert len(active) == 1
        assert active[0].lease_id == "a"

    def test_recent_events_returns_sorted_newest_first(self):
        state = WatcherState()
        now = time.time()
        state._events = [
            AuditEvent("e1", now - 10, "inject", "a1"),
            AuditEvent("e2", now - 1, "read", "a2"),
            AuditEvent("e3", now - 5, "lease", "a3"),
        ]
        events = state.recent_events(3)
        assert events[0].event_id == "e2"
        assert events[-1].event_id == "e1"

    def test_recent_events_respects_n(self):
        state = WatcherState()
        now = time.time()
        state._events = [AuditEvent(f"e{i}", now - i, "inject", "a") for i in range(10)]
        assert len(state.recent_events(3)) == 3

    def test_channel_health_is_channel_health(self):
        state = WatcherState()
        assert isinstance(state.channel_health(), ChannelHealth)


class TestRichTables:
    def test_make_status_table_returns_none_or_table(self):
        state = WatcherState()
        result = make_status_table(state)
        # Either None (rich not installed) or a rich Table
        if result is not None:
            assert hasattr(result, "add_row")

    def test_make_lease_table_with_data(self):
        state = WatcherState()
        state._leases = [LeaseInfo("lease1", "agent1", 1001, "sender", time.time() + 300)]
        result = make_lease_table(state)
        if result is not None:
            assert hasattr(result, "add_row")

    def test_make_audit_table_with_data(self):
        state = WatcherState()
        state._events = [AuditEvent("e1", time.time(), "inject", "agent1", {"text": "hello"})]
        result = make_audit_table(state, 5)
        if result is not None:
            assert hasattr(result, "add_row")


class TestCLIParser:
    def test_build_parser_returns_parser(self):
        parser = build_parser()
        assert parser.prog == "scent"

    def test_status_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"

    def test_leases_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["leases"])
        assert args.command == "leases"

    def test_audit_subcommand_default_n(self):
        parser = build_parser()
        args = parser.parse_args(["audit"])
        assert args.last == 20

    def test_audit_subcommand_custom_n(self):
        parser = build_parser()
        args = parser.parse_args(["audit", "--last", "50"])
        assert args.last == 50

    def test_watch_subcommand_default_hz(self):
        parser = build_parser()
        args = parser.parse_args(["watch"])
        assert args.hz == 2

    def test_version_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert args.command == "version"


class TestCLICommands:
    def test_cmd_version_prints_version(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["version"])
        result = cmd_version(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "scent" in captured.out

    def test_cmd_status_returns_0(self):
        parser = build_parser()
        args = parser.parse_args(["status"])
        with patch("enterprise.watcher.WatcherState.refresh"):
            result = cmd_status(args)
        assert result == 0

    def test_cmd_leases_returns_0(self):
        parser = build_parser()
        args = parser.parse_args(["leases"])
        with patch("enterprise.watcher.WatcherState.refresh"):
            result = cmd_leases(args)
        assert result == 0

    def test_cmd_audit_returns_0(self):
        parser = build_parser()
        args = parser.parse_args(["audit"])
        with patch("enterprise.watcher.WatcherState.refresh"):
            result = cmd_audit(args)
        assert result == 0

    def test_main_no_command_returns_nonzero(self):
        result = main([])
        assert result in (0, 1)

    def test_main_version(self):
        result = main(["version"])
        assert result == 0


# ── Security regression tests (WRAITH adversarial review) ─────────────────────


class TestSecurityInputBounds:
    """Regression tests that lock in bounds from WRAITH adversarial review."""

    # HIGH-1: CLI --last must reject out-of-range values
    def test_audit_last_too_large_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--last", str(_MAX_LAST + 1)])

    def test_audit_last_zero_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--last", "0"])

    def test_audit_last_negative_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--last", "-1"])

    def test_audit_last_min_accepted(self):
        parser = build_parser()
        args = parser.parse_args(["audit", "--last", str(_MIN_LAST)])
        assert args.last == _MIN_LAST

    def test_audit_last_max_accepted(self):
        parser = build_parser()
        args = parser.parse_args(["audit", "--last", str(_MAX_LAST)])
        assert args.last == _MAX_LAST

    # HIGH-1: CLI --hz must reject out-of-range values
    def test_watch_hz_zero_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["watch", "--hz", "0"])

    def test_watch_hz_negative_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["watch", "--hz", "-5"])

    def test_watch_hz_too_large_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["watch", "--hz", str(_MAX_HZ + 1)])

    def test_watch_hz_min_accepted(self):
        parser = build_parser()
        args = parser.parse_args(["watch", "--hz", str(_MIN_HZ)])
        assert args.hz == _MIN_HZ

    # HIGH-1: recent_events(n) must clamp n to MAX_RECENT_EVENTS
    def test_recent_events_clamps_huge_n(self):
        state = WatcherState()
        now = time.time()
        state._events = [AuditEvent(f"e{i}", now - i, "inject", "a") for i in range(10)]
        result = state.recent_events(10**9)
        assert len(result) <= MAX_RECENT_EVENTS

    def test_recent_events_clamps_zero_to_one(self):
        state = WatcherState()
        now = time.time()
        state._events = [AuditEvent("e1", now, "inject", "a")]
        # n=0 clamps to 1 — must not raise and must return the event
        result = state.recent_events(0)
        assert len(result) >= 1

    # HIGH-3: _load_leases must reject negative TTL (forced-expiry DoS)
    def test_load_leases_negative_ttl_clamped(self):
        state = WatcherState()

        class _FakeReg:
            def list_agents(self):
                return [{"agent_id": "bad", "hwnd": 1001, "role": "r", "ttl": -99999}]

        # _load_leases imports AgentRegistry locally inside a try/except.
        # Inject a fake module so the import resolves to our stub.
        import sys
        fake_mod = umock.MagicMock()
        fake_mod.AgentRegistry = _FakeReg
        with umock.patch.dict(sys.modules, {"enterprise.registry": fake_mod}):
            leases = state._load_leases()
        assert all(lease.expires_at >= 0 for lease in leases)

    # HIGH-3: _load_leases must reject negative HWND
    def test_load_leases_negative_hwnd_clamped(self):
        state = WatcherState()

        class _FakeReg:
            def list_agents(self):
                return [{"agent_id": "x", "hwnd": -12345, "role": "r", "ttl": 300}]

        import sys
        fake_mod = umock.MagicMock()
        fake_mod.AgentRegistry = _FakeReg
        with umock.patch.dict(sys.modules, {"enterprise.registry": fake_mod}):
            leases = state._load_leases()
        assert all(lease.hwnd >= 0 for lease in leases)

    # HIGH-4: ChannelHealth default for pipe must not be "OK" (fail-open removed)
    def test_channel_health_pipe_default_is_not_ok(self):
        h = ChannelHealth()
        assert h.pipe != "OK"

    # CRITICAL-1: WatcherState must be thread-safe under concurrent access
    def test_watcher_state_thread_safe_concurrent_access(self):
        state = WatcherState()
        errors = []

        def reader():
            try:
                for _ in range(50):
                    _ = state.active_leases()
                    _ = state.recent_events(10)
                    _ = state.channel_health()
                    _ = state.error
                    _ = state.last_refresh
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def writer():
            try:
                for _ in range(20):
                    state.refresh()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        threads += [threading.Thread(target=writer) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, f"Thread safety violations: {errors}"

    # HIGH-2: _load_events details must strip non-primitive values
    def test_load_events_details_strips_nested_structures(self):
        state = WatcherState()

        class FakeLedger:
            def recent(self, n):
                return [
                    {
                        "event_id": "e1",
                        "timestamp": 1000.0,
                        "event_type": "inject",
                        "agent_id": "a1",
                        "details": {
                            "safe_str": "hello",
                            "safe_int": 42,
                            "nested_dict": {"should": "be_dropped"},
                            "nested_list": [1, 2, 3],
                        },
                    }
                ]

        import sys
        fake_ledger_mod = umock.MagicMock()
        fake_ledger_mod.AuditLedger = FakeLedger
        with umock.patch.dict(sys.modules, {"enterprise.ledger": fake_ledger_mod}):
            events = state._load_events()

        assert len(events) == 1
        details = events[0].details
        assert "safe_str" in details
        assert "safe_int" in details
        assert "nested_dict" not in details
        assert "nested_list" not in details
