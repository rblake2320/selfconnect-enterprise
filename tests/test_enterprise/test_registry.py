"""tests/test_enterprise/test_registry.py — Unit tests for enterprise.registry

All Win32 calls are mocked — no live desktop required.
"""
from __future__ import annotations

import time
from unittest.mock import patch

from enterprise.registry import (
    PROP_BORN,
    PROP_CTIME,
    PROP_HB,
    PROP_ID,
    PROP_MODEL,
    PROP_PARENT,
    PROP_PID,
    PROP_SESSION,
    PROP_TYPE,
    BirthTag,
    HeartbeatDaemon,
    discover_mesh,
    find_agent,
    get_agent_prop,
    read_birth_tag,
    send_data,
    set_agent_prop,
    signal_ready,
    stamp_birth_tag,
    update_heartbeat,
    verify_tag,
    wait_for,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

FAKE_HWND  = 0xABC01234
FAKE_HWND2 = 0xDEF05678

def _make_tag(
    hwnd: int = FAKE_HWND,
    agent_id: str = "agent-test",
    agent_type: str = "claude_code",
    model: str = "claude-sonnet-4-6",
    born: float = 1000.0,
    parent: int = 0,
    heartbeat: float = 1000.0,
    pid: int = 1234,
    os_create_time: float = 999.0,
    session: str = "s16",
) -> BirthTag:
    return BirthTag(
        hwnd=hwnd, agent_id=agent_id, agent_type=agent_type,
        model=model, born=born, parent=parent, heartbeat=heartbeat,
        pid=pid, os_create_time=os_create_time, session=session,
    )


# ── BirthTag unit tests ────────────────────────────────────────────────────────

class TestBirthTag:
    def test_to_dict_shape(self):
        tag = _make_tag(born=time.time() - 5, heartbeat=time.time() - 2)
        d = tag.to_dict()
        assert d["hwnd"] == FAKE_HWND
        assert d["agent_id"] == "agent-test"
        assert "age_seconds" in d
        assert "seconds_since_heartbeat" in d
        assert "heartbeat_alive" in d
        assert d["pid"] == 1234
        assert d["os_create_time"] == 999.0

    def test_age_seconds(self):
        born = time.time() - 10
        tag = _make_tag(born=born)
        assert 9.0 <= tag.age_seconds() <= 12.0

    def test_is_alive_recent_heartbeat(self):
        tag = _make_tag(heartbeat=time.time())
        assert tag.is_alive()

    def test_is_alive_stale_heartbeat(self):
        tag = _make_tag(heartbeat=time.time() - 200)
        assert not tag.is_alive(stale_threshold=120.0)

    def test_is_alive_custom_threshold(self):
        tag = _make_tag(heartbeat=time.time() - 10)
        assert tag.is_alive(stale_threshold=30.0)
        assert not tag.is_alive(stale_threshold=5.0)

    def test_seconds_since_heartbeat(self):
        tag = _make_tag(heartbeat=time.time() - 7)
        assert 6.0 <= tag.seconds_since_heartbeat() <= 9.0


# ── set/get agent prop ─────────────────────────────────────────────────────────

class TestAgentProps:
    def test_set_prop_calls_setpropw(self):
        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry._str_to_atom", return_value=42):
            mock_u32.SetPropW.return_value = 1
            result = set_agent_prop(FAKE_HWND, PROP_ID, "agent-x")
            mock_u32.SetPropW.assert_called_once_with(FAKE_HWND, PROP_ID, 42)
            assert result is True

    def test_get_prop_returns_empty_when_absent(self):
        with patch("enterprise.registry.user32") as mock_u32:
            mock_u32.GetPropW.return_value = 0
            result = get_agent_prop(FAKE_HWND, PROP_ID)
            assert result == ""

    def test_get_prop_resolves_atom(self):
        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry._atom_to_str", return_value="agent-b"):
            mock_u32.GetPropW.return_value = 99  # non-zero atom
            result = get_agent_prop(FAKE_HWND, PROP_ID)
            assert result == "agent-b"


# ── stamp_birth_tag ────────────────────────────────────────────────────────────

class TestStampBirthTag:
    def test_returns_birth_tag(self):
        with patch("enterprise.registry.set_agent_prop", return_value=True), \
             patch("enterprise.registry.get_process_creation_time", return_value=12345.0):
            tag = stamp_birth_tag(
                hwnd=FAKE_HWND,
                agent_id="agent-b-local",
                agent_type="local_model",
                model="qwen3.6:27b",
                parent_hwnd=0xAABB,
                session="s16",
            )
        assert isinstance(tag, BirthTag)
        assert tag.hwnd == FAKE_HWND
        assert tag.agent_id == "agent-b-local"
        assert tag.agent_type == "local_model"
        assert tag.model == "qwen3.6:27b"
        assert tag.parent == 0xAABB
        assert tag.session == "s16"

    def test_stamps_all_required_props(self):
        calls_made = []
        def fake_set(hwnd, key, val):
            calls_made.append(key)
            return True
        with patch("enterprise.registry.set_agent_prop", side_effect=fake_set), \
             patch("enterprise.registry.get_process_creation_time", return_value=12345.0):
            stamp_birth_tag(FAKE_HWND, "x", "y", "z")
        for required in [PROP_ID, PROP_TYPE, PROP_BORN, PROP_PARENT, PROP_MODEL, PROP_HB, PROP_PID, PROP_CTIME]:
            assert required in calls_made, f"{required} not stamped"

    def test_stamp_includes_pid_and_ctime(self):
        with patch("enterprise.registry.set_agent_prop", return_value=True), \
             patch("enterprise.registry.get_process_creation_time", return_value=99999.5):
            tag = stamp_birth_tag(FAKE_HWND, "ag", "claude_code", "model-x")
        assert tag.pid > 0
        assert tag.os_create_time == 99999.5

    def test_session_prop_only_when_provided(self):
        calls_made = []
        def fake_set(hwnd, key, val):
            calls_made.append(key)
            return True
        with patch("enterprise.registry.set_agent_prop", side_effect=fake_set), \
             patch("enterprise.registry.get_process_creation_time", return_value=0.0):
            stamp_birth_tag(FAKE_HWND, "x", "y", "z", session="")
        assert PROP_SESSION not in calls_made

        calls_made.clear()
        with patch("enterprise.registry.set_agent_prop", side_effect=fake_set), \
             patch("enterprise.registry.get_process_creation_time", return_value=0.0):
            stamp_birth_tag(FAKE_HWND, "x", "y", "z", session="s16")
        assert PROP_SESSION in calls_made


# ── update_heartbeat ───────────────────────────────────────────────────────────

class TestUpdateHeartbeat:
    def test_returns_false_if_not_stamped(self):
        with patch("enterprise.registry.get_agent_prop", return_value=""):
            assert update_heartbeat(FAKE_HWND) is False

    def test_updates_hb_if_stamped(self):
        with patch("enterprise.registry.get_agent_prop", return_value="agent-x"), \
             patch("enterprise.registry.set_agent_prop", return_value=True) as mock_set:
            result = update_heartbeat(FAKE_HWND)
            assert result is True
            mock_set.assert_called_once()
            assert mock_set.call_args[0][1] == PROP_HB


# ── read_birth_tag ─────────────────────────────────────────────────────────────

class TestReadBirthTag:
    def test_returns_none_if_no_scid(self):
        with patch("enterprise.registry.get_agent_prop", return_value=""):
            assert read_birth_tag(FAKE_HWND) is None

    def test_returns_birth_tag_when_stamped(self):
        prop_values = {
            PROP_ID:      "agent-b",
            PROP_TYPE:    "local_model",
            PROP_BORN:    "1000.5",
            PROP_PARENT:  "12345",
            PROP_MODEL:   "qwen3.6:27b",
            PROP_HB:      "1001.0",
            PROP_SESSION: "s16",
            PROP_PID:     "9999",
            PROP_CTIME:   "888.5",
        }
        def fake_get(hwnd, key):
            return prop_values.get(key, "")
        with patch("enterprise.registry.get_agent_prop", side_effect=fake_get):
            tag = read_birth_tag(FAKE_HWND)
        assert tag is not None
        assert tag.agent_id == "agent-b"
        assert tag.agent_type == "local_model"
        assert tag.born == 1000.5
        assert tag.parent == 12345
        assert tag.model == "qwen3.6:27b"
        assert tag.heartbeat == 1001.0
        assert tag.pid == 9999
        assert tag.os_create_time == 888.5
        assert tag.session == "s16"


# ── verify_tag ────────────────────────────────────────────────────────────────

class TestVerifyTag:
    def test_fails_if_window_dead(self):
        tag = _make_tag(pid=1234, os_create_time=999.0)
        with patch("enterprise.registry.user32") as mock_u32:
            mock_u32.IsWindow.return_value = 0
            assert verify_tag(tag) is False

    def test_fails_if_no_pid(self):
        tag = _make_tag(pid=0)
        with patch("enterprise.registry.user32") as mock_u32:
            mock_u32.IsWindow.return_value = 1
            assert verify_tag(tag) is False

    def test_fails_if_pid_mismatch(self):
        tag = _make_tag(pid=1234)
        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.get_hwnd_pid", return_value=9999):
            mock_u32.IsWindow.return_value = 1
            assert verify_tag(tag) is False

    def test_fails_if_ctime_mismatch(self):
        tag = _make_tag(pid=1234, os_create_time=1000.0)
        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.get_hwnd_pid", return_value=1234), \
             patch("enterprise.registry.get_process_creation_time", return_value=5000.0):
            mock_u32.IsWindow.return_value = 1
            assert verify_tag(tag) is False

    def test_passes_when_all_match(self):
        tag = _make_tag(pid=1234, os_create_time=1000.0)
        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.get_hwnd_pid", return_value=1234), \
             patch("enterprise.registry.get_process_creation_time", return_value=1000.0):
            mock_u32.IsWindow.return_value = 1
            assert verify_tag(tag) is True

    def test_passes_without_ctime_if_zero(self):
        """Tags stamped without OS creation time (os_create_time=0) skip ctime check."""
        tag = _make_tag(pid=1234, os_create_time=0.0)
        with patch("enterprise.registry.user32") as mock_u32, \
             patch("enterprise.registry.get_hwnd_pid", return_value=1234):
            mock_u32.IsWindow.return_value = 1
            assert verify_tag(tag) is True


# ── discover_mesh ──────────────────────────────────────────────────────────────

class TestDiscoverMesh:
    def test_empty_when_no_stamped_windows(self):
        with patch("enterprise.registry.user32") as mock_u32:
            # EnumWindows calls the callback for 0 windows
            mock_u32.EnumWindows.return_value = 1
            with patch("enterprise.registry.read_birth_tag", return_value=None):
                result = discover_mesh()
            assert result == []

    def test_heartbeat_age_filters_stale(self):
        """Hung agents with stale heartbeat excluded when max_heartbeat_age set."""
        fresh = _make_tag(agent_id="fresh",  heartbeat=time.time() - 10)
        stale = _make_tag(agent_id="frozen", heartbeat=time.time() - 200, hwnd=FAKE_HWND2)
        with patch("enterprise.registry.user32"):
            with patch("enterprise.registry.discover_mesh", return_value=[fresh, stale]):
                result = [t for t in [fresh, stale] if t.seconds_since_heartbeat() <= 60]
        assert len(result) == 1
        assert result[0].agent_id == "fresh"

    def test_find_agent_returns_none_when_absent(self):
        with patch("enterprise.registry.discover_mesh", return_value=[]):
            assert find_agent("agent-x") is None

    def test_find_agent_returns_match(self):
        tag = _make_tag(agent_id="agent-b-local")
        with patch("enterprise.registry.discover_mesh", return_value=[tag, _make_tag(agent_id="agent-e")]):
            result = find_agent("agent-b-local")
            assert result is not None
            assert result.agent_id == "agent-b-local"


# ── send_data (WM_COPYDATA) ────────────────────────────────────────────────────

class TestSendData:
    def test_send_data_calls_sendmessagew(self):
        with patch("enterprise.registry.user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 1
            result = send_data(FAKE_HWND, {"task": "ping"})
            assert mock_u32.SendMessageW.called
            args = mock_u32.SendMessageW.call_args[0]
            assert args[0] == FAKE_HWND
            assert args[1] == 0x004A  # WM_COPYDATA
            assert result is True

    def test_send_data_returns_false_on_failure(self):
        with patch("enterprise.registry.user32") as mock_u32:
            mock_u32.SendMessageW.return_value = 0
            result = send_data(FAKE_HWND, {"task": "ping"})
            assert result is False


# ── Named Events ──────────────────────────────────────────────────────────────

class TestNamedEvents:
    def test_signal_ready_creates_and_sets(self):
        with patch("enterprise.registry.kernel32") as mock_k32:
            mock_k32.CreateEventW.return_value = 99
            mock_k32.SetEvent.return_value = 1
            result = signal_ready("AGENT-B-READY")
            mock_k32.CreateEventW.assert_called_once()
            mock_k32.SetEvent.assert_called_once_with(99)
            mock_k32.CloseHandle.assert_called_once_with(99)
            assert result is True

    def test_signal_ready_returns_false_on_create_failure(self):
        with patch("enterprise.registry.kernel32") as mock_k32:
            mock_k32.CreateEventW.return_value = 0
            assert signal_ready("AGENT-B-READY") is False

    def test_wait_for_returns_true_when_signaled(self):
        WAIT_OBJECT_0 = 0x00000000
        with patch("enterprise.registry.kernel32") as mock_k32:
            mock_k32.CreateEventW.return_value = 99
            mock_k32.WaitForSingleObject.return_value = WAIT_OBJECT_0
            assert wait_for("AGENT-B-READY", timeout_ms=100) is True

    def test_wait_for_returns_false_on_timeout(self):
        WAIT_TIMEOUT = 0x00000102
        with patch("enterprise.registry.kernel32") as mock_k32:
            mock_k32.CreateEventW.return_value = 99
            mock_k32.WaitForSingleObject.return_value = WAIT_TIMEOUT
            assert wait_for("AGENT-B-READY", timeout_ms=100) is False


# ── HeartbeatDaemon ────────────────────────────────────────────────────────────

class TestHeartbeatDaemon:
    def test_daemon_calls_update_heartbeat(self):
        calls = []
        with patch("enterprise.registry.update_heartbeat", side_effect=lambda h: calls.append(h)):
            hb = HeartbeatDaemon(FAKE_HWND, interval=0.05)
            hb.start()
            time.sleep(0.2)
            hb.stop()
        assert len(calls) >= 2
        assert all(c == FAKE_HWND for c in calls)
