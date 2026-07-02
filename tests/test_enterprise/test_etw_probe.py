"""Tests for experiments/win32_probe/etw_probe.py — ETW terminal monitoring."""
from __future__ import annotations

import ctypes
import sys
from unittest.mock import patch

import pytest

from experiments.win32_probe.etw_probe import (
    CONSOLE_HOST_PROVIDER_GUID,
    CONSOLE_HOST_PROVIDER_GUID_ALT,
    EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE,
    GUID,
    EtwConsoleSession,
    _is_elevated,
)


class TestEtwProbeConstants:
    def test_provider_guid_is_valid_guid_format(self):
        import uuid
        guid = uuid.UUID(CONSOLE_HOST_PROVIDER_GUID)
        assert str(guid) == CONSOLE_HOST_PROVIDER_GUID.lower().strip("{}")

    def test_alt_provider_guid_is_valid_guid_format(self):
        import uuid
        guid = uuid.UUID(CONSOLE_HOST_PROVIDER_GUID_ALT)
        assert str(guid) == CONSOLE_HOST_PROVIDER_GUID_ALT.lower().strip("{}")

    def test_event_trace_real_time_mode_is_nonzero(self):
        assert EVENT_TRACE_REAL_TIME_MODE != 0

    def test_session_name_is_set(self):
        assert EtwConsoleSession.SESSION_NAME == "SelfConnect-ETW-Console"
        assert len(EtwConsoleSession.SESSION_NAME) > 0


class TestGuidStructure:
    def test_guid_from_string_parses_correctly(self):
        import uuid
        guid_str = CONSOLE_HOST_PROVIDER_GUID
        g = GUID.from_string(guid_str)
        expected = uuid.UUID(guid_str)
        assert g.Data1 == expected.time_low
        assert g.Data2 == expected.time_mid
        assert g.Data3 == expected.time_hi_version

    @pytest.mark.skipif(sys.platform != "win32", reason="GUID struct size is Windows-specific (c_ulong is 4 bytes on Win32)")
    def test_guid_struct_size(self):
        assert ctypes.sizeof(GUID) == 16


class TestEventTracePropertiesStructure:
    def test_properties_has_expected_size(self):
        size = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        assert size > 64
        assert size < 1024

    def test_properties_wnode_buffer_size_accessible(self):
        buf_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 512
        buf = (ctypes.c_byte * buf_size)()
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents
        props.Wnode.BufferSize = buf_size
        assert props.Wnode.BufferSize == buf_size


class TestEtwConsoleSession:
    def test_initial_state_is_not_open(self):
        session = EtwConsoleSession()
        assert not session.is_open

    def test_open_requires_elevation(self):
        session = EtwConsoleSession()
        with patch("experiments.win32_probe.etw_probe._is_elevated", return_value=False):
            with pytest.raises(PermissionError, match="elevation"):
                session.open()

    def test_close_when_not_open_is_safe(self):
        session = EtwConsoleSession()
        session.close()
        assert not session.is_open

    def test_close_twice_is_safe(self):
        session = EtwConsoleSession()
        session.close()
        session.close()

    def test_subscribe_without_open_does_not_crash(self):
        session = EtwConsoleSession()
        session.subscribe(lambda e: None)
        session.close()

    def test_custom_provider_guid(self):
        session = EtwConsoleSession(provider_guid=CONSOLE_HOST_PROVIDER_GUID_ALT)
        assert session._provider_guid == CONSOLE_HOST_PROVIDER_GUID_ALT

    def test_open_calls_start_trace_when_elevated(self):
        session = EtwConsoleSession()

        def _fake_start_trace(handle_ptr, name, props_ptr):
            # Simulate Win32 StartTraceW writing a non-zero handle into the output
            # parameter.  handle_ptr is ctypes.byref(ctypes.c_uint64); we reach into
            # its _obj attribute to set the value.
            handle_ptr._obj.value = 12345
            return 0  # ERROR_SUCCESS

        with (
            patch("experiments.win32_probe.etw_probe._is_elevated", return_value=True),
            patch("experiments.win32_probe.etw_probe._advapi32") as mock_adv,
        ):
            mock_adv.StartTraceW.side_effect = _fake_start_trace
            mock_adv.EnableTrace.return_value = 0
            session.open()
            assert mock_adv.StartTraceW.called
            assert session._session_handle == 12345

    def test_close_calls_stop_trace_when_open(self):
        session = EtwConsoleSession()
        session._session_handle = 999
        with patch("experiments.win32_probe.etw_probe._advapi32") as mock_adv:
            mock_adv.StopTraceW.return_value = 0
            session.close()
            assert mock_adv.StopTraceW.called
            assert session._session_handle == 0


class TestIsElevated:
    def test_returns_bool(self):
        result = _is_elevated()
        assert isinstance(result, bool)

    def test_mock_elevated_true(self):
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
            assert _is_elevated() is True

    def test_mock_elevated_false(self):
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
            assert _is_elevated() is False
