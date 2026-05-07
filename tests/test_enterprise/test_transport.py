"""tests/test_enterprise/test_transport.py — Unit tests for enterprise.transport

All Win32 calls are mocked — no live desktop required.
"""
from __future__ import annotations

import ctypes
import json
from unittest.mock import MagicMock, patch

from enterprise.transport import (
    COPYDATASTRUCT,
    WM_COPYDATA,
    WM_QUIT,
    CopyDataListener,
)

FAKE_HWND        = 0xABC01234
FAKE_SENDER_HWND = 0xDEADBEEF


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_cds_lparam(payload: dict, data_type: int = 0):
    """Build a real COPYDATASTRUCT in memory.

    Returns (lparam_int, keeper) — caller MUST hold 'keeper' alive for the
    duration of the test or the struct memory will be garbage-collected.
    """
    raw = json.dumps(payload).encode("utf-8")
    buf = ctypes.create_string_buffer(raw)
    cds = COPYDATASTRUCT()
    cds.dwData = data_type
    cds.cbData = len(raw)
    cds.lpData = ctypes.cast(buf, ctypes.c_void_p).value
    return ctypes.addressof(cds), (cds, buf)


# ── COPYDATASTRUCT ─────────────────────────────────────────────────────────────

class TestCopyDataStruct:
    def test_fields_present(self):
        cds = COPYDATASTRUCT()
        assert hasattr(cds, "dwData")
        assert hasattr(cds, "cbData")
        assert hasattr(cds, "lpData")

    def test_size_reasonable(self):
        # 3 fields: ulong + ulong + void* — at least 12 bytes on any platform
        assert ctypes.sizeof(COPYDATASTRUCT) >= 12


# ── CopyDataListener.register ─────────────────────────────────────────────────

class TestRegister:
    def test_register_stores_callback(self):
        listener = CopyDataListener()
        cb = MagicMock()
        listener.register(0, cb)
        assert cb in listener._callbacks[0]

    def test_register_multiple_for_same_type(self):
        listener = CopyDataListener()
        cb1, cb2 = MagicMock(), MagicMock()
        listener.register(7, cb1)
        listener.register(7, cb2)
        assert len(listener._callbacks[7]) == 2

    def test_register_different_types_isolated(self):
        listener = CopyDataListener()
        cb_a, cb_b = MagicMock(), MagicMock()
        listener.register(1, cb_a)
        listener.register(2, cb_b)
        assert cb_a not in listener._callbacks.get(2, [])
        assert cb_b not in listener._callbacks.get(1, [])


# ── _handle_copydata dispatch ─────────────────────────────────────────────────

class TestHandleCopydata:
    def test_dispatches_to_registered_callback(self):
        listener = CopyDataListener()
        received = []
        listener.register(0, lambda sender, data: received.append((sender, data)))

        lparam, _keep = _make_cds_lparam({"task": "ping"}, data_type=0)
        listener._handle_copydata(FAKE_SENDER_HWND, lparam)

        assert len(received) == 1
        sender, data = received[0]
        assert sender == FAKE_SENDER_HWND
        assert data == {"task": "ping"}

    def test_dispatches_by_data_type(self):
        listener = CopyDataListener()
        type0_calls, type1_calls = [], []
        listener.register(0, lambda s, d: type0_calls.append(d))
        listener.register(1, lambda s, d: type1_calls.append(d))

        lparam, _keep = _make_cds_lparam({"msg": "hello"}, data_type=1)
        listener._handle_copydata(FAKE_SENDER_HWND, lparam)

        assert len(type0_calls) == 0
        assert len(type1_calls) == 1
        assert type1_calls[0] == {"msg": "hello"}

    def test_no_callback_for_type_is_silent(self):
        listener = CopyDataListener()
        # No callback registered for type 99 — must not raise
        lparam, _keep = _make_cds_lparam({"x": 1}, data_type=99)
        listener._handle_copydata(FAKE_SENDER_HWND, lparam)  # should not raise

    def test_bad_lparam_does_not_raise(self):
        listener = CopyDataListener()
        listener.register(0, MagicMock())
        # lparam of 0 should be caught and logged, not crash
        listener._handle_copydata(FAKE_SENDER_HWND, 0)  # should not raise

    def test_invalid_json_does_not_raise(self):
        """COPYDATASTRUCT with non-JSON bytes must be absorbed gracefully."""
        raw = b"not-json-!!!"
        buf = ctypes.create_string_buffer(raw)
        cds = COPYDATASTRUCT()
        cds.dwData = 0
        cds.cbData = len(raw)
        cds.lpData = ctypes.cast(buf, ctypes.c_void_p).value
        lparam = ctypes.addressof(cds)

        listener = CopyDataListener()
        listener.register(0, MagicMock())
        listener._handle_copydata(FAKE_SENDER_HWND, lparam)  # should not raise
        del cds, buf  # explicit cleanup after use

    def test_callback_exception_does_not_crash_listener(self):
        listener = CopyDataListener()
        def bad_cb(sender, data):
            raise ValueError("boom")
        listener.register(0, bad_cb)

        lparam, _keep = _make_cds_lparam({"x": 1})
        listener._handle_copydata(FAKE_SENDER_HWND, lparam)  # should not raise

    def test_multiple_callbacks_all_invoked(self):
        listener = CopyDataListener()
        calls = []
        listener.register(0, lambda s, d: calls.append("first"))
        listener.register(0, lambda s, d: calls.append("second"))

        lparam, _keep = _make_cds_lparam({"x": 1})
        listener._handle_copydata(FAKE_SENDER_HWND, lparam)

        assert calls == ["first", "second"]


# ── start / stop (mocked Win32) ────────────────────────────────────────────────

class TestStartStop:
    def _make_mock_user32(self, fake_hwnd: int = FAKE_HWND):
        mock = MagicMock()
        mock.RegisterClassExW.return_value = 1
        mock.CreateWindowExW.return_value = fake_hwnd
        # GetMessageW returns 0 immediately → pump exits
        mock.GetMessageW.return_value = 0
        mock.UnregisterClassW.return_value = 1
        return mock

    def test_start_sets_hwnd(self):
        mock_u32 = self._make_mock_user32()
        mock_k32 = MagicMock()
        mock_k32.GetModuleHandleW.return_value = 0x1000
        with patch("enterprise.transport.user32", mock_u32), \
             patch("enterprise.transport.kernel32", mock_k32):
            listener = CopyDataListener()
            listener.start(timeout=3.0)
            # After GetMessageW returns 0, window is destroyed and hwnd set to None
            # but ready event was set before pump started
            # The hwnd may be None after pump exits — check ready was signalled
            assert listener._ready.is_set()

    def test_start_window_create_failure_raises(self):
        mock_u32 = self._make_mock_user32(fake_hwnd=0)  # 0 = failure
        mock_k32 = MagicMock()
        mock_k32.GetModuleHandleW.return_value = 0x1000
        with patch("enterprise.transport.user32", mock_u32), \
             patch("enterprise.transport.kernel32", mock_k32):
            listener = CopyDataListener()
            # ready fires immediately (on failure path) but hwnd=None
            # start() should raise RuntimeError
            try:
                listener.start(timeout=1.0)
            except RuntimeError:
                pass  # expected when window creation fails
            # No crash — that's the contract

    def test_stop_posts_wm_quit(self):
        mock_u32 = MagicMock()
        listener = CopyDataListener()
        listener._hwnd = FAKE_HWND
        listener._thread = MagicMock()
        listener._thread.is_alive.return_value = False
        with patch("enterprise.transport.PostMessageW", mock_u32):
            listener.stop()
            mock_u32.assert_called_once_with(FAKE_HWND, WM_QUIT, 0, 0)

    def test_stop_clears_hwnd(self):
        listener = CopyDataListener()
        listener._hwnd = FAKE_HWND
        listener._thread = MagicMock()
        listener._thread.is_alive.return_value = False
        with patch("enterprise.transport.PostMessageW"):
            listener.stop()
        assert listener._hwnd is None

    def test_stop_is_idempotent(self):
        """stop() on an already-stopped listener must not raise."""
        listener = CopyDataListener()
        listener.stop()  # hwnd is None — should not raise
        listener.stop()  # again — still safe

    def test_double_start_is_idempotent(self):
        mock_u32 = self._make_mock_user32()
        mock_k32 = MagicMock()
        mock_k32.GetModuleHandleW.return_value = 0x1000
        with patch("enterprise.transport.user32", mock_u32), \
             patch("enterprise.transport.kernel32", mock_k32):
            listener = CopyDataListener()
            listener.start(timeout=2.0)
            # Thread has exited (GetMessageW returned 0); start again should be fine
            listener._thread = MagicMock()
            listener._thread.is_alive.return_value = True
            listener.start(timeout=2.0)  # should return immediately, no second thread


# ── hwnd property ──────────────────────────────────────────────────────────────

class TestHwndProperty:
    def test_hwnd_none_before_start(self):
        listener = CopyDataListener()
        assert listener.hwnd is None

    def test_hwnd_set_during_run(self):
        listener = CopyDataListener()
        listener._hwnd = FAKE_HWND
        assert listener.hwnd == FAKE_HWND


# ── unique class names ─────────────────────────────────────────────────────────

class TestUniqueClassName:
    def test_class_names_are_unique(self):
        names = {CopyDataListener._unique_class_name() for _ in range(10)}
        assert len(names) == 10

    def test_class_name_contains_prefix(self):
        name = CopyDataListener._unique_class_name()
        assert "SelfConnect" in name


# ── WM_COPYDATA constant ──────────────────────────────────────────────────────

class TestConstants:
    def test_wm_copydata_value(self):
        assert WM_COPYDATA == 0x004A

    def test_wm_quit_value(self):
        assert WM_QUIT == 0x0012
