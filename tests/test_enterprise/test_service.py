"""Tests for enterprise/service.py — Windows Service wrapper."""
from __future__ import annotations

import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

from enterprise.service import (
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    ControlPlaneThread,
    _WIN32_AVAILABLE,
    _setup_file_logging,
    _validate_env_path,
    main,
)


class TestServiceConstants:
    def test_service_name_not_empty(self):
        assert SERVICE_NAME == "SelfConnectEnterprise"

    def test_display_name_not_empty(self):
        assert len(SERVICE_DISPLAY_NAME) > 10

    def test_description_not_empty(self):
        assert len(SERVICE_DESCRIPTION) > 20

    def test_win32_available_is_bool(self):
        assert isinstance(_WIN32_AVAILABLE, bool)


class TestControlPlaneThread:
    def test_thread_is_daemon(self):
        stop = threading.Event()
        t = ControlPlaneThread(stop)
        assert t.daemon is True

    def test_thread_name(self):
        stop = threading.Event()
        t = ControlPlaneThread(stop)
        assert t.name == "scent-control-plane"

    def test_thread_stops_when_event_set(self):
        stop = threading.Event()
        t = ControlPlaneThread(stop)
        with patch("enterprise.control.ControlPlane") as mock_cp:
            mock_cp.return_value = MagicMock()
            t.start()
            import time
            time.sleep(0.05)
            stop.set()
            t.join(timeout=2.0)
            assert not t.is_alive()

    def test_thread_handles_import_error(self):
        stop = threading.Event()
        t = ControlPlaneThread(stop)
        with patch.dict("sys.modules", {"enterprise.control": None}):
            stop.set()
            t.run()

    def test_crashed_flag_set_on_exception(self):
        """A crashed ControlPlane must set the flag (no silent fail-open)."""
        stop = threading.Event()
        t = ControlPlaneThread(stop)

        def _bad_init():
            raise RuntimeError("simulated crash")

        with patch("enterprise.service.ControlPlaneThread.run", autospec=False) as _mock:
            # Bypass the real run; replicate the crash path directly.
            pass

        # Run with a control module that raises immediately.
        with patch.dict("sys.modules", {}):
            mock_control = MagicMock()
            mock_control.ControlPlane.side_effect = RuntimeError("simulated startup crash")
            with patch.dict("sys.modules", {"enterprise.control": mock_control}):
                t.run()

        assert t.crashed is True
        # The stop signal must also have been set so the service shuts down.
        assert stop.is_set()

    def test_crashed_flag_false_on_clean_stop(self):
        """Normal stop must NOT set the crashed flag."""
        stop = threading.Event()
        t = ControlPlaneThread(stop)
        stop.set()  # pre-signal a clean stop before the thread even calls wait
        mock_control = MagicMock()
        mock_control.ControlPlane.return_value = MagicMock()
        with patch.dict("sys.modules", {"enterprise.control": mock_control}):
            t.run()
        assert t.crashed is False


class TestPathValidation:
    """WRAITH: env-var path-traversal prevention tests."""

    def test_valid_relative_path_accepted(self, tmp_path):
        result = _validate_env_path("enterprise_config.toml", "SCENT_CONFIG")
        assert result.name == "enterprise_config.toml"

    def test_dotdot_traversal_rejected(self):
        with pytest.raises(ValueError, match="traversal"):
            _validate_env_path("../../etc/passwd", "SCENT_CONFIG")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows backslash path semantics only")
    def test_dotdot_in_middle_rejected(self):
        with pytest.raises(ValueError, match="traversal"):
            _validate_env_path(r"logs\..\..\..\Windows\System32\evil", "SCENT_LOG_DIR")

    def test_unc_path_rejected(self):
        with pytest.raises(ValueError, match="UNC"):
            _validate_env_path(r"\\attacker\share\config.toml", "SCENT_CONFIG")

    def test_unc_forward_slash_rejected(self):
        with pytest.raises(ValueError, match="UNC"):
            _validate_env_path("//attacker/share/config.toml", "SCENT_CONFIG")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows WINDIR path semantics only")
    def test_windows_system32_rejected(self, monkeypatch):
        import os
        windir = os.environ.get("WINDIR", r"C:\Windows")
        with pytest.raises(ValueError, match="protected system directory"):
            _validate_env_path(windir + r"\System32", "SCENT_LOG_DIR")

    def test_absolute_safe_path_accepted(self, tmp_path):
        # A fully resolved absolute path that is NOT under Windows/ should pass.
        result = _validate_env_path(str(tmp_path), "SCENT_LOG_DIR")
        assert result == tmp_path.resolve()


class TestFileLogging:
    def _close_root_handlers(self) -> None:
        """Remove and close any FileHandlers added to the root logger.

        _setup_file_logging always appends to the root logger.  On Windows,
        an open FileHandler holds a file lock that prevents pytest from cleaning
        up tmp_path directories.  Call this in a finally block after each test.
        """
        import logging as _logging
        root = _logging.root
        for handler in list(root.handlers):
            if isinstance(handler, _logging.FileHandler):
                handler.close()
                root.removeHandler(handler)

    def test_setup_creates_log_dir(self, tmp_path):
        log_file = tmp_path / "subdir" / "test.log"
        try:
            _setup_file_logging(log_file)
            assert log_file.parent.exists()
        finally:
            self._close_root_handlers()

    def test_setup_file_is_writable(self, tmp_path):
        import logging
        log_file = tmp_path / "test.log"
        try:
            _setup_file_logging(log_file)
            logging.getLogger("test.service").info("test message")
            assert log_file.exists()
        finally:
            self._close_root_handlers()


class TestMainEntryPoint:
    def test_main_no_win32_returns_1(self):
        with patch("enterprise.service._WIN32_AVAILABLE", False):
            result = main([])
            assert result == 1

    @pytest.mark.skipif(not _WIN32_AVAILABLE, reason="pywin32 not available")
    def test_main_delegates_to_win32serviceutil(self):
        with patch("enterprise.service.win32serviceutil.HandleCommandLine") as mock_handle:
            main(["test_service", "status"])
            mock_handle.assert_called_once()


class TestServiceClass:
    @pytest.mark.skipif(not _WIN32_AVAILABLE, reason="pywin32 not available")
    def test_service_class_attributes(self):
        from enterprise.service import SelfConnectEnterpriseService
        assert SelfConnectEnterpriseService._svc_name_ == SERVICE_NAME
        assert SelfConnectEnterpriseService._svc_display_name_ == SERVICE_DISPLAY_NAME
        assert SelfConnectEnterpriseService._svc_description_ == SERVICE_DESCRIPTION

    @pytest.mark.skipif(not _WIN32_AVAILABLE, reason="pywin32 not available")
    def test_service_inherits_service_framework(self):
        import win32serviceutil
        from enterprise.service import SelfConnectEnterpriseService
        assert issubclass(SelfConnectEnterpriseService, win32serviceutil.ServiceFramework)
