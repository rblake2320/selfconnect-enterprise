"""conftest.py — Root pytest configuration.

Redirects tmp_path to a project-local directory to avoid Windows
permission issues with the default system temp location.

Platform shim (non-Windows):
    enterprise/* modules call ctypes.windll at import time.  On Linux/macOS
    this raises AttributeError.  We install a minimal MagicMock shim for
    ctypes.windll and ctypes.wintypes so all modules import cleanly.
    Tests that exercise real Windows CNG must be marked:
        @pytest.mark.skipif(sys.platform != 'win32', reason='Windows CNG only')
"""
from __future__ import annotations
import sys
import ctypes
from unittest.mock import MagicMock


def pytest_configure(config):
    """Set basetemp to a project-local directory."""
    if not config.option.__dict__.get("basetemp"):
        config.option.basetemp = ".pytest_tmp"

    # ── Non-Windows platform shim ─────────────────────────────────────────────────────────
    if sys.platform != "win32":
        # Provide windll stub so enterprise modules import without error.
        # All actual CNG/Win32 calls will raise at runtime — tests that need
        # real Windows APIs must be skipped on non-Windows.
        if not hasattr(ctypes, "windll"):
            ctypes.windll = MagicMock()  # type: ignore[attr-defined]
        # Ensure specific DLL attributes are MagicMock objects
        for _dll in ("bcrypt", "ncrypt", "crypt32", "kernel32", "user32"):
            setattr(ctypes.windll, _dll, MagicMock())  # type: ignore[attr-defined]
        # WINFUNCTYPE is Windows-only — stub it so transport.py imports cleanly
        if not hasattr(ctypes, "WINFUNCTYPE"):
            def _winfunctype_stub(restype, *argtypes, **kw):  # type: ignore[misc]
                """Stub for ctypes.WINFUNCTYPE on non-Windows platforms."""
                return ctypes.CFUNCTYPE(restype, *argtypes)
            ctypes.WINFUNCTYPE = _winfunctype_stub  # type: ignore[attr-defined]
        # wintypes members must be real ctypes types (used in Structure _fields_)
        if not hasattr(ctypes, "wintypes") or isinstance(
            getattr(ctypes, "wintypes", None), MagicMock
        ):
            import types as _types
            _wt = _types.ModuleType("ctypes.wintypes")
            _wt.DWORD   = ctypes.c_ulong    # type: ignore[attr-defined]
            _wt.HANDLE  = ctypes.c_void_p   # type: ignore[attr-defined]
            _wt.BOOL    = ctypes.c_long     # type: ignore[attr-defined]
            _wt.HWND    = ctypes.c_void_p   # type: ignore[attr-defined]
            _wt.LPVOID  = ctypes.c_void_p   # type: ignore[attr-defined]
            _wt.LPCWSTR = ctypes.c_wchar_p  # type: ignore[attr-defined]
            ctypes.wintypes = _wt           # type: ignore[attr-defined]
