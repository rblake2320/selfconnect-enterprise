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
import pathlib
import shutil
import subprocess
import time
import urllib.request
from unittest.mock import MagicMock

# ── Ultra Server auto-start ───────────────────────────────────────────────────
_ultra_server_proc: subprocess.Popen | None = None
_ULTRA_SERVER_URL = "http://localhost:7777"
_ULTRA_SERVER_DIR = pathlib.Path(__file__).parent / "ultra_server"


def _server_reachable(timeout: float = 1.0) -> bool:
    try:
        urllib.request.urlopen(f"{_ULTRA_SERVER_URL}/status", timeout=timeout)
        return True
    except Exception:
        return False


def _wait_for_server(timeout: float = 12.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _server_reachable(timeout=1.0):
            return True
        time.sleep(0.25)
    return False


def pytest_sessionstart(session) -> None:  # noqa: ANN001
    """Start Ultra Server before test collection so pytestmark skip checks see it."""
    global _ultra_server_proc
    if not shutil.which("node"):
        return
    # Need the built @bpc/server dist to be present
    bpc_dist = _ULTRA_SERVER_DIR / "node_modules" / "@bpc" / "server" / "dist" / "index.js"
    if not bpc_dist.exists():
        return
    if _server_reachable():
        return  # already running (e.g. developer has it open manually)
    _ultra_server_proc = subprocess.Popen(
        ["node", "server.js"],
        cwd=str(_ULTRA_SERVER_DIR),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_server():
        _ultra_server_proc.kill()
        _ultra_server_proc = None


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ANN001
    """Shut down the Ultra Server process we started, if any."""
    global _ultra_server_proc
    if _ultra_server_proc is not None:
        _ultra_server_proc.terminate()
        try:
            _ultra_server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _ultra_server_proc.kill()
        _ultra_server_proc = None


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
