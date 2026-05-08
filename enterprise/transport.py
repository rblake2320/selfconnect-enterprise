"""enterprise/transport.py — WM_COPYDATA Structured Payload Transport

Receive side for the Win32 WM_COPYDATA transport layer.  The send side
(send_data) lives in enterprise.registry — import both for full duplex.

    from enterprise.registry import send_data
    from enterprise.transport import CopyDataListener

    # Sender:
    send_data(peer_hwnd, {"task": "ping", "session": "s16"})

    # Receiver:
    listener = CopyDataListener()
    listener.register(0, lambda sender_hwnd, payload: handle(payload))
    listener.start()
    peer_hwnd = listener.hwnd  # stamp this in birth tag so peers can target it

Architecture:
    CopyDataListener spins a background thread that:
      1. Creates a message-only window (HWND_MESSAGE parent — invisible, no taskbar entry)
      2. Runs a Win32 message pump (GetMessage / TranslateMessage / DispatchMessage)
      3. On WM_COPYDATA: deserialises the JSON payload, dispatches to registered callbacks

    The listener's HWND should be stamped in the birth tag via stamp_birth_tag so
    that mesh peers can target it directly with send_data().

    Message pump runs until stop() posts WM_QUIT to the listener window.

Transport contract:
    dwData  — caller-assigned integer type tag (use 0 for generic JSON)
    cbData  — payload byte length
    lpData  — UTF-8 encoded JSON bytes
    wParam  — sender HWND (OS-filled; peers MUST NOT spoof this)

Limitations:
    - Max payload: 64 KB (OS limit for WM_COPYDATA)
    - Same-machine only (WM_COPYDATA does not cross network; use Named Pipes for that)
    - Callbacks run on the listener thread — keep them fast; offload heavy work

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import ctypes
import json
import logging
import threading
from typing import Callable, Optional

log = logging.getLogger(__name__)

# ── Win32 handles ─────────────────────────────────────────────────────────────
user32   = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# ── Win32 constants ───────────────────────────────────────────────────────────
WM_COPYDATA    = 0x004A
WM_DESTROY     = 0x0002
WM_QUIT        = 0x0012
WM_NCCREATE    = 0x0081
HWND_MESSAGE   = ctypes.c_void_p(-3)   # message-only window parent sentinel
CS_HREDRAW     = 0x0002
CS_VREDRAW     = 0x0001
IDC_ARROW      = 32512
COLOR_WINDOW   = 5
CW_USEDEFAULT  = 0x80000000
GWLP_USERDATA  = -21

DefWindowProcW = user32.DefWindowProcW
DefWindowProcW.restype = ctypes.c_int64

PostMessageW   = user32.PostMessageW

# ── Win32 structures ──────────────────────────────────────────────────────────

class COPYDATASTRUCT(ctypes.Structure):
    """COPYDATASTRUCT — payload envelope for WM_COPYDATA."""
    _fields_ = [
        ("dwData",  ctypes.c_ulong),     # caller type tag
        ("cbData",  ctypes.c_ulong),     # payload byte length
        ("lpData",  ctypes.c_void_p),    # pointer to payload bytes
    ]


class WNDCLASSEX(ctypes.Structure):
    """WNDCLASSEXW — window class registration structure."""
    _fields_ = [
        ("cbSize",        ctypes.c_uint),
        ("style",         ctypes.c_uint),
        ("lpfnWndProc",   ctypes.c_void_p),
        ("cbClsExtra",    ctypes.c_int),
        ("cbWndExtra",    ctypes.c_int),
        ("hInstance",     ctypes.c_void_p),
        ("hIcon",         ctypes.c_void_p),
        ("hCursor",       ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName",  ctypes.c_wchar_p),
        ("lpszClassName", ctypes.c_wchar_p),
        ("hIconSm",       ctypes.c_void_p),
    ]


class MSG(ctypes.Structure):
    """MSG — Win32 message structure for the message pump."""
    _fields_ = [
        ("hwnd",    ctypes.c_void_p),
        ("message", ctypes.c_uint),
        ("wParam",  ctypes.c_size_t),
        ("lParam",  ctypes.c_size_t),
        ("time",    ctypes.c_ulong),
        ("pt",      ctypes.c_long * 2),
    ]


# Function type for WndProc: LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM)
WNDPROCTYPE = ctypes.WINFUNCTYPE(
    ctypes.c_int64,          # return: LRESULT
    ctypes.c_void_p,         # hwnd
    ctypes.c_uint,           # uMsg
    ctypes.c_size_t,         # wParam
    ctypes.c_size_t,         # lParam
)

# ── CopyDataListener ──────────────────────────────────────────────────────────

class CopyDataListener:
    """Receive structured WM_COPYDATA JSON payloads on a hidden message-only window.

    Usage:
        listener = CopyDataListener()
        listener.register(0, lambda sender, data: print(sender, data))
        listener.start()
        # stamp listener.hwnd in your birth tag for peers to target
        ...
        listener.stop()

    Thread safety:
        register() is safe to call before start() or after start() from any thread.
        Callbacks are invoked on the listener's internal thread.
    """

    _CLASS_COUNTER = 0
    _CLASS_LOCK    = threading.Lock()

    def __init__(self) -> None:
        self._hwnd:      Optional[int] = None
        self._thread:    Optional[threading.Thread] = None
        self._ready:     threading.Event = threading.Event()
        self._callbacks: dict[int, list[Callable[[int, dict], None]]] = {}
        self._lock:      threading.Lock = threading.Lock()
        self._wndproc:   Optional[WNDPROCTYPE] = None  # type: ignore[valid-type]  # keep reference alive

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def hwnd(self) -> Optional[int]:
        """HWND of the listener window, or None if not yet started."""
        return self._hwnd

    def register(
        self,
        data_type: int,
        callback: Callable[[int, dict], None],
    ) -> None:
        """Register a callback for a WM_COPYDATA dwData type tag.

        Args:
            data_type:  The dwData value to match (use 0 for untyped JSON).
            callback:   Called as callback(sender_hwnd, payload_dict) on receipt.
                        Runs on the listener thread — keep it fast.
        """
        with self._lock:
            self._callbacks.setdefault(data_type, []).append(callback)

    def start(self, timeout: float = 5.0) -> None:
        """Launch the listener background thread and wait for the window to be ready.

        Args:
            timeout: Seconds to wait for the message-only window to be created.

        Raises:
            RuntimeError: If the window fails to create within timeout.
        """
        if self._thread and self._thread.is_alive():
            return
        self._ready.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="CopyDataListener",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("CopyDataListener window failed to create within timeout")

    def stop(self) -> None:
        """Signal the listener to shut down and wait for the thread to exit."""
        if self._hwnd:
            PostMessageW(self._hwnd, WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=3.0)
        self._hwnd   = None
        self._thread = None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Background thread: register window class, create window, pump messages."""
        class_name = self._unique_class_name()
        hinstance  = kernel32.GetModuleHandleW(None)

        # Hold a ctypes reference so the WndProc function pointer stays alive
        self._wndproc = WNDPROCTYPE(self._wnd_proc)

        wc = WNDCLASSEX()
        wc.cbSize        = ctypes.sizeof(WNDCLASSEX)
        wc.style         = CS_HREDRAW | CS_VREDRAW
        wc.lpfnWndProc   = ctypes.cast(self._wndproc, ctypes.c_void_p).value
        wc.hInstance     = hinstance
        wc.lpszClassName = class_name

        if not user32.RegisterClassExW(ctypes.byref(wc)):
            log.error("RegisterClassExW failed — error %d", kernel32.GetLastError())
            self._ready.set()
            return

        hwnd = user32.CreateWindowExW(
            0,                     # dwExStyle
            class_name,            # lpClassName
            "SelfConnect-Listener",# lpWindowName
            0,                     # dwStyle (no visible style)
            0, 0, 0, 0,            # x, y, nWidth, nHeight
            HWND_MESSAGE,          # hWndParent — message-only window
            None,                  # hMenu
            hinstance,             # hInstance
            None,                  # lpParam
        )

        if not hwnd:
            log.error("CreateWindowExW failed — error %d", kernel32.GetLastError())
            user32.UnregisterClassW(class_name, hinstance)
            self._ready.set()
            return

        self._hwnd = hwnd
        self._ready.set()

        # ── Message pump ──────────────────────────────────────────────────────
        msg = MSG()
        while True:
            ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if ret == 0 or ret == -1:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        user32.UnregisterClassW(class_name, hinstance)
        self._hwnd = None

    def _wnd_proc(
        self,
        hwnd:   ctypes.c_void_p,
        msg:    ctypes.c_uint,
        wparam: ctypes.c_size_t,
        lparam: ctypes.c_size_t,
    ) -> ctypes.c_int64:
        """Win32 WndProc — handles WM_COPYDATA, delegates rest to DefWindowProc."""
        if msg == WM_COPYDATA:
            self._handle_copydata(int(wparam), int(lparam))  # type: ignore[arg-type]
            return ctypes.c_int64(1)  # type: ignore[return-value]

        return DefWindowProcW(hwnd, msg, wparam, lparam)

    def _handle_copydata(self, sender_hwnd: int, lparam: int) -> None:
        """Decode COPYDATASTRUCT, deserialise JSON, dispatch to callbacks."""
        try:
            cds = ctypes.cast(lparam, ctypes.POINTER(COPYDATASTRUCT)).contents
            raw = ctypes.string_at(cds.lpData, cds.cbData)
            payload = json.loads(raw.decode("utf-8"))
            data_type = int(cds.dwData)
        except Exception:
            log.exception("WM_COPYDATA decode error (sender=%#x)", sender_hwnd)
            return

        with self._lock:
            handlers = list(self._callbacks.get(data_type, []))

        for cb in handlers:
            try:
                cb(sender_hwnd, payload)
            except Exception:
                log.exception(
                    "CopyDataListener callback error (type=%d sender=%#x)",
                    data_type, sender_hwnd,
                )

    @classmethod
    def _unique_class_name(cls) -> str:
        with cls._CLASS_LOCK:
            cls._CLASS_COUNTER += 1
            return f"SelfConnect-CopyDataListener-{cls._CLASS_COUNTER}"
