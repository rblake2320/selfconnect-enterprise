"""
Linux shim for ctypes.windll — implements Windows CNG (BCrypt/NCrypt) API
using the Python `cryptography` library so that enterprise.crypto tests
can run on Linux with real ECDSA P-384 / SHA-384 operations.

This is NOT a mock — it performs real cryptographic operations using
FIPS-approved algorithms (P-384, SHA-384) via OpenSSL through the
cryptography library. The shim translates Windows CNG API calls to
equivalent OpenSSL calls.

BCrypt functions implemented:
  BCryptOpenAlgorithmProvider, BCryptCloseAlgorithmProvider
  BCryptCreateHash, BCryptHashData, BCryptFinishHash, BCryptDestroyHash
  BCryptImportKeyPair, BCryptDestroyKey
  BCryptVerifySignature

NCrypt functions implemented:
  NCryptOpenStorageProvider
  NCryptCreatePersistedKey, NCryptFinalizeKey
  NCryptOpenKey, NCryptDeleteKey
  NCryptExportKey, NCryptSignHash
  NCryptFreeObject
"""
from __future__ import annotations
import ctypes
import hashlib
import struct
import threading
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

_PREHASHED_SHA384 = ec.ECDSA(Prehashed(hashes.SHA384()))

# ── Constants ─────────────────────────────────────────────────────────────────
_STATUS_SUCCESS  = 0x00000000
_NTE_BAD_KEYSET  = 0x80090016   # Key not found
_NTE_EXISTS      = 0x8009000F   # Key already exists
_NTE_BAD_DATA    = 0x80090005

_BCRYPT_ECDSA_PUBLIC_P384_MAGIC  = 0x33534345  # "ECS3"
_BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345  # "ECS4"
_BCRYPT_ECCKEY_BLOB_HEADER_SIZE  = 8
P384_COORD_BYTES = 48
SHA384_BYTES     = 48
P384_SIG_BYTES   = 96

# ── In-memory NCrypt software KSP ────────────────────────────────────────────
_key_store: Dict[str, ec.EllipticCurvePrivateKey] = {}
_key_store_lock = threading.Lock()

# ── Handle table ──────────────────────────────────────────────────────────────
_handles: Dict[int, object] = {}
_handle_counter = 0x1000
_handle_lock = threading.Lock()


def _alloc_handle(obj) -> int:
    global _handle_counter
    with _handle_lock:
        h = _handle_counter
        _handle_counter += 1
        _handles[h] = obj
    return h


def _get_handle(h) -> Optional[object]:
    if isinstance(h, ctypes.c_void_p):
        h = h.value
    if h is None:
        return None
    return _handles.get(h)


def _free_handle(h):
    if isinstance(h, ctypes.c_void_p):
        h = h.value
    if h is not None:
        _handles.pop(h, None)


def _write_handle(ptr, value: int):
    """Write an integer handle value into a ctypes pointer-to-void-pointer."""
    ctypes.cast(ptr, ctypes.POINTER(ctypes.c_size_t))[0] = value


# ── Object types stored in handle table ──────────────────────────────────────
class _BcryptAlgo:
    def __init__(self, algo_id: str):
        self.algo_id = algo_id
        self.hash_data = b""   # accumulator for hash operations


class _BcryptHash:
    def __init__(self):
        self.data = b""


class _BcryptKey:
    def __init__(self, pub_key: ec.EllipticCurvePublicKey):
        self.pub_key = pub_key


class _NcryptProvider:
    pass


class _NcryptKey:
    def __init__(self, name: str, priv_key: ec.EllipticCurvePrivateKey):
        self.name = name
        self.priv_key = priv_key

    @property
    def pub_key(self) -> ec.EllipticCurvePublicKey:
        return self.priv_key.public_key()


# ── BCrypt shim ───────────────────────────────────────────────────────────────
class _BcryptShim:
    """Shim for bcrypt.dll — real SHA-384 and ECDSA P-384 via OpenSSL."""

    # ── Algorithm provider ────────────────────────────────────────────────────
    def BCryptOpenAlgorithmProvider(self, ph_algo, algo_id, impl, flags):
        if isinstance(algo_id, bytes):
            algo_id = algo_id.decode("utf-16-le").rstrip("\x00")
        elif isinstance(algo_id, str):
            pass
        algo = _BcryptAlgo(algo_id)
        h = _alloc_handle(algo)
        _write_handle(ph_algo, h)
        return _STATUS_SUCCESS

    def BCryptCloseAlgorithmProvider(self, h_algo, flags):
        _free_handle(h_algo)
        return _STATUS_SUCCESS

    # ── Hash operations ───────────────────────────────────────────────────────
    def BCryptCreateHash(self, h_algo, ph_hash, pb_hash_obj, cb_hash_obj,
                         pb_secret, cb_secret, flags):
        h_hash = _alloc_handle(_BcryptHash())
        _write_handle(ph_hash, h_hash)
        return _STATUS_SUCCESS

    def BCryptHashData(self, h_hash, pb_input, cb_input, flags):
        hash_obj = _get_handle(h_hash)
        if not isinstance(hash_obj, _BcryptHash):
            return _NTE_BAD_DATA
        if isinstance(pb_input, ctypes.Array):
            hash_obj.data += bytes(pb_input[:cb_input])
        else:
            hash_obj.data += bytes(pb_input)
        return _STATUS_SUCCESS

    def BCryptFinishHash(self, h_hash, pb_output, cb_output, flags):
        hash_obj = _get_handle(h_hash)
        if not isinstance(hash_obj, _BcryptHash):
            return _NTE_BAD_DATA
        digest = hashlib.sha384(hash_obj.data).digest()
        for i in range(min(cb_output, len(digest))):
            pb_output[i] = digest[i]
        return _STATUS_SUCCESS

    def BCryptDestroyHash(self, h_hash):
        _free_handle(h_hash)
        return _STATUS_SUCCESS

    # ── Key import ────────────────────────────────────────────────────────────
    def BCryptImportKeyPair(self, h_algo, h_import_key, blob_type,
                            ph_key, pb_input, cb_input, flags):
        try:
            if isinstance(blob_type, bytes):
                btype = blob_type.decode("utf-16-le").rstrip("\x00")
            else:
                btype = str(blob_type)
            if isinstance(pb_input, ctypes.Array):
                raw = bytes(pb_input[:cb_input])
            else:
                raw = bytes(pb_input)
            # ECCPUBLICBLOB: 8-byte header (magic + cbKey) + X || Y
            if len(raw) < _BCRYPT_ECCKEY_BLOB_HEADER_SIZE + P384_COORD_BYTES * 2:
                return _NTE_BAD_DATA
            xy = raw[_BCRYPT_ECCKEY_BLOB_HEADER_SIZE:]
            x = int.from_bytes(xy[:P384_COORD_BYTES], 'big')
            y = int.from_bytes(xy[P384_COORD_BYTES:P384_COORD_BYTES * 2], 'big')
            pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key()
            h = _alloc_handle(_BcryptKey(pub_key))
            _write_handle(ph_key, h)
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def BCryptDestroyKey(self, h_key):
        _free_handle(h_key)
        return _STATUS_SUCCESS

    # ── Signature verification ────────────────────────────────────────────────
    def BCryptVerifySignature(self, h_key, padding_info,
                              pb_hash, cb_hash,
                              pb_signature, cb_signature, flags):
        try:
            key_obj = _get_handle(h_key)
            if not isinstance(key_obj, _BcryptKey):
                return _NTE_BAD_DATA
            if isinstance(pb_hash, ctypes.Array):
                digest = bytes(pb_hash[:cb_hash])
            else:
                digest = bytes(pb_hash)
            if isinstance(pb_signature, ctypes.Array):
                sig_raw = bytes(pb_signature[:cb_signature])
            else:
                sig_raw = bytes(pb_signature)
            if len(sig_raw) != P384_SIG_BYTES:
                return 0xC000A000  # STATUS_INVALID_SIGNATURE
            r = int.from_bytes(sig_raw[:P384_COORD_BYTES], 'big')
            s = int.from_bytes(sig_raw[P384_COORD_BYTES:], 'big')
            der_sig = encode_dss_signature(r, s)
            key_obj.pub_key.verify(
                der_sig,
                digest,
                _PREHASHED_SHA384
            )
            return _STATUS_SUCCESS
        except InvalidSignature:
            return 0xC000A000
        except Exception:
            return _NTE_BAD_DATA


# ── NCrypt shim ───────────────────────────────────────────────────────────────
class _NcryptShim:
    """Shim for ncrypt.dll — real ECDSA P-384 key management via OpenSSL."""

    def NCryptOpenStorageProvider(self, ph_prov, prov_name, flags):
        h = _alloc_handle(_NcryptProvider())
        _write_handle(ph_prov, h)
        return _STATUS_SUCCESS

    def NCryptCreatePersistedKey(self, h_prov, ph_key, algo_id,
                                 key_name, legacy_key_spec, flags):
        try:
            if isinstance(key_name, bytes):
                name = key_name.decode("utf-16-le").rstrip("\x00")
            elif key_name:
                name = str(key_name)
            else:
                name = ""
            # NCRYPT_OVERWRITE_KEY_FLAG = 0x80
            overwrite = bool(flags & 0x80)
            with _key_store_lock:
                if name in _key_store and not overwrite:
                    return _NTE_EXISTS
            priv_key = ec.generate_private_key(ec.SECP384R1())
            nk = _NcryptKey(name, priv_key)
            h = _alloc_handle(nk)
            _write_handle(ph_key, h)
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def NCryptFinalizeKey(self, h_key, flags):
        try:
            key_obj = _get_handle(h_key)
            if not isinstance(key_obj, _NcryptKey):
                return _NTE_BAD_DATA
            with _key_store_lock:
                _key_store[key_obj.name] = key_obj.priv_key
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def NCryptOpenKey(self, h_prov, ph_key, key_name, legacy_key_spec, flags):
        try:
            if isinstance(key_name, bytes):
                name = key_name.decode("utf-16-le").rstrip("\x00")
            elif key_name:
                name = str(key_name)
            else:
                name = ""
            with _key_store_lock:
                priv_key = _key_store.get(name)
            if priv_key is None:
                return _NTE_BAD_KEYSET
            nk = _NcryptKey(name, priv_key)
            h = _alloc_handle(nk)
            _write_handle(ph_key, h)
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def NCryptDeleteKey(self, h_key, flags):
        try:
            key_obj = _get_handle(h_key)
            if not isinstance(key_obj, _NcryptKey):
                return _NTE_BAD_DATA
            with _key_store_lock:
                _key_store.pop(key_obj.name, None)
            _free_handle(h_key)
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def NCryptExportKey(self, h_key, h_export_key, blob_type, param_list,
                        pb_output, cb_output, pcb_result, flags):
        try:
            key_obj = _get_handle(h_key)
            if not isinstance(key_obj, _NcryptKey):
                return _NTE_BAD_DATA
            if isinstance(blob_type, bytes):
                btype = blob_type.decode("utf-16-le").rstrip("\x00")
            else:
                btype = str(blob_type) if blob_type else "ECCPUBLICBLOB"
            pub_nums = key_obj.pub_key.public_numbers()
            x_bytes = pub_nums.x.to_bytes(P384_COORD_BYTES, 'big')
            y_bytes = pub_nums.y.to_bytes(P384_COORD_BYTES, 'big')
            if "PUBLIC" in btype.upper():
                header = struct.pack('<II', _BCRYPT_ECDSA_PUBLIC_P384_MAGIC, P384_COORD_BYTES)
                blob_data = header + x_bytes + y_bytes
            else:
                priv_nums = key_obj.priv_key.private_numbers()
                d_bytes = priv_nums.private_value.to_bytes(P384_COORD_BYTES, 'big')
                header = struct.pack('<II', _BCRYPT_ECDSA_PRIVATE_P384_MAGIC, P384_COORD_BYTES)
                blob_data = header + x_bytes + y_bytes + d_bytes
            # Write result size
            if pcb_result:
                ctypes.cast(pcb_result, ctypes.POINTER(ctypes.c_ulong))[0] = len(blob_data)
            # Write blob data if buffer provided
            if pb_output and cb_output >= len(blob_data):
                for i, b in enumerate(blob_data):
                    pb_output[i] = b
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def NCryptSignHash(self, h_key, padding_info,
                       pb_hash_value, cb_hash_value,
                       pb_signature, cb_signature,
                       pcb_result, flags):
        try:
            key_obj = _get_handle(h_key)
            if not isinstance(key_obj, _NcryptKey):
                return _NTE_BAD_DATA
            if isinstance(pb_hash_value, ctypes.Array):
                digest = bytes(pb_hash_value[:cb_hash_value])
            else:
                digest = bytes(pb_hash_value)
            der_sig = key_obj.priv_key.sign(
                digest,
                _PREHASHED_SHA384
            )
            r, s = decode_dss_signature(der_sig)
            r_bytes = r.to_bytes(P384_COORD_BYTES, 'big')
            s_bytes = s.to_bytes(P384_COORD_BYTES, 'big')
            sig_raw = r_bytes + s_bytes
            if pcb_result:
                ctypes.cast(pcb_result, ctypes.POINTER(ctypes.c_ulong))[0] = len(sig_raw)
            if pb_signature and cb_signature >= len(sig_raw):
                for i, b in enumerate(sig_raw):
                    pb_signature[i] = b
            return _STATUS_SUCCESS
        except Exception:
            return _NTE_BAD_DATA

    def NCryptFreeObject(self, h):
        _free_handle(h)
        return _STATUS_SUCCESS


# ── DPAPI shim (crypt32 + kernel32) ──────────────────────────────────────────
# On Linux we use AES-256-GCM with a per-process key as a passthrough.
# This is NOT user-bound like real DPAPI but allows the tests to exercise
# the full identity lifecycle with real encryption/decryption.
import os as _os
import hashlib as _hashlib

_DPAPI_KEY = _os.urandom(32)   # per-process symmetric key
_DPAPI_MAGIC = b"LINUXDPAPI"

# Freed blobs storage (simulate LocalFree)
_local_alloc_store: Dict[int, bytes] = {}
_local_alloc_counter = 0x8000
_local_alloc_lock = threading.Lock()


def _local_alloc(data: bytes) -> ctypes.c_void_p:
    global _local_alloc_counter
    with _local_alloc_lock:
        addr = _local_alloc_counter
        _local_alloc_counter += 1
        _local_alloc_store[addr] = data
    return ctypes.c_void_p(addr)


class _Crypt32Shim:
    """Shim for crypt32.dll — implements DPAPI using AES-256-GCM."""

    def CryptProtectData(self, p_data_in, sz_data_descr, p_optional_entropy,
                         pv_reserved, p_prompt_struct, dw_flags, p_data_out):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            in_blob = p_data_in._obj
            plaintext = bytes(in_blob.pbData[:in_blob.cbData])
            nonce = _os.urandom(12)
            aesgcm = AESGCM(_DPAPI_KEY)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            blob = _DPAPI_MAGIC + nonce + ciphertext
            # Write output blob
            out_blob = p_data_out._obj
            buf = (ctypes.c_ubyte * len(blob))(*blob)
            out_blob.cbData = len(blob)
            out_blob.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
            # Keep buf alive in our store
            addr = id(buf)
            _local_alloc_store[addr] = buf
            return 1  # TRUE
        except Exception:
            return 0  # FALSE

    def CryptUnprotectData(self, p_data_in, pp_sz_data_descr, p_optional_entropy,
                           pv_reserved, p_prompt_struct, dw_flags, p_data_out):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            in_blob = p_data_in._obj
            blob = bytes(in_blob.pbData[:in_blob.cbData])
            if not blob.startswith(_DPAPI_MAGIC):
                return 0
            offset = len(_DPAPI_MAGIC)
            nonce = blob[offset:offset + 12]
            ciphertext = blob[offset + 12:]
            aesgcm = AESGCM(_DPAPI_KEY)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            out_blob = p_data_out._obj
            buf = (ctypes.c_ubyte * len(plaintext))(*plaintext)
            out_blob.cbData = len(plaintext)
            out_blob.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
            addr = id(buf)
            _local_alloc_store[addr] = buf
            return 1  # TRUE
        except Exception:
            return 0  # FALSE


class _Kernel32Shim:
    """Shim for kernel32.dll — implements LocalFree, GetLastError, and atom functions."""

    _atom_store: Dict[str, int] = {}
    _atom_counter = 0xC000
    _atom_lock = threading.Lock()

    def LocalFree(self, h_mem):
        # Just a no-op; Python GC handles memory
        return None

    def GetLastError(self):
        return 0

    def GlobalAddAtomW(self, value):
        """Add a string to the global atom table and return its atom."""
        if isinstance(value, bytes):
            value = value.decode('utf-16-le').rstrip('\x00')
        elif not isinstance(value, str):
            value = str(value)
        with self._atom_lock:
            if value in self._atom_store:
                return self._atom_store[value]
            atom = self._atom_counter
            self._atom_counter += 1
            self._atom_store[value] = atom
            # Reverse mapping
            self._atom_store[atom] = value
        return atom

    def GlobalGetAtomNameW(self, atom, buf, buf_size):
        """Retrieve the string for an atom."""
        with self._atom_lock:
            value = self._atom_store.get(atom)
        if value is None:
            return 0
        # Write to buffer
        try:
            for i, ch in enumerate(value[:buf_size - 1]):
                buf[i] = ch
            buf[len(value)] = '\x00'
        except Exception:
            pass
        return len(value)

    def GlobalDeleteAtom(self, atom):
        """Remove an atom from the global atom table."""
        with self._atom_lock:
            value = self._atom_store.pop(atom, None)
            if value is not None:
                self._atom_store.pop(value, None)
        return 0

    def GetCurrentProcess(self):
        return ctypes.c_void_p(0xFFFFFFFF)

    def GetCurrentProcessId(self):
        import os
        return os.getpid()


class _CTypesCallable:
    """A callable that also supports .restype and .argtypes attributes,
    mimicking a ctypes function object."""
    def __init__(self, func=None, name='<shim>'):
        self._func = func
        self.restype = None
        self.argtypes = None
        self.__name__ = name

    def __call__(self, *args, **kwargs):
        if self._func is not None:
            return self._func(*args, **kwargs)
        return 0

    def __setattr__(self, name, value):
        # Allow setting restype/argtypes without error
        object.__setattr__(self, name, value)


class _User32Shim:
    """Shim for user32.dll — stubs Win32 window/message functions.
    All actual logic is mocked in tests; this shim only needs to be importable.
    """

    def SetPropW(self, hwnd, key, value):
        return 1  # TRUE

    def GetPropW(self, hwnd, key):
        return 0  # NULL

    def RemovePropW(self, hwnd, key):
        return 0

    def IsWindow(self, hwnd):
        return 1  # TRUE

    def GetWindowThreadProcessId(self, hwnd, lpdw_process_id):
        if lpdw_process_id:
            import os
            ctypes.cast(lpdw_process_id, ctypes.POINTER(ctypes.c_ulong))[0] = os.getpid()
        return 1

    def EnumWindows(self, lp_enum_func, l_param):
        return 1  # TRUE (no windows to enumerate)

    def SendMessageW(self, hwnd, msg, w_param, l_param):
        return 0

    def RegisterClassExW(self, wnd_class):
        return 1  # Non-zero = success

    def CreateWindowExW(self, dw_ex_style, lp_class_name, lp_window_name,
                        dw_style, x, y, n_width, n_height,
                        h_wnd_parent, h_menu, h_instance, lp_param):
        return ctypes.c_void_p(0x12345678)  # Fake HWND

    def UnregisterClassW(self, lp_class_name, h_instance):
        return 1

    def GetMessageW(self, lp_msg, h_wnd, w_msg_filter_min, w_msg_filter_max):
        return 0  # WM_QUIT

    def TranslateMessage(self, lp_msg):
        return 1

    def DispatchMessageW(self, lp_msg):
        return 0

    def DefWindowProcW(self, h_wnd, msg, w_param, l_param):
        return 0

    def PostMessageW(self, h_wnd, msg, w_param, l_param):
        return 1

    def __getattr__(self, name):
        # Return a _CTypesCallable for any unimplemented function
        # This supports .restype and .argtypes assignment
        return _CTypesCallable(name=name)

    def __getattribute__(self, name):
        # For named methods, wrap them in _CTypesCallable so .restype works
        val = object.__getattribute__(self, name)
        if callable(val) and not isinstance(val, _CTypesCallable) and not name.startswith('_'):
            wrapper = _CTypesCallable(func=val, name=name)
            return wrapper
        return val


# ── windll shim ───────────────────────────────────────────────────────────────
class _WindllShim:
    """Shim for ctypes.windll — provides bcrypt, ncrypt, crypt32, kernel32, user32."""
    def __init__(self):
        self.bcrypt   = _BcryptShim()
        self.ncrypt   = _NcryptShim()
        self.crypt32  = _Crypt32Shim()
        self.kernel32 = _Kernel32Shim()
        self.user32   = _User32Shim()

    def __getattr__(self, name):
        raise AttributeError(f"windll shim: {name!r} not implemented")


# ── wintypes shim ─────────────────────────────────────────────────────────────
def _make_wintypes():
    import types
    wt = types.ModuleType("ctypes.wintypes")
    wt.DWORD    = ctypes.c_uint32
    wt.HANDLE   = ctypes.c_void_p
    wt.BOOL     = ctypes.c_int
    wt.LPWSTR   = ctypes.c_wchar_p
    wt.LPCWSTR  = ctypes.c_wchar_p
    wt.WORD     = ctypes.c_uint16
    wt.BYTE     = ctypes.c_uint8
    wt.LONG     = ctypes.c_long
    wt.ULONG    = ctypes.c_ulong
    return wt


def install_windll_shim():
    """Install the windll shim into ctypes so enterprise modules can load on Linux."""
    ctypes.windll = _WindllShim()
    if not hasattr(ctypes, "wintypes"):
        ctypes.wintypes = _make_wintypes()
    # WINFUNCTYPE is Windows-only — provide a CFUNCTYPE equivalent
    if not hasattr(ctypes, "WINFUNCTYPE"):
        ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
    # WinError is Windows-only — provide a stub
    if not hasattr(ctypes, "WinError"):
        def _win_error(code=None, descr=None):
            return OSError(code or 0, descr or "WinError")
        ctypes.WinError = _win_error
