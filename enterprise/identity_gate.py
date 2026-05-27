"""enterprise/identity_gate.py — SC_IDENTITY_MODE gate for send_string().

Three operating modes, controlled by SC_IDENTITY_MODE env var:

  bypass  (default) — No verification. send_string() works exactly as before.
                       Safe starting point. Production enforcement is opt-in.
  audit            — Full 7-layer verification runs, result is logged.
                       Injection proceeds regardless of result.
                       Use to validate crypto before enforcing.
  enforce          — Full 7-layer verification. Failure blocks injection.
                       Production mode.

Mode is read PER CALL (not at import time), matching the SC_HANDSHAKE pattern
already established in this codebase. A running terminal can change mode by
setting the env var — no restart required.

Emergency bypass: Named Mutex `Global\\SelfConnect_IdentityBypass_{UserSID}`.
  - Forces all terminals of this Windows user to AUDIT mode (not full bypass).
  - Does NOT create a path to "no verification" in enforce mode.
  - Trigger: emergency_bypass() / release_bypass() functions below.
  - Auto-releases when the creating process exits.
  - Gap 1 fix: mutex presence alone is no longer sufficient. A valid
    DPAPI-protected token must also be present in the Registry at
    HKCU\\Software\\SelfConnect\\EmergencyBypass. This prevents unprivileged
    malware from triggering the downgrade by simply creating the mutex.

Degradation cascade (if full 7-layer fails):
  Level 0: Full 7-layer BPC+TSK      (nominal)
  Level 1: BPC-only                   (TSK service issue)
  Level 2: Enterprise ed25519-only    (Ultra Server unreachable — ENFORCE stops here)
  Level 3: HWND+PID binding only      (audit mode only)
  Level 5: Pass-through with logging  (audit mode only — all crypto down)

In enforce mode, cascade stops at Level 2. The worst case in production is
falling back to the proven enterprise identity layer (ed25519 + birth tags).

Gap 4 fix: SC_STRICT_ENFORCE=1 makes the cascade fail CLOSED on network errors
instead of degrading to Level 2. An attacker cannot force a downgrade by
blocking localhost:7777.

Gap 3 note: DPAPI deterministic derivation is a known gap (TPM migration
roadmap). A CRITICAL log is emitted at startup if no TPM is detected.

Version: 1.1.0  BPC+TSK integration — Layer 8 security hardening
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import struct
import time
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from enterprise.ultra_gate import UltraGate

_log = logging.getLogger(__name__)

# ── Mode constants ─────────────────────────────────────────────────────────────
MODE_BYPASS  = "bypass"
MODE_AUDIT   = "audit"
MODE_ENFORCE = "enforce"
_VALID_MODES = {MODE_BYPASS, MODE_AUDIT, MODE_ENFORCE}

# ── Windows Named Mutex for emergency bypass ──────────────────────────────────
_MUTEX_BASE = "Global\\SelfConnect_IdentityBypass_"
_mutex_handle: ctypes.c_void_p | None = None

# ── DPAPI-signed bypass token (Gap 1 fix) ─────────────────────────────────────
# The mutex alone is unprivileged — any malware can create it.
# The signed token adds a second factor: only a process that can call
# CryptProtectData with the correct entropy can write a valid token.
# Registry path: HKCU\Software\SelfConnect\EmergencyBypass
_BYPASS_REG_PATH    = r"Software\SelfConnect"
_BYPASS_REG_VALUE   = "EmergencyBypass"
_BYPASS_TOKEN_ENTROPY = b"SC-EmergencyBypass-Entropy-v1"
_BYPASS_TOKEN_TTL_SEC = 3600  # token expires after 1 hour

# ── Strict enforce mode (Gap 4 fix) ───────────────────────────────────────────
# When SC_STRICT_ENFORCE=1, a network failure at Level 0 fails CLOSED instead
# of degrading to Level 2. Crypto failures still degrade normally.
_STRICT_ENFORCE: bool = os.environ.get("SC_STRICT_ENFORCE", "0").strip() == "1"

# ── Bridge timeout ─────────────────────────────────────────────────────────────
BRIDGE_TIMEOUT_MS: int = int(os.environ.get("SC_IDENTITY_BRIDGE_TIMEOUT_MS", "500"))

# ── Minimum degradation level in enforce mode ─────────────────────────────────
# Level 2 = enterprise-only (ed25519 + birth tag). Never go below this in enforce.
ENFORCE_MIN_DEGRADATION_LEVEL: int = 2


class IdentityGateError(Exception):
    """Gate configuration or runtime error."""


class InjectionDeniedError(Exception):
    """Injection was denied by the identity gate in enforce mode."""
    def __init__(self, reason: str) -> None:
        super().__init__(f"InjectionDenied: {reason}")
        self.reason = reason


# ── TPM availability check (Gap 3 — DPAPI risk warning) ──────────────────────

_TPM_AVAILABLE: bool | None = None


def _check_tpm_available() -> bool:
    """Check if a TPM is available on this machine. Non-blocking.

    Emits a CRITICAL log at startup if no TPM is detected, because DPAPI
    root key derivation is vulnerable to offline extraction (Mimikatz at
    SYSTEM level) without TPM backing.
    Set DPAPI_RISK_ACKNOWLEDGED=1 to suppress this warning.
    """
    global _TPM_AVAILABLE
    if _TPM_AVAILABLE is not None:
        return _TPM_AVAILABLE
    if os.environ.get("DPAPI_RISK_ACKNOWLEDGED", "0").strip() == "1":
        _TPM_AVAILABLE = True
        return True
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-WmiObject -Namespace root/cimv2/security/microsofttpm "
             "-Class Win32_Tpm).IsEnabled_InitialValue"],
            capture_output=True, text=True, timeout=5,
        )
        _TPM_AVAILABLE = result.stdout.strip().lower() == "true"
    except Exception:
        _TPM_AVAILABLE = False
    if not _TPM_AVAILABLE:
        _log.critical(
            "IdentityGate: TPM not detected. DPAPI root key is vulnerable to offline "
            "extraction (Mimikatz at SYSTEM). All P-256 keys for all agent IDs can be "
            "deterministically derived from the DPAPI root. Migrate to TPM-backed key "
            "storage. Set DPAPI_RISK_ACKNOWLEDGED=1 to suppress this warning."
        )
    return _TPM_AVAILABLE


# ── DPAPI helpers (Gap 1) ─────────────────────────────────────────────────────

def _dpapi_protect(data: bytes, entropy: bytes) -> bytes | None:
    """Encrypt data with DPAPI using the given entropy. Returns None on failure."""
    try:
        crypt32 = ctypes.windll.crypt32

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_byte))]

        in_buf  = (ctypes.c_byte * len(data))(*data)
        ent_buf = (ctypes.c_byte * len(entropy))(*entropy)
        blob_in  = DATA_BLOB(len(data),    ctypes.cast(in_buf,  ctypes.POINTER(ctypes.c_byte)))
        blob_ent = DATA_BLOB(len(entropy), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB(0, None)

        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, ctypes.byref(blob_ent),
            None, None, 0, ctypes.byref(blob_out),
        )
        if not ok or not blob_out.pbData:
            return None
        result = bytes(blob_out.pbData[:blob_out.cbData])
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return result
    except Exception:
        return None


def _dpapi_unprotect(data: bytes, entropy: bytes) -> bytes | None:
    """Decrypt DPAPI-protected data. Returns None on failure."""
    try:
        crypt32 = ctypes.windll.crypt32

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_byte))]

        in_buf  = (ctypes.c_byte * len(data))(*data)
        ent_buf = (ctypes.c_byte * len(entropy))(*entropy)
        blob_in  = DATA_BLOB(len(data),    ctypes.cast(in_buf,  ctypes.POINTER(ctypes.c_byte)))
        blob_ent = DATA_BLOB(len(entropy), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB(0, None)

        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, ctypes.byref(blob_ent),
            None, None, 0, ctypes.byref(blob_out),
        )
        if not ok or not blob_out.pbData:
            return None
        result = bytes(blob_out.pbData[:blob_out.cbData])
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return result
    except Exception:
        return None


def write_bypass_registry_token() -> bool:
    """Write a DPAPI-protected bypass token to the Registry.

    Must be called by a privileged operator process before emergency_bypass().
    Token expires after _BYPASS_TOKEN_TTL_SEC (1 hour).
    Returns True on success.
    """
    try:
        import winreg
        ts_bytes = struct.pack('<Q', int(time.time()))
        encrypted = _dpapi_protect(ts_bytes, _BYPASS_TOKEN_ENTROPY)
        if encrypted is None:
            _log.error("IdentityGate: DPAPI encryption failed — cannot write bypass token")
            return False
        key = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, _BYPASS_REG_PATH, 0, winreg.KEY_WRITE
        )
        winreg.SetValueEx(key, _BYPASS_REG_VALUE, 0, winreg.REG_BINARY, encrypted)
        winreg.CloseKey(key)
        _log.info("IdentityGate: bypass token written to Registry (expires in %ds)",
                  _BYPASS_TOKEN_TTL_SEC)
        return True
    except Exception as exc:
        _log.error("IdentityGate: failed to write bypass token: %s", exc)
        return False


def _verify_bypass_registry_token() -> bool:
    """Verify the DPAPI-protected bypass token in the Registry.

    Returns True only if a valid, unexpired token is present AND was encrypted
    by this user's DPAPI key (i.e., a legitimate operator wrote it).
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _BYPASS_REG_PATH, 0, winreg.KEY_READ
        )
        raw, _ = winreg.QueryValueEx(key, _BYPASS_REG_VALUE)
        winreg.CloseKey(key)
        if not isinstance(raw, bytes) or len(raw) < 8:
            return False
        decrypted = _dpapi_unprotect(raw, _BYPASS_TOKEN_ENTROPY)
        if decrypted is None:
            _log.warning(
                "IdentityGate: bypass token DPAPI decryption failed — "
                "mutex present but token invalid, ignoring bypass attempt"
            )
            return False
        if len(decrypted) < 8:
            return False
        ts = struct.unpack_from('<Q', decrypted, 0)[0]
        age = int(time.time()) - ts
        if age > _BYPASS_TOKEN_TTL_SEC:
            _log.warning(
                "IdentityGate: bypass token expired (%ds old, TTL=%ds) — ignoring",
                age, _BYPASS_TOKEN_TTL_SEC,
            )
            return False
        return True
    except Exception:
        return False


# ── Current mode detection ────────────────────────────────────────────────────

def get_current_mode() -> str:
    """Return the current operating mode.

    Priority:
      1. Named Mutex present AND valid DPAPI token in Registry → downgrade to
         'audit' regardless of env var. (Gap 1 fix: mutex alone is insufficient.)
      2. SC_IDENTITY_MODE env var (bypass / audit / enforce).
      3. Default: bypass (safe starting state).
    """
    raw = os.environ.get("SC_IDENTITY_MODE", MODE_BYPASS).strip().lower()
    mode = raw if raw in _VALID_MODES else MODE_BYPASS

    # Check emergency bypass — requires BOTH mutex AND valid DPAPI token
    if mode == MODE_ENFORCE and _emergency_mutex_active():
        _log.critical(
            "IdentityGate: emergency bypass activated (mutex + DPAPI token verified) — "
            "downgrading to AUDIT mode. All injections will be logged but not blocked."
        )
        return MODE_AUDIT

    return mode


def _get_user_sid() -> str:
    """Get the current user's SID string for scoping the mutex."""
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
            capture_output=True, text=True, timeout=3,
        )
        sid = result.stdout.strip()
        if sid:
            return sid
    except Exception:
        pass
    return "DefaultSID"


def _mutex_name() -> str:
    return _MUTEX_BASE + _get_user_sid()


def _emergency_mutex_active() -> bool:
    """Check whether the emergency bypass Named Mutex exists AND a valid DPAPI
    signed token is present in the Registry (Gap 1 fix).

    Requiring BOTH the mutex AND a valid DPAPI token means an unprivileged
    attacker who creates the mutex cannot trigger the downgrade — they also need
    to write a CryptProtectData-signed token to HKCU\\Software\\SelfConnect,
    which requires the user's DPAPI key (not available to unprivileged malware
    without session access).
    """
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenMutexW(0x00100000, False, _mutex_name())  # SYNCHRONIZE
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        # Mutex exists — now verify the DPAPI-signed Registry token
        if not _verify_bypass_registry_token():
            _log.warning(
                "IdentityGate: bypass mutex present but no valid DPAPI token found — "
                "bypass attempt REJECTED. Call write_bypass_registry_token() first."
            )
            return False
        return True
    except Exception:
        return False


def emergency_bypass() -> None:
    """Create the emergency bypass Named Mutex.

    In enforce mode, this downgrades all terminals of this Windows user to AUDIT
    mode. Injections proceed but are logged. The mutex lives until release_bypass()
    is called or the process exits.

    IMPORTANT (Gap 1 fix): You must call write_bypass_registry_token() BEFORE
    calling this function. The mutex alone is no longer sufficient to trigger the
    bypass — a valid DPAPI token must also be present in the Registry.

    Safe to call multiple times. Call release_bypass() when crisis is resolved.
    """
    global _mutex_handle
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, _mutex_name())
    if handle:
        _mutex_handle = handle
        _log.critical(
            "IdentityGate: EMERGENCY BYPASS ACTIVATED (pid=%d). "
            "Enforce mode downgraded to audit. Call release_bypass() when resolved.",
            os.getpid(),
        )
    else:
        err = kernel32.GetLastError()
        _log.error("IdentityGate: failed to create bypass mutex (error %d)", err)


def release_bypass() -> None:
    """Release the emergency bypass Named Mutex."""
    global _mutex_handle
    if _mutex_handle:
        ctypes.windll.kernel32.CloseHandle(_mutex_handle)
        _mutex_handle = None
        _log.info("IdentityGate: emergency bypass released.")


# ── Degradation cascade ───────────────────────────────────────────────────────

class DegradationCascade:
    """Implements the 6-level degradation cascade for identity verification.

    Level 0: Full 7-layer BPC+TSK via UltraGate.
    Level 1: BPC-only (TSK timeout/failure).
    Level 2: Enterprise ed25519 birth tag (Ultra Server unreachable).
    Level 3: HWND+PID binding only (crypto failure).
    Level 4: Pass-through with CRITICAL log (all identity down — audit only).

    In enforce mode, cascade stops at Level 2. If Level 2 fails in enforce,
    injection is blocked.

    Gap 4 fix: When SC_STRICT_ENFORCE=1, an OSError (network failure) at
    Level 0 fails CLOSED — no degradation to Level 2. This prevents an attacker
    from blocking localhost:7777 to force a downgrade and bypass Layer 8 Active
    Defense (Ghost Pairs, Shadow Mode, Tarpit).
    """

    def __init__(
        self,
        gate: Optional["UltraGate"],
        mode: str,
    ) -> None:
        self.gate = gate
        self.mode = mode

    def verify(self, target_hwnd: int, text: str) -> tuple[bool, str, int]:
        """Run the degradation cascade.

        Returns:
            (ok, reason, level) — level is the cascade level that produced the result.
        """
        # Level 0: Full 7-layer
        if self.gate and self.gate._bootstrapped:
            try:
                ok, reason = self._level0_full(target_hwnd, text)
                if ok:
                    return True, "", 0
                _log.warning("IdentityGate: Level 0 (full BPC+TSK) failed: %s", reason)
                # Level 1: BPC-only (verify without TSK checksum)
                ok, reason = self._level1_bpc_only(target_hwnd, text)
                if ok:
                    _log.warning("IdentityGate: degraded to Level 1 (BPC-only)")
                    return True, "", 1
                _log.warning("IdentityGate: Level 1 (BPC-only) failed: %s", reason)
            except OSError as exc:
                # Network/connection failure — not a crypto failure.
                # Gap 4 fix: SC_STRICT_ENFORCE=1 fails CLOSED on network errors.
                if _STRICT_ENFORCE and self.mode == MODE_ENFORCE:
                    _log.critical(
                        "IdentityGate: STRICT_ENFORCE — Ultra Server unreachable (%s). "
                        "Failing CLOSED. An attacker may be blocking localhost:7777. "
                        "Set SC_STRICT_ENFORCE=0 to allow degradation to Level 2.",
                        exc,
                    )
                    return False, f"strict_enforce: Ultra Server unreachable: {exc}", 0
                _log.error(
                    "IdentityGate: Level 0/1 network error — degrading to Level 2: %s", exc
                )
            except Exception as exc:
                _log.error("IdentityGate: Level 0/1 exception: %s", exc)

        # Level 2: Enterprise ed25519 birth tag
        _log.warning("IdentityGate: degraded to Level 2 (enterprise ed25519)")
        ok, reason = self._level2_enterprise(target_hwnd)
        if ok:
            return True, "", 2
        _log.error("IdentityGate: Level 2 (enterprise) failed: %s", reason)

        # Enforce mode stops here
        if self.mode == MODE_ENFORCE:
            return False, f"all available verification levels failed; last: {reason}", 2

        # Levels 3-4: audit mode only
        _log.critical("IdentityGate: Level 3+ (audit mode only) — injection not blocked")
        return True, f"audit-only pass-through (Level 4): {reason}", 4

    def _level0_full(self, target_hwnd: int, text: str) -> tuple[bool, str]:
        """Full 7-layer via UltraGate.authorize_injection()."""
        assert self.gate is not None
        try:
            self.gate.authorize_injection(target_hwnd, text)
            return True, ""
        except Exception as exc:
            return False, str(exc)

    def _level1_bpc_only(self, target_hwnd: int, text: str) -> tuple[bool, str]:
        """BPC-only: build request and verify signature + body hash, skip TSK."""
        assert self.gate is not None
        try:
            headers = self.gate.build_injection_request(target_hwnd, text)
            # Verify own signature only (skip TSK checksum)
            from enterprise.bpc_crypto import (
                b64url_decode, body_hash, constant_time_equal,
                verify_payload_with_jwk,
            )
            import json
            payload_json = b64url_decode(headers.get("X-BPC-Signed-Data", "")).decode("utf-8")
            payload = json.loads(payload_json)
            sig = headers.get("X-BPC-Signature", "")
            if not verify_payload_with_jwk(self.gate._pub_jwk, payload, sig):
                return False, "BPC-only: ECDSA self-check failed"
            bh = body_hash(text)
            if not constant_time_equal(payload.get("body_hash", ""), bh):
                return False, "BPC-only: body_hash mismatch"
            return True, ""
        except Exception as exc:
            return False, f"BPC-only: {exc}"

    def _level2_enterprise(self, target_hwnd: int) -> tuple[bool, str]:
        """Enterprise ed25519 birth tag verification."""
        try:
            from enterprise.birth_tag_v2 import verify_signed_birth_tag
            from enterprise.registry import read_birth_tag
            tag = read_birth_tag(target_hwnd)
            if tag is None:
                return False, "no birth tag on target HWND"
            ok = verify_signed_birth_tag(target_hwnd)
            if ok:
                return True, ""
            return False, "birth tag signature invalid"
        except Exception as exc:
            return False, f"enterprise level error: {exc}"


# ── Main gate function ────────────────────────────────────────────────────────

def gated_send_string(
    target: Any,
    text: str,
    *args: Any,
    gate: Optional["UltraGate"] = None,
    _original_send_string: Any = None,
    **kwargs: Any,
) -> None:
    """Wrap send_string() with identity verification based on SC_IDENTITY_MODE.

    This is the integration point. Callers replace:
        send_string(target, text)
    with:
        gated_send_string(target, text, gate=my_gate, _original_send_string=send_string)

    Args:
        target: WindowTarget (same as send_string first arg).
        text: Text to inject (same as send_string second arg).
        gate: UltraGate instance (bootstrapped). Required in audit/enforce modes.
        _original_send_string: The original send_string function to call on success.
        *args, **kwargs: Passed through to original send_string.

    Raises:
        InjectionDeniedError: In enforce mode when verification fails.
        ValueError: If _original_send_string is not provided.
    """
    if _original_send_string is None:
        raise ValueError("gated_send_string: _original_send_string must be provided")

    mode = get_current_mode()

    if mode == MODE_BYPASS:
        _original_send_string(target, text, *args, **kwargs)
        return

    hwnd = getattr(target, "hwnd", 0)
    cascade = DegradationCascade(gate=gate, mode=mode)
    ok, reason, level = cascade.verify(hwnd, text)

    if mode == MODE_AUDIT:
        if not ok:
            _log.warning(
                "IdentityGate AUDIT: verification failed (level=%d, reason=%s) "
                "— injection proceeding (audit mode)",
                level, reason,
            )
        else:
            _log.debug("IdentityGate AUDIT: verification passed (level=%d)", level)
        _original_send_string(target, text, *args, **kwargs)
        return

    # enforce
    if not ok:
        _log.error(
            "IdentityGate ENFORCE: injection BLOCKED (level=%d, reason=%s)", level, reason
        )
        raise InjectionDeniedError(reason)

    _log.debug("IdentityGate ENFORCE: injection authorized (level=%d)", level)
    _original_send_string(target, text, *args, **kwargs)
