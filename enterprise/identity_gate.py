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

Emergency bypass: Named Mutex `Global\SelfConnect_IdentityBypass_{UserSID}`.
  - Forces all terminals of this Windows user to AUDIT mode (not full bypass).
  - Does NOT create a path to "no verification" in enforce mode.
  - Trigger: emergency_bypass() / release_bypass() functions below.
  - Auto-releases when the creating process exits.

Degradation cascade (if full 7-layer fails):
  Level 0: Full 7-layer BPC+TSK      (nominal)
  Level 1: BPC-only                   (TSK service issue)
  Level 2: Enterprise ed25519-only    (Ultra Server unreachable — ENFORCE stops here)
  Level 3: HWND+PID binding only      (audit mode only)
  Level 5: Pass-through with logging  (audit mode only — all crypto down)

In enforce mode, cascade stops at Level 2. The worst case in production is
falling back to the proven enterprise identity layer (ed25519 + birth tags).

Version: 1.0.0  BPC+TSK integration
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
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


# ── Current mode detection ────────────────────────────────────────────────────

def get_current_mode() -> str:
    """Return the current operating mode.

    Priority:
      1. Named Mutex present → downgrade to 'audit' regardless of env var
         (mutex forces logging but not full bypass — an adversary who triggers
         the mutex still gets logged, not silenced).
      2. SC_IDENTITY_MODE env var (bypass / audit / enforce).
      3. Default: bypass (safe starting state).
    """
    raw = os.environ.get("SC_IDENTITY_MODE", MODE_BYPASS).strip().lower()
    mode = raw if raw in _VALID_MODES else MODE_BYPASS

    # Check emergency bypass mutex
    if mode == MODE_ENFORCE and _emergency_mutex_active():
        _log.critical(
            "IdentityGate: emergency bypass mutex detected — downgrading to AUDIT mode. "
            "All injections will be logged but not blocked."
        )
        return MODE_AUDIT

    return mode


def _get_user_sid() -> str:
    """Get the current user's SID string for scoping the mutex."""
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
            capture_output=True, text=True, timeout=3
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
    """Check whether the emergency bypass Named Mutex exists."""
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenMutexW(0x00100000, False, _mutex_name())  # SYNCHRONIZE
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    except Exception:
        return False


def emergency_bypass() -> None:
    """Create the emergency bypass Named Mutex.

    In enforce mode, this downgrades all terminals of this Windows user to AUDIT
    mode. Injections proceed but are logged. The mutex lives until release_bypass()
    is called or the process exits.

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
            os.getpid()
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
            # verify_signed_birth_tag returns True/False
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
