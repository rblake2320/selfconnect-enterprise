"""enterprise/identity_gate.py — Identity Gate: Mode Management + Failsafe System

Controls the three operating modes for the BPC + TSK Ultra identity gate:

  bypass  — No verification. Raw send_string() as today. DEFAULT.
  audit   — Full 7-layer runs, result logged, injection proceeds regardless.
  enforce — Full 7-layer. Failure blocks injection.

Mode is read per-call (not import-time) from SC_IDENTITY_MODE env var.
Follows the existing SC_HANDSHAKE / SC_SUNSET_V1 env-var pattern.

Emergency Bypass (Named Mutex — cross-platform implementation):
  - Creates a file-based mutex: {APPDATA}/SelfConnect/identity_bypass_{username}
  - Forces all terminals to audit mode (NOT full bypass — still logs)
  - Auto-releases when creating process exits (atexit handler)
  - Trigger: python -c "from enterprise.identity_gate import emergency_bypass; emergency_bypass()"
  - Username-scoped — other users can't affect your agents

Graceful Degradation Cascade (enforce mode stops at Level 2):
  Level 0: Full 7-layer (BPC 1-5 + TSK 6-7)     — nominal
  Level 1: BPC-only (5 layers, TSK failed)        — TSK service issue
  Level 2: Enterprise-only (ed25519 + P-384)       — Node.js bridge down
  Level 3: ed25519-only (birth tag verify)          — CNG unavailable
  Level 4: HWND+PID binding only                    — crypto broken
  Level 5: Audit-only pass-through                  — all identity down

In enforce mode: cascade stops at Level 2. Levels 3-5 only in audit mode.

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import atexit
import logging
import os
import platform
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from enterprise.ultra_gate import GateResult, InjectionDeniedError, UltraGate

_log = logging.getLogger(__name__)

# ── Mode constants ────────────────────────────────────────────────────────────

MODE_BYPASS  = "bypass"
MODE_AUDIT   = "audit"
MODE_ENFORCE = "enforce"

_VALID_MODES = {MODE_BYPASS, MODE_AUDIT, MODE_ENFORCE}

# Maximum degradation level allowed in enforce mode.
# Levels 3-5 are only permitted in audit mode.
ENFORCE_MAX_DEGRADATION = 2


# ── Mutex path ────────────────────────────────────────────────────────────────

def _bypass_mutex_path() -> Path:
    """Return the path for the file-based emergency bypass mutex."""
    username = os.environ.get("USERNAME") or os.environ.get("USER") or "default"
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", tempfile.gettempdir()))
    else:
        base = Path(os.environ.get("XDG_RUNTIME_DIR", tempfile.gettempdir()))
    return base / "SelfConnect" / f"identity_bypass_{username}.lock"


def _is_bypass_active() -> bool:
    """Check if the emergency bypass mutex file exists."""
    return _bypass_mutex_path().exists()


def _release_bypass_mutex() -> None:
    """Remove the bypass mutex file (atexit handler)."""
    try:
        p = _bypass_mutex_path()
        if p.exists():
            p.unlink()
            _log.info("IdentityGate: emergency bypass mutex released")
    except Exception:
        pass


def emergency_bypass() -> None:
    """Activate emergency bypass — forces all terminals to audit mode.

    Creates the bypass mutex file and registers an atexit handler to
    release it when the calling process exits.

    Usage:
        python -c "from enterprise.identity_gate import emergency_bypass; emergency_bypass()"
    """
    p = _bypass_mutex_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"bypass activated by pid={os.getpid()} at {time.time()}\n")
    atexit.register(_release_bypass_mutex)
    _log.warning("IdentityGate: EMERGENCY BYPASS ACTIVATED — all gates forced to audit mode. "
                 "Mutex: %s", p)


# ── Mode reader ───────────────────────────────────────────────────────────────

def get_identity_mode() -> str:
    """Read SC_IDENTITY_MODE per-call (not cached at import time).

    If emergency bypass mutex is active, returns audit regardless of env var.
    Defaults to bypass if env var is unset or invalid.
    """
    if _is_bypass_active():
        _log.debug("IdentityGate: emergency bypass active — returning audit mode")
        return MODE_AUDIT

    raw = os.environ.get("SC_IDENTITY_MODE", MODE_BYPASS).strip().lower()
    if raw not in _VALID_MODES:
        _log.warning("IdentityGate: invalid SC_IDENTITY_MODE=%r, defaulting to bypass", raw)
        return MODE_BYPASS
    return raw


# ── Degradation level checker ─────────────────────────────────────────────────

def _check_degradation_allowed(degraded_level: int, mode: str) -> bool:
    """Return True if the degradation level is permitted in the given mode."""
    if mode == MODE_ENFORCE:
        return degraded_level <= ENFORCE_MAX_DEGRADATION
    # bypass and audit allow all degradation levels
    return True


# ── Gate result dataclass ─────────────────────────────────────────────────────

@dataclass
class IdentityGateDecision:
    """Final decision from the identity gate for a single injection attempt."""
    allowed: bool
    mode: str
    gate_result: Optional[GateResult]
    degraded: bool = False
    degraded_level: int = 0
    reason: str = "ok"
    bypass_active: bool = False


# ── IdentityGate ──────────────────────────────────────────────────────────────

class IdentityGate:
    """Mode-aware wrapper around UltraGate.

    Usage:
        gate = IdentityGate(ultra_gate, ledger)
        decision = gate.check_injection(target_hwnd, text)
        if not decision.allowed:
            raise InjectionDeniedError(decision.reason)
    """

    def __init__(
        self,
        ultra_gate: Optional[UltraGate],
        ledger: Any,  # enterprise.ledger.AgentLedger
        agent_id: str = "",
    ) -> None:
        self._ultra_gate = ultra_gate
        self._ledger = ledger
        self._agent_id = agent_id

    def check_injection(
        self,
        target_hwnd: int,
        text: str,
        method: str = "INJECT",
        path: str = "/inject",
    ) -> IdentityGateDecision:
        """Run the identity gate for a single injection attempt.

        Returns IdentityGateDecision with allowed=True/False.
        Always logs to ledger in audit and enforce modes.
        """
        mode = get_identity_mode()
        bypass_active = _is_bypass_active()

        # ── bypass mode ───────────────────────────────────────────────────────
        if mode == MODE_BYPASS:
            return IdentityGateDecision(
                allowed=True,
                mode=mode,
                gate_result=None,
                reason="bypass_mode",
                bypass_active=bypass_active,
            )

        # ── audit / enforce: run UltraGate ────────────────────────────────────
        gate_result: Optional[GateResult] = None
        degraded_level = 0

        if self._ultra_gate is None:
            # No gate bootstrapped — degrade to Level 5 (audit-only pass-through)
            degraded_level = 5
            gate_result = GateResult(ok=True, layer=0, reason="no_gate_bootstrapped",
                                     degraded=True, degraded_level=5)
        elif not self._ultra_gate.bootstrapped:
            degraded_level = 5
            gate_result = GateResult(ok=True, layer=0, reason="gate_not_bootstrapped",
                                     degraded=True, degraded_level=5)
        else:
            try:
                gate_result = self._ultra_gate.verify_injection(target_hwnd, text, method, path)
                degraded_level = gate_result.degraded_level
            except Exception as exc:
                _log.error("IdentityGate: UltraGate.verify_injection raised: %s", exc)
                degraded_level = 5
                gate_result = GateResult(ok=False, layer=0, reason=f"gate_exception:{exc}",
                                         degraded=True, degraded_level=5)

        # ── Degradation level check (enforce mode) ────────────────────────────
        if mode == MODE_ENFORCE and not _check_degradation_allowed(degraded_level, mode):
            # Degradation level too high for enforce mode — block injection
            self._log_ledger("ultra_gate_deny",
                             f"degradation_level_{degraded_level}_not_allowed_in_enforce",
                             gate_result)
            return IdentityGateDecision(
                allowed=False,
                mode=mode,
                gate_result=gate_result,
                degraded=True,
                degraded_level=degraded_level,
                reason=f"degradation_level_{degraded_level}_not_allowed_in_enforce",
                bypass_active=bypass_active,
            )

        # ── Gate result evaluation ────────────────────────────────────────────
        if gate_result.ok:
            self._log_ledger("ultra_gate_pass", "ok", gate_result)
            return IdentityGateDecision(
                allowed=True,
                mode=mode,
                gate_result=gate_result,
                degraded=gate_result.degraded,
                degraded_level=degraded_level,
                reason="ok",
                bypass_active=bypass_active,
            )
        else:
            # Gate failed
            self._log_ledger("ultra_gate_deny", gate_result.reason, gate_result)
            if mode == MODE_AUDIT:
                # Audit: log but allow
                _log.warning("IdentityGate [AUDIT]: injection would be denied reason=%s layer=L%d agent=%s",
                             gate_result.reason, gate_result.layer, self._agent_id)
                return IdentityGateDecision(
                    allowed=True,
                    mode=mode,
                    gate_result=gate_result,
                    degraded=gate_result.degraded,
                    degraded_level=degraded_level,
                    reason=gate_result.reason,
                    bypass_active=bypass_active,
                )
            else:
                # Enforce: block
                return IdentityGateDecision(
                    allowed=False,
                    mode=mode,
                    gate_result=gate_result,
                    degraded=gate_result.degraded,
                    degraded_level=degraded_level,
                    reason=gate_result.reason,
                    bypass_active=bypass_active,
                )

    def _log_ledger(self, action: str, result: str, gate_result: Optional[GateResult]) -> None:
        """Log gate decision to AgentLedger."""
        if self._ledger is None:
            return
        try:
            metadata = {}
            if gate_result:
                metadata = {
                    "layer": gate_result.layer,
                    "degraded": gate_result.degraded,
                    "degraded_level": gate_result.degraded_level,
                }
            self._ledger.log(action, result=result, metadata=metadata)
        except Exception as exc:
            _log.warning("IdentityGate: ledger.log failed: %s", exc)


# ── Convenience: guarded send_string wrapper ──────────────────────────────────

def guarded_send_string(
    send_fn: Callable[[Any, str], None],
    target: Any,
    text: str,
    gate: Optional[IdentityGate] = None,
    ledger: Any = None,
) -> None:
    """Wrap a send_string() call with the identity gate.

    This is the 4-line guard described in the integration plan for self_connect.py:

        from enterprise.identity_gate import guarded_send_string
        guarded_send_string(original_send_string, target, text, gate=self._gate)

    If gate is None or mode is bypass, falls through to send_fn immediately.
    In audit mode: logs result, always calls send_fn.
    In enforce mode: raises InjectionDeniedError if gate rejects.
    """
    if gate is None:
        send_fn(target, text)
        return

    hwnd = getattr(target, "hwnd", 0) or getattr(target, "_hwnd", 0) or 0
    decision = gate.check_injection(hwnd, text)

    if decision.allowed:
        send_fn(target, text)
    else:
        raise InjectionDeniedError(decision.reason, layer=decision.gate_result.layer if decision.gate_result else 0)


# ── Degradation level descriptions ───────────────────────────────────────────

DEGRADATION_DESCRIPTIONS = {
    0: "Full 7-layer (BPC L1-5 + TSK L6-7) — nominal",
    1: "BPC-only (5 layers, TSK failed) — TSK service issue",
    2: "Enterprise-only (ed25519 + P-384) — Node.js bridge down",
    3: "ed25519-only (birth tag verify) — CNG unavailable",
    4: "HWND+PID binding only — crypto broken",
    5: "Audit-only pass-through — all identity down",
}
