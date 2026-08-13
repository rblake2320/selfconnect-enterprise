"""Fail-closed signed birth-tag verifier.

Legacy sunset variables remain observable for deployment reporting, but they
never authorize an unsigned or unverifiable peer.  There is deliberately no
environment-variable bypass for identity verification.

Usage:
    from enterprise.version_gate import VersionGate

    gate = VersionGate()
    result = gate.check_peer(peer_hwnd, public_key_bytes)
    if not result.ok:
        raise RuntimeError(f"peer rejected: {result.reason}")

Flags:
    SC_SUNSET_V1=<ISO-8601 date>  — e.g. "2026-08-01" (date only, UTC midnight)
Version: 1.0.0-enterprise  Tier 2
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_log = logging.getLogger(__name__)

# ── Env config ────────────────────────────────────────────────────────────────

def _sunset_date() -> Optional[datetime]:
    """Parse SC_SUNSET_V1 env var as UTC midnight datetime, or None if unset."""
    raw = os.environ.get("SC_SUNSET_V1", "")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        _log.error("SC_SUNSET_V1 value %r is not a valid ISO date — enforcement disabled", raw)
        return None


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class GateResult:
    ok:     bool
    reason: str
    phase:  str   # "none" | "grace" | "sunset"


# ── VersionGate ───────────────────────────────────────────────────────────────

class VersionGate:
    """Per-peer version gate check.  Instantiate once; call check_peer() for each candidate.

    Thread-safe: all state is derived from env vars at call time.  No mutable instance state.
    """

    def check_peer(
        self,
        peer_hwnd: int,
        public_key_bytes: Optional[bytes],
        *,
        now: Optional[datetime] = None,
        max_sig_age_seconds: float = 60.0,
    ) -> GateResult:
        """Evaluate whether a peer should be accepted given current gate phase.

        Args:
            peer_hwnd:          HWND of the peer to check.
            public_key_bytes:   32-byte ed25519 public key to verify SCID_SIG with.
                                Pass None to trigger the 'no pubkey' path (peer not
                                identified yet).
            now:                Override current time (for testing).
            max_sig_age_seconds: Positive maximum SCID_SIG age.

        Returns:
            GateResult with ok=True if peer is accepted.
        """
        sunset = _sunset_date()
        now_dt = now or datetime.now(tz=timezone.utc)
        after_sunset = sunset is not None and now_dt >= sunset
        phase = "sunset" if after_sunset else ("grace" if sunset is not None else "enforced")

        # Read SCID_SIG from the peer's window
        from enterprise.registry import get_agent_prop
        sig_hex = get_agent_prop(peer_hwnd, "SCID_SIG")

        if not sig_hex:
            _log.warning(
                "unsigned_peer_rejected peer_hwnd=%#x phase=%s",
                peer_hwnd,
                phase,
            )
            return GateResult(
                ok=False,
                reason="unsigned peer rejected: SCID_SIG is required",
                phase=phase,
            )

        # Peer has SCID_SIG — verify it
        if public_key_bytes is None:
            return GateResult(
                ok=False,
                reason="SCID_SIG present but no public_key_bytes provided for verification",
                phase=phase,
            )

        from enterprise.birth_tag_v2 import verify_signed_birth_tag
        ok, btag_reason = verify_signed_birth_tag(
            peer_hwnd, public_key_bytes, max_age_seconds=max_sig_age_seconds
        )
        if ok:
            return GateResult(ok=True, reason="SCID_SIG valid", phase=phase)
        else:
            _log.warning(
                "scid_sig_verification_failed peer_hwnd=%#x reason=%s",
                peer_hwnd, btag_reason,
            )
            return GateResult(
                ok=False,
                reason=f"SCID_SIG verification failed: {btag_reason}",
                phase=phase,
            )

    @staticmethod
    def current_phase(now: Optional[datetime] = None) -> str:
        """Return the current gate phase: 'none', 'grace', or 'sunset'."""
        sunset = _sunset_date()
        if sunset is None:
            return "enforced"
        now_dt = now or datetime.now(tz=timezone.utc)
        return "sunset" if now_dt >= sunset else "grace"
