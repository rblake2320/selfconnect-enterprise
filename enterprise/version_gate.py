"""enterprise/version_gate.py — Signed-Tag Verifier + v1 Sunset Gate (Tier 2)

Controls whether peers without a valid SCID_SIG are accepted or rejected.
Gated on SC_SUNSET_V1=<ISO date> (default: unset = no enforcement, v1 accepted).

Behaviour by phase:

    Phase 0 — no flag set:
        All peers accepted regardless of SCID_SIG presence.  No logging of
        unsigned peers.  This is the Tier 1 baseline behaviour.

    Phase 1 — flag set, before sunset date (grace period):
        Unsigned peers: accepted with a WARNING log and a
        `v1_peer_accepted_during_grace` ledger event.
        Signed peers with valid SCID_SIG: accepted normally.
        Signed peers with invalid SCID_SIG: rejected.

    Phase 2 — flag set, on or after sunset date:
        Unsigned peers: rejected with `v1_peer_rejected_at_sunset` log.
        Signed peers with valid SCID_SIG: accepted.
        Signed peers with invalid/expired SCID_SIG: rejected.

    Emergency override (SC_DISABLE_SIG_VERIFY=1):
        Skips ALL signature checks — every peer is accepted.
        Emits `emergency_override_activated` log every time it is invoked.
        Documented in ROLLBACK.md.

Usage:
    from enterprise.version_gate import VersionGate

    gate = VersionGate()
    result = gate.check_peer(peer_hwnd, public_key_bytes)
    if not result.ok:
        raise RuntimeError(f"peer rejected: {result.reason}")

Flags:
    SC_SUNSET_V1=<ISO-8601 date>  — e.g. "2026-08-01" (date only, UTC midnight)
    SC_DISABLE_SIG_VERIFY=1       — emergency override (ROLLBACK.md)

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


def _emergency_override() -> bool:
    return os.environ.get("SC_DISABLE_SIG_VERIFY", "").strip() == "1"


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
            max_sig_age_seconds: Maximum SCID_SIG age.  Pass 0.0 to disable anti-replay
                                 (useful in tests).

        Returns:
            GateResult with ok=True if peer is accepted.
        """
        if _emergency_override():
            _log.critical(
                "emergency_override_activated peer_hwnd=%#x — SC_DISABLE_SIG_VERIFY=1",
                peer_hwnd,
            )
            return GateResult(ok=True, reason="emergency override active", phase="override")

        sunset = _sunset_date()
        now_dt = now or datetime.now(tz=timezone.utc)

        if sunset is None:
            # Phase 0: no enforcement
            return GateResult(ok=True, reason="no sunset configured", phase="none")

        after_sunset = now_dt >= sunset

        # Read SCID_SIG from the peer's window
        from enterprise.registry import get_agent_prop
        sig_hex = get_agent_prop(peer_hwnd, "SCID_SIG")

        if not sig_hex:
            # Unsigned peer
            if after_sunset:
                _log.warning(
                    "v1_peer_rejected_at_sunset peer_hwnd=%#x — no SCID_SIG after sunset %s",
                    peer_hwnd, sunset.date(),
                )
                return GateResult(
                    ok=False,
                    reason="unsigned peer rejected: past SC_SUNSET_V1 date",
                    phase="sunset",
                )
            else:
                _log.warning(
                    "v1_peer_accepted_during_grace peer_hwnd=%#x — no SCID_SIG (grace until %s)",
                    peer_hwnd, sunset.date(),
                )
                return GateResult(
                    ok=True,
                    reason="unsigned peer accepted during grace period",
                    phase="grace",
                )

        # Peer has SCID_SIG — verify it
        if public_key_bytes is None:
            return GateResult(
                ok=False,
                reason="SCID_SIG present but no public_key_bytes provided for verification",
                phase="sunset" if after_sunset else "grace",
            )

        from enterprise.birth_tag_v2 import verify_signed_birth_tag
        ok, btag_reason = verify_signed_birth_tag(
            peer_hwnd, public_key_bytes, max_age_seconds=max_sig_age_seconds
        )
        if ok:
            phase = "sunset" if after_sunset else "grace"
            return GateResult(ok=True, reason="SCID_SIG valid", phase=phase)
        else:
            _log.warning(
                "scid_sig_verification_failed peer_hwnd=%#x reason=%s",
                peer_hwnd, btag_reason,
            )
            return GateResult(
                ok=False,
                reason=f"SCID_SIG verification failed: {btag_reason}",
                phase="sunset" if after_sunset else "grace",
            )

    @staticmethod
    def current_phase(now: Optional[datetime] = None) -> str:
        """Return the current gate phase: 'none', 'grace', or 'sunset'."""
        if _emergency_override():
            return "override"
        sunset = _sunset_date()
        if sunset is None:
            return "none"
        now_dt = now or datetime.now(tz=timezone.utc)
        return "sunset" if now_dt >= sunset else "grace"
