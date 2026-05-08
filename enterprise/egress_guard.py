"""enterprise/egress_guard.py — Outbound Call Restriction Enforcer

Wraps any outbound API call (cloud LLM, external service) and enforces the
ClassifiedModeProfile.allow_cloud_egress flag.  Every check — allowed or
denied — is logged to the agent's ledger for full auditability.

Usage:
    from enterprise.egress_guard import EgressGuard
    from enterprise.classified_mode import ClassifiedModeProfile

    profile = ClassifiedModeProfile.secret_baseline()
    guard   = EgressGuard(profile, ledger)

    # Inline check
    if guard.check_outbound("api.anthropic.com", agent_id="SC-AGENT1"):
        response = call_api(...)

    # Wrapping pattern
    result = guard.wrap(call_api, "api.anthropic.com", "SC-AGENT1")

Version: 1.0.0-enterprise  Session 18
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from enterprise.classified_mode import ClassifiedModeProfile


class EgressGuard:
    """Enforces outbound call restrictions from a ClassifiedModeProfile.

    Every check is logged to the ledger regardless of outcome.  When
    allow_cloud_egress is False, the check returns False and logs a denial.
    The actual outbound call is never made.

    Args:
        profile: The active ClassifiedModeProfile.
        ledger:  Optional AgentLedger / CngLedger.  When provided, every
                 check is recorded as an "egress_check" entry.
    """

    def __init__(
        self,
        profile: ClassifiedModeProfile,
        ledger: Any = None,
    ) -> None:
        self._profile = profile
        self._ledger  = ledger

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_outbound(self, destination: str, agent_id: str = "") -> bool:
        """Return True if outbound call to destination is permitted.

        Args:
            destination: Human-readable destination name (e.g. "api.anthropic.com").
            agent_id:    The agent making the call (for ledger attribution).

        Returns:
            True if profile.allow_cloud_egress is True.
            False otherwise — the call must NOT be made.
        """
        allowed = self._profile.allow_cloud_egress
        self._log(
            agent_id    = agent_id,
            destination = destination,
            allowed     = allowed,
        )
        return allowed

    def wrap(
        self,
        fn: Callable[..., Any],
        destination: str,
        agent_id: str = "",
        *args: Any,
        **kwargs: Any,
    ) -> Optional[Any]:
        """Call fn(*args, **kwargs) only if check_outbound passes.

        Args:
            fn:          The function to call if egress is permitted.
            destination: Destination name for logging.
            agent_id:    Agent making the call.
            *args:       Forwarded to fn.
            **kwargs:    Forwarded to fn.

        Returns:
            Return value of fn(...) if allowed, or None if denied.
        """
        if not self.check_outbound(destination, agent_id):
            return None
        return fn(*args, **kwargs)

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def profile(self) -> ClassifiedModeProfile:
        return self._profile

    # ── Internal ──────────────────────────────────────────────────────────────

    def _log(self, agent_id: str, destination: str, allowed: bool) -> None:
        if self._ledger is None:
            return
        self._ledger.log(
            "egress_check",
            result = "allowed" if allowed else "denied",
            metadata = {
                "destination":  destination,
                "agent_id":     agent_id,
                "profile_id":   self._profile.profile_id,
                "decision":     "allow" if allowed else "deny",
            },
        )


__all__ = ["EgressGuard"]
