"""enterprise/composition_monitor.py — Stateful Composition Constraint Monitor

Closes GAPS.md gap #2 (composition attacks). Sits AFTER PolicyEnforcer.check():
per-call proofs verify each call is authorized; this layer verifies the
*sequence* of authorized calls does not compose into a dangerous shape.

Design contract:
    - Fail-CLOSED: any internal error -> deny.
    - Non-bypassing: evaluates only calls the PolicyEnforcer already ALLOWED.
      (An already-denied call never reaches here; this can only *further*
      restrict, never widen.)
    - Auditable: every verdict is emitted as ledger metadata, same shape as
      PolicyDecision.to_ledger_metadata().
    - Deterministic + patent-relevant: signatures are declarative "effect
      shapes" over a bounded sliding window, so a verdict is reproducible from
      the window contents alone (proof-carrying composition constraint).

Version: 1.0.0-enterprise
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional


# ── Effect taxonomy ─────────────────────────────────────────────────────────
# Map raw actions to coarse *effects*. This is the effect-scoping substrate
# GAPS.md:BPC-2 lacks. Unmapped actions default to "unknown" (treated as
# elevated, never benign) so new tools cannot silently bypass composition rules.
DEFAULT_EFFECT_MAP: dict[str, str] = {
    "read_text":      "recon",
    "read_screen":    "recon",
    "enumerate":      "recon",
    "list_targets":   "recon",
    "read_file":      "access",
    "assign_task":    "control",
    "write_file":     "mutate",
    "subprocess":     "execute",
    "http_request":   "egress",
    "send_string":    "egress",
    "socket_open":    "egress",
}
ELEVATED_EFFECTS = frozenset({"mutate", "execute", "egress", "unknown"})


@dataclass(frozen=True)
class CompositionSignature:
    """A declarative dangerous-sequence shape evaluated over the window.

    ordered_effects: effects that must appear IN ORDER (not necessarily
                     adjacent) within the window to trip the signature.
    reason:          human-readable verdict reason.
    """
    name: str
    ordered_effects: tuple[str, ...]
    reason: str

    def matches(self, effect_stream: list[str]) -> bool:
        it = iter(effect_stream)
        return all(any(e == want for e in it) for want in self.ordered_effects)


# The classic exploit arc: look around -> get in -> act -> ship it out.
DEFAULT_SIGNATURES: tuple[CompositionSignature, ...] = (
    CompositionSignature(
        "recon_to_egress", ("recon", "access", "egress"),
        "recon->access->egress arc: authorized calls compose toward exfiltration",
    ),
    CompositionSignature(
        "execute_then_egress", ("execute", "egress"),
        "code execution followed by outbound call: exploit-then-exfil shape",
    ),
    CompositionSignature(
        "mutate_then_execute", ("mutate", "execute"),
        "file write followed by execution: drop-then-run shape",
    ),
)


@dataclass
class CompositionVerdict:
    allowed: bool
    reason: str
    signature: Optional[str] = None
    window_effects: tuple[str, ...] = ()

    def to_ledger_metadata(self) -> dict:
        return {
            "layer":     "composition_monitor",
            "decision":  "allow" if self.allowed else "deny",
            "reason":    self.reason,
            "signature": self.signature or "",
            "window":    ",".join(self.window_effects),
        }


@dataclass
class _AgentWindow:
    effects: Deque[tuple[float, str]] = field(default_factory=deque)
    elevated_count: int = 0


class CompositionMonitor:
    """Stateful, per-agent sliding-window composition constraint enforcer.

    Args:
        window_seconds:  time horizon of the sliding window.
        max_window_len:  hard cap on entries per agent (bounds memory; DoS-safe).
        signatures:      dangerous effect-sequence shapes.
        effect_map:      action -> effect taxonomy.
        max_elevated_rate: max elevated-effect calls allowed within the window
                           before the sequence is denied as anomalous velocity.
        ledger:          optional ledger with .log(event, result=, metadata=).
    """

    def __init__(
        self,
        window_seconds: float = 30.0,
        max_window_len: int = 256,
        signatures: tuple[CompositionSignature, ...] = DEFAULT_SIGNATURES,
        effect_map: Optional[dict[str, str]] = None,
        max_elevated_rate: int = 8,
        ledger=None,
    ) -> None:
        self._window_seconds = float(window_seconds)
        self._max_window_len = int(max_window_len)
        self._signatures = tuple(signatures)
        self._effect_map = dict(effect_map or DEFAULT_EFFECT_MAP)
        self._max_elevated_rate = int(max_elevated_rate)
        self._ledger = ledger
        self._windows: dict[str, _AgentWindow] = {}

    def effect_of(self, action: str) -> str:
        return self._effect_map.get(action, "unknown")

    def observe(self, agent_id: str, action: str, now: Optional[float] = None) -> CompositionVerdict:
        """Record an already-ALLOWED call and evaluate the resulting sequence.

        Returns a fail-closed CompositionVerdict. Callers MUST honor .allowed.
        """
        try:
            now = time.time() if now is None else float(now)
            win = self._windows.setdefault(agent_id, _AgentWindow())
            effect = self.effect_of(action)
            win.effects.append((now, effect))

            # Evict by time and by hard length cap (bounded memory).
            horizon = now - self._window_seconds
            while win.effects and win.effects[0][0] < horizon:
                win.effects.popleft()
            while len(win.effects) > self._max_window_len:
                win.effects.popleft()

            stream = [e for _, e in win.effects]
            elevated = sum(1 for e in stream if e in ELEVATED_EFFECTS)

            # 1. Velocity anomaly.
            if elevated > self._max_elevated_rate:
                return self._deny(agent_id,
                    f"elevated-effect velocity {elevated} > {self._max_elevated_rate} in window",
                    "elevated_velocity", stream)

            # 2. Dangerous composition shapes.
            for sig in self._signatures:
                if sig.matches(stream):
                    return self._deny(agent_id, sig.reason, sig.name, stream)

            return self._allow(stream)
        except Exception as exc:  # fail-closed
            return self._deny(agent_id, f"composition monitor internal error: {exc!r}",
                              "internal_error", ())

    # ── internal ────────────────────────────────────────────────────────────
    def _allow(self, stream: list[str]) -> CompositionVerdict:
        return CompositionVerdict(True, "composition within policy", None, tuple(stream))

    def _deny(self, agent_id, reason, sig, stream) -> CompositionVerdict:
        v = CompositionVerdict(False, reason, sig, tuple(stream))
        if self._ledger is not None:
            try:
                self._ledger.log("composition_check", result="denied", metadata=v.to_ledger_metadata())
            except Exception:
                pass  # ledger failure must not convert a deny into an allow
        return v


__all__ = ["CompositionMonitor", "CompositionSignature", "CompositionVerdict",
           "DEFAULT_SIGNATURES", "DEFAULT_EFFECT_MAP"]
