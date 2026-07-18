"""enterprise/control.py — Operator Control Plane

Thread-safe runtime controls for pause, quarantine, revoke, and mesh-level
kill-switch.  Every control action is a first-class ledger entry — the full
blast radius is auditable.

Integrates with PolicyEnforcer via an optional control_plane= constructor
argument.  When present, enforcer.check() executes a Step 0 control-plane
gate before the 8 existing steps:

    active      → normal evaluation continues
    paused      → deny (approval_mode="paused")
    quarantined → deny (approval_mode="quarantined")
    revoked     → deny (approval_mode="revoked")

State machine (transitions are one-way except pause↔resume):

    active ──pause──► paused ──resume──► active
    active ──quarantine──► quarantined         (no resume; requires revoke + re-register)
    active ──revoke──► revoked                 (terminal)
    paused ──quarantine──► quarantined
    paused ──revoke──► revoked
    quarantined ──revoke──► revoked
    any ──kill_all──► revoked  (all currently registered agents)

OperatorQueue integration:
    quarantine() auto-denies all pending approvals for the affected agent.
    kill_all() auto-denies all pending approvals for all agents.

Ledger integration:
    Every control action produces a ledger entry with action="operator_control"
    and metadata carrying command, agent_id, operator_id, reason, prev_state,
    new_state.  kill_all produces one entry per affected agent.

Version: 1.0.0-enterprise  Session 17
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from enterprise.runtime_lifetime import RuntimeLifetime, governed_operation

# ── AgentControlRecord ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentControlRecord:
    """Immutable record of a single control action.

    Written to the ledger immediately when the state transition is committed.
    """
    agent_id:    str
    command:     str      # "pause" | "resume" | "quarantine" | "revoke" | "kill_all"
    operator_id: str
    reason:      str
    prev_state:  str
    new_state:   str
    ts:          float


# ── Valid states and transition table ─────────────────────────────────────────

_VALID_STATES = frozenset({"active", "paused", "quarantined", "revoked"})

# (current_state, command) → new_state  or None if transition is forbidden
_TRANSITIONS: dict[tuple[str, str], str] = {
    ("active",      "pause"):       "paused",
    ("active",      "quarantine"):  "quarantined",
    ("active",      "revoke"):      "revoked",
    ("paused",      "resume"):      "active",
    ("paused",      "quarantine"):  "quarantined",
    ("paused",      "revoke"):      "revoked",
    ("quarantined", "revoke"):      "revoked",
}


def _next_state(current: str, command: str) -> Optional[str]:
    """Return the resulting state or None if the transition is invalid."""
    return _TRANSITIONS.get((current, command))


# ── ControlPlane ───────────────────────────────────────────────────────────────

class ControlPlane:
    """Thread-safe operator control surface for the agent mesh.

    Maintains runtime state for every registered agent.  Agents are
    auto-registered as "active" on first control action if not already known.
    Use register() to pre-register agents at startup.

    Args:
        ledger:         Optional AgentLedger / CngLedger.  When provided,
                        every state transition is logged as an "operator_control"
                        entry.
        operator_queue: Optional OperatorQueue.  When provided, quarantine()
                        and kill_all() auto-deny pending approvals.
    """

    def __init__(
        self,
        ledger: Any = None,
        operator_queue: Any = None,
        *,
        _system_denier: Any = None,
        runtime_lifetime: RuntimeLifetime | None = None,
    ) -> None:
        self._lock           = threading.Lock()
        self._states:  dict[str, str] = {}        # agent_id → state
        self._history: list[AgentControlRecord] = []
        self._ledger: Any    = ledger
        self._queue: Any     = operator_queue
        self._system_deny = _system_denier
        self._runtime_lifetime = runtime_lifetime
        if self._system_deny is None and operator_queue is not None:
            # Compatibility-only in-memory queues have no privileged proof path.
            from enterprise.operator import OperatorQueue

            if type(operator_queue) is OperatorQueue:
                self._system_deny = operator_queue.deny

    # ── Registration ─────────────────────────────────────────────────────────

    @governed_operation
    def register(self, agent_id: str) -> None:
        """Pre-register an agent as active.  No-op if already registered."""
        with self._lock:
            if agent_id not in self._states:
                self._states[agent_id] = "active"

    # ── Per-agent commands ────────────────────────────────────────────────────

    @governed_operation
    def pause(
        self,
        agent_id: str,
        operator_id: str,
        reason: str = "",
    ) -> AgentControlRecord:
        """Pause an active agent.  Paused agents are denied by the enforcer.

        Raises:
            ValueError: if the transition is not permitted from the current state.
        """
        return self._transition(agent_id, "pause", operator_id, reason)

    @governed_operation
    def resume(
        self,
        agent_id: str,
        operator_id: str,
        reason: str = "",
    ) -> AgentControlRecord:
        """Resume a paused agent back to active.

        Raises:
            ValueError: if the agent is not currently paused.
        """
        return self._transition(agent_id, "resume", operator_id, reason)

    @governed_operation
    def quarantine(
        self,
        agent_id: str,
        operator_id: str,
        reason: str = "",
    ) -> AgentControlRecord:
        """Quarantine an agent.  Drains pending approvals from the operator queue.

        Quarantined agents cannot be resumed — they must be revoked and
        re-registered under a new identity/policy.

        Raises:
            ValueError: if the transition is not permitted (e.g. already revoked).
        """
        record = self._transition(agent_id, "quarantine", operator_id, reason)
        self._drain_queue(agent_id, operator_id)
        return record

    @governed_operation
    def revoke(
        self,
        agent_id: str,
        operator_id: str,
        reason: str = "",
    ) -> AgentControlRecord:
        """Permanently revoke an agent.  Terminal — cannot be un-revoked.

        Raises:
            ValueError: if already revoked.
        """
        return self._transition(agent_id, "revoke", operator_id, reason)

    # ── Mesh-level ────────────────────────────────────────────────────────────

    @governed_operation
    def kill_all(
        self,
        operator_id: str,
        reason: str = "",
    ) -> list[AgentControlRecord]:
        """Revoke all currently registered non-revoked agents in one operation.

        Drains all pending operator queue approvals.

        Returns:
            List of AgentControlRecords — one per affected agent.
            Empty list if all agents are already revoked or none are registered.
        """
        records: list[AgentControlRecord] = []
        with self._lock:
            targets = [
                aid for aid, state in self._states.items()
                if state != "revoked"
            ]

        for aid in targets:
            try:
                rec = self._transition(aid, "revoke", operator_id, reason)
                records.append(rec)
            except ValueError:
                pass  # Already transitioned by a concurrent call

        # Drain the entire queue
        if self._queue is not None and records:
            self._drain_all_queue(operator_id)

        return records

    # ── State queries ──────────────────────────────────────────────────────────

    def get_state(self, agent_id: str) -> str:
        """Return the current state for agent_id.

        Returns "active" for unregistered agents (unknown = not controlled).
        """
        with self._lock:
            return self._states.get(agent_id, "active")

    def get_all_states(self) -> dict[str, str]:
        """Return a snapshot of all registered agent states."""
        with self._lock:
            return dict(self._states)

    def is_active(self, agent_id: str) -> bool:
        """Return True only if the agent is in the "active" state."""
        return self.get_state(agent_id) == "active"

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self, agent_id: Optional[str] = None) -> list[AgentControlRecord]:
        """Return control history, optionally filtered to a single agent."""
        with self._lock:
            if agent_id is None:
                return list(self._history)
            return [r for r in self._history if r.agent_id == agent_id]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _transition(
        self,
        agent_id: str,
        command: str,
        operator_id: str,
        reason: str,
    ) -> AgentControlRecord:
        """Execute a state transition under the lock.

        Raises:
            ValueError: if the transition is not permitted.
        """
        with self._lock:
            prev = self._states.get(agent_id, "active")
            new  = _next_state(prev, command)
            if new is None:
                raise ValueError(
                    f"Cannot {command!r} agent {agent_id!r}: "
                    f"transition from {prev!r} is not permitted"
                )
            record = AgentControlRecord(
                agent_id    = agent_id,
                command     = command,
                operator_id = operator_id,
                reason      = reason,
                prev_state  = prev,
                new_state   = new,
                ts          = time.time(),
            )
            # A governed transition is not visible or accepted until its
            # authoritative provenance receipt commits. Keep the lock so a
            # concurrent reader cannot observe an unaudited intermediate state.
            self._log(record)
            self._states[agent_id] = new
            self._history.append(record)
        return record

    def _log(self, record: AgentControlRecord) -> None:
        """Write the control record to the ledger if one is configured."""
        if self._ledger is None:
            return
        self._ledger.log(
            "operator_control",
            result=f"agent {record.agent_id} {record.new_state}",
            metadata={
                "command":     record.command,
                "subject_agent_id": record.agent_id,
                "operator_id": record.operator_id,
                "reason":      record.reason,
                "prev_state":  record.prev_state,
                "new_state":   record.new_state,
                "event_ts":    record.ts,
            },
        )

    def _drain_queue(self, agent_id: str, operator_id: str) -> int:
        """Deny all pending queue items for a specific agent.  Returns count denied."""
        if self._queue is None:
            return 0
        denied = 0
        for item in self._queue.get_pending():
            if item.agent_id == agent_id:
                if self._system_deny is None:
                    raise RuntimeError("safety-denial capability is unavailable")
                self._system_deny(item.approval_id, f"system/quarantine:{operator_id}")
                denied += 1
        return denied

    def _drain_all_queue(self, operator_id: str) -> int:
        """Deny all pending queue items for all agents.  Returns count denied."""
        if self._queue is None:
            return 0
        denied = 0
        for item in self._queue.get_pending():
            if self._system_deny is None:
                raise RuntimeError("safety-denial capability is unavailable")
            self._system_deny(item.approval_id, f"system/kill_all:{operator_id}")
            denied += 1
        return denied


# ── Public API ─────────────────────────────────────────────────────────────────

__all__ = ["AgentControlRecord", "ControlPlane"]
