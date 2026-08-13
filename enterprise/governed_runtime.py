"""Mandatory composition for an enterprise SelfConnect execution runtime.

The component classes remain independently useful, but an actuator is only
governed when identity, signed policy, operator control, target verification,
and signed audit are wired into the same execution path. This module provides
that composition and deliberately refuses insecure defaults.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.approval_audit import (
    DecisionProofVerification,
    LedgerApprovalDecisionSink,
)
from enterprise.composition_monitor import CompositionMonitor
from enterprise.control import ControlPlane
from enterprise.identity import AgentIdentity
from enterprise.ledger import ThreadSafeAgentLedger
from enterprise.mcp_dispatch import MCPDispatcher
from enterprise.mcp_dispatch import DelegationBoundary
from enterprise.acp_shim import RevocationSnapshot, SQLiteActionReplayStore
from enterprise.delegation import public_key_fingerprint
from enterprise.operator import DurableOperatorQueue, _bind_system_denier
from enterprise.policy import PolicyBundle, PolicyEnforcer
from enterprise.runtime_ownership import RuntimeOwnershipLock
from enterprise.runtime_lifetime import RuntimeLifetime
from enterprise.agt_adapter import AGTCedarAdapter


class RuntimeConfigurationError(RuntimeError):
    """The requested runtime cannot meet its declared governance posture."""


@dataclass(frozen=True)
class GovernedRuntime:
    """A single, mandatory governance composition for MCP actuation."""

    identity: AgentIdentity
    ledger: ThreadSafeAgentLedger
    operator_queue: DurableOperatorQueue
    control_plane: ControlPlane
    policy_enforcer: PolicyEnforcer
    composition_monitor: CompositionMonitor
    dispatcher: MCPDispatcher
    ownership_lock: RuntimeOwnershipLock
    runtime_lifetime: RuntimeLifetime
    delegation_replay_store: SQLiteActionReplayStore

    @classmethod
    def from_signed_policy(
        cls,
        *,
        policy_path: Path,
        trust_root_pub: bytes,
        agent_name: str,
        identity_data_dir: Path | None = None,
        ledger_path: Path | None = None,
        approval_db_path: Path | None = None,
        router: Any | None = None,
        target_verifier: Callable[..., dict[str, Any]] | None = None,
        output_reader: Callable[[int], str] | None = None,
        decision_writer_verifier: (
            Callable[
                [dict[str, str], str | bytes | None],
                DecisionProofVerification | None,
            ] | None
        ) = None,
        profile: str = "enterprise",
        ledger_max_entries_per_segment: int = 100_000,
        ledger_max_bytes_per_segment: int = 128 * 1024 * 1024,
        agt_manifest_path: Path | None = None,
        delegation_trust_roots: tuple[bytes, ...] | None = None,
        delegation_revocation_provider: Callable[[], RevocationSnapshot] | None = None,
        delegation_replay_db_path: Path | None = None,
    ) -> "GovernedRuntime":
        """Build a fail-closed runtime from an externally pinned policy root.

        ``government`` is intentionally rejected here. The convenience factory
        uses a DPAPI-backed Ed25519 identity; the government profile requires a
        separately provisioned CNG/TPM identity and deployment-specific FIPS
        validation evidence. Callers must not get an implied downgrade.
        """
        if not trust_root_pub:
            raise RuntimeConfigurationError("an external policy trust root is required")
        if profile != "enterprise":
            raise RuntimeConfigurationError(
                "from_signed_policy currently supports only the enterprise profile; "
                "government deployments require an explicitly provisioned CNG/TPM runtime"
            )
        if decision_writer_verifier is None:
            raise RuntimeConfigurationError(
                "governed runtime requires an operator decision proof verifier"
            )

        policy = PolicyBundle.from_file(Path(policy_path))
        if AgentIdentity.exists(agent_name, data_dir=identity_data_dir):
            identity = AgentIdentity.load(agent_name, data_dir=identity_data_dir)
        else:
            identity = AgentIdentity.init(agent_name, data_dir=identity_data_dir)

        resolved_ledger_path = (
            Path(ledger_path)
            if ledger_path is not None
            else ThreadSafeAgentLedger._default_path(agent_name)
        )
        resolved_approval_path = (
            Path(approval_db_path)
            if approval_db_path is not None
            else resolved_ledger_path.with_suffix(resolved_ledger_path.suffix + ".approvals.sqlite3")
        )
        trusted_delegation_keys = tuple(delegation_trust_roots or (trust_root_pub,))
        trusted_delegation_by_fingerprint = {
            public_key_fingerprint(key): bytes(key) for key in trusted_delegation_keys
        }
        resolved_delegation_replay_path = (
            Path(delegation_replay_db_path)
            if delegation_replay_db_path is not None
            else resolved_approval_path.with_suffix(
                resolved_approval_path.suffix + ".delegation.sqlite3"
            )
        )
        # Acquire stable path locks and reject identical/cross-linked resources
        # before either persistence constructor can open them.
        runtime_lifetime = RuntimeLifetime()
        ownership_lock = RuntimeOwnershipLock(resolved_ledger_path, resolved_approval_path)
        delegation_replay_store: SQLiteActionReplayStore | None = None
        try:
            ledger = ThreadSafeAgentLedger(
                identity,
                log_path=resolved_ledger_path,
                redact_denied=True,
                max_entries_per_segment=ledger_max_entries_per_segment,
                max_bytes_per_segment=ledger_max_bytes_per_segment,
                runtime_lifetime=runtime_lifetime,
            )
            # Bind any existing resource file identities before queue startup
            # reconciliation can append approval evidence to the ledger.
            ownership_lock.bind_opened_resources()
            operator_queue = DurableOperatorQueue(
                resolved_approval_path,
                audit_sink=LedgerApprovalDecisionSink(ledger),
                audit_required=True,
                decision_writer_verifier=decision_writer_verifier,
                runtime_lifetime=runtime_lifetime,
            )
            # A fresh approval database now has an OS file identity; bind and
            # revalidate both paths again before exposing the runtime.
            ownership_lock.bind_opened_resources()
            control_plane = ControlPlane(
                ledger=ledger,
                operator_queue=operator_queue,
                _system_denier=_bind_system_denier(operator_queue),
                runtime_lifetime=runtime_lifetime,
            )
            composition_monitor = CompositionMonitor(
                effect_map={"sc_inject_text": "egress"},
                ledger=ledger,
            )
            classified_profile = ClassifiedModeProfile.cui_baseline()
            policy_enforcer = PolicyEnforcer(
                policy,
                trust_root_pub=trust_root_pub,
                require_signature=True,
                control_plane=control_plane,
                profile=classified_profile,
                composition_monitor=composition_monitor,
                ledger=ledger,
            )
            delegation_replay_store = SQLiteActionReplayStore(resolved_delegation_replay_path)
            delegation_boundary = DelegationBoundary(
                issuer_resolver=lambda fingerprint: trusted_delegation_by_fingerprint.get(fingerprint),
                revocation_provider=(
                    delegation_revocation_provider
                    if delegation_revocation_provider is not None
                    else lambda: RevocationSnapshot(epoch=0)
                ),
                replay_store=delegation_replay_store,
            )
            dispatcher = MCPDispatcher(
                profile=profile,
                router=router,
                control_plane=control_plane,
                ledger=ledger,
                policy_enforcer=policy_enforcer,
                operator_queue=operator_queue,
                target_verifier=target_verifier,
                output_reader=output_reader,
                identity_type="dpapi",
                runtime_lifetime=runtime_lifetime,
                agt_policy_adapter=(
                    AGTCedarAdapter.from_manifest(agt_manifest_path)
                    if agt_manifest_path is not None
                    else None
                ),
                delegation_identity=identity,
                delegation_boundary=delegation_boundary,
            )
            return cls(
                identity=identity,
                ledger=ledger,
                operator_queue=operator_queue,
                control_plane=control_plane,
                policy_enforcer=policy_enforcer,
                composition_monitor=composition_monitor,
                dispatcher=dispatcher,
                ownership_lock=ownership_lock,
                runtime_lifetime=runtime_lifetime,
                delegation_replay_store=delegation_replay_store,
            )
        except Exception:
            runtime_lifetime.close_and_drain()
            if delegation_replay_store is not None:
                delegation_replay_store.close()
            ownership_lock.close()
            raise

    def close(self) -> None:
        self.runtime_lifetime.close_and_drain()
        self.delegation_replay_store.close()
        self.ownership_lock.close()

    def verify_audit(self) -> tuple[bool, int, str]:
        """Verify every signature and hash link in the runtime action ledger."""
        return self.ledger.verify()


__all__ = ["GovernedRuntime", "RuntimeConfigurationError"]
