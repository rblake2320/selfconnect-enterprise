"""enterprise/policy.py — Signed Policy Bundles and Deny-by-Default Enforcer

Every agent action passes through PolicyEnforcer.check() before execution.
The enforcer evaluates eight conditions in order and denies by default — if any
check fails, the action is blocked and the reason is recorded.

Policy bundles are JSON files signed with CngSigner (ECDSA P-384).  The admin
creates and signs a bundle; agents load and verify it at startup.  No signature
→ no policy.  Invalid signature → reject.

Example policy bundle (JSON):
    {
        "policy_id": "policy-2026-05-07-v1",
        "signed_by": "SC-ADMIN1234",
        "signed_by_pub": "<96-byte hex public key>",
        "valid_from": 1746662400.0,
        "valid_until": null,
        "agents": {
            "SC-E9D14FA8": {
                "role": "orchestrator",
                "clearance": "SECRET",
                "allowed_targets": ["SC-B7121C44"],
                "allowed_apps": ["WindowsTerminal.exe"],
                "blocked_apps": ["chrome.exe", "outlook.exe"],
                "allowed_actions": ["assign_task", "read_text"],
                "requires_operator_approval": ["export_content"],
                "max_classification": "SECRET",
                "revoked": false
            }
        },
        "sig": "<hex signature>"
    }

Evaluation order (PolicyEnforcer.check):
    1. Agent registered in policy
    2. Agent not revoked                       (→ quarantined)
    3. Policy time window valid
    4. Policy signature valid                  (if require_signature=True)
    5. Target agent permitted
    6. Application permitted
    7. Action permitted
    8. Classification ceiling not exceeded
    9. Approval gate                           (flagged, not enforced — caller handles queue)

Ledger integration:
    decision.to_ledger_metadata() returns a dict ready to pass to
    AgentLedger.log() or CngLedger.log() as the metadata= argument.

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ── Classification levels ──────────────────────────────────────────────────────

_CLASSIFICATION_RANK: dict[str, int] = {
    "UNCLASSIFIED": 0,
    "CUI":          1,
    "SECRET":       2,
    "TOP_SECRET":   3,
}

CLASSIFICATION_LEVELS = list(_CLASSIFICATION_RANK.keys())


def _rank(level: str) -> int:
    """Return numeric rank for a classification string.  Unknown → -1."""
    return _CLASSIFICATION_RANK.get(level.upper(), -1)


# ── AgentPolicy ────────────────────────────────────────────────────────────────

@dataclass
class AgentPolicy:
    """Per-agent policy record loaded from a PolicyBundle.

    allowed_targets:               empty list = no restriction (any target)
    allowed_apps:                  empty list = all apps permitted (use blocked_apps to restrict)
    blocked_apps:                  explicit deny list — checked before allowed_apps
    allowed_actions:               empty list = deny-by-default (no actions permitted)
    requires_operator_approval:    actions that need a human step-up approval
    max_classification:            highest data label this agent may process
    revoked:                       True → every action is quarantined
    """
    agent_id:                   str
    role:                       str
    clearance:                  str
    allowed_targets:            list[str]
    allowed_apps:               list[str]
    blocked_apps:               list[str]
    allowed_actions:            list[str]
    requires_operator_approval: list[str]
    max_classification:         str
    revoked:                    bool = False

    @classmethod
    def from_dict(cls, agent_id: str, d: dict) -> "AgentPolicy":
        return cls(
            agent_id                   = agent_id,
            role                       = d.get("role", "unknown"),
            clearance                  = d.get("clearance", "UNCLASSIFIED"),
            allowed_targets            = list(d.get("allowed_targets", [])),
            allowed_apps               = list(d.get("allowed_apps", [])),
            blocked_apps               = list(d.get("blocked_apps", [])),
            allowed_actions            = list(d.get("allowed_actions", [])),
            requires_operator_approval = list(d.get("requires_operator_approval", [])),
            max_classification         = d.get("max_classification", "UNCLASSIFIED"),
            revoked                    = bool(d.get("revoked", False)),
        )


# ── PolicyDecision ─────────────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    """Result of a PolicyEnforcer.check() evaluation.

    Pass to_ledger_metadata() as the metadata= argument on AgentLedger.log()
    or CngLedger.log() to record the policy decision in the audit chain.
    """
    allowed:          bool
    reason:           str
    requires_approval: bool  = False
    policy_id:        str   = ""
    classification:   str   = "UNCLASSIFIED"
    approval_mode:    str   = "autonomous"     # "autonomous"|"human_approved"|"denied"|"quarantined"
    agent_id:         str   = ""
    action:           str   = ""

    def to_ledger_metadata(self) -> dict:
        """Return fields suitable for AgentLedger/CngLedger.log(metadata=...)."""
        return {
            "policy_id":     self.policy_id,
            "classification": self.classification,
            "approval_mode": self.approval_mode,
            "decision":      "allow" if self.allowed else "deny",
        }


# ── PolicyBundle ───────────────────────────────────────────────────────────────

class PolicyBundle:
    """An immutable signed policy bundle loaded from a JSON file or dict.

    Call from_file() or from_dict() to construct.  After construction the
    bundle is read-only — modifications require a new sign-and-save cycle
    via enterprise.policy_sign.sign_policy().
    """

    def __init__(self, raw: dict) -> None:
        self._raw       = raw
        self._policy_id = raw.get("policy_id", "")
        self._signed_by = raw.get("signed_by", "")
        self._signed_by_pub = raw.get("signed_by_pub", "")
        self._valid_from    = float(raw.get("valid_from", 0.0))
        _until = raw.get("valid_until")
        self._valid_until: Optional[float] = float(_until) if _until is not None else None
        self._sig = raw.get("sig", "")

        agents_raw = raw.get("agents", {})
        self._agents: dict[str, AgentPolicy] = {
            aid: AgentPolicy.from_dict(aid, agent_raw)
            for aid, agent_raw in agents_raw.items()
        }

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyBundle":
        """Build a PolicyBundle from a Python dict."""
        return cls(d)

    @classmethod
    def from_file(cls, path: Path) -> "PolicyBundle":
        """Load a PolicyBundle from a JSON file."""
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return a copy of the raw dict (includes sig if present)."""
        return dict(self._raw)

    def to_signable_bytes(self) -> bytes:
        """Canonical bytes over which the signature is computed.

        Excludes 'sig' and 'signed_by_pub' so that adding a signature does not
        invalidate itself.  Canonical form: sorted keys, no whitespace.
        """
        d = {k: v for k, v in self._raw.items() if k not in ("sig", "signed_by_pub")}
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    def save(self, path: Path) -> None:
        """Write the bundle as formatted JSON to path."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._raw, indent=2), encoding="utf-8")

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def policy_id(self) -> str:
        return self._policy_id

    @property
    def signed_by(self) -> str:
        """agent_id of the signing authority."""
        return self._signed_by

    @property
    def signed_by_pub(self) -> str:
        """Hex-encoded 96-byte ECDSA P-384 public key of the signing authority."""
        return self._signed_by_pub

    @property
    def sig(self) -> str:
        """Hex-encoded signature over to_signable_bytes()."""
        return self._sig

    def is_time_valid(self, now: Optional[float] = None) -> bool:
        """Return True if the current time is within [valid_from, valid_until]."""
        t = now if now is not None else time.time()
        if t < self._valid_from:
            return False
        if self._valid_until is not None and t > self._valid_until:
            return False
        return True

    def get_agent(self, agent_id: str) -> Optional[AgentPolicy]:
        """Return the AgentPolicy for agent_id, or None if not registered."""
        return self._agents.get(agent_id)

    def agent_ids(self) -> list[str]:
        return list(self._agents.keys())

    def __repr__(self) -> str:
        return f"PolicyBundle(id={self._policy_id!r}, agents={len(self._agents)})"


# ── PolicyEnforcer ─────────────────────────────────────────────────────────────

class PolicyEnforcer:
    """8-step deny-by-default policy enforcer.

    Construct once at agent startup.  Call check() before every action.

    Args:
        policy:           The loaded and optionally pre-verified PolicyBundle.
        trust_root_pub:   32 or 96-byte public key of the signing authority.
                          If provided, signature is verified on first check().
                          If None and require_signature=True, sig is verified
                          using the 'signed_by_pub' field embedded in the bundle.
        require_signature: If True (default), fail-closed if signature is absent
                          or invalid.  Set False only in development/test mode.
    """

    def __init__(
        self,
        policy: PolicyBundle,
        trust_root_pub: Optional[bytes] = None,
        require_signature: bool = True,
    ) -> None:
        self._policy          = policy
        self._trust_root_pub  = trust_root_pub
        self._require_sig     = require_signature
        self._sig_ok: Optional[bool] = None   # lazily cached

    # ── Public API ─────────────────────────────────────────────────────────────

    def check(
        self,
        agent_id: str,
        action: str,
        *,
        target_agent: Optional[str] = None,
        app: Optional[str] = None,
        classification: str = "UNCLASSIFIED",
    ) -> PolicyDecision:
        """Evaluate whether agent_id may perform action.

        Args:
            agent_id:       The acting agent's SC-XXXXXXXX identifier.
            action:         The action string, e.g. "assign_task".
            target_agent:   Recipient agent_id (for routed messages).
            app:            Application name being targeted (e.g. "notepad.exe").
            classification: Data classification label of the payload/context.

        Returns:
            PolicyDecision — callers must check .allowed before proceeding.
            Pass .to_ledger_metadata() to the ledger to record the decision.
        """
        pid  = self._policy.policy_id
        base = dict(
            policy_id      = pid,
            classification = classification,
            agent_id       = agent_id,
            action         = action,
        )

        def _deny(reason: str, mode: str = "denied") -> PolicyDecision:
            return PolicyDecision(allowed=False, reason=reason, approval_mode=mode, **base)

        def _allow(reason: str, *, requires_approval: bool = False) -> PolicyDecision:
            mode = "human_approved" if requires_approval else "autonomous"
            return PolicyDecision(
                allowed=True, reason=reason,
                requires_approval=requires_approval, approval_mode=mode, **base,
            )

        # 1. Agent registered
        agent = self._policy.get_agent(agent_id)
        if agent is None:
            return _deny(f"agent {agent_id!r} not registered in policy {pid!r}")

        # 2. Not revoked
        if agent.revoked:
            return _deny(f"agent {agent_id!r} is revoked", mode="quarantined")

        # 3. Time window
        if not self._policy.is_time_valid():
            return _deny(f"policy {pid!r} is outside its valid time window")

        # 4. Signature
        if self._require_sig:
            if not self._verify_sig():
                return _deny(f"policy {pid!r} signature invalid or missing")

        # 5. Target permitted
        if target_agent is not None and agent.allowed_targets:
            if target_agent not in agent.allowed_targets:
                return _deny(
                    f"target {target_agent!r} not in allowed_targets for {agent_id!r}"
                )

        # 6. App permitted
        if app is not None:
            if app in agent.blocked_apps:
                return _deny(f"app {app!r} is explicitly blocked for {agent_id!r}")
            if agent.allowed_apps and app not in agent.allowed_apps:
                return _deny(f"app {app!r} not in allowed_apps for {agent_id!r}")

        # 7. Action permitted
        if action not in agent.allowed_actions:
            return _deny(f"action {action!r} not in allowed_actions for {agent_id!r}")

        # 8. Classification ceiling
        if _rank(classification) > _rank(agent.max_classification):
            return _deny(
                f"classification {classification!r} exceeds max "
                f"{agent.max_classification!r} for {agent_id!r}"
            )

        # Step 9 — approval gate (flagged, not blocked — caller drives queue)
        requires_approval = action in agent.requires_operator_approval
        return _allow(
            f"action {action!r} permitted for agent {agent_id!r}",
            requires_approval=requires_approval,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _verify_sig(self) -> bool:
        """Verify policy bundle signature.  Result is cached after first call."""
        if self._sig_ok is not None:
            return self._sig_ok

        if not self._policy.sig:
            self._sig_ok = False
            return False

        try:
            from enterprise.policy_sign import verify_policy_signature
            # Use caller-supplied trust root, or fall back to the bundle's embedded pubkey
            pub: Optional[bytes] = self._trust_root_pub
            if pub is None and self._policy.signed_by_pub:
                pub = bytes.fromhex(self._policy.signed_by_pub)
            if pub is None:
                self._sig_ok = False
                return False
            self._sig_ok = verify_policy_signature(self._policy, pub)
        except Exception:
            self._sig_ok = False

        return self._sig_ok


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_bundle(
    policy_id: str,
    agents: dict,
    signed_by: str = "",
    valid_from: Optional[float] = None,
    valid_until: Optional[float] = None,
) -> PolicyBundle:
    """Construct an unsigned PolicyBundle dict — pass to sign_policy() before use.

    Args:
        policy_id:   Unique string identifier for this policy version.
        agents:      Dict mapping agent_id → AgentPolicy field dict.
        signed_by:   Signer agent_id (filled by sign_policy()).
        valid_from:  Unix epoch; defaults to now.
        valid_until: Unix epoch; None = no expiry.

    Returns:
        An unsigned PolicyBundle (sig field absent).
    """
    return PolicyBundle.from_dict({
        "policy_id":   policy_id,
        "signed_by":   signed_by,
        "valid_from":  valid_from if valid_from is not None else time.time(),
        "valid_until": valid_until,
        "agents":      agents,
    })


__all__ = [
    "AgentPolicy",
    "PolicyDecision",
    "PolicyBundle",
    "PolicyEnforcer",
    "make_bundle",
    "CLASSIFICATION_LEVELS",
]
