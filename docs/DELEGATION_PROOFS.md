# Delegation Proofs

`enterprise.delegation` keeps permission and authorship distinct:

1. an authority signs a narrowly scoped `DelegationGrant`;
2. the delegated agent signs the exact `AgentActionProof` it authored;
3. a verifier validates both signatures and their shared action context.

The contract is transport-neutral. It does not execute an action, replace
`PolicyEnforcer`, or persist revocation/replay state.

## Minimal flow

```python
from enterprise.delegation import (
    issue_delegation_grant,
    sign_delegated_action,
    verify_delegated_action,
)

grant = issue_delegation_grant(
    signer=owner_identity,
    issuer_principal="OWNER:RON",
    subject_public_key=agent_identity.public_key_bytes,
    allowed_actions=("sc_inject_text",),
    target_constraints={"hwnd": 42, "exe": protected_executable_path},
    governance_mode="enterprise",
    classification_ceiling="UNCLASSIFIED",
    issued_at=issued_at,
    not_before=issued_at,
    expires_at=expires_at,
    revocation_epoch=current_revocation_epoch,
    nonce=grant_nonce,
)

proof = sign_delegated_action(
    grant=grant,
    agent_identity=agent_identity,
    action_id=one_time_action_id,
    action="sc_inject_text",
    target={"hwnd": 42, "pid": 1234, "exe": protected_executable_path},
    payload=payload_bytes,
    governance_mode="enterprise",
    classification="UNCLASSIFIED",
    occurred_at=occurred_at,
)

result = verify_delegated_action(
    grant,
    proof,
    now=trusted_time,
    payload=payload_bytes,
    trusted_issuer_public_key=pinned_owner_public_key,
    revoked_grant_ids=current_revoked_grants,
    revoked_agent_ids=current_revoked_agents,
    minimum_revocation_epoch=current_revocation_epoch,
    seen_action_ids=consumed_action_ids,
)
if not result.ok:
    raise PermissionError(result.reason)

# The caller must atomically persist proof.action_id as consumed before or with
# actuation. verify_delegated_action intentionally does not mutate caller state.
```

## Security boundaries

- Pin `trusted_issuer_public_key`; an embedded key alone is not a trust root.
- Use the full public key/fingerprint as the principal binding. `SC-XXXXXXXX`
  remains a short lookup/display label.
- Obtain `now`, revocation state, and replay state from deployment-controlled
  sources and fail closed when required state is unavailable.
- Atomically consume `action_id` with authorization/actuation. Passing a set of
  seen IDs verifies a snapshot but does not create durable replay protection.
- The v1 classification field is exact-match. It does not infer a hierarchy or
  permit every label below a ceiling.
- A successful verification does not prove the action executed or had its
  intended effect. Bind the verified grant/proof digests into the governed
  execution receipt and signed provenance chain during runtime integration.

See `GAPS.md` entries DG-1 through DG-3 for the implementation and open
integration boundary.
