# Agent Revocation Lifecycle

SelfConnect separates durable human ownership from replaceable agent
principals. Revoking an agent does not deactivate, rotate, or replace the
enrolled human owner key.

```text
human owner trust root (unchanged)
  -> revoke compromised agent ID
  -> monotonic revocation epoch advances
  -> ACP denies the revoked agent and terminates its session
  -> owner may authorize a new agent identity
```

`RevocationRegistry` stores terminal agent and delegation-grant revocations in
SQLite with WAL and full synchronous durability. Each new target advances one
global monotonic epoch. Repeating the same revocation is idempotent and does not
inflate the epoch. There is intentionally no un-revoke operation.

```python
registry = RevocationRegistry("revocations.sqlite3")
registry.revoke_agent(
    compromised_agent_id,
    operator_id="OWNER:RON",
    reason="key compromise",
    revoked_at=trusted_time,
)

shim = ACPShim(
    # ...
    revocation_provider=registry.acp_snapshot,
)
```

When a revoked agent presents an ACP action, verification fails before replay
claim or backend dispatch and the process-local ACP session is removed. A new
agent requires a new identity, owner delegation, and session. The human owner
trust root remains available to authorize that replacement.

After the first successful verified action, ACP records the agent-to-session
binding. A deployment watcher can call `shim.refresh_revocations()` whenever
the registry changes; all sessions bound to a newly revoked agent are removed
immediately. Snapshot-provider failure raises a bounded fail-closed error rather
than being treated as an empty revocation list.

For multiple local processes sharing the SQLite file, `RevocationWatcher`
polls the monotonic epoch at a bounded interval and calls
`apply_revocations()` only for a new epoch. It exposes `last_epoch` and a
bounded `last_error` exception type for health monitoring and supports explicit
start/stop lifecycle.

## Boundaries

- Local shared-storage propagation can use `RevocationWatcher`. Remote hosts
  still require an authenticated distribution/push design.
- The SQLite registry is durable single-node state, not a replicated HA
  authority.
- Operator authentication and authorization for calling `revoke_agent()` are
  deployment/control-plane responsibilities; possession of the database API is
  not itself policy authority.
- BPC/TSK lifecycle and the existing `ControlPlane` remain authoritative in
  their current scopes. This registry supplies the portable delegation/ACP
  revocation view and does not replace them.
