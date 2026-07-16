# Ultra Shared-State Active/Passive Runbook

**Status:** Implemented shared-state application-node fencing; not independent-
state, multi-site, or deployment availability evidence.

## Boundary

This mode runs two Ultra Node processes on different loopback ports while both
use the same production PostgreSQL database and Redis service. PostgreSQL holds
authoritative BPC, TSK, identity-binding, and idempotency state. Redis holds the
cluster-scoped monotonic writer fence, nonce state, and anomaly counters.

It does not replicate either database, select infrastructure failover policy,
perform automated leader election, restore a backup, or prove a site outage.
Issue #21 remains open for the larger composed HA requirement. Follow-up issue
#28 must cover transactional outbox/checkpoints,
secret unseal, convergence, resynchronization, repeated failover, and restore.

## Required Configuration

Each process requires the normal production settings plus:

```text
ULTRA_HA_ENABLED=true
ULTRA_HA_CLUSTER_ID=<same non-secret cluster identifier on both nodes>
ULTRA_HA_NODE_ID=<unique stable node identifier>
ULTRA_HA_NODE_ROLE=primary|replica
ULTRA_HA_GUARD_SECRET=<same independently generated secret on both nodes>
ULTRA_HA_MAX_COMMAND_AGE_MS=60000
ULTRA_HA_MAX_LEASE_MS=300000
ULTRA_HA_MIN_LEASE_REMAINING_MS=5000
```

The guard secret must contain at least 32 bytes and must differ from current
and previous operator/recovery secrets. Store all secrets in the deployment's
approved secret manager. Do not put them in commands, evidence, screenshots,
Git, logs, or this runbook. The HMAC guard proves possession of that shared
secret; it does not independently attribute a named person. The `--by` label
must be bound to an authenticated operator and approval record by the selected
deployment procedure.

## Start And Inspect

1. Start both processes. Confirm `GET /health` is 200 on both.
2. Confirm `GET /ready` is 503 on both. Startup never restores local write
   authority from Redis.
3. Inspect `GET /ha/status` on each node with the operator bearer. Do not retain
   the bearer in evidence.
4. Select a monotonically increasing epoch from the authorized operational
   record. Never infer the next epoch only from a process-local counter.

## Activate Or Promote

From `ultra_server`, inject `ULTRA_ADMIN_TOKEN` and `ULTRA_HA_GUARD_SECRET`
through the approved secret mechanism, then run:

```powershell
npm run ha:command -- --url http://127.0.0.1:7777 `
  --command activate --cluster-id CLUSTER_ID --node-id PRIMARY_ID `
  --fence-epoch 101 --lease-ms 240000 --by OPERATOR_ID `
  --reason "approved activation record CHANGE-123"
```

For the passive node use its URL/node ID and `--command promote` with a higher
epoch. A successful command is not enough by itself: verify the selected
node's `/ready` is 200, the other node's `/ready` is 503, and a governed
same-principal verification succeeds only on the selected node.

Exact command replay, changed signed fields, stale commands, equal/lower
epochs, wrong node/cluster, wrong role, corrupt Redis state, or unavailable
Redis fail closed. A command whose response is lost may have changed the shared
fence; reconcile with authenticated `/ha/status` before issuing a higher epoch.

## Drain And Transition Contract

New governed requests are refused when less than
`ULTRA_HA_MIN_LEASE_REMAINING_MS` remains. Each admitted request holds a shared
cluster PostgreSQL advisory lock until its response finishes or closes, so
ordinary requests may overlap. Promotion holds the exclusive form of the same
lock and waits for all admitted requests rather than overlapping them. On the
tested PostgreSQL version, a queued exclusive holder also precedes later shared
holders. Safety does not depend on indefinite queue fairness: after the lease
enters the drain window, later shared holders fail the writer check and release
promptly. Do not describe this as forced cancellation at lease expiry or as a
fence check in every SQL row mutation.

## Non-Secret Evidence

Record only:

- repository commit and locked BPC/TSK commits;
- node IDs, cluster ID, ports, roles, fence epochs, and timestamps;
- `/health`, `/ready`, and command status codes without authorization values;
- same-principal verification result and bounded state-before/state-after
  comparison;
- restart, replay, tamper, stale-command, outage, and corruption outcomes;
- PostgreSQL and Redis versions/topology; and
- CI run or controlled-drill artifact links.

Do not retain secret-bearing state files, request headers, guard signatures,
recovery material, TSK shared secrets, or full credential payloads.

## Rollback

To return to the prior single-process composition:

1. Stop both HA-enabled processes.
2. Preserve non-secret incident/evidence records and verify no request is in
   flight.
3. Start exactly one production process with `ULTRA_HA_ENABLED=false` or unset.
4. Run the normal production restart and key-rotation conformance checks.
5. Keep the HA guard secret retired in approved secret custody; do not reuse it
   as an operator or recovery secret.

Rollback removes cross-process writer fencing. It must not be presented as an
HA configuration.

## Executable Evidence

The hosted `Ultra production durability (PostgreSQL + Redis)` job starts two
Node processes on ports 7777 and 7778 and runs
`ultra_server/ha-live-conformance.mjs`. Unit coverage is in
`ultra_server/ha-controller.test.mjs`; concurrent schema initialization is
covered in `ultra_server/runtime-stores.test.mjs`. These tests cover this
shared-state slice only. Independent-state and site-level work remains open in
issue #28.
