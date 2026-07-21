# Ultra Final HA Acceptance

**Scope:** the named controlled-deployment topology only  
**Not established:** an ATO, compliance certification, legal admissibility, or
availability outside the recorded topology. The hosted topology is one runner
and does not establish independent physical host or site failure domains.

## Topology

The final acceptance command composes exact reviewed commits rather than local
copies or compatible version ranges:

- two independent Ultra/TSK PostgreSQL authority instances on one hosted runner;
- one independent TSK control PostgreSQL authority;
- three separate BPC PostgreSQL authorities and a three-member Redis quorum;
- the completed TSK credential authority;
- a Redis Sentinel deployment with three data nodes and three sentinels;
- the authenticated Enterprise state publisher/receiver and durable nonce,
  identity-binding, and idempotency authorities.

`portfolio-lock.json` is authoritative. The command refuses a checkout whose
full Git commit does not match the lock.

## Command

Set the database and Redis URLs named in `final-ha-acceptance.mjs`, then run:

```bash
BPC_PROTOCOL_ROOT=/reviewed/bpc-protocol \
TSK_PROTOCOL_ROOT=/reviewed/tsk-protocol \
ULTRA_FINAL_EVIDENCE_FILE=/empty/path/ultra-final-ha-evidence.json \
npm run test:final-ha --prefix ultra_server
```

The evidence path must not already exist. Every step is bounded, uses direct
process spawning without a shell, and must emit its required semantic evidence
markers. A zero exit code without the expected RPO, fencing, activation, and
failback evidence is a failure.

## Acceptance Matrix

| Requirement | Direct evidence |
|---|---|
| BPC pair authority | BPC frozen HA acceptance over its PG18 A/B/control authorities and three Redis members |
| TSK secret authority | Atomic credential-authority drill over separate PG16 A/B/control authorities; secret-free replication, no duplicate effect, no stale write |
| Process loss | Real child `SIGKILL` before and after every TSK cutover phase, followed by idempotent resume |
| Network/split brain | Live Redis master isolation; old master refuses writes, surviving quorum promotes, healed node converges |
| Redis loss | Abrupt master loss with Sentinel quorum and enforced replica acknowledgement |
| Database recovery | Exact promoted PostgreSQL `SIGKILL`/restart plus destructive Enterprise-table rebuild from signed state |
| Protocol failback | Governed BPC A -> B -> A and TSK A -> B -> A return-authority drills; Enterprise-owned state is currently A -> B only |
| Same principal | Pair and agent identity remain unchanged across the recorded protocol failover/failback and Enterprise A -> B handoff |
| Old writer fencing | BPC and TSK pre-commit authority checks deny the prior authority after promotion/restart/heal |
| Tamper/gap/replay/rollback | Component and Enterprise drills reject each class before readiness or mutation |
| Secret custody | State transport strips TSK and idempotency secrets; each target requires fresh governed reprovisioning |
| RPO/RTO | Component drills print per-fault values; the final evidence retains only bounded lines and output hashes |

## Evidence Boundary

The JSON artifact contains commit identities, topology counts, timings, bounded
non-secret evidence lines, and SHA-256 hashes of full command output. It does
not retain environment variables, credentials, private keys, protocol
payloads, or transcripts. Hosted CI uploads the file with a pinned artifact
action and a 90-day retention period. Provider-side immutability or legal hold
still requires the separately governed WORM deployment control.

## Recovery and Failback

Failback is a new higher-epoch handoff, never a reversal of history. The BPC
and TSK protocol authorities exercise that return path directly. The current
Enterprise-owned state drill imports A into B, restores B after process and
database faults, and does not claim an Enterprise B -> A return handoff.
Previously redacted idempotency results remain redacted; they are not re-hashed
as ordinary responses. Readiness is granted only after the new credential
binding and authority digest agree. Physical host/site loss and the Enterprise
return handoff remain issue #28 acceptance gates.

## Operations

Run this acceptance after any change to BPC authority, TSK authority,
Enterprise state format, Redis durability policy, cutover ordering, or the
named topology. A component pin change requires review in the same pull
request. Never reinterpret a result from a different commit or topology as
evidence for this one.
