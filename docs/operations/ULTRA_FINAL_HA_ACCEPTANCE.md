# Ultra Final HA Acceptance

**Scope:** the named controlled-deployment topology only
**Not established:** an ATO, compliance certification, legal admissibility, or
availability outside the recorded topology. The hosted topology is one runner.
The Spark-2 supplement in `SPARK2_HOST_ACCEPTANCE.md` establishes a
two-physical-host same-LAN TSK handoff, but not an independent site domain.
`HA_TEST_STANDARDS_MATRIX.md` is the machine-checked PASS/PARTIAL/OPEN ledger
for required fault and recovery levels; an omitted or substitute test is not a
pass.

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
| Protocol failback and recovery | Governed BPC, TSK, and Enterprise authorities complete two A -> B -> A cycles, then rebuild the exact stale B authorities and perform a third A -> B recovery on six distinct PostgreSQL systems plus real Redis; each Enterprise transition consumes the exact pinned protocol artifacts |
| Same principal | Pair and agent identity remain unchanged across both complete protocol and Enterprise failover/failback cycles while fresh target credentials are reprovisioned at each authority epoch |
| Old writer fencing | Ten distinct restarted BPC child writers and ten restarted TSK child writers are denied across the five cuts before and after real Redis partition/heal; five restarted Enterprise completion processes run after heal. Each of the 25 processes requires the protocol-specific typed rejection and an unchanged SHA-256 digest of the exact authoritative rows before/after its attempted effect. Post-heal protocol evidence is bound to the exact healed Redis authority tuple. |
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
and TSK protocol authorities exercise that return path directly. The
Enterprise-owned state test performs two real-PostgreSQL A -> B -> A cycles,
then rebuilds the exact stale B authority in place and performs one governed
A -> B recovery. It
exports, independently countersigns, imports, reprovisions a fresh target
credential, verifies exact manifest convergence and readiness, preserves the
principal, denies stale completion, and reports per-cycle data-loss RPO zero.
At each of the five cuts, fresh child processes reconnect to the stale BPC,
TSK, and Enterprise databases; any successful stale mutation or completion
fails the acceptance. BPC and TSK run once before and once after real Redis
partition/heal, and the Enterprise completion probe runs after heal, for 25
distinct process probes. The child probes use distinct operating-system
process IDs and are not callbacks or reconstructed connections in the
orchestrator process.
The composed acceptance consumes the exact pinned BPC and TSK receipts and
leases; it does not substitute synthetic protocol evidence. Redis
partition/heal proves the exact current authority tuple survives and the old
master refuses writes. The post-heal BPC and TSK probes are bound to that exact
tuple; the Enterprise probes execute after the heal. This is a tested
cross-product at the five named cuts, not a claim that every possible process
interleaving occurs inside every network-fault window.
Previously redacted idempotency results remain redacted; they are not re-hashed
as ordinary responses. Readiness is granted only after the new credential
binding and authority digest agree. Separate-host execution is evidenced by the
Spark-1/Spark-2 supplement. Whole-host loss and separate-site operation remain
issue #28 acceptance gates.

## Operations

Run this acceptance after any change to BPC authority, TSK authority,
Enterprise state format, Redis durability policy, cutover ordering, or the
named topology. A component pin change requires review in the same pull
request. Never reinterpret a result from a different commit or topology as
evidence for this one.
