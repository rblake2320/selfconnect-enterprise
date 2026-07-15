# Ultra Disaster Recovery Runbook

This runbook defines the minimum repeatable recovery drill for the Ultra
production composition. Deployment owners must set and approve their own RPO,
RTO, retention, geographic, and authorization requirements.

## Protected State

PostgreSQL is the durable authority for BPC pairs, TSK tumbler maps, identity
bindings, and idempotency records. Redis holds replay nonces, anomaly counters,
and rate-limit windows. Agent identity material is separately protected by its
configured DPAPI/CNG/TPM mechanism. Immutable provenance objects and their
retention policy are a separate recovery boundary.

Rows left in `processing` are recovered by the named lifecycle route under its
resource lock. The route must reconcile exactly one owned durable resource or
perform the absent side effect under the lock; multiple matches are an incident
and remain fail-closed.

Back up these elements under separate custody:

1. PostgreSQL base backups plus transaction logs or an equivalent consistent
   managed-service backup.
2. Redis persistence/replication appropriate to the deployment's replay and
   anomaly continuity requirement.
3. Secret-manager versions for the current and bounded previous Ultra secrets.
4. Agent identity recovery material and public-key registry under the identity
   system's documented ceremony.
5. Off-host provenance objects, retention configuration, and witness receipts.
6. Exact application and protocol dependency commits, lock files, and SBOM.

Do not export plaintext TSK shared secrets or agent private keys into an
ordinary evidence bundle.

## Isolated Restore Drill

1. Create an isolated network and new service identities. Do not restore over a
   running production database.
2. Restore PostgreSQL to a new instance and run database integrity checks.
3. Restore or deliberately reinitialize Redis according to the approved RPO.
   Reinitializing Redis invalidates replay/anomaly continuity and must be
   recorded as a security-relevant recovery event.
4. Inject the restored current secrets from the secret manager. Keep network
   listeners loopback-only until verification is complete.
5. Start Ultra with `ULTRA_RUNTIME_MODE=production`. Startup must fail if a
   required store or secret is unavailable.
6. Run `npm test` with `DATABASE_URL` set so the PostgreSQL atomicity test is not
   skipped.
7. Run the live Node contract and Python Ultra suite with
   `SC_REQUIRE_ULTRA_SERVER=1`.
8. Run `python -m tools.ultra_restart_conformance seed`, kill the server,
   restart it, and run the `verify` phase. The probe rotates TSK before restart
   and requires the same agent, pair, rotated client, HOTP state, and successful
   verification afterward.
9. Verify the signed action ledger and every archived local segment.
10. Verify immutable provenance objects and retention settings directly against
    the provider, then restore a sample evidence object and validate its chain
    and recorder signature.
11. Record pass/fail, timestamps, versions, commit SHA, recovery point, elapsed
    time, and non-secret object identifiers.
12. Destroy the isolated plaintext restore after evidence review according to
    the approved media-sanitization procedure.

## Failure Conditions

Do not return the system to service if any of these occur:

- a pair, binding, or active TSK client is missing or changes identity;
- an old revoked TSK client authorizes;
- HOTP counters roll backward;
- an archived ledger segment, signature, sequence, or hash link fails;
- a previous key remains accepted after retirement;
- the immutable provider cannot confirm retention configuration; or
- the deployment cannot explain an RPO gap in Redis, PostgreSQL, identity, or
  provenance state.

An application restart is not a disaster-recovery test. Closure requires an
actual restore into an isolated environment and a recorded verification result.
