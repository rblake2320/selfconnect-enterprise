# Ultra Independent-State HA

This Enterprise-owned state handoff composes the completed BPC and TSK
promotion authorities. It does not replace either protocol. It moves only
Ultra identity bindings, completed idempotency tombstones, and unexpired replay
nonce hashes between independent PostgreSQL authorities.

## Safety boundary

- Source export runs at `SERIALIZABLE` under the same exclusive advisory lock
  that drains governed HTTP mutations. It refuses any `processing`
  idempotency row.
- The manifest binds the exact BPC promotion-attestation digest and TSK
  activation-receipt digest. Source and guard sign in separate steps with
  Ed25519 keys.
- Raw nonces never persist; only SHA-256 tombstones and expiry are transferred.
- An idempotency response containing a secret-like field is not exported. The
  target receives a deterministic `SECRET_REPROVISION_REQUIRED` tombstone.
  Secret unseal or re-provisioning is a separate authorized ceremony.
- TSK shared secrets never enter the manifest. Manifest v2 proves each source
  binding referenced an active owned credential and refuses an unfinished
  active rotation candidate. Import deletes target credential state, records a
  durable obligation per binding, and remains unready until each identity is
  rebound to a fresh target-only credential.
- Import is one `SERIALIZABLE` transaction. It refuses the source PostgreSQL
  system identifier, in-flight target work, rollback, same-epoch forks,
  signature failure, inventory mismatch, and protocol-receipt mismatch.
- `ULTRA_HA_STATE_MODE=independent` replaces Redis nonce storage with durable
  PostgreSQL nonce tombstones. Redis remains coordination/rate/anomaly state,
  not the replay authority.
- Every owned independent-state transaction pins the `public` schema, locks all
  six governed relations against concurrent DDL, and verifies columns,
  constraints, indexes, triggers, relation/RLS properties, and policies against
  the compiled catalog digest. A restore with missing or altered DDL is not an
  authority and fails closed before data access.

The production serving role must not hold `CREATE`, `ALTER`, or `DROP`
privileges on the governed schema. Provisioning and intentional migrations use
a separate offline identity. A reviewed DDL change requires regenerating and
reviewing the compiled manifest pin; there is no runtime override or
trust-on-first-use path.

## Custody-separated commands

All JSON descriptors are non-secret. `DATABASE_URL` stays in the process
environment. PEM key files are supplied by path and must be ACL-protected.

```powershell
# A/source custody
$env:DATABASE_URL = 'postgresql://...site-a...'
node ultra_server/independent-state-command.mjs export export.json source-bundle.json

# Guard custody (a separate process/identity)
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
node ultra_server/independent-state-command.mjs countersign guard.json signed-bundle.json

# B/import custody
$env:DATABASE_URL = 'postgresql://...site-b...'
node ultra_server/independent-state-command.mjs import import.json
node ultra_server/independent-state-command.mjs ready ready.json
```

The export descriptor includes `clusterId`, `commandId`, `sourceEpoch`,
`advisoryLockKey`, the full `protocolEvidence` object (BPC promotion
attestation, TSK B-finalized receipt, and TSK activated lease), `sourceKeyId`,
and `sourcePrivateKeyFile`. Guard and import descriptors provide public-key
file maps for all three protocol resolvers. Import also repeats the three
expected receipt digests, so a valid bundle cannot be substituted across an
operator-approved cutover. Never transfer either private key with the bundle.

## Runtime gate

Set `ULTRA_HA_STATE_MODE=independent` for the named topology. A promoted site
also sets `ULTRA_HA_REQUIRED_COMMAND_ID`, `ULTRA_HA_REQUIRED_SOURCE_EPOCH`, and
`ULTRA_HA_REQUIRED_MANIFEST_DIGEST`. Startup verifies the imported head against
the exact local PostgreSQL system identifier. `/ready` remains fail-closed
until that attestation exists and the ordinary writer fence is valid.

After import, call `POST /ha/reprovision-tsk` once per imported binding with
the exact pinned `clusterId`, `commandId`, `sourceEpoch`, `pairId`,
`sourceClientId`, and `agentId`. The route requires both operator bearer auth
and the body-bound agent proof, plus the current Redis writer fence. It returns
the fresh secret and provision payload only to that authorized caller; the
durable receipt contains no secret. Retries return the same credential.

Manifest v1 heads are not upgraded at the same epoch. Run a new governed
promotion to produce a v2 manifest and new target credentials.

This mechanism is not a government authorization or a claim about an untested
cloud/site topology. Site-fault, restore/resync, failback, monitoring, and
measured RPO/RTO evidence remain required before closing Enterprise issue #28.
