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

## Ordered mutation tail

`ultra-state-outbox.js` maps identity-binding changes, idempotency claims and
completions, and replay-nonce tombstones onto the reviewed BPC durable-outbox
contract. The source mutation, sequence allocation, sanitized record, and
checkpoint advance share one serializable transaction. The independent
receiver revalidates the record digest and fence, applies in strict order, and
advances its own checkpoint in one transaction. A secret-bearing idempotency
response is never placed in the record; the receiver stores a deterministic
reprovision-required tombstone bound to the source response digest.

The adapter module alone does not select a production stream or transport.
Deployment must provision a stream at the signed promotion epoch, bind its
current fence capability, run the authenticated publisher/receiver transport,
and verify checkpoint convergence before declaring a target current. BPC pair
authority and TSK HOTP/source authority continue to use their own pinned
protocol implementations; this Ultra stream does not replace them.

The same module exposes `createUltraStateHttpPublisher` and
`createUltraStateHttpReceiver`. They compose BPC's hard-capped HMAC transport,
PostgreSQL replay-nonce authority, ordered publisher, and receiver checkpoint.
The receiver additionally signs its exact decision with an Ed25519 custody key;
the publisher pins the expected receiver ID and public key. Request HMAC,
response-envelope HMAC, and receiver-signing keys are separate rotation and
custody boundaries.

## Custody-separated commands

Export, countersign, import, and readiness JSON descriptors are non-secret;
`DATABASE_URL` stays in those command processes' environments. The separate
promoted-runtime descriptor named by `ULTRA_TSK_AUTHORITY_CONFIG_FILE` is an
explicit exception: it currently contains `runtimeDatabaseUrl` and is therefore
secret-bearing. Store it under a service-identity ACL, exclude it from retained
evidence and ordinary backups, and rotate it with the database credential. PEM
key files referenced by either descriptor are likewise ACL-protected.

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
`sourcePrivateKeyFile`, and `sourceCredentialProofBindings`. Each credential
binding names a secret-free signed TSK source proof file, its exact
`agentId`/`pairId`/`sourceClientId`, and public-key file maps for the proof's
lease and stream head. Export verifies those proofs through opaque authority
capabilities and carries only the signed secret digest; it never reads or
copies a legacy Enterprise tumbler map. Guard and import descriptors provide
public-key file maps for all three protocol resolvers. Import also repeats the three
expected receipt digests, so a valid bundle cannot be substituted across an
operator-approved cutover. Never transfer either private key with the bundle.

## Runtime gate

Set `ULTRA_HA_STATE_MODE=independent` for the named topology. A promoted site
also sets `ULTRA_HA_REQUIRED_COMMAND_ID`, `ULTRA_HA_REQUIRED_SOURCE_EPOCH`, and
`ULTRA_HA_REQUIRED_MANIFEST_DIGEST`. Startup verifies the imported head against
the exact local PostgreSQL system identifier. `/ready` remains fail-closed
until that attestation exists and the ordinary writer fence is valid.

Production independent mode also requires `ULTRA_TSK_AUTHORITY_CONFIG_FILE`.
That protected descriptor points at the promoted site's TSK PostgreSQL
authority and binds its exact active source lease, stream/epoch/holder/lease,
public verification keys, file-held stream-head private key, and file-held
credential-mutation secret. Startup builds TSK's reviewed
`PgHaTumblerMapStore` with real schema, credential-authority, mutation-boundary,
and source-fence readiness capabilities. Failure to load or attest it aborts
startup; the legacy Enterprise-local TSK store is not a fallback.

After import, call `POST /ha/reprovision-tsk` once per imported binding with
the exact pinned `clusterId`, `commandId`, `sourceEpoch`, `pairId`,
`sourceClientId`, and `agentId`. The route requires both operator bearer auth
and the body-bound agent proof, plus the current Redis writer fence. The actual
TSK authority creates or resumes the command-bound credential and emits a
signed public ledger proof. Enterprise verifies that proof through an opaque
authority capability and persists only public digests before rebinding the
identity. It returns the provision payload only to that authorized caller; the
Enterprise database, logs, and receipt contain no shared secret. Authenticated
retries return the same credential so a lost HTTP response is recoverable.

Manifest v1 heads are not upgraded at the same epoch. Run a new governed
promotion to produce a v2 manifest and new target credentials.

## Authenticated stream process

`ultra-state-stream-command.mjs receiver` opens the attested receiver database
and durable replay-nonce authority, then binds loopback. `publish-once` opens
the attested source database, drains in order, and exits with a JSON result.
Neither command provisions schemas or authority rows. Remote plaintext URLs and
direct non-loopback receiver binds are refused; use an authenticated TLS/mTLS
proxy between sites. Request, response-envelope, and receiver-signing keys are
separate file-held custody boundaries.

## Governed Ultra source authority

`createGovernedUltraStateAuthority()` is the only composed constructor for
independent-mode Ultra identity bindings, idempotency state, and nonce
tombstones. It requires a real TSK `SourceFenceReadyToken` bound to the same
PostgreSQL transactor, schema, stream, holder, lease, and signed grant digest.
The BPC outbox invokes TSK's source-lease check again immediately before commit.
A revoke that races after application DML therefore causes the serializable
transaction, including its outbox append, to roll back rather than committing a
stale-site mutation.

Set `ULTRA_STATE_AUTHORITY_CONFIG_FILE` on a promoted runtime to an exact JSON
descriptor containing `streamId`, numeric `sourceEpoch`, `holderNodeId`,
`leaseId`, signed `grantDigest`, `controlToASkewBoundMs`, and a map of guard
key IDs to public Ed25519 key files. Private keys in that verifier map are
rejected. When the independent-state promotion pins are configured, startup
must attest the imported state and this source authority before constructing
any writable Ultra-owned store. With no promotion pins, the node remains a
read-only standby behind the readiness gate.

This mechanism is not a government authorization or a claim about an untested
cloud/site topology. Site-fault, restore/resync, failback, monitoring, and
measured RPO/RTO evidence remain required before closing Enterprise issue #28.
