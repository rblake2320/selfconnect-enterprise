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
- Import is one `SERIALIZABLE` transaction. It refuses the source PostgreSQL
  system identifier, in-flight target work, rollback, same-epoch forks,
  signature failure, inventory mismatch, and protocol-receipt mismatch.
- `ULTRA_HA_STATE_MODE=independent` replaces Redis nonce storage with durable
  PostgreSQL nonce tombstones. Redis remains coordination/rate/anomaly state,
  not the replay authority.

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

This mechanism is not a government authorization or a claim about an untested
cloud/site topology. Site-fault, restore/resync, failback, monitoring, and
measured RPO/RTO evidence remain required before closing Enterprise issue #28.
