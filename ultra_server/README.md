# Ultra Server 1.3

Ultra Server is SelfConnect Enterprise's loopback BPC+TSK identity sidecar. It
does not make SelfConnect Government-authorized and it is not a remote network
gateway.

## Security Contract

- Agent lifecycle calls carry `X-SC-Agent-Auth`: an Ed25519 signature over the
  exact request-body hash, timestamp, and one-time nonce.
- The server derives `SC-XXXXXXXX` from the supplied public key and rejects a
  mismatched identity, stale proof, replay, body change, and cross-agent bind.
- Production first enrollment requires the agent proof and an independent
  operator bearer. Provisioning and binding must resolve to that enrolled
  agent.
- Administrative inventory and mutation routes require the operator bearer.
- Recovery token issuance requires both operator authorization and proof of
  possession of the replacement key. The versioned token binds the agent name,
  derived agent ID, replacement public key, recovery challenge hash, issuance
  time, and signing-key ID.
- Source-IP and pair verification limits are independent. Production counters
  use Redis. A BPC shadow or ghost response is always converted to a hard Ultra
  denial before TSK evaluation; deceptive shadow success is never permission.
- TSK rotation uses prepare, compare-and-swap commit, old-key revocation, and
  owner-authenticated resume. Retrying a lost prepare or commit response does
  not move the binding to a second candidate.
- The server binds only to `127.0.0.1`. Production also requires service-account
  isolation and approved secret custody; loopback is not a trust boundary by
  itself.

## Runtime Modes

`ULTRA_RUNTIME_MODE=development` uses bounded memory stores and emits a warning.
State is lost on restart.

`ULTRA_RUNTIME_MODE=production` refuses startup unless PostgreSQL, Redis,
`ULTRA_ADMIN_TOKEN`, and `ULTRA_RECOVERY_HMAC_KEY` are configured. PostgreSQL
stores pairs, complete tumbler records, identity bindings, and idempotency
responses. Redis supplies shared nonce replay protection and anomaly counters.
Pair, provisioning, binding, and rotation-prepare mutations serialize on a
resource lock and reconcile their durable resource before recovering a request
stranded in `processing`; ambiguous duplicates fail closed.
The production token and recovery key must each contain at least 32 bytes.
One distinct previous operator token and recovery key may be configured during
a bounded rolling rotation. They are verification-only and must be removed
after the documented drain and token-TTL window.

The provisioning response omits literal segment `position` fields and never
returns the complete record verbatim. It does return the owning client's shared
secret, segment types, lengths, order, initial HOTP counters, and total key
length because those values are required to construct a key. This is a reduced
provisioning view, not a claim that the effective layout is secret from the
owning client.

See [`.env.example`](.env.example) for names only. Real secrets must come from
the deployment's approved secret manager, not a committed environment file.
See [`ULTRA_KEY_ROTATION.md`](../docs/operations/ULTRA_KEY_ROTATION.md) and
[`ULTRA_DISASTER_RECOVERY.md`](../docs/operations/ULTRA_DISASTER_RECOVERY.md)
for the operator procedures and their explicit evidence boundaries.

## Pinned Protocol Sources

The package currently consumes local protocol source packages. CI checks out,
builds, and tests these exact commits before starting the sidecar:

- `bpc-protocol`: `d023c248d7661f1211081771075a900c65fb77ed`
- `tsk-protocol`: `235f644f8ac84998802ffe4ddba6c34dfb5fdcb1`

From `ultra_server`, the file dependencies resolve at
`../../bpc-protocol/packages/*` and `../../tsk-protocol/packages/*`. This layout
is a source-checkout contract, not a published package contract.
`package.json` is therefore marked private. Its explicit runtime-file allowlist
and package-content test prevent local logs, restart state, tests, and key-like
artifacts from entering `npm pack`; this does not close the published-dependency
and provenance gap recorded as US-6.

## Conformance

```powershell
npm ci
npm test
npm run test:live
```

The repository CI additionally runs the real Python `UltraGate` against the
Node server on Windows. A separate production job uses digest-pinned PostgreSQL
and Redis, exercises concurrent HOTP compare-and-swap, kills/restarts the Node
process, and proves the same agent, pair, tumbler client, and verification path
survive. The production job also rotates operator and recovery keys through one
bounded overlap generation, retires the old generation, and restarts after TSK
rotation. `SC_REQUIRE_ULTRA_SERVER=1` converts an unavailable sidecar from a
skip to a test failure. These checks establish the tested composition only;
they do not establish deployment secret custody or a completed backup restore.
