# SelfConnect Governed ACP Shim

`enterprise.acp_shim` exposes SelfConnect governed actions through the stable
Agent Client Protocol v1 core lifecycle:

- `initialize`
- `session/new`
- `session/prompt`
- `session/cancel`
- newline-delimited JSON-RPC over stdio

The implementation was mapped against the official ACP schema repository at
commit `0bfa27d5bf30c98d5d9a6bfec523597756188333`. ACP wire compatibility is
negotiated with `protocolVersion`; artifact/package versions are separate.

## Trust model

ACP supplies the client/session transport. It does not become SelfConnect's
authorization authority.

```text
ACP client/session
  -> owner-signed DelegationGrant (authorization)
  -> agent-signed AgentActionProof (authorship)
  -> live revocation snapshot
  -> durable atomic action-ID claim
  -> exact GovernedRuntime backend
```

ACP is an interoperability surface for clients such as Goose, Codex, Claude,
Cursor, and Copilot CLI. It is not a replacement architecture. Governed ACP
requests still terminate in `GovernedRuntime`; terminal-as-medium injection
remains the user-visible actuation mechanism, and BPC/TSK remain the core
identity, authorization, and trust protocols.

The shim never interprets free-form text as authority. `session/prompt` must
contain exactly one text block holding this JSON object:

```json
{
  "schema": "selfconnect.acp.governed-action.v1",
  "tool": "sc_inject_text",
  "arguments": {},
  "delegationGrant": {},
  "actionProof": {}
}
```

Optional ACP `resource_link` blocks are accepted but are not fetched. Their
exact values are included in the signed action payload, so substitution fails.

Use `acp_action_payload()` to produce the exact bytes the agent must sign after
`session/new` returns the session ID. The payload binds session ID, canonical
working directory, tool, arguments, and resource links.

## Production construction

Use `GovernedRuntimeBackend`; it rejects anything other than the exact canonical
`GovernedRuntime` type. Inject deployment-owned trust and revocation providers:

```python
from enterprise.acp_shim import (
    ACPShim,
    GovernedRuntimeBackend,
    SQLiteActionReplayStore,
    serve_stdio,
)

shim = ACPShim(
    backend=GovernedRuntimeBackend(governed_runtime),
    replay_store=SQLiteActionReplayStore(replay_database_path),
    issuer_resolver=resolve_pinned_owner_key,
    revocation_provider=load_current_revocation_snapshot,
    clock=trusted_clock,
)
serve_stdio(shim)
```

## Terminal authentication setup

When the client advertises ACP terminal-auth support and the shim has an
`ACPTrustStore`, `initialize` advertises the same executable with `--setup`.
The installed `scent-acp --setup` path requires exact operator confirmation,
proves private-key possession with a fresh signed challenge, and persists only
the public trust root. `session/new` fails closed until an active root exists.
If active trust is removed after session creation, the next prompt is denied
before parsing or dispatch and that session is deleted; later re-enrollment
requires a fresh session rather than reviving prior authority.
Successful proofs also bind their agent ID to the session. Hosts can call
`refresh_revocations()` after a revocation update to remove affected sessions
without waiting for another prompt.
Deployment configuration is supplied by the documented `--trust-store`,
`--identity-name`, `--identity-dir`, `--principal`, and `--factory` options (or
their `SELFCONNECT_ACP_*` environment equivalents).

The replay database consumes an action ID before backend dispatch. A backend
failure leaves the ID consumed because blindly retrying an ambiguous action can
duplicate effects.

## Explicit limits

- This is an ACP v1 governed-action shim, not a general coding-agent/model
  proxy and not a claim of complete ACP conformance.
- ACP transport must not bypass or replace terminal-as-medium injection,
  BPC/TSK, target validation, approval, policy, or signed audit controls.
- Terminal authentication uses ACP's Preview/unstable extension and has schema
  validation but not yet a real-client setup/reconnect acceptance result.
- Registry publication remains on hold pending a real supported distribution,
  final metadata/icon, and registry CI. See
  [`acp/REGISTRY_READINESS.md`](acp/REGISTRY_READINESS.md).
- MCP-server forwarding, session load/resume/list/delete, modes, configuration,
  filesystem callbacks, terminal callbacks, elicitation, images, audio, and
  embedded resources are unsupported and unadvertised.
- The synchronous stdio runner can cancel the next prompt turn but cannot
  interrupt a backend call already executing.
- Sessions are process-local. Replay consumption is durable; session recovery
  is not.
- Deployment controls must protect the replay database and provide trusted
  clock, issuer-key, and fail-closed revocation sources.

See `GAPS.md` ACP-1 through ACP-6 for tracked boundaries. See
[`ACP_COMPETITIVE_POSITIONING.md`](ACP_COMPETITIVE_POSITIONING.md) for the
time-bounded ecosystem comparison and permitted positioning language.
