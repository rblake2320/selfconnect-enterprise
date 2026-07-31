# ACP Registry Readiness

Status: **HOLD — not published and not yet registry-eligible.**

The governed ACP shim now implements the ACP Preview terminal-authentication
shape: when a client advertises terminal-auth support, `initialize` offers an
out-of-band `--setup` command. `scent-acp --setup` requires an explicit typed
confirmation, proves possession of the selected owner key with a fresh nonce,
and stores only its public trust root. Serving is gated until an active root
exists, and deactivation closes that gate again.

The initialize response was validated locally against the unstable ACP v1
schema pinned at `0bfa27d5bf30c98d5d9a6bfec523597756188333`. That is schema
evidence, not a successful end-to-end client acceptance test.

## Publication blockers

- No registry-supported distribution has been published. A local
  `scent-acp` console entry point is not a `binary`, `npx`, or `uvx`
  distribution and must not be represented as one.
- No final `agent.json` or `icon.svg` should be submitted until the real
  release URL/package, version, and checksum are known.
- A real ACP client still needs to execute setup, observe successful exit, and
  reconnect to the authenticated agent.
- The registry's own schema/build/CI remains the publication authority.

`python tools/acp_registry_readiness.py agent.json --icon icon.svg
--terminal-auth-verified` provides a local, fail-closed preflight. Passing it
means only "ready for registry CI review"; it does not claim acceptance or
publication.

Reference snapshots inspected on 2026-07-31:

- ACP specification: `agentclientprotocol/agent-client-protocol` commit
  `0bfa27d5bf30c98d5d9a6bfec523597756188333`
- ACP registry: `agentclientprotocol/registry` commit
  `ed10be087c85606dd6442785600c867d7a6e0eaf`
