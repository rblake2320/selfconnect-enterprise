# Spark-2 Physical-Host Acceptance

On 2026-07-21, the governed TSK A -> B -> A lifecycle completed across two
physical NVIDIA Spark systems on the private LAN.

This supplements the exact-master one-runner acceptance in
`ULTRA_FINAL_HA_ACCEPTANCE.md`. It replaces the assumption that every authority
was only a container on one host with direct evidence that the promoted TSK
authority can reside on a second physical machine.

## Reviewed Inputs

- Enterprise base: `60f8ae76fa52f868a704dbf51865b268d2d0886f`
- TSK protocol: `20bf099e0b4f7479b93cf1d5e245b3f7c87e1675`
- Controller: Node.js `v24.18.0` ARM64 archive, verified against the official
  Node.js `SHASUMS256.txt`
- PostgreSQL image:
  `postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777`
- Redis image:
  `redis:7.4.5-alpine@sha256:bb186d083732f669da90be8b0f975a37812b15e913465bb14d845db72a4e3e08`

## Observed Topology

| Authority | Physical host | PostgreSQL system identifier |
|---|---|---|
| source A | `spark-3cdf` (Spark-1) | `7664860993977270305` |
| control | `spark-3cdf` (Spark-1) | `7664860993991704610` |
| receiver B | `spark-3173` (Spark-2) | `7664860268000567330` |

The target services use isolated persistent volumes and private-interface
bindings. No pre-existing Spark voice, memory, model, or database service was
modified.

### Deployed Services

| Service | Host/bind | Purpose |
|---|---|---|
| PostgreSQL source | `spark-3cdf:5541` | initial and returned source authority |
| PostgreSQL control | `spark-3cdf:5542` | signed cutover authority |
| Redis authority | `spark-3cdf:6391` | active fencing record for the drill |
| PostgreSQL target | `spark-3173:5543` | promoted receiver/source authority |
| Redis target primitive | `spark-3173:6395` | isolated durability service, not a quorum claim |

Both Compose projects use named persistent volumes, generated secrets in
mode-`0600` untracked files, digest-pinned images, health checks, and
`no-new-privileges`. Spark-2 binds only to `10.0.0.2`; Spark-1 binds only to its
private LAN address. Credentials, connection strings, private keys, and
protocol payloads are absent from committed files and evidence.

Spark-1's normal Docker CLI selects Docker Desktop and references a credential
helper unavailable in non-interactive SSH. The drill uses a separate
`~/.docker-selfconnect/config.json` containing `{}` to select the native daemon.
The owner's normal Docker configuration was not changed.

## Result

- TSK commit: `20bf099e0b4f7479b93cf1d5e245b3f7c87e1675`
- command: `spark2-host-20260721T062218Z`
- data-loss RPO: `0`
- initial sequence: `4`
- promoted sequence: `5`
- returned sequence: `6`
- stale source writer denied: `true`
- stale target writer denied after return: `true`
- measured end-to-end duration: `31098 ms`

Success was not inferred from a zero exit code. The verifier required three
different PostgreSQL system identifiers, exact admission of the pre-recorded
Spark-2 identifier, signed activation/finalization artifacts, strict `N`,
`N+1`, `N+2` ordering, the returned Redis authority tuple, and both stale-writer
denials.

The secret-free receipt is retained on the acceptance controller at:

`~/selfconnect-ha-drill/evidence/spark2-host-20260721T062218Z.json`

The receipt is mode `0600` and contains only bounded topology, commit, timing,
sequence, outcome, and SHA-256 digest fields. It passed a secret-pattern check.

## Reproduction

1. Copy `deploy/spark2-ha-lab` to the two hosts.
2. Generate separate `.env` and `.env.source-control` secrets; never commit
   either file.
3. Start the Spark-2 target and Spark-1 source/control Compose projects.
4. Record all three PostgreSQL system identifiers and refuse duplicates.
5. Check out and build the exact TSK commit, then run:

```bash
npm run test:spark2-host --prefix ultra_server
```

The command requires explicit source, control, target, Redis, expected TSK SHA,
expected Spark-2 system identifier, stream, command, and new evidence-file
environment values. It destructively resets only the dedicated acceptance
databases and creates evidence with write-once file semantics.

## Verification Performed

- both Compose files passed `docker compose config --quiet` on their hosts;
- all five new services reached healthy state;
- Spark-1 reached Spark-2 PostgreSQL and Redis over the private inter-host link;
- PostgreSQL `fsync`, `full_page_writes`, and `synchronous_commit` were `on`;
- Redis used AOF with `appendfsync=always`;
- the focused evidence validator passed `2/2`;
- the full Ultra unit suite passed `61`, skipped `2` integration-only tests,
  and failed `0` on Spark-1;
- the live cross-host lifecycle completed and produced the receipt above.

## Boundary

This closes the missing separate-physical-host execution gap for the recorded
same-LAN topology. It does not establish separate geography, independent power,
independent network, a cloud-region failure domain, or a production SLO. Those
remain deployment/evidence requirements for an unqualified multi-site claim.

Existing Spark-2 voice, ASR, MemoryWeb, Ollama, PostgreSQL, Redis, and other
application containers remain separate and were not stopped, reconfigured, or
joined to this network. A whole-host power-loss test was intentionally not run
because it would disrupt those owner workloads. This proves cross-host
operation, not loss of the entire Spark-2 chassis.
