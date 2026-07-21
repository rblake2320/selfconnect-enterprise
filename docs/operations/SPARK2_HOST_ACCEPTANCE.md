# Spark-2 Physical-Host Acceptance

On 2026-07-21, the governed TSK A -> B -> A lifecycle completed across two
physical NVIDIA Spark systems on the private LAN.

This supplements the exact-master one-runner acceptance in
`ULTRA_FINAL_HA_ACCEPTANCE.md`. It replaces the assumption that every authority
was only a container on one host with direct evidence that the promoted TSK
authority can reside on a second physical machine.

## Reviewed Inputs

- Enterprise reviewed base: `60f8ae76fa52f868a704dbf51865b268d2d0886f`
- Evidence controller code: `03add3ecbb3ff6939b6a09491cb751242e5483bd`
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

The reviewed admission record is
`deploy/spark2-ha-lab/admission.json` (SHA-256
`4cdc122be5c7a431d4e4b98086d9df54fdbe0dc8bf9393032f22a3a3732a49bc`).
Before database work, the controller strictly verifies the local and remote
hostnames, both SSH Ed25519 host keys, normalized machine-id hashes, the target
container image reference, and the target image ID/architecture. SSH uses only
the admitted target key in a temporary `known_hosts` file with strict checking.
The two systems have distinct SSH host keys. Their cloned OS images currently
have the same machine-id, so machine-id is recorded and checked for drift but
is explicitly **not** the evidence of physical-host distinctness.

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
- command: `spark2-admission-03add3e`
- data-loss RPO: `0`
- initial sequence: `4`
- promoted sequence: `5`
- returned sequence: `6`
- stale source writer denied: `true`
- stale target writer denied after return: `true`
- measured end-to-end duration: `31279 ms`

Success was not inferred from a zero exit code. The verifier required three
different PostgreSQL system identifiers, exact admission of the pre-recorded
Spark-2 identifier, signed activation/finalization artifacts, strict `N`,
`N+1`, `N+2` ordering, the returned Redis authority tuple, and both stale-writer
denials.

The secret-free receipt is retained immutably in reviewed source at:

`docs/verification/spark2-host-evidence-03add3e.json`

Its SHA-256 is
`8fd64d22fc87d53fc52c134683d4db2117a175b72889e130dcdbd739aa842086`.
The controller's original mode-`0600` copy remains at
`~/selfconnect-ha-drill/evidence/spark2-host-admission-03add3e.json`. The receipt
contains only bounded admission, topology, commit, timing, sequence, outcome,
and digest fields and passed a secret-pattern check. It binds the exact clean
Enterprise controller commit, exact clean TSK commit, and reviewed admission
digest; a dirty or different checkout is a hard failure. The later docs-only
commit that retains this receipt does not claim to be the evidence controller.

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

The command requires explicit source, control, target, Redis, expected
Enterprise and TSK SHAs, stream, command, and new evidence-file environment
values. Physical host, PostgreSQL, and image identities come only from the
reviewed admission file. It destructively resets only the dedicated acceptance
databases and creates evidence with write-once file semantics.

## Verification Performed

- both Compose files passed `docker compose config --quiet` on their hosts;
- all five new services reached healthy state;
- Spark-1 reached Spark-2 PostgreSQL and Redis over the private inter-host link;
- PostgreSQL `fsync`, `full_page_writes`, and `synchronous_commit` were `on`;
- Redis used AOF with `appendfsync=always`;
- the focused evidence validator passed `4/4`, including refusal of loopback,
  wrong-host endpoint substitution, reused SSH identity, and reused database
  authority;
- the full Ultra unit suite passed `61`, skipped `2` integration-only tests,
  and failed `0` on Spark-1;
- the live cross-host lifecycle completed and produced the receipt above;
- negative control: with only the isolated Spark-2 PostgreSQL target stopped,
  the live command exited nonzero and produced no evidence file;
- after restart, Spark-2 returned with the same PostgreSQL system identifier
  `7664860268000567330`.

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
