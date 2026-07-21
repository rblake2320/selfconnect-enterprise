# Spark-2 HA Target

This bundle provisions Spark-2 as a physically separate SelfConnect Enterprise
target host. It deliberately uses ports that do not overlap Spark-2's existing
voice, MemoryWeb, Ollama, PostgreSQL, or Redis services.

`compose.source-control.yml` provisions two low-footprint, independent
PostgreSQL clusters and the active Redis fencing authority on Spark-1. They
supply the source/control side of the cross-host acceptance drill; the target
PostgreSQL cluster remains on Spark-2. Spark-2's Redis instance is retained as
an isolated target-side durability primitive for later multi-host tests.

It proves a separate-host state authority. It does **not** by itself prove a
separate site, independent power/network, or a three-host Redis quorum.

## Boundaries

- Bind only to Spark-2's private inter-Spark address (`10.0.0.2`).
- Keep `.env` mode `0600`; never commit it.
- PostgreSQL and Redis use persistent named volumes.
- Redis AOF is synchronous so this service can support a future host-loss
  drill. It is a target-side durability primitive, not a Sentinel quorum claim.
- Existing Spark-2 containers are not modified or joined to this network.

## Start

```bash
cd ~/selfconnect-enterprise/deploy/spark2-ha-lab
docker compose --env-file .env -p selfconnect-spark2-ha up -d
docker compose --env-file .env -p selfconnect-spark2-ha ps
```

On Spark-1:

```bash
cd ~/selfconnect-enterprise/deploy/spark2-ha-lab
docker compose --env-file .env.source-control \
  -f compose.source-control.yml -p selfconnect-spark1-ha up -d
```

Spark-1's interactive Docker configuration selects Docker Desktop and uses a
credential helper that is not installed in non-interactive SSH sessions. The
deployed drill uses an isolated `DOCKER_CONFIG=~/.docker-selfconnect` containing
an empty `config.json`, which selects the native daemon without changing the
owner's normal Docker configuration.

The acceptance controller runs outside Spark-2 and records PostgreSQL's
`pg_control_system().system_identifier` before admitting this target into a
handoff. A different identifier from the source and control authorities is the
minimum independent-state requirement.

The accepted three-cluster topology is:

- source: `spark-3cdf:5541`
- control: `spark-3cdf:5542`
- target: `spark-3173:5543`

The source and control clusters are distinct state authorities but share a
physical host. Spark-1 and Spark-2 are separate physical hosts on the same LAN;
this remains separate-host evidence, not separate-site evidence.

## Acceptance

`npm run test:spark2-host --prefix ultra_server` runs the reviewed TSK
A -> B -> A lifecycle. It refuses unpinned TSK code, reused PostgreSQL cluster
identities, an unexpected Spark-2 cluster identity, a stale writer that remains
writable, or a result that does not return at exactly `N+2`. Its JSON evidence
contains no connection strings, credentials, keys, or protocol payloads. The
controller and TSK checkouts must both be clean and exactly match full commit
SHAs supplied to the command.
