# Spark-2 Physical-Host Acceptance

On 2026-07-21, the governed TSK A -> B -> A lifecycle completed across two
physical NVIDIA Spark systems on the private LAN.

## Observed Topology

| Authority | Physical host | PostgreSQL system identifier |
|---|---|---|
| source A | `spark-3cdf` (Spark-1) | `7664860993977270305` |
| control | `spark-3cdf` (Spark-1) | `7664860993991704610` |
| receiver B | `spark-3173` (Spark-2) | `7664860268000567330` |

The target services use isolated persistent volumes and private-interface
bindings. No pre-existing Spark voice, memory, model, or database service was
modified.

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

The secret-free receipt is retained on the acceptance controller at:

`~/selfconnect-ha-drill/evidence/spark2-host-20260721T062218Z.json`

## Boundary

This closes the missing separate-physical-host execution gap for the recorded
same-LAN topology. It does not establish separate geography, independent power,
independent network, a cloud-region failure domain, or a production SLO. Those
remain deployment/evidence requirements for an unqualified multi-site claim.
