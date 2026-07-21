# HA Test Standards And Evidence Matrix

This record answers four questions for every HA test level: what is required,
what was actually executed, why any substitute is not equivalent, and what
closes the gap. The machine-checked source is
`docs/assurance/ha_test_coverage.json`. An omitted test is not a pass.

## External Basis

- [NIST SP 800-53 Rev. 5.1](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final),
  especially CP-4 testing, alternate-site testing, full recovery and
  reconstitution, and self-challenge.
- [NIST SP 800-34 Rev. 1](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final),
  which distinguishes system recovery from a disaster recovery exercise that
  relocates operations to an alternate site.
- [Redis Sentinel deployment guidance](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/),
  which requires at least three Sentinels for a robust deployment and says they
  should occupy independently failing computers or virtual machines.
- [PostgreSQL current HA guidance](https://www.postgresql.org/docs/current/high-availability.html),
  which distinguishes synchronous zero-loss behavior from asynchronous designs
  that can lose an unreplicated tail.

These sources guide engineering evidence. They do not make this repository
authorized, certified, or compliant.

## Current Result

| Level | Status | Precise boundary |
|---|---|---|
| Process loss | PASS | Real `SIGKILL`, rollback/resume, no torn state |
| PostgreSQL process loss | PASS | Real promoted database kill/restart; not host/storage destruction |
| Redis functional failover | PASS | Real crash/partition/heal; one-runner failure domains |
| Redis independent failure domains | OPEN | A third independent host/VM is required |
| Cross-host A -> B -> A | PASS | Spark-1/Spark-2, same LAN, TSK authority |
| Cross-host service-path partition | PARTIAL | Real disconnect/refusal/heal; operator record, not host/LAN loss |
| Whole-host loss | OPEN | Spark-2 cannot be called lost while its OS and unrelated workloads remain alive |
| Alternate site | OPEN | No independent geography/power/network exists in this lab |
| Full recovery/reconstitution | PARTIAL | Signed logical rebuild and DB restart, not full alternate-site restore |
| Backup restore | OPEN | Runbook exists; complete isolated restore artifact does not |
| Enterprise B -> A failback | OPEN | BPC/TSK return; Enterprise-owned state does not yet return |
| Approved RPO/RTO objectives | PARTIAL | Measurements exist; owner-approved business targets do not |
| Database integration skips | PASS | Exact master production CI ran 65/65 Ultra tests with zero skips |

`OPEN` and `PARTIAL` are deliberate failures to claim completion, not waived
tests. Issue [#28](https://github.com/rblake2320/selfconnect-enterprise/issues/28)
remains the authoritative closure work.

## Real Cross-Host Partition Observation

On 2026-07-21, Spark-2's dedicated acceptance PostgreSQL container was removed
from `selfconnect-spark2-ha_default` while remaining alive. Spark-1's exact
merged controller (`197fedc3ccc70f0ea3a36f13479f8eadb4c121ad`) received
`ECONNREFUSED`, exited nonzero, and created no evidence file. After reconnect:

- PostgreSQL was reachable in `557 ms`;
- the complete governed A -> B -> A handoff converged in `33942 ms`;
- data-loss RPO was `0` for the completed lifecycle;
- sequences were `4 -> 5 -> 6`;
- both stale writers were denied; and
- the post-heal secret-free receipt SHA-256 was
  `0bcb4038a5dc4d2fd3627c01fc92e11e6b7052913be9abfdf0f2e261620af8aa`.

This is real service-path isolation. It is not described as host network,
router, power, or site loss. The matrix therefore keeps it `PARTIAL` until an
automated write-once fault receipt and the independent-domain tests exist.

## Skip Policy

A skipped integration test can support diagnosis but cannot support a release
claim. The Spark shell run omitted `DATABASE_URL`, so two PostgreSQL tests
reported explicit skips. Exact master CI `29866745029` supplied real
PostgreSQL and reported:

- Ultra suite: `65` tests, `0` skipped;
- independent-state suite: `2` tests, `0` skipped; and
- Ultra outbox suite: `1` test, `0` skipped.

Where a test cannot run, the JSON matrix requires a limitation and closure
condition. Changing an `open` or `partial` result to `pass` requires reviewed
evidence, not only a prose edit.
