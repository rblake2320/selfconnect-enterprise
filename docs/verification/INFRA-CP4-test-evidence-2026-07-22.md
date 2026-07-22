# INFRA-CP4 — Local Test Evidence

**Date (UTC):** 2026-07-22
**Branch:** `agent/enterprise-infra-cp4`
**Commit under test:** `4dfa17bd437d0e676c7eb4b229a46708e8fb4813` (== `origin/master` at time of run)
**Environment:** Windows 11, Python 3.12.10, Node.js v24.17.0, isolated git worktree

This record documents a from-clean test run of the existing `master` tree in a
freshly created worktree. No application code changed; this commit only adds
this evidence file.

## Environment provisioning performed

A fresh worktree checkout does not by itself carry everything the suite needs.
The following one-time, local, non-code steps were required before tests would
run at all, and are recorded here because their absence produced misleading
"no tests" / "module not found" failures rather than real defects:

1. `git submodule update --init --recursive` — the `sdk` submodule was
   uninitialized.
2. `npm install` in `ultra_server/`.
3. `pip install -e . --no-deps` — without editable-install metadata,
   `tests/test_enterprise/test_provenance_deploy.py::test_wheel_binding_covers_complete_archive_and_record`
   fails looking for `selfconnect_enterprise.egg-info/PKG-INFO`. This is a
   worktree-provisioning gap, not a regression; the test passes once metadata
   exists.
4. `ultra_server/package.json` pins `@bpc/*` and `@tsk/*` via source-relative
   `file:../../bpc-protocol` / `file:../../tsk-protocol` paths (tracked as
   **GAPS.md US-6**). This worktree lives three directories deeper than the
   layout that convention assumes, so the sibling checkouts did not exist at
   the expected relative path. Per `portfolio-lock.json` / CI (`ci.yml`), the
   exact pinned commits are:
   - `bpc-protocol` @ `aedf67b89574066e1df0575e68fdb58ea0dc9297`
   - `tsk-protocol` @ `20bf099e0b4f7479b93cf1d5e245b3f7c87e1675`

   Fresh, independent checkouts of both were created at the sibling path,
   pinned to those exact commits, and built (`npm install && npm run build`),
   reproducing what `.github/workflows/ci.yml` does. Neither the user's
   existing `bpc-protocol` nor `tsk-protocol` working clones elsewhere on this
   machine were read from or modified.

None of the above touched any git-tracked file in this repository (verified
clean `git status` throughout).

## Results

### Python (`python -m pytest -q`)

```
1748 passed, 4 skipped, 2 warnings in 78.39s
```

All 4 skips are platform-conditional and expected on Windows
(`tests/test_enterprise/test_runtime_ownership.py`):
- POSIX ownership/mode semantics (x3)
- Windows denies unlink of locked file (x1)

Two `UserWarning`s are expected: no `ReplicationSink` (S3 Object Lock / R2) is
configured in this local run — tracked as **GAPS.md CC-6 / AL-2**, external
deployment evidence, not a local defect.

`conftest.py` auto-starts the Ultra Server sidecar for the session once the
built `@bpc/server` dist is present, which is why fixing item 4 above also
raised the pass count (previously-skipped live-integration tests now execute).

### Node (`npm test` in `ultra_server/`)

```
tests 67
pass 65
fail 0
skipped 2
```

The 2 skips (`runtime-stores.test.mjs`) require a live PostgreSQL instance and
are explicit, expected skips, not failures:
- "PostgreSQL HA shared holders overlap and queued transition is exclusive"
- "PostgreSQL stores preserve monotonic counters and atomic idempotency"

### Not run in this pass

- `test:protocol-composition`, `test:final-ha`, `test:live`, `test:ha-live`,
  `test:independent-state`, `test:ultra-outbox` (ultra_server) — these spin up
  multi-node Postgres/Redis Sentinel stacks. This machine already has several
  *other* checkpoints' HA lab containers running (`ha28-*`, `tsk-cred-*`,
  `ent28-final-pga`, etc.) from concurrent worktrees; starting a competing
  stack risked port/network collisions with in-progress sibling work, so it
  was deliberately not attempted here. These are exercised in
  `.github/workflows/ci.yml` and in the dedicated per-checkpoint evidence docs
  under `docs/operations/`.
- `bpc-protocol` and `tsk-protocol` own suites (`npm test` in each) were not
  re-run standalone in this pass beyond their build step; CI runs them
  independently per commit.

## What can run on Spark-2

`npm run test:spark2-host --prefix ultra_server` is the live cross-host drill
(`deploy/spark2-ha-lab/`) that specifically targets Spark-1 (`10.0.0.2` control
plane) and Spark-2 (private inter-Spark address) as physically separate hosts.
It was **not** run in this pass — it requires:
- SSH access and the `spark2-ha-lab` compose stack already up on both physical
  Spark hosts (owner-provisioned; boundaries documented in
  `deploy/spark2-ha-lab/README.md`).
- The reviewed controller and TSK checkouts both clean and pinned to full
  commit SHAs supplied to the command (same `tsk-protocol` commit pinned
  above).

This exact drill has real prior evidence already recorded in
`docs/operations/SPARK2_HOST_ACCEPTANCE.md` (dated 2026-07-21, one day before
this run), at `tsk-protocol@20bf099e0b4f7479b93cf1d5e245b3f7c87e1675` — the
same commit pinned in this pass. Re-running it now would reproduce that
acceptance against current `master`, but needs the owner's live two-host
session, not just this local worktree.

## Owner / external blockers (unchanged by this pass — see `GAPS.md`)

None of these are new; they are the standing open items relevant to what was
exercised here:
- **US-6** — Ultra's protocol deps are source-relative `file:` paths, not
  published/signed packages; this is exactly what made local provisioning
  necessary above.
- **US-7 / CC-16** — operator bearer, recovery-HMAC, and mesh-secret custody,
  secret-manager integration, and an actual deployment ceremony are external
  to this repository.
- **US-9** — no composed two-node Ultra test proves shared fencing/promotion
  in production; do not read this pass as production-HA evidence.
- **CC-6 / AL-2** — no live off-host immutable (S3 Object Lock / R2) sink is
  deployed; the two `UserWarning`s above are the local symptom of this open
  item.
- **CC-7 / IRS-1..5** — IRS/Treasury authorization package, agency inventory
  submission, and external live-workflow acceptance are program/partner work
  outside this repository's control.
- **SDK-2** — the SDK is unsigned; Defender/enterprise AV may flag it.

## Verdict

Green: 1748 Python + 65 Node tests passed, 0 failures, 6 total skips (all
expected/platform-conditional). No code changed. Opened as a draft PR for
review; not merged.
