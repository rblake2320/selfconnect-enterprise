# Decision Rationale

This append-only record explains why material repository decisions were made.
It separates rationale from the chronological action record in `LOG.md` and the
restoration material in `PARKED.md`.

The linked record chain is:

`CHANGELOG.md` summary -> `LOG.md` action -> `WHY.md` rationale -> `PARKED.md`
recovery record, when material was removed or changed.

## Recording Rules

1. Create a `WHY-*` record for material implementation, security, compliance,
   release, architecture, or evidence-policy decisions.
2. State the evidence and uncertainty available at the time. Do not rewrite a
   decision later to make it appear better informed than it was.
3. Record alternatives considered, consequences, and explicit rollback
   conditions.
4. Link the action log, parked recovery record when applicable, issues or pull
   requests, source commits, tests, and external authorities.
5. Supersede a decision with a new `WHY-*` record. Retain the former rationale
   and link both directions.

## Entry Template

```markdown
## WHY-<UTC-date>-<sequence> - Short decision title

**Status:** Accepted | Superseded | Reversed
**Decision date (UTC):** YYYY-MM-DDTHH:MM:SSZ
**Decision owner:** Person or accountable role
**Action log:** LOG-<UTC-date>-<sequence>
**Parked records:** PARK-<UTC-date>-<sequence>, or `None`
**Source state:** Repository, branch, and full Git SHA

**Decision:** What was decided.

**Why:** The problem, evidence, and constraints that drove the decision.

**Alternatives considered:** Options rejected or deferred and why.

**Consequences:** Benefits, costs, risks, and patent/compliance effects.

**Rollback conditions:** Observable conditions that should trigger restoration
or a replacement decision.

**Evidence and links:** Tests, artifacts, commits, issues, authorities, and all
related records.
```

## Register

## WHY-20260710-001 - Use linked, restorable change records

**Status:** Accepted
**Decision date (UTC):** 2026-07-10T04:43:01Z
**Decision owner:** Repository owner
**Action log:** [LOG-20260710-001](LOG.md#log-20260710-001)
**Parked records:** None
**Source state:** `selfconnect-enterprise`, `origin/master`,
`cf0f2a36b05cca2acce943a036ae6b7239d1cd57`

**Decision:** Maintain separate but cross-linked records for release summaries,
full actions, decision rationale, and restorable prior states.

**Why:** Git retains historical content but does not reliably explain intent,
the evidence used, rollback triggers, or the complete procedure for restoring a
previous implementation. Security, compliance, and patent-evidence corrections
also need a clear record showing that narrower language preserves history rather
than erasing prior reduction-to-practice artifacts.

**Alternatives considered:** A larger `CHANGELOG.md` was rejected because release
readers should not have to parse operational detail. Relying only on commit
messages was rejected because messages do not provide a stable recovery index or
require links between rationale, evidence, and parked material.

**Consequences:** Documentation work requires additional recordkeeping. In
return, material changes have a traceable reason, recovery source, rollback
condition, and validation path. Parking a claim records its history; it does not
endorse the former wording or make a patentability or authorization conclusion.

**Rollback conditions:** Replace this structure only if it becomes unmaintainable,
fails to preserve recovery information, or an adopted repository governance
system provides equivalent traceability. Any replacement must first preserve
these records and document a migration path.

**Evidence and links:** [LOG-20260710-001](LOG.md#log-20260710-001),
[PARKED.md](PARKED.md), [CHANGELOG.md](CHANGELOG.md), and
`tests/test_documentation_records.py`.
