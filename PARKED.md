# Parked and Restorable Records

This append-only register preserves wording, code, configuration, and behavior
that was removed, replaced, or materially changed. Its primary purpose is
recovery: if a change causes a regression, a parked record identifies the exact
prior state, why it changed, how to restore it, and how to validate restoration.

Parking material does not endorse it, concede it, or erase its history. It
records the prior state and links to the decision that changed it.

Every parked record has a stable `PARK-*` ID. The work-log event, decision
rationale, and changelog entry that perform the change must link to that ID.

## When Parking Is Required

Create a parked recovery record when a change:

- removes or narrows a security, compliance, authorization, performance, or
  patent-evidence statement;
- removes or materially changes implementation behavior, configuration,
  interfaces, dependencies, data formats, or operational procedures;
- changes the scope of what a named test is said to establish;
- replaces a factual assertion because its evidence, version, or environment
  changed; or
- retires terminology while the former wording remains relevant to provenance.

Do not create a parked record for spelling, formatting, link repair, or another
change that does not alter meaning.

## Record Rules

1. Preserve the former wording or material exactly when practical. For code or
   larger content, identify a durable pre-change commit and path. When Git is not
   sufficient, store a recovery patch or artifact under `docs/parked/` and
   include its SHA-256 digest.
2. Record the original repository, branch, file, line or section, and full source
   commit.
3. Explain the reason without making a new unsupported legal or compliance
   conclusion.
4. Identify the replacement wording or state explicitly that there is none.
5. Include non-destructive restore steps, prerequisites, rollback triggers, and
   verification commands.
6. Never copy credentials, private keys, tokens, controlled data, or other
   secrets into this register or a plaintext recovery artifact. Record the
   secret identifier and approved reprovisioning procedure instead.
7. Record whether the restoration procedure was rehearsed. An untested recovery
   procedure must be labeled `Not rehearsed` rather than presented as proven.
8. Do not delete a parked record. If material is restored, append a new work-log
   and decision record, then update status while retaining the complete history.

## Record Template

```markdown
## PARK-<UTC-date>-<sequence> - Short description

**Status:** Parked | Superseded | Restored
**Category:** patent evidence | security property | authorization | release | other
**Former location:** Repository, file, and section
**Source commit:** Full Git SHA
**Affected paths:** All files, data, interfaces, and configuration involved
**Action log:** LOG-<UTC-date>-<sequence>
**Why changed:** WHY-<UTC-date>-<sequence>
**Parked by:** Change commit or PR

**Former wording:**

> Exact former wording, or an artifact path and SHA-256 digest.

**Recovery source:** Pre-change Git object, patch, artifact path, and checksum.

**Reason parked:** Evidence-bounded explanation with a link to the full decision.

**Replacement:** Exact replacement wording and current location, or `None`.

**Restore when:** Observable rollback triggers.

**Restore procedure:** Ordered, non-destructive restoration steps and required
dependencies.

**Validation after restore:** Commands and expected results.

**Recovery rehearsal:** Not rehearsed | Passed, with timestamp, environment,
and evidence link.

**Restoration risks:** Data loss, compatibility, security, compliance, or
operational risks introduced by restoring the prior state.

**Evidence and links:** Named tests, artifacts, commits, issues, authoritative
sources, limitations, and all related records.
```

## Register

No records have been parked yet.
