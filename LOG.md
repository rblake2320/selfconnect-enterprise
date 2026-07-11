# Work Log

This is the chronological evidence log for repository work. It records what was
changed, why it was changed, the source state used, and how the result was
validated. It supplements, but does not replace, Git history or `CHANGELOG.md`.

- `CHANGELOG.md` summarizes user-visible and release-level changes.
- `LOG.md` records individual work, audit, evidence, and documentation events.
- `WHY.md` records the rationale, alternatives, consequences, and rollback
  conditions for a material decision.
- `PARKED.md` preserves restorable wording, code, configuration, or behavior
  removed or materially changed by an event recorded here.

## Recording Rules

1. Add new entries at the top of the register. Do not silently rewrite a closed
   entry. Correct it with a later entry that cites the earlier log ID.
2. Use UTC timestamps and identify the exact repository base commit. Test and
   audit results must also identify the commit on which they ran.
3. Distinguish implementation, test evidence, security properties, patent
   evidence, and authorization status. One category must not imply another.
4. Link each material decision to a stable `WHY-*` record.
5. When behavior, configuration, or wording is removed or materially changed,
   preserve its recovery source in `PARKED.md` and cite its stable `PARK-*` ID
   from this log and the changelog.
6. Formatting-only and typographical changes do not require a parked record.
7. Never use a log entry as a substitute for an external approval, assessment,
   patentability opinion, or authorization decision.

## Entry Template

```markdown
## LOG-<UTC-date>-<sequence> - Short title

**Timestamp (UTC):** YYYY-MM-DDTHH:MM:SSZ  
**Actor:** Name or automation identity  
**Category:** implementation | test | audit | documentation | release | decision  
**Base commit:** Full Git SHA  
**Change reference:** Commit, PR, or `commit containing this entry`  
**Why:** WHY-<UTC-date>-<sequence>  
**Parked records:** PARK-<UTC-date>-<sequence>, or `None`

**Changed:** Exact files and behavior or wording changed.

**Reason:** Why the change was necessary.

**Full actions and links:** Files, commands, commits, issues, artifacts, and
related records sufficient to reconstruct the action.

**Validation:** Commands, results, evidence paths, and relevant environment.

**Notes:** Limitations, follow-up work, or `None`.
```

## Register

## LOG-20260710-001 - Add evidence-preserving documentation records

**Timestamp (UTC):** 2026-07-10T04:43:01Z  
**Actor:** Codex, requested by the repository owner  
**Category:** documentation  
**Base commit:** `cf0f2a36b05cca2acce943a036ae6b7239d1cd57`  
**Change reference:** commit containing this entry  
**Why:** [WHY-20260710-001](WHY.md#why-20260710-001)  
**Parked records:** None

**Changed:** Added `LOG.md`, `WHY.md`, and `PARKED.md`; linked the records from
`CHANGELOG.md` and `README.md`; and added
`tests/test_documentation_records.py` to validate record IDs and cross-record
references.

**Reason:** Security, compliance, and patent-evidence wording must remain
traceable when it is corrected or narrowed. Git history preserves bytes, but it
does not by itself explain why wording changed or point release readers to the
retired language.

**Full actions and links:** [WHY-20260710-001](WHY.md#why-20260710-001),
[PARKED.md](PARKED.md), [CHANGELOG.md](CHANGELOG.md), [README.md](README.md),
and `tests/test_documentation_records.py`. The base state is the full Git SHA
recorded above; the resulting state is the commit containing this entry.

**Validation:** Recorded at 2026-07-10T04:47:21Z:
`python -m pytest tests/test_documentation_records.py -q` passed 5 tests and
`python -m ruff check tests/test_documentation_records.py` passed with no
findings. `git diff --check` reported no whitespace errors.

**Notes:** This event adds recordkeeping infrastructure only. It does not alter
an implementation, security property, patent statement, or authorization
status.
