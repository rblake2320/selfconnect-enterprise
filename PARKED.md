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

## PARK-20260715-007 - Enqueue-only delivery and basename-only target assurance

**Status:** Parked
**Category:** security property, runtime behavior, evidence claim
**Former location:** Channel router, watcher, target guard, MCP receipt text,
and ATO evidence documentation
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Affected paths:** `experiments/win32_probe/channel_router.py`,
`experiments/win32_probe/target_guard.py`, `enterprise/mcp_dispatch.py`,
`enterprise/mcp_tools.py`, `enterprise/watcher.py`, `enterprise/registry.py`,
and `docs/ato/`
**Action log:** [LOG-20260715-005](LOG.md#log-20260715-005)
**Why changed:** [WHY-20260715-005](WHY.md#why-20260715-005)
**Parked by:** commit containing this record

**Former wording:** Router `success=True` meant only that character posts did
not raise, while `readback_hash` remained empty. The watcher marked WM_CHAR and
UIA `OK` from API presence. The target guard discarded the image directory,
required `conhost.exe` for all classic consoles, and documentation described the
result as kernel-verified or not spoofable.

**Recovery source:** Named paths at Git object `bee4c3f`.

**Reason parked:** A real Windows run disproved delivery semantics and classic
console ownership assumptions. Basename-only checks did not enforce the stated
protected-path boundary.

**Replacement:** Separate enqueue/delivery/effect states; mandatory new UIA
readback for governed delivery; independent expected-output check for full live
conformance; protected-root image validation; and `UNKNOWN` channel health
until a target-bound live probe runs.

**Restore when:** Never restore as a governed or security claim. Use the old
implementation only in an isolated regression branch to reproduce the failure.

**Restore procedure:** Create a new branch at `bee4c3f`; do not overwrite the
current working tree or run the restored sender against a non-disposable target.

**Validation after restore:** Reproduce the dead-session false positive, stale
readback case, user-writable executable lookalike, and classic `cmd.exe` false
rejection. The restored state is expected to fail these checks.

**Recovery rehearsal:** The false-positive behavior was reproduced during the
2026-07-15 live acceptance run; restoration itself was not rehearsed.

**Restoration risks:** Duplicate actions after blind retry, delivery claims with
no target evidence, class-name/image-path spoof acceptance, and false channel
health reporting.

**Evidence and links:** [WHY-20260715-005](WHY.md#why-20260715-005),
`tools/irs_runtime_conformance.py`, and
`docs/assurance/CONTROL_CATALOG.md`.

## PARK-20260715-006 - Named partnership briefing and structural-secrecy wording

**Status:** Parked
**Category:** product boundary, security claim
**Former location:** proposed integration briefing and `enterprise/ultra_gate.py`
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f` plus uncommitted review material
**Affected paths:** product documentation, Ultra client description, TSK claim wording
**Action log:** [LOG-20260715-004](LOG.md#log-20260715-004)
**Why changed:** [WHY-20260715-004](WHY.md#why-20260715-004)
**Parked by:** commit containing this record

**Former wording:**

> TSK layers 6-7 add tumbler keys with structural secrecy. An attacker who
> compromises all BPC credentials still cannot forge a TSK key without knowing
> the server-only positional map.

The review worktree also contained a prospective-company briefing inside the
product repository.

**Recovery source:** Git object `bee4c3f:enterprise/ultra_gate.py`; the discarded
briefing remains in the owner-controlled session record, not this repository.

**Reason parked:** The effective ordered layout is derivable from client-visible
provisioning metadata. Named prospective relationships do not belong in the
product's source or assurance record.

**Replacement:** Precise reduced-view disclosure language, executable response
shape assertions, product-neutral sector profiles, and generic adapter gates.

**Restore when:** Restore neither claim nor named briefing here. A stronger TSK
claim requires a redesigned protocol and adversarial evidence; a named briefing
requires a separate authorized diligence location.

**Restore procedure:** Create a separate review branch and obtain owner plus
legal/IP approval before any alternative wording is proposed.

**Validation after restore:** Re-run live TSK disclosure tests, threat review,
repository-neutrality review, and all release gates.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Creates a technically unsupported security claim and
possible endorsement, confidentiality, IP, or procurement confusion.

**Evidence and links:** [WHY-20260715-004](WHY.md#why-20260715-004) and
`ultra_server/server.test.mjs`.

## PARK-20260715-005 - Unknown classification ranked below UNCLASSIFIED

**Status:** Parked
**Category:** security behavior
**Former location:** label ranking, policy/profile construction, observer filtering
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Affected paths:** `enterprise/labels.py`, `enterprise/policy.py`,
`enterprise/classified_mode.py`, `enterprise/observer.py`, related tests
**Action log:** [LOG-20260715-003](LOG.md#log-20260715-003)
**Why changed:** [WHY-20260715-003](WHY.md#why-20260715-003)
**Parked by:** commit containing this record

**Former wording:** Unknown classification names returned rank `-1`, and some
constructors silently normalized unknown values to UNCLASSIFIED.

**Recovery source:** Named paths at Git object `bee4c3f`.

**Reason parked:** The behavior allowed invalid labels through every valid
classification ceiling.

**Replacement:** Strict construction validation and runtime deny/exclude paths.

**Restore when:** Do not restore; replace only with an equally fail-closed label
registry.

**Restore procedure:** Restore in an isolated adversarial branch only.

**Validation after restore:** Run all label, policy, observer, classified-mode,
fuzz, and red-team suites and demonstrate no unknown label can pass.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Reopens a direct classification-bypass condition.

**Evidence and links:** [WHY-20260715-003](WHY.md#why-20260715-003).

## PARK-20260715-004 - Unauthenticated volatile Ultra lifecycle behavior

**Status:** Parked
**Category:** security behavior, durability
**Former location:** Python/Node Ultra lifecycle clients, routes, and stores
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Affected paths:** `enterprise/ultra_gate.py`, `enterprise/key_recovery.py`,
`ultra_server/server.js`, Ultra tests and CI
**Action log:** [LOG-20260715-002](LOG.md#log-20260715-002)
**Why changed:** [WHY-20260715-002](WHY.md#why-20260715-002)
**Parked by:** commit containing this record

**Former wording:** Python emitted an agent-auth header that Node did not verify;
registration, provisioning, and recovery had inconsistent or absent guards;
production authority state was process memory; unavailable live servers skipped
tests.

**Recovery source:** Named paths at Git object `bee4c3f`.

**Reason parked:** The composition did not authenticate lifecycle mutations or
survive restart and could not support production identity claims.

**Replacement:** Body-bound agent proof, operator authorization, dual-control
recovery, ownership checks, PostgreSQL/Redis state, and mandatory live tests.

**Restore when:** Only if a compatibility sandbox is explicitly marked volatile
and unreachable from production; never as production behavior.

**Restore procedure:** Restore in an isolated development branch with production
startup refusal retained.

**Validation after restore:** Run auth, replay, ownership, concurrency, live
cross-language, and kill/restart suites.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Reopens unauthorized enrollment/recovery, replay, identity
loss, counter rollback, and false-green CI.

**Evidence and links:** [WHY-20260715-002](WHY.md#why-20260715-002) and
`tools/ultra_restart_conformance.py`.

## PARK-20260715-001 - Universal production and verification claims

**Status:** Parked
**Category:** security property, authorization, release
**Former location:** `README.md`, overview, test, and implementation-evidence sections
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Affected paths:** `README.md`, `SECURITY.md`
**Action log:** [LOG-20260715-001](LOG.md#log-20260715-001)
**Why changed:** [WHY-20260715-001](WHY.md#why-20260715-001)
**Parked by:** commit containing this record

**Former wording:**

> A production-grade policy enforcement and audit substrate... Every agent
> action passes through a deny-by-default policy evaluator. Every decision is
> logged to a tamper-evident hash chain.

> The security posture is verified continuously — not claimed. Every guarantee
> listed in SECURITY.md has a named test that proves it.

**Recovery source:** Git object `bee4c3f:README.md`.

**Reason parked:** Default MCP actuation did not require PolicyEnforcer or a
persistent ledger, and named component tests do not establish a deployed system
or authorization.

**Replacement:** Evidence-bounded engineering-prototype language in `README.md`
and `SECURITY.md`.

**Restore when:** Only after executable whole-system conformance and deployment
evidence establish the exact restored proposition.

**Restore procedure:** Restore the source text from the named Git object in a
new branch, update the linked WHY/LOG records, and attach the qualifying evidence.

**Validation after restore:** Run full CI, live conformance, off-host recovery,
partner integration, and applicable independent assessment.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Reintroduces unsupported security and authorization
implications.

**Evidence and links:** [WHY-20260715-001](WHY.md#why-20260715-001).

## PARK-20260715-002 - Raw denied entries in training context windows

**Status:** Parked
**Category:** security property
**Former location:** `enterprise/observer.py` and
`tests/test_enterprise/test_observer.py`
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Affected paths:** Observer extraction and training evidence tests
**Action log:** [LOG-20260715-001](LOG.md#log-20260715-001)
**Why changed:** [WHY-20260715-001](WHY.md#why-20260715-001)
**Parked by:** commit containing this record

**Former wording:**

> Context window pulls raw log entries (including denied); they are not training records.

**Recovery source:** Git objects `bee4c3f:enterprise/observer.py` and
`bee4c3f:tests/test_enterprise/test_observer.py`.

**Reason parked:** `context_before` is exported with the training record, so raw
denied entries were exposed to training despite not being primary records.

**Replacement:** Context entries now pass the same ObserverFilter as primary records.

**Restore when:** Do not restore unless context is removed from every exported
training format or another control establishes equivalent exclusion.

**Restore procedure:** Restore both files from the source commit on a branch.

**Validation after restore:** Run observer and adversarial training-poisoning tests.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Reopens policy-denied training-data exposure.

**Evidence and links:** `test_context_window_does_not_include_denied_in_output`.

## PARK-20260715-003 - Lease-only MCP actuation and chain-only provenance verification

**Status:** Parked
**Category:** security property, other
**Former location:** `enterprise/mcp_dispatch.py`, `enterprise/service.py`,
`enterprise/provenance.py`
**Source commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Affected paths:** MCP injection, service provenance, standalone verifier
**Action log:** [LOG-20260715-001](LOG.md#log-20260715-001)
**Why changed:** [WHY-20260715-001](WHY.md#why-20260715-001)
**Parked by:** commit containing this record

**Former wording:** The source commit accepted `sc_inject_text` after lease
validation and routing; the default dispatcher had no policy or persistent
ledger. The service constructed but did not start its recorder. `verify_log()`
checked chain continuity without verifying `recorder_sig`.

**Recovery source:** The three paths at source commit `bee4c3f`.

**Reason parked:** The behavior did not support mandatory governance or signed
attribution claims.

**Replacement:** `GovernedRuntime`, fail-closed MCP gates, started/signed service
provenance, and external-public-key signature verification.

**Restore when:** Only if a verified compatibility requirement cannot be met by
an adapter and the restored path is explicitly labeled ungoverned.

**Restore procedure:** Restore the named paths on a branch and retain the current
runtime as the governed default.

**Validation after restore:** Run MCP, service, provenance, signature-tamper,
and live conformance suites.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Reopens policy, target, approval, persistence, and
attribution gaps.

**Evidence and links:** `tests/test_enterprise/test_governed_runtime.py` and
`tests/test_enterprise/test_provenance.py`.
