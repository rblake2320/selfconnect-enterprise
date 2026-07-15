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

## LOG-20260715-005 - Require confirmed delivery, execution effect, and protected target paths

**Timestamp (UTC):** 2026-07-15T06:38:00Z
**Actor:** Codex, requested by the repository owner
**Category:** runtime correctness, security fix, live acceptance, claim correction
**Base commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-005](WHY.md#why-20260715-005)
**Parked records:** [PARK-20260715-007](PARKED.md#park-20260715-007)

**Changed:** Windows Terminal routing now targets its InputSite child. Governed
injection reads the terminal before and after enqueue, requires a new visible
payload occurrence, rejects stale/unchanged readback, and separates enqueue from
confirmed delivery. Full live conformance additionally requires a new output
token that is absent from the command. The target guard now checks full image
paths against protected roots and supports the observed classic `cmd.exe`
owner. Watcher API-presence checks no longer report live channels as `OK`.

**Reason:** A real Windows acceptance run showed that `PostMessage` returning
without exception could produce a false successful receipt. It also exposed a
dead terminal session, a false `ConsoleWindowClass -> conhost.exe` assumption,
basename-only image validation, and channel health labels unrelated to delivery.

**Full actions and links:** `experiments/win32_probe/channel_router.py`,
`experiments/win32_probe/target_guard.py`, `enterprise/mcp_dispatch.py`,
`enterprise/watcher.py`, `tools/irs_runtime_conformance.py`, the executable
control catalog, [GAPS.md](GAPS.md), and the linked WHY/PARK records.

**Validation:** 88 targeted router, dispatcher, governed-runtime tests passed;
the 15-check target-guard load/spoof suite passed. On Windows Terminal
`1.24.11321.0`, a fresh protected-path `cmd.exe /K` target accepted a governed
command, UIA confirmed the injected command, the separate output token
`SC-FINAL-EFFECT-20260715-0645` newly appeared, and the signed ledger verified
32 entries. Receipt: `d5addee1-ffd6-49c2-a2a7-97433a99ddd4`. The run did not
assess an external workflow, immutable sink, government boundary, or scale.

## LOG-20260715-004 - Enforce product-neutral documentation and narrow TSK disclosure claims

**Timestamp (UTC):** 2026-07-15T06:05:16Z
**Actor:** Codex, requested by the repository owner
**Category:** security claim, product boundary, documentation, test
**Base commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-004](WHY.md#why-20260715-004)
**Parked records:** [PARK-20260715-006](PARKED.md#park-20260715-006)

**Changed:** Removed prospective-company material from the product repository,
replaced integration gaps with vendor-neutral acceptance gates, corrected
WM_COPYDATA sender claims, and documented the actual TSK provisioning disclosure
boundary. Added live-contract assertions that the reduced TSK payload omits
literal `position` fields while retaining client-required lengths. Added a
tiered executable control catalog with scope, evidence, and blind spots.

**Reason:** The repository is SelfConnect's product and evidence record, not a
prospective partner briefing. The TSK client receives enough ordered segment
metadata to derive the effective layout, so literal position omission cannot be
marketed as a hidden-layout security guarantee.

**Full actions and links:** `enterprise/ultra_gate.py`, `ultra_server/README.md`,
`ultra_server/server.test.mjs`, `SECURITY.md`, `GAPS.md`,
`docs/assurance/SECTOR_PROFILES.md`,
`docs/assurance/CONTROL_CATALOG.md`, and the linked WHY/PARK records.

**Validation:** Bounded repository scans passed; documentation/catalog tests
passed 7/7; the release catalog passed with named blind spots; and the live Node
contract passed all 14 checks. Full isolated and production results are recorded
in LOG-20260715-001 and LOG-20260715-002.

## LOG-20260715-003 - Reject unknown classification values at every current ingress

**Timestamp (UTC):** 2026-07-15T05:52:00Z
**Actor:** Codex, requested by the repository owner
**Category:** security fix, adversarial test
**Base commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-003](WHY.md#why-20260715-003)
**Parked records:** [PARK-20260715-005](PARKED.md#park-20260715-005)

**Changed:** Classification ranking now rejects unknown strings; label, policy,
profile, and observer ingress either raises during configuration or denies and
excludes malformed runtime records. Adversarial tests now require fail-closed
behavior.

**Reason:** The prior `rank(unknown) == -1` rule placed unknown markings below
UNCLASSIFIED, allowing malformed or attacker-selected values through ceilings.

**Full actions and links:** `enterprise/labels.py`, `enterprise/policy.py`,
`enterprise/classified_mode.py`, `enterprise/observer.py`, relevant tests under
`tests/test_enterprise/`, [GAPS.md](GAPS.md), and the linked WHY/PARK records.

**Validation:** 295 targeted classification, policy, observer, and adversarial
tests passed locally. The complete isolated suite also passed as recorded in
LOG-20260715-001.

## LOG-20260715-002 - Authenticate and persist Ultra lifecycle state

**Timestamp (UTC):** 2026-07-15T05:40:00Z
**Actor:** Codex, requested by the repository owner
**Category:** security fix, durability, live integration test, CI
**Base commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-002](WHY.md#why-20260715-002)
**Parked records:** [PARK-20260715-004](PARKED.md#park-20260715-004)

**Changed:** Added body-bound Ed25519 lifecycle proofs, production enrollment
authorization, dual-authorized recovery, ownership checks, replay protection,
PostgreSQL/Redis production stores, atomic HOTP counter updates, idempotency,
restart conformance, and mandatory live CI composition tests.

**Reason:** Python emitted a signature that Node ignored; lifecycle mutations
were inconsistently protected; production identity state was process memory;
and unavailable sidecars could skip the integration suite. Real PostgreSQL
testing then exposed counter rollback and stale idempotent provisioning defects.

**Full actions and links:** `enterprise/lifecycle_auth.py`,
`enterprise/ultra_gate.py`, `enterprise/key_recovery.py`,
`ultra_server/agent-auth.js`, `ultra_server/runtime-stores.js`,
`ultra_server/server.js`, `tools/ultra_restart_conformance.py`, CI workflow,
tests, [GAPS.md](GAPS.md), and the linked WHY/PARK records.

**Validation:** Node auth 6/6; live Node contract 14 checks; PostgreSQL store
7/7; production Python-to-Node 31/31; deterministic HOTP restart continuity
passed for agent `SC-0AC95B7E`, pair `pair_1fd589682ec2b7b0`, and TSK client
`tsk_fb057d8e67b9f06b`. These are local results until published CI evidence exists.

## LOG-20260715-001 - Harden governed execution and regulated-workflow evidence

**Timestamp (UTC):** 2026-07-15T05:17:47Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, test, audit, documentation
**Base commit:** `bee4c3fc8660a9ed27fb672c07d61f8ece252a3f`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-001](WHY.md#why-20260715-001)
**Parked records:** [PARK-20260715-001](PARKED.md#park-20260715-001),
[PARK-20260715-002](PARKED.md#park-20260715-002),
[PARK-20260715-003](PARKED.md#park-20260715-003)

**Changed:** Added mandatory `GovernedRuntime` composition; fail-closed MCP
policy, approval, target-binding, and signed-ledger gates; reserved ledger-field
protection; filtered observer context; persistent signed service provenance;
external recorder-signature verification; structured IRS evidence records; a
live no-mock conformance tool; and product-neutral sector documentation.

**Reason:** The repository contained strong independent controls but the default
MCP actuator did not require their composition. Several universal and IRS claims
therefore exceeded the tested runtime behavior.

**Full actions and links:** `enterprise/governed_runtime.py`,
`enterprise/mcp_dispatch.py`, `enterprise/irs_evidence.py`,
`enterprise/provenance.py`, `enterprise/ledger.py`,
`tools/irs_runtime_conformance.py`, [sector profiles](docs/assurance/SECTOR_PROFILES.md),
[GAPS.md](GAPS.md), and the linked WHY/PARK records.

**Validation:** In a clean Python 3.12 environment with `cryptography==49.0.0`,
`pip check` and Ruff passed. The complete offline suite passed 1,373 tests with
32 explicit environment/live skips and two expected warnings about the absent
immutable sink. The 31 Ultra live tests then passed separately against the real
production-mode sidecar, yielding 1,404 passing test executions across the
offline and live runs; one unrelated environment-dependent test remains skipped.
`pip-audit` found zero dependency vulnerabilities while explicitly skipping the
two non-PyPI local packages, and `npm audit --omit=dev` found zero known
vulnerabilities. A final commit and published CI result remain pending.

**Notes:** No external tax-workflow adapter, off-host WORM sink, or IRS-authorized
environment was available for a live integration test. Those results remain open,
not inferred from unit tests.

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
