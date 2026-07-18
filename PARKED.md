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

## PARK-20260718-006 - Historical participant, executor, and bridge expansion

**Status:** Parked
**Category:** security boundary and deferred capability
**Former location:** `feat/participant-mode` at `125c24d70526ba29f42ba7c3d408b89ccddba0a8`
**Source commit:** `125c24d70526ba29f42ba7c3d408b89ccddba0a8`
**Affected paths:** `enterprise/registry.py`, `enterprise/policy.py`,
`enterprise/target_registry.py`, `enterprise/executor_win32.py`, and
`enterprise/bridge_connector.py`
**Action log:** [LOG-20260718-006](LOG.md#log-20260718-006)
**Why changed:** [WHY-20260718-006](WHY.md#why-20260718-006)
**Parked by:** commit containing this record

**Former wording:** The preserved branch described participant modes, five
built-in logical targets, a generalized Win32 executor, and a GenAI.mil bridge.

**Recovery source:** Git commit `125c24d70526ba29f42ba7c3d408b89ccddba0a8`.

**Reason parked:** Unknown historical participant modes fall through, target
selection uses the first class match, runtime target definitions can overwrite
built-ins, and broad direct Win32/file/subprocess operations do not use the
current governed dispatcher boundary.

**Replacement:** Only the bounded immutable logical-terminal alias and signed
lease issuance path in `enterprise/logical_targets.py`.

**Restore when:** A specific new action has a reviewed use case and is rebuilt
individually on the current policy, approval, audit, transport, and verification
contracts. Do not restore the old modules wholesale.

**Restore procedure:** Start from current master, recover only the required
behavior, reject unknown authority states, use the canonical guard/router, and
add real adapter evidence where feasible.

**Validation after restore:** Adversarial policy, target-replacement, approval,
pre-effect evidence, post-effect verification, and current full-suite gates.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Directly restoring the branch can reintroduce ambiguous
window selection, prompt-to-actuation coupling, weak path checks, and broader
execution authority.

**Evidence and links:** Issue #27 and `docs/LOGICAL_TARGET_LEASES.md`.

## PARK-20260718-005 - External CI supply-chain custody

**Status:** Parked
**Category:** supply-chain evidence
**Former location:** Not implemented; separate control boundary
**Source commit:** `8a4cdad4f1a723f4bb03e5d07ba73a12d974b87b`
**Affected paths:** Release workflow, dependency artifacts, runner bootstrap
**Action log:** [LOG-20260718-005](LOG.md#log-20260718-005)
**Why changed:** [WHY-20260718-005](WHY.md#why-20260718-005)
**Parked by:** commit containing this record

**Former wording:** Candidate-local RECORD and workflow checks risked being
described as supply-chain trust evidence.

**Recovery source:** This record; no removed implementation exists.

**Reason parked:** Candidate code controls its expected hashes and runner, so
it cannot establish independent custody.

**Replacement:** Candidate-local deterministic drift detection with bounded
claims.

**Restore when:** A protected reusable workflow or equivalent external gate
owns exact wheel hashes and runs from a clean bootstrap outside candidate
control.

**Restore procedure:** Provision protected workflow custody, pin externally
reviewed wheel hashes, execute from a clean bootstrap runner, and bind evidence
to the reviewed commit.

**Validation after restore:** Change candidate runner/hash files and prove the
external gate still rejects them.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** A nominally external workflow that candidates can edit
would reproduce the same self-attestation gap.

**Evidence and links:** [WHY-20260718-005](WHY.md#why-20260718-005).

## PARK-20260718-004 - Duplicate hidden CI test execution

**Status:** Parked
**Category:** test evidence
**Former location:** `.github/workflows/ci.yml`, `Unit tests` and
`Verify test count` steps
**Source commit:** `f0e2d820f4488f4ff0622f213220cc5da45d8439`
**Affected paths:** `.github/workflows/ci.yml`
**Action log:** [LOG-20260718-004](LOG.md#log-20260718-004)
**Why changed:** [WHY-20260718-004](WHY.md#why-20260718-004)
**Parked by:** commit containing this record

**Former wording:** The workflow contained a `Unit tests` step that ran pytest,
followed by `Verify test count`, which ran the complete pytest suite again with
captured output.

**Recovery source:** Git object
`f0e2d820f4488f4ff0622f213220cc5da45d8439:.github/workflows/ci.yml`.

**Reason parked:** The workflow ran the full suite twice and suppressed the
captured second run's failure identity. The two executions could produce
different results while the gate reported only a count.
**Replacement:** One candidate-local dedicated pytest runner prints complete
output, checks pytest's installed distribution and repository test inputs,
and applies the result, collection, and exact skip policy to structured pytest
report objects.

**Restore when:** A demonstrated requirement for two independent suite
executions that cannot be met by repeatability or stress jobs with retained
artifacts.

**Restore procedure:** Restore the source commit's two steps, make both runs
fully observable, and explicitly treat them as separate evidence.

**Validation after restore:** Run actionlint, the workflow regression test, and
a hosted Windows CI job.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Duplicate cost, nondeterministic disagreement between
runs, and loss of failure diagnostics if captured output is hidden again.

**Evidence and links:** Hosted run 29650683874,
`tests/test_enterprise/test_ci_test_execution.py`, and
[WHY-20260718-004](WHY.md#why-20260718-004).

## PARK-20260718-003 - Descriptive lease roles without capability enforcement

**Status:** Parked security behavior; do not restore.
**Category:** runtime authorization
**Former location:** `enterprise/mcp_dispatch.py`, lease issuance and
`_require_lease`
**Source commit:** `c094fb3c2de238aeb3c8411dd7366b7c4b6f246f`
**Affected paths:** Channel lease issuance, injection, output reads, audit evidence
**Action log:** [LOG-20260718-003](LOG.md#log-20260718-003)
**Why changed:** [WHY-20260718-003](WHY.md#why-20260718-003)
**Parked by:** commit containing this record

**Former wording:** The schema accepted `sender`, `receiver`, or `observer`, but
`_require_lease` checked only existence, expiry/revocation, and HWND. Any valid
role could therefore call `sc_inject_text`.

**Recovery source:** Git object
`c094fb3c2de238aeb3c8411dd7366b7c4b6f246f:enterprise/mcp_dispatch.py`.

**Reason parked:** A role presented as part of a security lease did not restrict
the authority that lease carried. Observer and receiver leases could actuate a
target, and replacing the stored frozen lease object could rewrite its role.

**Replacement:** Closed `_LEASE_TOOL_ROLES`, a dedicated authority store with
full-lease Ed25519 snapshots and independent revocation state, per-operation
signature and exact binding checks, and fail-closed role-denial evidence.

**Restore when:** Do not restore. Replace only with a stronger capability system
that proves equivalent sender-only actuation and fail-closed role mutation.

**Restore procedure:** None for production. The former file remains available
from the named Git object for isolated regression reproduction.

**Validation after restore:** Not applicable; restoration reopens the verified
observer-to-inject authorization bypass.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Restores role confusion, read-only-to-actuator privilege
escalation, and misleading audit metadata.

**Evidence and links:** `tests/test_enterprise/test_mcp_dispatch.py`, issue #27,
and [WHY-20260718-003](WHY.md#why-20260718-003).

## PARK-20260718-002 - Caller-selected system denial and unbound operator subject

**Status:** Parked security behavior; do not restore.
**Category:** operator attribution and persistence ownership
**Former location:** `enterprise/operator.py` and `enterprise/governed_runtime.py`
**Source commit:** `b58353dc9fdd2551014ccfd2253091e868b96854`
**Affected paths:** Governed approve/deny and runtime persistence composition
**Action log:** [LOG-20260718-002](LOG.md#log-20260718-002)
**Why changed:** [WHY-20260718-002](WHY.md#why-20260718-002)
**Parked by:** commit containing this record

**Former wording:**

> A durable denial whose caller-supplied operator id began with `system/` could
> synthesize internal proof. Verifier metadata did not identify the operator
> subject, and runtime startup did not own the approval and ledger resources.

**Recovery source:** Git object
`b58353dc9fdd2551014ccfd2253091e868b96854:enterprise/operator.py`.

**Reason parked:** Durable approval denial treated any operator identifier
starting with `system/` as an internal safety action and synthesized proof.
Decision verification metadata did not carry an authenticated operator subject,
so a verifier result could be accepted without proving it named the claimed
operator. Governed runtime instances also lacked a shared process-ownership lock
for their approval database and signed ledger resources.

**Replacement:** Human approve/deny always requires injected proof verification
whose authenticated subject equals `operator_id`. `ControlPlane` obtains a
private queue capability for safety denials. `RuntimeOwnershipLock`
independently rejects a second local writer for either persistence resource and
rejects same-resource and hard-link aliases present during acquisition or
startup revalidation. Owner-controlled immutable path entries are a deployment
precondition because advisory locks cannot prevent privileged later replacement.
Closing the composed runtime revokes and drains its shared mutation lifetime
before releasing ownership. An admitted outer synchronous operation may finish
its nested queue/control/ledger work as one unit, while close from inside that
unit fails explicitly instead of waiting on itself. On Windows the governed
suffix is protected by a native owner/SYSTEM/Administrators DACL and its
known-folder/suffix path is held by non-delete-sharing handles with pre/post-open
retarget checks. Child lock files also require a trusted owner and a protected
current-user/SYSTEM/Administrators-only DACL; remediation is confined to an
identity-checked child of that pinned suffix. Restoring environment-derived paths, shell-based SID/ACL
discovery, lstat-only junction checks, or unlock-only close would recreate the
retarget, PATH-poisoning, deadlock, or stale-object-graph risks.

**Restore when:** Never restore the public prefix bypass or unbound subject.
A future replacement for the local ownership lock must provide stronger tested
multi-host fencing and must preserve fail-closed startup.

**Restore procedure:** Work only on an isolated branch and replace the local
ownership mechanism with stronger fencing while retaining all adversarial tests.

**Validation after restore:** Wrong-subject, spoofed-prefix, concurrent writer,
restart, audit reconciliation, nested close/drain, Windows DACL/known-folder,
deterministic junction/retarget, and complete governed-runtime suites.

**Recovery rehearsal:** Reconstruct the former behavior only from the named Git
object in a disposable test workspace; never use it with real authority.

**Restoration risks:** Operator impersonation, unaudited internal-denial
spoofing, and ambiguous approval/ledger lineage from concurrent writers.

**Evidence and links:** [WHY-20260718-002](WHY.md#why-20260718-002), issue #26,
and `tests/test_enterprise/test_runtime_ownership.py`.

## PARK-20260718-001 - Historical participant, target, executor, and bridge branch

**Status:** Parked
**Category:** security property, release, other
**Former location:** branch `feat/participant-mode`; `enterprise/policy.py`,
`enterprise/registry.py`, `enterprise/target_registry.py`,
`enterprise/executor_win32.py`, and `enterprise/bridge_connector.py`
**Source commit:** `125c24d70526ba29f42ba7c3d408b89ccddba0a8`
**Affected paths:** Historical modules and tests named in issue #27
**Action log:** [LOG-20260718-001](LOG.md#log-20260718-001)
**Why changed:** [WHY-20260718-001](WHY.md#why-20260718-001)
**Parked by:** commit containing this record

**Former wording:** The source branch described participant modes, a logical
target registry, a deterministic Win32/UIA executor, and a GenAI.mil browser
connector as enterprise capabilities with 717 passing tests.

**Recovery source:** Git objects `4698b5d` (participant mode), `cfb76ff`
(target registry), `6ee675d` (Win32 executor), `d6bdaf1` (bridge connector), and
`125c24d` (historical tests). The branch and commits remain intact.

**Reason parked:** Unknown participant modes could bypass the mode gate and
invalid stored modes downgraded to `agent`. Logical resolution ignored its
title pattern and used class-only `FindWindowW`. The executor did not use the
current canonical target guard or consume required approvals. The bridge wrote
browser text directly without the current policy, approval, and precommit
composition. Historical mocked coverage does not repair those boundaries.

**Replacement:** The narrower `GovernedRuntime` MCP text path, strengthened by
the immutable final-boundary binding in LOG-20260718-001. There is no replacement
participant-mode, generalized executor, logical target registry, or external
LLM bridge claim.

**Restore when:** Only when a current product requirement and reviewed interface
exist and the rebuilt capability passes every adversarial acceptance item in
issue #27 on the then-current core transport pin.

**Restore procedure:** Create a new branch from current master; use the named
Git objects only as design evidence; rebuild one capability at a time through
the canonical governed runtime and target guard; do not cherry-pick the commits.

**Validation after restore:** Run full Python and package suites, Ruff, release
and claim gates, deterministic replacement/policy races, live Windows adapter
tests, and hosted CI for the exact restored commit.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Reintroduces participant confusion, wrong-window input,
approval bypass, proposal-to-actuation coupling, path/hash validation defects,
and unsupported product or government-interface claims.

**Evidence and links:** Issue #27, [WHY-20260718-001](WHY.md#why-20260718-001),
and the source commits listed above.

## PARK-20260717-002 - Caller-selected consume time and row-local replay history

**Status:** Parked
**Category:** authorization integrity, replay retention, migration
**Parked on (UTC):** 2026-07-17T14:58:07Z
**Former location:** `enterprise/operator.py`, `enterprise/ledger.py`, and
`enterprise/approval_audit.py`
**Source commit:** `5e8ffbe6ca0d6ee2eda68b6a88a028d43ecec3a3`
**Affected paths:** Approval expiry, decision replay, ledger receipt lookup,
and approval/outbox schema initialization
**Action log:** [LOG-20260717-002](LOG.md#log-20260717-002)
**Why changed:** [WHY-20260717-002](WHY.md#why-20260717-002)
**Parked by:** commit containing this record

**Former wording:**

> `consume_approved(..., now=...)` selected expiry time per call;
> `decision_nonce TEXT UNIQUE` retained replay history only on approval rows;
> ledger nested lookup returned shallow copies.

**Recovery source:** Git objects
`5e8ffbe6ca0d6ee2eda68b6a88a028d43ecec3a3:enterprise/operator.py`,
`5e8ffbe6ca0d6ee2eda68b6a88a028d43ecec3a3:enterprise/ledger.py`, and
`5e8ffbe6ca0d6ee2eda68b6a88a028d43ecec3a3:enterprise/approval_audit.py`.

**Reason parked:** Consume APIs accepted a public `now=` override, decision
nonce uniqueness disappeared with the approval row, ledger nested indexes used
shallow copies, receipt lookup depended on that cache after a separate verify
pass, and schema initialization inspected approvals without independently
requiring a modern outbox.

**Replacement:** Constructor-injected validated clocks; durable nonce
tombstones with explicit retention; deep-copy ledger boundaries; exact
verified-snapshot receipt lookup; and one-transaction rebuild plus versioned
structural and behavioral attestation of approvals, outbox, replay tombstones,
indexes, constraints, and foreign keys.

**Restore when:** Do not restore in a governed authorization path. A research
fixture may reproduce the former behavior only on an isolated branch with no
real authorization consumer and with the gap stated explicitly.

**Restore procedure:** Restore the named source object on a separate branch,
keep current tests intact, and demonstrate why replay-after-purge, clock
selection, cache aliasing, and orphan migration are acceptable in that bounded
experiment before changing any claim.

**Validation after restore:** The nested-alias, public-clock, backward-skew,
nonce-after-purge, mixed-schema, orphan, comment-spoof,
duplicate/conflicting-replay-state, forged-row, migration-rollback, full
approval, and MCP actuation tests must be rerun and any expected failures
recorded as open gaps.

**Recovery rehearsal:** Not rehearsed; the exact source commit and test boundary
are recorded.

**Restoration risks:** Reopens caller-selected expiry, replay after row purge,
mutable-cache receipt interpretation, and orphaned-outbox acceptance.

**Evidence and links:** [WHY-20260717-002](WHY.md#why-20260717-002),
`tests/test_enterprise/test_approval_audit.py`,
`tests/test_enterprise/test_ledger.py`, and `GOV-APPROVAL-001`.

---

## PARK-20260717-001 - Durable approval state without transition evidence

**Status:** Parked
**Category:** security property, audit durability
**Former location:** `enterprise/operator.py`, `enterprise/mcp_dispatch.py`
**Source commit:** `7c2ce4c4bba1313a5fe187129062180aa4e37af8`
**Affected paths:** DurableOperatorQueue and governed MCP approval consumption
**Action log:** [LOG-20260717-001](LOG.md#log-20260717-001)
**Why changed:** [WHY-20260717-001](WHY.md#why-20260717-001)
**Parked by:** commit containing this record

**Former wording:**

> `DurableOperatorQueue` stores the same state in SQLite, uses transactional
> state changes, and is the required governed-runtime path.

**Recovery source:** Git object
`7c2ce4c4bba1313a5fe187129062180aa4e37af8:enterprise/operator.py`.

**Reason parked:** SQLite made approval state restart-safe, but request,
approve, deny, consume, and expiry transitions were not independently appended
to the authoritative signed ledger. The dispatcher trusted the consumed queue
record without requiring a matching durable audit receipt.

**Replacement:** Same-transaction transition outbox, non-authorizing
`audit_pending`, durable ledger append rollback, transaction-locked idempotent
reconciliation, deployment-provided decision-writer verification with a bounded
nonce-bound envelope, and exact transition-lineage/receipt/chain binding before
actuation.

**Restore when:** Do not restore for hardened profiles. A non-audited queue may
remain only as an explicitly selected consumer/test implementation outside the
governed-runtime claim.

**Restore procedure:** Restore the named source object on a separate branch,
retain the current audited implementation, label every caller posture, and
update linked LOG/WHY/control records before review.

**Validation after restore:** Run approval concurrency, restart, audit failure,
receipt tamper, MCP actuation, full release, and live Windows suites.

**Recovery rehearsal:** Not rehearsed; source object and bounded restoration
conditions are recorded.

**Restoration risks:** Reopens approved-but-unaudited and
consumed-without-evidence failure windows.

**Evidence and links:** [WHY-20260717-001](WHY.md#why-20260717-001),
`tests/test_enterprise/test_approval_audit.py`, and `GOV-APPROVAL-001`.

## PARK-20260716-010 - Admin-authorized and unbounded initial monitoring slice

**Status:** Parked
**Category:** configuration, security property, operations
**Former location:** `ultra_server/server.js` and `ultra_server/monitoring/`
**Source commit:** `b3c2707298d3fb92659ab1e574dd4ce3ce77db49`
**Affected paths:** Ultra metrics middleware and the Prometheus/Grafana
reference configuration
**Action log:** [LOG-20260716-010](LOG.md#log-20260716-010)
**Why changed:** [WHY-20260716-010](WHY.md#why-20260716-010)
**Parked by:** commit containing this record

**Former wording:** `/metrics` used `requireAdminAuth`; request metrics used
`req.route?.path ?? req.path`; Prometheus and Grafana used mutable version tags,
listened on all host interfaces, and Grafana started with the inline `admin`
password.

**Recovery source:** Restore the affected paths from commit
`b3c2707298d3fb92659ab1e574dd4ce3ce77db49`.

**Reason parked:** The scraper held mutation authority, hostile unknown paths
could create unbounded labels, and the deployment defaults exposed management
interfaces and reusable credentials too broadly.

**Replacement:** Dedicated metrics credentials, closed-set labels,
digest-pinned images, loopback bindings, ignored secret files, persistent
volumes, and verified lifecycle instructions.

**Restore when:** Do not restore as a security configuration. A temporary
diagnostic restoration requires an isolated non-production host, no sensitive
state, and explicit owner approval.

**Restore procedure:** Restore the source commit on an isolated branch. Never
copy its credentials or port bindings into an active deployment.

**Validation after restore:** Re-run the metrics authorization, hostile-path
cardinality, configuration, live HTTP, and Compose tests; expected failures
demonstrate why the source state remains parked.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Administrator credential exposure, privileged scraper
compromise, telemetry resource exhaustion, mutable image drift, and management
UI exposure.

**Evidence and links:** [WHY-20260716-010](WHY.md#why-20260716-010), issue #14,
and pull request #25.

## PARK-20260716-009 - Hardened profiles writing provenance in process

**Status:** Parked
**Category:** security property, implementation behavior
**Former location:** `enterprise/service.py`, `enterprise/control.py`, and
`enterprise/provenance.py`
**Source commit:** `b001274419f378d8487e44f980bee3a09464000b`
**Affected paths:** Hardened runtime construction and authoritative audit writes
**Action log:** [LOG-20260716-009](LOG.md#log-20260716-009)
**Why changed:** [WHY-20260716-009](WHY.md#why-20260716-009)
**Parked by:** commit containing this record

**Former wording:** Enterprise and Government runtime objects could share an
in-process `ProvenanceRecorder` with the code whose actions were being audited.

**Recovery source:** The named paths at source commit `b0012744`.

**Reason parked:** The composition did not create an OS identity or filesystem
boundary between an agent process and the authoritative local ledger writer.

**Replacement:** `SelfConnectProvenance`, its service-SID DACL, signed local IPC,
durable request store, and fail-closed client adapter.

**Restore when:** Only for an explicitly named consumer/development posture.
Do not restore it as a hardened-profile fallback.

**Restore procedure:** Restore the source paths from the named commit on a new
branch and select consumer mode explicitly.

**Validation after restore:** Run consumer provenance tests and verify that all
Enterprise/Government configuration continues to refuse the fallback.

**Recovery rehearsal:** Not rehearsed.

**Restoration risks:** Recombines the audited actor and authoritative writer and
invalidates service-boundary claims.

**Evidence and links:** [WHY-20260716-009](WHY.md#why-20260716-009),
[service guide](docs/PROVENANCE_SERVICE.md), and
[redacted installed-service acceptance](docs/operations/2026-07-16-provenance-service-acceptance.json).

## PARK-20260716-008 - Presence-only Windows cleanup conformance

**Status:** Parked
**Category:** CI behavior, test evidence, release gate
**Former location:** `tools/portfolio_conformance.py` and
`tests/test_portfolio_conformance.py`
**Source commit:** `eb4e033f3402245ceca6c16c2c4de82ed37694c3`
**Affected paths:** `.github/workflows/ci.yml`,
`tools/portfolio_conformance.py`, and `tests/test_portfolio_conformance.py`
**Action log:** [LOG-20260716-008](LOG.md#log-20260716-008)
**Why changed:** [WHY-20260716-008](WHY.md#why-20260716-008)
**Parked by:** Codex, requested by the repository owner

**Former wording:** The conformance gate required `finally {}` and
`Stop-Process` to occur somewhere in the live-contract step. It did not require
stop or log capture to be inside the `finally` block.

**Recovery source:** The merged PR #30 source at Enterprise commit
`eb4e033f3402245ceca6c16c2c4de82ed37694c3`.

**Reason parked:** Independent mutation moved cleanup after an empty `finally`
while retaining every marker; `run_checks()` returned PASS. The former gate did
not establish the cleanup-on-failure proposition attributed to it.

**Replacement:** Quote-aware, brace-balanced extraction of the lifecycle `try`
after `Start-Process` and its immediately paired `finally`; live-contract
markers required in that try; guarded stop/stdout/stderr required in that exact
finally; negative outside/later-finally and guard mutations; and an executable
PowerShell test proving three cleanup failures do not replace a deliberate
primary contract failure.

**Restore when:** Never without an equal or stronger control-flow-aware and
failure-injection test.

**Restore procedure:** Not applicable. Implement and review a stronger
replacement, preserve this record, and rerun the focused and hosted gates.

**Validation after restore:** Outside-cleanup, later-finally cleanup, and
unguarded-cleanup mutations must fail conformance. Injected cleanup failures
must leave the primary contract failure as the nonzero process result.

**Recovery rehearsal:** The weakness was independently reproduced against
commit `eb4e033f3402245ceca6c16c2c4de82ed37694c3`; restoration is not approved.

**Restoration risks:** Leaked sidecar processes, missing failure logs, masked
contract failures, and false confidence in the release gate.

**Evidence and links:** [LOG-20260716-008](LOG.md#log-20260716-008),
[WHY-20260716-008](WHY.md#why-20260716-008), merged PR #30, and the repair pull
request including Actions run `29479444593`.

## PARK-20260716-007 - Sequential Windows native commands with last-exit evidence

**Status:** Parked
**Category:** CI behavior, test evidence, release gate
**Former location:** `.github/workflows/ci.yml`
**Source commit:** `e503c86548dfd6b6f608e75a424796ede71956e5`
**Affected paths:** `.github/workflows/ci.yml`,
`tools/portfolio_conformance.py`, and `tests/test_portfolio_conformance.py`
**Action log:** [LOG-20260716-007](LOG.md#log-20260716-007)
**Why changed:** [WHY-20260716-007](WHY.md#why-20260716-007)
**Parked by:** Codex, requested by the repository owner

**Former wording:** Critical Windows steps ran multiple git, npm, and Python
commands without enabling native-command error propagation. A later zero exit
could make a step green after an earlier failure. The development Ultra
sidecar also started in a separate Actions step from the contracts that used
it, relying on process lifetime that the runner did not preserve.

**Recovery source:** `.github/workflows/ci.yml` at Enterprise commit
`e503c86548dfd6b6f608e75a424796ede71956e5` and Actions runs `29476950456`
and `29477612730`.

**Reason parked:** The hosted run contained a failed BPC test and failed live
Node request but concluded success. The green check was therefore not faithful
evidence for those propositions.

**Replacement:** `$ErrorActionPreference = 'Stop'` and
`$PSNativeCommandUseErrorActionPreference = $true` in each named critical
Windows step, plus one live-contract step that starts, verifies,
uses, logs, and stops the sidecar under `try`/`finally`. Portfolio conformance
and negative regressions bind both requirements.

**Restore when:** Never without an equal or stronger fail-fast shell wrapper
and executable negative test.

**Restore procedure:** Not applicable. A replacement must first demonstrate
that a deliberately failing intermediate native command makes the job fail.

**Validation after restore:** Run the negative repository regression and a
disposable hosted workflow containing a failing intermediate command followed
by a successful command; the job must remain failed.

**Recovery rehearsal:** The former behavior was reproduced by Actions run
`29476950456`; the process-lifetime failure was reproduced by fail-closed run
`29477612730`. Both are retained as failure evidence, not rollback targets.

**Restoration risks:** False-green release evidence, untested dependency
composition, and inaccurate security claims.

**Evidence and links:** [LOG-20260716-007](LOG.md#log-20260716-007),
[WHY-20260716-007](WHY.md#why-20260716-007), Actions runs `29476950456` and
`29477612730`, clean replacement run `29478571278`, and BPC PR #17.

## PARK-20260716-006 - Prior BPC portfolio pin

**Status:** Parked
**Category:** configuration, release, security property
**Former location:** `portfolio-lock.json`
**Source commit:** `2e8e934536bc695f15119009b48eeaac7d59751a`
**Affected paths:** `portfolio-lock.json`
**Action log:** [LOG-20260716-006](LOG.md#log-20260716-006)
**Why changed:** [WHY-20260716-006](WHY.md#why-20260716-006)
**Parked by:** Codex, requested by the repository owner

**Former wording:** BPC
`ad6516698f3bb85a3517577f647cf46901205fd1` at package version `0.2.0`.

**Recovery source:** `portfolio-lock.json` at Enterprise commit
`2e8e934536bc695f15119009b48eeaac7d59751a`.

**Reason parked:** The former pin remains reproducible and contains the earlier
fail-closed Redis replay guard and immutable authorization snapshot, but it
predates the merged governed Redis replay-continuity work in BPC PR #14.

**Replacement:** BPC
`772271e174769f91a980cc3ee69a6eb9cc36bf39` in `portfolio-lock.json`.
The TSK pin remains `bc31c234100a6e6432d2ac5de82783fc136bc2ea`.

The intermediate PR #14-only candidate
`2aafcec93a1236e9994ba7e75907b398207b270e` was preserved in branch history
but superseded before acceptance after hosted evidence exposed a timing-test
boundary and Windows result-propagation defect. PR #17's canonical merge is
the reviewed replacement.

**Restore when:** Hosted composition fails, an incompatible runtime behavior
is reproduced, or a reviewed security finding requires bounded rollback.

**Restore procedure:** Create a new recorded decision, restore only the BPC
SHA, and run portfolio conformance plus the complete Windows live and Linux
PostgreSQL/Redis composition jobs. Do not silently follow either default
branch.

**Validation after restore:** Require exact checkout/package conformance, BPC
and TSK builds and suites, Ultra Node and Python live contracts, and both
hosted composition jobs.

**Recovery rehearsal:** Not rehearsed; Git retains the exact former lock.

**Restoration risks:** Omits the new governed Redis continuity implementation
and may attach current portfolio wording to an older source set.

**Evidence and links:** [LOG-20260716-006](LOG.md#log-20260716-006),
[WHY-20260716-006](WHY.md#why-20260716-006), `portfolio-lock.json`, and BPC
PR #14.

## PARK-20260716-005 - Prior single-process Ultra composition

**Status:** Parked
**Category:** runtime behavior, configuration, security property
**Former location:** `ultra_server/server.js`, `ultra_server/.env.example`, and
the production durability CI job
**Source commit:** `b001274419f378d8487e44f980bee3a09464000b`
**Affected paths:** `ultra_server/server.js`, `ultra_server/runtime-stores.js`,
`ultra_server/.env.example`, `.github/workflows/ci.yml`, and Ultra operational
documentation
**Action log:** [LOG-20260716-005](LOG.md#log-20260716-005)
**Why changed:** [WHY-20260716-005](WHY.md#why-20260716-005)
**Parked by:** Codex, requested by the repository owner

**Former wording:** Ultra production supported one application process with
PostgreSQL/Redis restart durability. It had no application-node writer lease,
signed promotion endpoint, shared transition lock, or current-writer readiness
contract.

**Recovery source:** Enterprise commit
`b001274419f378d8487e44f980bee3a09464000b`, or the disabled HA path in the
replacement (`ULTRA_HA_ENABLED=false`).

**Reason parked:** Single-process restart durability remains a valid bounded
deployment mode but cannot prevent concurrent old/new application writers.
Shared-state HA is therefore optional and fail-closed rather than silently
changing existing production startup behavior.

**Replacement:** The production-only shared-state active/passive mode and
[`ULTRA_SHARED_STATE_HA.md`](docs/operations/ULTRA_SHARED_STATE_HA.md).

**Restore when:** A shared-state fencing regression is reproduced, the pinned
TSK fencing API becomes incompatible, or an approved workload cannot tolerate
the bounded exclusive transition drain.

**Restore procedure:** Stop all HA-enabled nodes, confirm no request is in
flight, retain non-secret incident evidence, and start exactly one production
process with `ULTRA_HA_ENABLED=false` or unset. Run production restart and key
rotation conformance. Do not run multiple unfenced production processes.

**Validation after restore:** `/health` and `/ready` must return 200 on the one
process, the live Node/Python contract and production restart ceremony must
pass, and no second application process may serve the same state plane.

**Recovery rehearsal:** The disabled HA path retains existing unit/live
coverage. A deployment-specific stop-two/start-one rollback drill has not been
performed.

**Restoration risks:** Removes cross-process writer fencing and therefore
requires an operationally enforced single-process topology.

**Evidence and links:** [LOG-20260716-005](LOG.md#log-20260716-005),
[WHY-20260716-005](WHY.md#why-20260716-005), issues #21 and #28, and the
associated draft pull request.

## PARK-20260716-004 - Prior core transport composition

**Status:** Parked
**Category:** configuration, release, security property
**Former location:** `portfolio-lock.json` and `pyproject.toml`
**Source commit:** `8dcd6e58afb05f05d6fee97bba4c8d46a0ae9907`
**Affected paths:** `portfolio-lock.json`, `pyproject.toml`
**Action log:** [LOG-20260716-004](LOG.md#log-20260716-004)
**Why changed:** [WHY-20260716-004](WHY.md#why-20260716-004)
**Parked by:** Codex, requested by the repository owner
**Former wording:** SelfConnect
`a87e490c88c4ccb18ccaac514d018c7bba779d55` at package version `0.12.0`.
**Recovery source:** `portfolio-lock.json` and `pyproject.toml` at Enterprise
commit `8dcd6e58afb05f05d6fee97bba4c8d46a0ae9907`.
**Reason parked:** The former pin contains the repaired core CI and remains
historically reproducible, but it predates the merged fail-closed
`ConsoleWindowClass` transport and structured caller failure propagation.
**Replacement:** SelfConnect `56d5ff1802dca5d4136bcc32fa37aa122d4944dc`
implemented the transport correction. The active exact replacement is canonical
merge `5c493300b937a0f912e32a131061a132d2c11fe8`, which also contains PR #15's
deterministic external-target smoke evidence, in `portfolio-lock.json` and the
matching VCS dependency.
**Restore when:** Historical reproduction only, or after a new decision record
identifies a regression in the replacement and approves a bounded rollback.
**Restore procedure:** Create an isolated branch from the source commit and run
the same hosted composition workflow. Do not silently overwrite the active
portfolio lock.
**Validation after restore:** Require portfolio conformance and every Windows
and Linux composed job, and label the evidence historical.
**Recovery rehearsal:** Not rehearsed; Git retains the exact former lock.
**Restoration risks:** Reintroduces the known distinction failure between
PostMessage queue acceptance and actual `ConsoleWindowClass` input delivery.
**Evidence and links:** [LOG-20260716-004](LOG.md#log-20260716-004),
[WHY-20260716-004](WHY.md#why-20260716-004), `portfolio-lock.json`, and
SelfConnect PR #14 and SelfConnect PR #15.

## PARK-20260716-003 - Unbounded Enterprise-specific BPC error names

**Status:** Parked
**Category:** runtime behavior, security property, test evidence
**Former location:** `ultra_server/security-boundary.js` and related tests
**Source commit:** `de9dd25`
**Affected paths:** `ultra_server/security-boundary.js`,
`ultra_server/security-boundary.test.mjs`, `tests/test_e2e_ultra_gate.py`
**Action log:** [LOG-20260716-003](LOG.md#log-20260716-003)
**Why changed:** [WHY-20260716-003](WHY.md#why-20260716-003)
**Parked by:** Codex, requested by the repository owner
**Former wording:** Enterprise emitted `BPC_SHADOW_QUARANTINED` and
`BPC_INVALID_RESULT`; the live test searched for `SHADOW_QUARANTINED`.
**Recovery source:** The named paths at Git commit `de9dd25`.
**Reason parked:** The strict bridge correctly rejected those uppercase codes
from its bounded callback error vocabulary and returned
`BPC: VERIFICATION_FAILED`.
**Replacement:** Lowercase `shadow_denied` and `invalid_result`, with an exact
live assertion for `BPC: shadow_denied`.
**Restore when:** Never as free-form callback text. Restore only after a new
closed error schema explicitly includes and validates equivalent codes.
**Restore procedure:** Introduce the schema and cross-repository compatibility
tests first; then update all three layers in one reviewed composition change.
**Validation after restore:** Require hostile error/accessor tests plus live
shadow lockout and composed durability CI.
**Recovery rehearsal:** Not rehearsed; prior behavior is retained in Git.
**Restoration risks:** Weakens error sanitization or creates silent evidence
drift between BPC, TSK, and Enterprise.
**Evidence and links:** [LOG-20260716-003](LOG.md#log-20260716-003),
[WHY-20260716-003](WHY.md#why-20260716-003), and failed hosted job
`87515299829`.

## PARK-20260716-002 - Prior tested portfolio composition

**Status:** Parked
**Category:** configuration, release, security property
**Former location:** `portfolio-lock.json` and `pyproject.toml`
**Source commit:** `229c5598b2bf4bd3d40cbf2648a412896e96c0bd`
**Affected paths:** `portfolio-lock.json`, `pyproject.toml`
**Action log:** [LOG-20260716-002](LOG.md#log-20260716-002)
**Why changed:** [WHY-20260716-002](WHY.md#why-20260716-002)
**Parked by:** Codex, requested by the repository owner
**Former wording:** SelfConnect
`8cf151dbc5f312ce888e51aa429f62960e1a2ee6` at package version `0.10.0`, BPC
`7304e86d1d5df30b63e647146b20312a2a0da0c5`, and TSK
`63afcb83a033a82ce21f8f473e6a186cc195e801`.
**Recovery source:** `portfolio-lock.json` and `pyproject.toml` at Git commit
`229c5598b2bf4bd3d40cbf2648a412896e96c0bd`.
**Reason parked:** The former set remains valid historical evidence but does not
contain the completed core CI, Redis replay, immutable snapshot, and strict
composition corrections.
**Replacement:** SelfConnect `a87e490c88c4ccb18ccaac514d018c7bba779d55`,
BPC `ad6516698f3bb85a3517577f647cf46901205fd1`, and TSK
`bc31c234100a6e6432d2ac5de82783fc136bc2ea` in `portfolio-lock.json`.
**Restore when:** Historical reproduction only, or after a new decision record
identifies a regression in the replacement and approves a bounded rollback.
**Restore procedure:** Create an isolated branch from the source commit and run
the same hosted composition workflow. Do not silently overwrite the active
lock.
**Validation after restore:** Require lock conformance plus both Windows live
and Linux durable composition lanes, then label the result as historical.
**Recovery rehearsal:** Not rehearsed; the exact lock is retained in Git.
**Restoration risks:** Omits merged security fixes and can attach current
readiness wording to an older portfolio composition.
**Evidence and links:** [LOG-20260716-002](LOG.md#log-20260716-002),
[WHY-20260716-002](WHY.md#why-20260716-002), and `portfolio-lock.json`.

## PARK-20260716-001 - Duplicated protocol commit pins in CI and prose

**Status:** Parked
**Category:** release, security property
**Former location:** `.github/workflows/ci.yml` protocol checkout steps and
`ultra_server/README.md` Pinned Protocol Sources
**Source commit:** `ce249afa89a2bb3022ee93acc8309f8c63dad8b9`
**Affected paths:** `.github/workflows/ci.yml`, `ultra_server/README.md`,
`portfolio-lock.json`, `tools/portfolio_conformance.py`
**Action log:** [LOG-20260716-001](LOG.md#log-20260716-001)
**Why changed:** Independent literals could drift and did not prove the actual
checkout or package metadata used by a composition run.
**Parked by:** Codex, requested by the repository owner
**Former wording:** The Windows and Linux jobs independently checked out BPC
commit `7304e86d1d5df30b63e647146b20312a2a0da0c5` and TSK commit
`63afcb83a033a82ce21f8f473e6a186cc195e801`; the same values were repeated in
`ultra_server/README.md`.
**Recovery source:** Git commit
`ce249afa89a2bb3022ee93acc8309f8c63dad8b9` at the former paths.
**Reason parked:** Repeating immutable-looking values did not enforce equality
between jobs and supplied no executable verification of the resolved sources.
**Replacement:** `portfolio-lock.json` plus `tools.portfolio_conformance.py` and
the `PORTFOLIO-PIN-001` control.
**Restore when:** Restore only for historical reproduction of the former CI,
never as the active dependency-control design.
**Restore procedure:** Create an isolated branch at the source commit and run
the historical workflow against disposable checkouts. Do not overwrite the
current lock or active workflow.
**Validation after restore:** Confirm both historical workflow jobs resolve the
recorded commits, then label resulting evidence as historical and superseded.
**Recovery rehearsal:** Not rehearsed; Git contains the complete prior state.
**Restoration risks:** Reintroduces cross-job pin drift and can attach current
readiness language to an older, unidentified portfolio composition.
**Evidence and links:** [LOG-20260716-001](LOG.md#log-20260716-001),
[WHY-20260716-001](WHY.md#why-20260716-001), and
`tests/test_portfolio_conformance.py`.

## PARK-20260715-017 - Local self-verification presented as full Ultra authorization

**Status:** Parked
**Category:** security property, configuration, runtime behavior
**Former location:** `enterprise/ultra_gate.py`,
`enterprise/identity_gate.py`, and related tests
**Source commit:** `e071d745a5c87aaa0d008e35d2bd0928dea384e0`
**Affected paths:** Ultra injection authorization, degradation cascade,
server-required wrapper behavior, mesh-secret configuration, and tests
**Action log:** [LOG-20260715-008](LOG.md#log-20260715-008)
**Why changed:** [WHY-20260715-008](WHY.md#why-20260715-008)
**Parked by:** commit containing this record

**Former wording:** `UltraGate.authorize_injection()` called
`_self_verify()` and returned success without requiring the Ultra server.
`SC_STRICT_ENFORCE` defaulted off and only network errors were considered for
strict failure. Tests for `SC_REQUIRE_ULTRA_SERVER` reproduced intended logic
without exercising the production wrapper. A repository-known mesh secret
could be used when no deployment secret was provided.

**Recovery source:** The named files at Git object
`e071d745a5c87aaa0d008e35d2bd0928dea384e0`.

**Reason parked:** The local path did not evaluate durable server replay,
anomaly, full TSK lifecycle, or authoritative peer-binding state and therefore
could not support the Level 0 description.

**Replacement:** Authoritative `verify_server()` authorization, strict
fail-closed enforcement by default, real wrapper tests, atomic local nonce
handling, and explicit high-assurance mesh-secret provisioning.

**Restore when:** Do not restore as an authorization path. A local diagnostic
may be reintroduced only with a name and return type that cannot be mistaken
for server authorization.

**Restore procedure:** If needed for diagnostics, implement a separate
non-authorizing probe on a new branch; do not alter the authoritative gate.

**Validation after restore:** Assert that diagnostic success cannot dispatch an
action, bypass `SC_REQUIRE_ULTRA_SERVER`, or produce a governed receipt.

**Recovery rehearsal:** Not rehearsed; restoration as authorization is not
approved.

**Restoration risks:** Silent policy downgrade, replay acceptance across
processes, bypass of anomaly/identity state, and false whole-system claims.

**Evidence and links:** [LOG-20260715-008](LOG.md#log-20260715-008),
[WHY-20260715-008](WHY.md#why-20260715-008), and the named production tests.

## PARK-20260715-016 - Hardware, secrecy, readiness, and control-satisfaction overclaims

**Status:** Parked
**Category:** security property, authorization, compliance, release
**Former location:** `README.md`, `SECURITY.md`, `CHANGELOG.md`, `GAPS.md`,
`enterprise/identity.py`, `enterprise/identity_cng.py`,
`enterprise/tsk_client.py`, `enterprise/observer.py`,
`enterprise/mcp_tools.py`, `enterprise/service.py`,
`bench/tpm_sign_bench.py`,
`experiments/win32_probe/chained_channel.py`,
`experiments/win32_probe/target_guard.py`,
`experiments/win32_probe/tpm_identity.py`, `installer/selfconnect-enterprise.wxs`,
`installer/INSTALL.md`, and the affected files under
`docs/ato`, `docs/briefing`, `docs/compliance`, `docs/operations`, and
`docs/ROLLBACK.md`
**Source commit:** `e071d745a5c87aaa0d008e35d2bd0928dea384e0`
**Affected paths:** The former locations above
**Action log:** [LOG-20260715-007](LOG.md#log-20260715-007)
**Why changed:** [WHY-20260715-007](WHY.md#why-20260715-007)
**Parked by:** commit containing this record

**Former wording:** Examples included `machine-bound`, `hardware-bound`,
`cannot be faked`, `structural secrecy`, `hardware birth_id`,
`Ed25519+TPM`, `TPM-backed identity leases`, `dual-factor emergency bypass`,
`TPM identity` for the bounded Platform-KSP chain probe, `Satisfied`, `Ready`,
a universal three-year AU-11 retention period, and claims
that filtered data means a model cannot learn forbidden behavior.

**Recovery source:** The named paths at Git object
`e071d745a5c87aaa0d008e35d2bd0928dea384e0`.

**Reason parked:** DPAPI protects data in the current-user Windows context but
is not a process or hardware identity. The NCrypt software KSP is not a TPM.
The current TSK client can derive the layout needed to assemble its keys. The
MCP signing path used software Ed25519 with a separate platform claim rather
than TPM-bound payload signing. Component tests and candidate mappings do not
establish control satisfaction, authorization, legal non-repudiation, or model
behavior outside the tested data path.

**Replacement:** Bounded implementation statements, candidate-control mapping,
explicit open risks, run-specific test evidence, and precise distinctions
between key possession, OS protection, local platform claims, hardware-key
custody, remote attestation, and authorization status.

**Restore when:** Restore only an exact, narrow statement after the required
implementation and current evidence exist. Hardware wording requires a named
non-exportable hardware key and binding protocol. FIPS wording requires the
validated module, version, mode, configuration, and service-indicator evidence.
Control/readiness wording requires deployment assessment and accountable
authorization. Structural-secrecy wording requires a redesigned protocol whose
owning client cannot reconstruct the claimed secret structure.

**Restore procedure:** Start from the current bounded statement, add the exact
artifact/test/deployment evidence next to it, obtain the required assessor or
legal review where applicable, and add a new LOG/WHY record. Do not restore the
blanket former wording.

**Validation after restore:** Run the executable control catalog, documentation
claim regressions, relevant cryptographic/adversarial tests, and the live
deployment probe. Confirm the assertion states its scope and blind spots.

**Recovery rehearsal:** Not rehearsed; restoring unsupported wording is not an
approved recovery action.

**Restoration risks:** False hardware/security attribution, misleading buyers
or assessors, contaminated patent evidence, and unsupported authorization or
compliance claims.

**Evidence and links:** [LOG-20260715-007](LOG.md#log-20260715-007),
[WHY-20260715-007](WHY.md#why-20260715-007), Microsoft
[`CryptProtectData`](https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
NIST [FIPS 140-3 standards and guidance](https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards),
and NIST [SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).

## PARK-20260715-015 - Blanket guarantee and proof labels for component tests

**Status:** Parked
**Category:** security claim scope, test evidence language
**Former location:** `SECURITY.md`, `enterprise/identity_gate.py`, and
`enterprise/tpm_attestation.py`
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** Named former locations and
`tests/test_documentation_records.py`
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:** `What This System Guarantees`, repeated `Proven by:` labels,
`Concurrent safety proven by:`, `proven enterprise identity layer`, and
`proven DLL handles`.

**Recovery source:** The named files at Git object `b0c9fa8`.

**Reason parked:** A named test establishes only its exercised proposition in
its exact environment. A collection of component tests does not by itself prove
the whole deployed system, every concurrent schedule, authorization status, or
the reliability of an implementation layer beyond the tested boundary.

**Replacement:** `Narrowly Tested Component Properties`, `Tested by:`,
`Concurrent case tested by:`, and tested/exercised implementation language,
with the existing explicit deployment and authorization boundaries retained.

**Restore when:** Never restore as blanket language. A narrowly scoped use of
`proved` may be added only for an exact logical/test proposition whose scope,
inputs, environment, and blind spots are stated next to it.

**Restore procedure:** Reproduce the former text only on a historical review
branch. Do not overwrite current evidence wording.

**Validation after restore:** Claim regression must reject blanket guarantee or
proof labels. Review each named test to confirm the nearby property is no wider
than the assertion it executes.

**Recovery rehearsal:** The former phrases were found by a repository-wide
claim scan and removed; the documentation regression now scans their current
product surfaces.

**Restoration risks:** Compliance overclaim, evidence contamination, misleading
partner materials, and conflating component behavior with deployment approval.

**Evidence and links:** [LOG-20260715-006](LOG.md#log-20260715-006),
[WHY-20260715-006](WHY.md#why-20260715-006), `SECURITY.md`, and
`tests/test_documentation_records.py`.

## PARK-20260715-014 - Permanent conflict for stranded lifecycle requests

**Status:** Parked
**Category:** lifecycle durability, idempotency recovery behavior
**Former location:** `ultra_server/server.js` `claimIdempotency()`
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `ultra_server/server.js`, `runtime-stores.js`, their tests,
GAPS CC-13, the Ultra operation-recovery control, and production runbooks
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:** A repeated idempotency key whose durable state was
`processing` always returned HTTP 409 `IDEMPOTENCY_REQUEST_IN_PROGRESS`, even
after the process that owned the operation no longer existed.

**Recovery source:** `ultra_server/server.js` and `runtime-stores.js` at Git
object `b0c9fa8`.

**Reason parked:** A crash after pair/key/binding creation but before response
persistence left the request unavailable indefinitely. A generic time lease was
still unsafe because the side effect might already have occurred.

**Replacement:** Per-resource in-memory locks for development, PostgreSQL
advisory locks for production, idempotent completion, and operation-specific
durable reconciliation for pair registration, initial TSK provisioning,
identity binding, and rotation preparation. Missing resources execute only
while holding the lock; multiple matching resources fail closed.

**Restore when:** Only if a newly discovered reconciliation flaw can authorize
the wrong principal or duplicate a resource and immediate fail-closed service
is safer while a corrected operation-specific protocol is built.

**Restore procedure:** Revert only the four route recovery paths and store-lock
methods on an incident branch. Preserve the idempotency rows and resource state
for investigation; do not delete ambiguous records to force a retry.

**Validation after restore:** Verify that stranded requests return 409, no
side-effect route retries automatically, and an operator runbook exists to
reconcile every affected resource before service resumes.

**Recovery rehearsal:** The former behavior was reproduced by rewriting real
PostgreSQL rows to `processing`. The replacement recovered all four operations,
returned the original resource identifiers, and left one pair plus one initial
and one rotation key for the tested agent.

**Restoration risks:** Permanent request outage, manual database repair,
duplicate resources if operators bypass the conflict, and loss of deterministic
restart recovery.

**Evidence and links:** [LOG-20260715-006](LOG.md#log-20260715-006),
[WHY-20260715-006](WHY.md#why-20260715-006), GAPS CC-13,
`ULTRA-OP-RECOVERY-001`, and `ultra_server/server.test.mjs`.

## PARK-20260715-013 - Implicit Ultra npm package contents

**Status:** Parked
**Category:** release packaging, secret and state exposure prevention
**Former location:** `ultra_server/package.json` without `private` or `files`
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `ultra_server/package.json`,
`ultra_server/package-content.test.mjs`, control catalog, CI, and GAPS US-8
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:** There was no explicit package-content statement. The
effective behavior was an implicit npm artifact containing runtime files plus
local `.ultra-*.log` and `.ultra-*.json` test/restart artifacts.

**Recovery source:** `ultra_server/package.json` at Git object `b0c9fa8` and
the local npm dry-run evidence observed during release validation.

**Reason parked:** The parent repository `.gitignore` did not constrain the
nested npm package. A release artifact could therefore disclose local logs or
identity/restart state and was not a reproducible runtime-only package.

**Replacement:** `private: true` while protocol dependencies use relative
`file:` paths; an explicit seven-file runtime allowlist; a Node test that runs
and verifies the actual `npm pack --dry-run --json` manifest; and release-
control entry `ULTRA-PACKAGE-001`.

**Restore when:** Never restore implicit broad packing. Remove `private` only
after BPC/TSK dependencies have signed, publishable, pinned artifacts and the
registry publication/provenance procedure is exercised.

**Restore procedure:** Reproduce on an isolated branch only. Run the package
test and inspect the exact npm manifest before and after any manifest change.

**Validation after restore:** The manifest must contain only reviewed runtime
files plus npm-required metadata and must contain no log, state, test, private
key, environment-secret, or restart artifact.

**Recovery rehearsal:** The former package was reproduced with `npm pack
--dry-run --json`; it listed 32 entries, including local logs and restart-state
JSON. The replacement listed eight expected entries and no forbidden file.

**Restoration risks:** Secret or identity disclosure, unreproducible packages,
test evidence leakage, and distribution of an artifact whose relative
dependencies cannot be resolved by a consumer.

**Evidence and links:** [LOG-20260715-006](LOG.md#log-20260715-006),
[WHY-20260715-006](WHY.md#why-20260715-006), `US-8`,
`ULTRA-PACKAGE-001`, and `ultra_server/package-content.test.mjs`.

## PARK-20260715-012 - Unconditional FIPS and CNSA implementation wording

**Status:** Parked
**Category:** cryptographic security claim, evidence format
**Former location:** `enterprise/crypto.py`, `enterprise/identity_cng.py`, and
CNG ledger entries
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `enterprise/crypto.py`, `enterprise/identity_cng.py`,
`tests/test_enterprise/test_crypto.py`,
`tests/test_enterprise/test_identity_cng.py`
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:**

> FIPS-Validated Cryptographic Primitives via Windows CNG
>
> Algorithm suite (CNSA 2.0 compliant)
>
> fully CNSA 2.0 compliant audit trail

The same algorithm ID was also used by the portable test backend without a
signed backend field in ledger entries.

**Recovery source:** Named files at Git object `b0c9fa8`.

**Reason parked:** ECDSA P-384/SHA-384 selection and use of Windows CNG do not
alone establish FIPS module validation, CNSA system compliance, or an approved
operating environment. The portable backend is test-only and must be
distinguishable in evidence. The stored public identity also was not compared
to the key returned by the active backend during load.

**Replacement:** Deployment-conditional validation language;
`CRYPTO_BACKEND_ID`; persisted backend metadata; signed `crypto_backend` ledger
field; stored-public-key, algorithm, and backend mismatch refusal.

**Restore when:** Never restore unconditional validation/compliance language.
A deployment may cite a specific active CMVP certificate only after verifying
all certificate conditions, module versions, OS build, configuration, and
operating environment and preserving that evidence separately.

**Restore procedure:** For historical reproduction, create a branch at
`b0c9fa8`. Do not use its wording or backend-ambiguous ledger as current
assurance evidence.

**Validation after restore:** Run CNG/portable suites, swap the public identity
file, change the backend marker, and inspect signed entries. The former state is
expected to lack backend attribution and accept an unchecked stored public
file.

**Recovery rehearsal:** The mismatch attacks were exercised by the replacement
tests; restoration itself was not rehearsed.

**Restoration risks:** False FIPS/CNSA claims, portable-test evidence mistaken
for Windows CNG evidence, identity continuity ambiguity, and invalid assessor
or customer conclusions.

**Evidence and links:** [WHY-20260715-006](WHY.md#why-20260715-006),
`tests/test_enterprise/test_crypto.py`,
`tests/test_enterprise/test_identity_cng.py`, NIST CMVP guidance, and NSA CNSA
guidance.

## PARK-20260715-011 - Default prompt retention for every IRS action record

**Status:** Parked
**Category:** evidence schema, retention behavior
**Former location:** `enterprise/irs_evidence.py`, `IRSActionEvidence` and
`IRSEvidenceRecorder.record_action()`
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `enterprise/irs_evidence.py`, `enterprise/__init__.py`,
`tests/test_enterprise/test_irs_evidence.py`
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:** `record_action()` defaulted `retention_class` to
`PROMPT_LOG_1_YEAR` and wrote schema `selfconnect.irs-action-evidence.v1` even
when the record represented a test or incident event.

**Recovery source:** `enterprise/irs_evidence.py` at Git object `b0c9fa8`.

**Reason parked:** IRM 10.24.1.8 assigns different retention rules to prompt,
test, and incident logs. A generic prompt-log default can under-retain incident
evidence or incorrectly classify test evidence.

**Replacement:** `IRSActionRecordKind` is required. The v2 recorder derives
prompt, test, or incident retention from that enum and rejects unknown kinds.

**Restore when:** Restore v1 decoding only in an explicit migration reader for
historical records. Never restore its default as the write contract.

**Restore procedure:** Add a version-aware read adapter that treats retained v1
records as historical input, requires an operator-approved classification, and
writes a new v2 classification event without altering the original entry.

**Validation after restore:** Test all three v2 mappings, unknown-kind refusal,
historical v1 read-only handling, and retention-policy enforcement in the actual
storage boundary.

**Recovery rehearsal:** Not rehearsed; no production migration was performed.

**Restoration risks:** Under-retention, incorrect records schedules, silent
schema ambiguity, and false claims that a stored label enforces provider
retention.

**Evidence and links:** [WHY-20260715-006](WHY.md#why-20260715-006),
`tests/test_enterprise/test_irs_evidence.py`, IRM 10.24.1.8, and GAPS IRS-4.

## PARK-20260715-010 - Blanket no-mock test claim and obsolete impact-level label

**Status:** Parked
**Category:** evidence claim, authorization wording
**Former location:** `TEST_REGISTRY.md` title, introduction, and BPC security section
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `TEST_REGISTRY.md`, documentation claim regression surface
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:**

> Complete Test Registry — Every Test Ever Written
>
> Tests are real — no mocks, no stubs that return True.
>
> Security Hardening (IL4-7)

**Recovery source:** `TEST_REGISTRY.md` at Git object `b0c9fa8`.

**Reason parked:** The repository contains appropriate deterministic unit test
doubles and monkeypatching alongside live integration tests. A hand-maintained
cross-repository list is not automatically exhaustive. Test names and counts do
not establish a DoD Impact Level authorization, and the obsolete range included
a level not present in the current model.

**Replacement:** The registry identifies itself as a maintained named-coverage
inventory, distinguishes unit/test-double evidence from live evidence, and uses
a normalized security-hardening label with an explicit authorization boundary.

**Restore when:** Never restore as a blanket evidence or authorization claim.
Individual sections may state no-test-double execution only when their commands
and dependencies actually exercise the named real boundary.

**Restore procedure:** Create a review branch at `b0c9fa8`; do not overwrite the
current registry. Reintroduce only a narrowly scoped statement tied to a named
live test and exact commit.

**Validation after restore:** Enumerate `unittest.mock`, `MagicMock`, patching,
and monkeypatch usage; compare registry totals to collected tests; scan current
documentation for obsolete Impact Level ranges. The former blanket statement is
expected to fail this review.

**Recovery rehearsal:** Not rehearsed; the contradictory unit-test usage was
observed directly during the 2026-07-15 repository audit.

**Restoration risks:** False assurance, misleading customer evidence, obsolete
government language, and conflation of deterministic unit coverage with live
production acceptance.

**Evidence and links:** [WHY-20260715-006](WHY.md#why-20260715-006),
`tests/test_identity_gate.py`, `tests/test_enterprise/test_classified_mode.py`,
`tests/test_e2e_ultra_gate.py`, and `docs/assurance/CONTROL_CATALOG.md`.

## PARK-20260715-009 - Empty distillation capability placeholder

**Status:** Parked
**Category:** product surface, security property
**Former location:** top-level `distillation/__init__.py`
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `distillation/__init__.py`, `GAPS.md`
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:** The file was zero bytes; its presence alone exposed a
top-level `distillation` package name without implementation, enforcement,
tests, or a package declaration.

**Recovery source:** `b0c9fa8:distillation/__init__.py` (empty Git blob).

**Reason parked:** An empty security-adjacent package can be mistaken for a
capability even though it performs no control. Retaining it adds claim surface
and maintenance ambiguity without executable value.

**Replacement:** No package and no model-extraction/distillation control claim.
`GAPS.md` records that a future component requires a scoped requirement, threat
model, enforcement point, and executable assertion.

**Restore when:** Restore only with an approved design and implementation that
names inputs, outputs, trust boundary, abuse cases, owner, tests, and operational
evidence. Do not restore an empty placeholder.

**Restore procedure:** Implement the reviewed component on a branch, add it to
packaging, add control-catalog and gap entries in the same commit, then restore
the package path with substantive code.

**Validation after restore:** Build the wheel, inspect its contents, run the
component's adversarial tests, and run release conformance. Importability alone
is not a pass condition.

**Recovery rehearsal:** Not rehearsed; the former file contained no behavior to
rehearse.

**Restoration risks:** Recreating false capability surface, package-name
collision, unowned security claims, and untested model-data handling.

**Evidence and links:** [WHY-20260715-006](WHY.md#why-20260715-006),
`GAPS.md` DL-1, `pyproject.toml`, and the source Git object.

## PARK-20260715-008 - Unbound recovery tokens and non-ceremonial Ultra key replacement

**Status:** Parked
**Category:** security behavior, key lifecycle
**Former location:** `ultra_server/server.js`, `enterprise/ultra_gate.py`, Ultra environment contract
**Source commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Affected paths:** `ultra_server/server.js`, `ultra_server/agent-auth.js`,
`ultra_server/runtime-stores.js`, `enterprise/key_recovery.py`,
`enterprise/ultra_gate.py`, `.github/workflows/ci.yml`
**Action log:** [LOG-20260715-006](LOG.md#log-20260715-006)
**Why changed:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked by:** commit containing this record

**Former wording:** Recovery HMACs covered agent name, agent ID, replacement
public key, and issue time but not the recovery challenge or a signing-key ID.
Only one operator/recovery secret was accepted. TSK replacement required a new
provision/bind sequence without prepare/commit/resume semantics.

**Recovery source:** Named paths at Git object `b0c9fa8`.

**Reason parked:** The prior token could be replayed across recovery challenges
within its TTL, ordinary secret replacement created an avoidable availability
cutover, and TSK local/server state lacked a retry-safe rotation boundary.

**Replacement:** Versioned challenge-bound recovery tokens with key IDs; one
bounded previous verification generation; prepare/CAS-commit/revoke/resume TSK
rotation; real PostgreSQL/Redis restart and retirement exercises.

**Restore when:** Never restore to a production or governed path. Use the prior
state only on an isolated regression branch to reproduce the token-binding and
rotation gaps.

**Restore procedure:** Create a detached review branch at `b0c9fa8`, use only
ephemeral secrets and stores, and do not connect external clients or data.

**Validation after restore:** Demonstrate challenge substitution, lack of
current/previous overlap, lost-response ambiguity, and inability to resume a
rotated binding. The restored state is expected to fail current tests.

**Recovery rehearsal:** The former state was exercised before replacement;
restoration was not rehearsed.

**Restoration risks:** Cross-challenge replay, rotation outage, duplicate or
orphaned TSK clients, loss of binding continuity, and unsupported readiness
claims.

**Evidence and links:** [WHY-20260715-006](WHY.md#why-20260715-006),
`ultra_server/recovery-token.test.mjs`,
`ultra_server/server.test.mjs`, `tests/test_e2e_ultra_gate.py`, and
`docs/operations/ULTRA_KEY_ROTATION.md`.

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
