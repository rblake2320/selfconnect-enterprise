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

## LOG-20260716-003 - Normalize Enterprise BPC denial codes at composition

**Timestamp (UTC):** 2026-07-16T01:43:00Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, test, security hardening
**Base commit:** `de9dd25`
**Change reference:** commit containing this entry and Enterprise PR #23
**Why:** [WHY-20260716-003](WHY.md#why-20260716-003)
**Parked records:** [PARK-20260716-003](PARKED.md#park-20260716-003)

**Changed:** Normalized Enterprise-generated BPC boundary errors to bounded
lowercase codes (`shadow_denied`, `invalid_result`) accepted by the strict TSK
bridge. Updated unit and live lockout assertions to require the exact composed
denial `BPC: shadow_denied`.

**Reason:** The first hosted run against the merged BPC/TSK commits failed one
live assertion: Enterprise emitted `BPC_SHADOW_QUARANTINED`, while the hardened
bridge intentionally converts non-bounded callback text to
`VERIFICATION_FAILED`. Authorization remained denied, but the adapter contract
and evidence assertion disagreed. Normalizing at the adapter preserves the
specific safe denial without allowing arbitrary callback-controlled errors.

**Full actions and links:** `ultra_server/security-boundary.js`,
`ultra_server/security-boundary.test.mjs`,
`tests/test_e2e_ultra_gate.py`, [WHY-20260716-003](WHY.md#why-20260716-003),
[PARK-20260716-003](PARKED.md#park-20260716-003), and Enterprise Actions run
`29464702436` job `87515299829`.

**Validation:** Unit tests, focused Python tests, and a replacement hosted
composition run execute on the commit containing this entry. PR #23 remains
blocked until all Windows live and Linux PostgreSQL/Redis jobs pass.

**Notes:** This changes only the bounded external error contract. Shadow and
ghost decisions remain hard denials; internal BPC audit detail remains a
separate evidence source.

## LOG-20260716-002 - Advance the portfolio lock to merged security heads

**Timestamp (UTC):** 2026-07-16T01:38:40Z
**Actor:** Codex, requested by the repository owner
**Category:** release, test, supply-chain hardening
**Base commit:** `229c5598b2bf4bd3d40cbf2648a412896e96c0bd`
**Change reference:** commit containing this entry and the associated pull request
**Why:** [WHY-20260716-002](WHY.md#why-20260716-002)
**Parked records:** [PARK-20260716-002](PARKED.md#park-20260716-002)

**Changed:** Advanced `portfolio-lock.json` and the matching `pyproject.toml`
VCS dependency to merged SelfConnect
`a87e490c88c4ccb18ccaac514d018c7bba779d55`, BPC
`ad6516698f3bb85a3517577f647cf46901205fd1`, and TSK
`bc31c234100a6e6432d2ac5de82783fc136bc2ea`. Updated the SelfConnect package
identity from `0.10.0` to the merged manifest value `0.12.0`.

**Reason:** These are the canonical merge commits for the repaired core CI,
fail-closed Redis replay guard, immutable BPC authorization snapshot, and strict
BPC-before-TSK composition boundary. The portfolio gate must test those exact
merged sources rather than older known-good inputs or pull-request heads.

**Full actions and links:** `portfolio-lock.json`, `pyproject.toml`, SelfConnect
PR #12, BPC PRs #7 and #8, TSK PR #9,
[WHY-20260716-002](WHY.md#why-20260716-002), and
[PARK-20260716-002](PARKED.md#park-20260716-002).

**Validation:** Local lock parsing and focused conformance tests run on the
commit containing this entry. The authoritative evidence is the associated
hosted Enterprise composition workflow, which checks out all three locked
commits, verifies Git/package identity, builds the protocols, and executes the
Windows live and Linux PostgreSQL/Redis composition lanes.

**Notes:** A green composition run establishes compatibility for this source
set only. It does not establish deployment configuration, FIPS validation,
Impact Level authorization, an ATO, external key custody, or immutable storage.

## LOG-20260716-001 - Make the tested portfolio composition machine-verifiable

**Timestamp (UTC):** 2026-07-16T01:13:16Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, test, supply-chain hardening
**Base commit:** `ce249afa89a2bb3022ee93acc8309f8c63dad8b9`
**Change reference:** commit containing this entry and the associated pull request
**Why:** [WHY-20260716-001](WHY.md#why-20260716-001)
**Parked records:** [PARK-20260716-001](PARKED.md#park-20260716-001)

**Changed:** Added `portfolio-lock.json` as the single runtime source identity
for the SelfConnect SDK, BPC, and TSK inputs consumed by Enterprise. Added
`tools.portfolio_conformance.py`, real-Git regression tests, a quick-tier
control-catalog entry, and CI checkout verification of commit and package
metadata. Removed duplicated BPC/TSK SHA literals from CI and documentation.

**Reason:** Separate repository suites and duplicated CI pins allowed the
portfolio to remain green against older component commits after security work
moved forward elsewhere. A passing component suite did not identify which
cross-repository composition Enterprise had actually tested.

**Full actions and links:** `portfolio-lock.json`,
`tools/portfolio_conformance.py`, `tests/test_portfolio_conformance.py`,
`.github/workflows/ci.yml`, `docs/assurance/control_catalog.json`,
`ultra_server/README.md`, [WHY-20260716-001](WHY.md#why-20260716-001), and
[PARK-20260716-001](PARKED.md#park-20260716-001).

**Validation:** `python -m tools.portfolio_conformance` returned `PASS`;
`python -m pytest tests/test_portfolio_conformance.py
tests/test_documentation_records.py -q` returned 10 passed; both JSON files
parsed successfully; Ruff and actionlint passed; `git diff --check` reported no
whitespace errors. The full shared-environment suite returned 1,423 passed, 34
skipped, and two release-gate failures because that interpreter contains
`cryptography==44.0.3`, below the repository's declared `>=48.0.1` floor. The
gate was not weakened. Release-tier composition checks also refused to infer
Ultra readiness without installed BPC/TSK dependencies or a VCS-traceable SDK;
the hosted jobs assemble and verify those exact locked inputs.

**Notes:** The initial lock preserves the previously tested commits. Updating a
pin remains a reviewed compatibility change and requires the composed CI jobs
to pass. Source identity does not establish deployment or authorization.

## LOG-20260715-012 - Execute the pinned SDK dependency gate in generic CI

**Timestamp (UTC):** 2026-07-15T11:54:20Z
**Actor:** Codex, requested by the repository owner
**Category:** test, supply-chain hardening
**Base commit:** `cb00e36a9845d901e6299cc34b9f5d2a6483e369`
**Change reference:** commit containing this entry and draft PR #20
**Why:** [WHY-20260715-008](WHY.md#why-20260715-008)
**Parked records:** None

**Changed:** Installed the exact commit-pinned SelfConnect SDK in the generic
Windows CI lane so the declared-dependency integrity test executes. Normalized
pytest skip-report paths before applying the named live-Ultra allowlist.

**Reason:** Hosted CI showed the allowlist correctly rejected an unapproved
dependency-integrity skip and also revealed that Windows path separators made
approved live-Ultra node IDs fail a POSIX-style comparison.

**Full actions and links:** `.github/workflows/ci.yml`, draft PR #20, GitHub
Actions run `29413084872`, and job `87344547270`.

**Validation:** The dedicated Windows Ultra contract and production
PostgreSQL/Redis durability jobs passed in run `29413084872`. Exact actionlint,
documentation conformance, and the full generic lane must rerun on the
containing commit.

**Notes:** The dependency-integrity skip was not added to the allowlist. The
missing pinned dependency is now installed and must be scanned.

## LOG-20260715-011 - Make CI skip evidence and platform imports explicit

**Timestamp (UTC):** 2026-07-15T11:50:48Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, test, audit
**Base commit:** `5f55c931877e39fe39715989ee99c180f64c7b64`
**Change reference:** commit containing this entry and draft PR #20
**Why:** [WHY-20260715-008](WHY.md#why-20260715-008)
**Parked records:** None

**Changed:** Replaced the generic Windows test lane's hard-coded skip count
with a node/reason allowlist for the live Ultra tests exercised by the dedicated
contract job. Moved `GovernedRuntime` behind the package's existing Windows
import boundary so the portable Ultra client and restart conformance probe load
on Linux without installing a Windows API shim.

**Reason:** Hosted CI passed all 1,421 generic Windows tests but correctly
reported 35 live-service skips rather than the stale count of 30. The production
durability job then reached the restart probe and found package initialization
eagerly imported the Windows-only DPAPI identity module on Linux.

**Full actions and links:** `.github/workflows/ci.yml`,
`enterprise/__init__.py`, draft PR #20, GitHub Actions run `29412807803`,
jobs `87343644017` and `87343643970`.

**Validation:** The complete Windows suite passed 1,456 tests with two expected
negative-test warnings. The exact hosted actionlint v1.7.12 and `git diff
--check` passed. A clean Linux Python 3.12 container imported and executed the
real `tools.ultra_restart_conformance` CLI using real cryptography without a
ctypes/Win32 mock. Hosted live CI must rerun on the containing commit.

**Notes:** Skip authorization is now tied to named live-test files and reasons,
not a number. Any different skip still fails the release gate.

## LOG-20260715-010 - Complete the PostgreSQL TSK validation transaction

**Timestamp (UTC):** 2026-07-15T11:46:01Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, security fix, test
**Base commit:** `47fa8ba6fbba67c4ef77aa3cdd27ffbe15aa4cd6`
**Change reference:** commit containing this entry and draft PR #20
**Why:** [WHY-20260715-008](WHY.md#why-20260715-008)
**Parked records:** None

**Changed:** Added PostgreSQL implementations of TSK's atomic
`commitValidation()` and `replaceCredential()` store operations. Expanded the
live PostgreSQL test to prove a concurrent duplicate produces one commit and
one replay rejection, all replay-sensitive counters and usage commit together,
replacement revokes the old credential, and repeated replacement is denied.

**Reason:** Hosted production CI exercised the merged hardened TSK verifier
against Enterprise's PostgreSQL adapter and found the adapter still implemented
the older store interface. The resulting missing method failed closed, but
prevented every production-mode verification.

**Full actions and links:** `ultra_server/runtime-stores.js`,
`ultra_server/runtime-stores.test.mjs`, draft PR #20, GitHub Actions run
`29412603725`, and failed job `87342988818`.

**Validation:** The Ultra Node suite passed 15/15 without PostgreSQL. Against a
fresh digest-pinned PostgreSQL 17.5 container it passed 16/16, including the new
atomic validation/replacement assertions. Documentation conformance passed
7/7, the exact hosted actionlint v1.7.12 passed, and `git diff --check` passed.
Hosted production durability CI must rerun on the containing commit.

**Notes:** This closes the single PostgreSQL-store interface mismatch found by
the hosted composition run. It does not establish two-node HA or external
deployment authorization.

## LOG-20260715-009 - Align CI shell checks with the hosted gate

**Timestamp (UTC):** 2026-07-15T11:42:16Z
**Actor:** Codex, requested by the repository owner
**Category:** test, supply-chain hardening
**Base commit:** `92356607f22d39ca2051b9c15b4f9fedd94686d4`
**Change reference:** commit containing this entry and draft PR #20
**Why:** [WHY-20260715-008](WHY.md#why-20260715-008)
**Parked records:** None

**Changed:** Replaced two unused Bash retry-loop variables in the production
Ultra CI job with the conventional `_` placeholder.

**Reason:** Draft PR #20's hosted workflow-syntax job ran actionlint v1.7.12
with ShellCheck and rejected the dead assignments under SC2034. The correction
keeps the hard gate intact and removes dead workflow state.

**Full actions and links:** `.github/workflows/ci.yml`, GitHub Actions run
`29412460642`, job `87342530758`, and draft PR #20.

**Validation:** `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`
passed against every `.github/workflows/*.yml` file after the change, and
`git diff --check` passed. Hosted CI must rerun on the containing commit.

**Notes:** This is a workflow correctness fix. It does not widen any security,
availability, compliance, or authorization claim.

## LOG-20260715-008 - Make Ultra authorization authoritative and fail closed

**Timestamp (UTC):** 2026-07-15T11:30:07Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, security fix, test, supply-chain hardening
**Base commit:** `e071d745a5c87aaa0d008e35d2bd0928dea384e0`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-008](WHY.md#why-20260715-008)
**Parked records:** [PARK-20260715-017](PARKED.md#park-20260715-017)

**Changed:** Replaced the Level 0 local self-check with authoritative Ultra
server verification; made strict enforce mode default-deny for every Level 0
rejection; made `SC_REQUIRE_ULTRA_SERVER=1` an executable runtime requirement;
serialized local nonce and peer-registration state; required an explicit
32-byte mesh secret in high-assurance modes; separated software Ed25519 payload
signing from locally verified TPM platform-state claims; pinned BPC and TSK to
their reviewed full commit identifiers; and pinned release-workflow actions to
immutable commits. The direct-dependency pip-audit hard gate now fails instead
of skipping when its scanner is absent or returns malformed output, and CI
installs that scanner explicitly.

**Reason:** The previous Level 0 label implied composed BPC/TSK server
authorization while `authorize_injection()` only ran a local checksum and
nonce check. This bypassed server anomaly state, durable replay state, complete
TSK verification, and authoritative identity binding. The server-required flag
was also asserted by tests that reimplemented the desired condition instead of
calling the production wrapper.

**Full actions and links:** `enterprise/ultra_gate.py`,
`enterprise/identity_gate.py`, `enterprise/mcp_dispatch.py`,
`enterprise/tpm_attestation.py`, `ultra_server/server.js`,
`conftest.py`, `scripts/run_all_tests.py`, `.github/workflows/ci.yml`,
`.github/workflows/release-msi.yml`, the associated tests, and the linked
WHY/PARK records. Protocol pins reference BPC
`7304e86d1d5df30b63e647146b20312a2a0da0c5` and TSK
`63afcb83a033a82ce21f8f473e6a186cc195e801`.

**Validation:** The full isolated Python suite passed 1,456 tests with two
expected warnings for tests that intentionally omit an immutable sink. Ruff,
pip-audit, actionlint, Ultra's 15 executed Node tests (one live-PostgreSQL unit
case explicitly skipped in that unit command), and npm audit passed. The exact
pinned BPC commit built and passed 171 Node tests; the exact pinned TSK commit
built, passed 168 core/runtime cases plus 25 HA cases, and passed typecheck.
Focused identity/live-gate tests included a 64-way same-nonce race with one
accepted request and 63 replay denials. Focused TPM/MCP tests passed 79 cases,
and the documentation/identity audit passed 193 focused tests plus 7 record
tests. Published CI remains required before merge.

**Notes:** This does not establish production two-node Ultra HA, hardware-bound
agent signing, remote attestation, FIPS validation, a DoD Impact Level, an ATO,
or an externally anchored audit system.

## LOG-20260715-007 - Correct hardware, secrecy, control, and readiness claim boundaries

**Timestamp (UTC):** 2026-07-15T11:24:27Z
**Actor:** Codex, requested by the repository owner
**Category:** audit, security fix, documentation
**Base commit:** `e071d745a5c87aaa0d008e35d2bd0928dea384e0`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-007](WHY.md#why-20260715-007)
**Parked records:** [PARK-20260715-016](PARKED.md#park-20260715-016)

**Changed:** Corrected DPAPI and software-KSP identity descriptions; removed
owning-client TSK structural-secrecy claims; bounded ObserverFilter to its data
path; corrected MCP tool schemas/descriptions to Ed25519-only verification and
software-capable session stamping; removed TPM-backed service/signing claims;
made the local TPM hardware-property probe fail closed; narrowed target-guard,
UIA, challenge-response, and chained-channel evidence; replaced legacy NIST
`Satisfied`/`Ready` maps with candidate-evidence boundaries; corrected AU-11,
FIPS, threat-model, historical briefing, installer/deployment, and evidence
index claims; and recorded the resulting gaps and recovery source.

**Reason:** Repository-wide claim review found multiple cases where a useful
component property had been promoted to a stronger composition, hardware,
secrecy, compliance, or authorization statement. The affected statements were
not established by the code or named tests and could mislead a buyer, assessor,
partner, or patent evidence review.

**Full actions and links:** `README.md`, `SECURITY.md`, `CHANGELOG.md`,
`GAPS.md`, `enterprise/identity.py`, `enterprise/identity_cng.py`,
`enterprise/tsk_client.py`, `enterprise/observer.py`,
`enterprise/mcp_tools.py`, `enterprise/service.py`,
`bench/tpm_sign_bench.py`,
`experiments/win32_probe/chained_channel.py`,
`experiments/win32_probe/target_guard.py`,
`experiments/win32_probe/tpm_identity.py`,
`installer/selfconnect-enterprise.wxs`, `installer/INSTALL.md`,
`docs/ROLLBACK.md`, `docs/operations/ULTRA_KEY_ROTATION.md`,
`docs/ato/TPM_LIVE_PROBE_2026-06-21.md`,
`docs/GOVERNANCE_PROFILES.md`, `docs/ato/DEPLOYMENT_GUIDE.md`,
`docs/ato/EVIDENCE_INDEX.md`, `docs/ato/NIST_800-53_control_map.md`,
`docs/ato/THREAT_MODEL.md`,
`docs/briefing/selfconnect-enterprise-v1.0.0.md`,
`docs/compliance/control-baselines.md`,
`docs/compliance/nist-800-53-mapping.md`, and the linked WHY/PARK record.

**Validation:** `python -m ruff check` passed for the nine Python files in this
audit; `python -m py_compile` passed for the same files; 193 focused identity,
observer, and MCP-tool tests passed; all 7 documentation-record tests passed;
the bounded-term claim scan returned only explicit non-guarantees/open-gap
language plus runtime files owned by the concurrent root fix; and
`git diff --check` passed. One initial pytest command named a nonexistent
`test_tsk_client.py`, ran zero tests, and was corrected to the existing focused
files. Full-suite combined validation is owned by the root hardening pass
because this worktree contains concurrent runtime changes.

**Notes:** This audit does not add a hardware-bound agent signing protocol,
remote attestation, a FIPS-validated deployment, NIST control assessment, ATO,
or risk acceptance. Direct/legacy send-path inventory, same-user emergency
bypass authority, independent audit custody, UIA confidentiality, and Ultra HA
deployment composition remain explicit open boundaries.

## LOG-20260715-006 - Add bounded rotation, fail-closed abuse handling, and ledger lifecycle

**Timestamp (UTC):** 2026-07-15T07:07:32Z
**Actor:** Codex, requested by the repository owner
**Category:** implementation, security fix, durability, test, documentation
**Base commit:** `b0c9fa80a1b327c80bbb1b14b81c8cf7504ac72f`
**Change reference:** commit containing this entry
**Why:** [WHY-20260715-006](WHY.md#why-20260715-006)
**Parked records:** [PARK-20260715-008](PARKED.md#park-20260715-008),
[PARK-20260715-009](PARKED.md#park-20260715-009), and
[PARK-20260715-010](PARKED.md#park-20260715-010), and
[PARK-20260715-011](PARKED.md#park-20260715-011), and
[PARK-20260715-012](PARKED.md#park-20260715-012), and
[PARK-20260715-013](PARKED.md#park-20260715-013), and
[PARK-20260715-014](PARKED.md#park-20260715-014), and
[PARK-20260715-015](PARKED.md#park-20260715-015)

**Changed:** Ultra now has independent source-IP/pair rate limits, converts BPC
shadow or ghost success into hard denial, rotates operator and recovery secrets
through one bounded previous generation, binds versioned recovery tokens to the
recovery challenge, and rotates TSK clients through retry-safe prepare/commit/
resume operations. AgentLedger now fsyncs appends, seals verified segments at
entry/byte thresholds, verifies one sequence across segments, and refuses
corrupt resume. Added rotation and disaster-recovery runbooks, removed an empty
distillation placeholder, and narrowed the test registry's blanket evidence
wording. IRS action evidence now requires an explicit record kind and derives
the IRM retention class instead of defaulting every action to prompt-log
retention.
Corrected unconditional FIPS/CNSA wording, bound stored CNG public identity to
the loaded key, recorded the active cryptographic backend in identity metadata
and signed ledger entries, and rejected backend mismatches.
The Ultra package is private while its protocol dependencies remain source-
relative and now uses an executable runtime-only package allowlist; local logs,
restart state, tests, and key-like files are excluded from the npm artifact.
Lifecycle mutations now recover stranded `processing` records under per-
resource locks by reconciling the exact durable pair, key, candidate, or
binding, while ambiguous state fails closed.
Security property headings now say `Tested by` and name the exact proposition;
blanket `guarantees` and `proven` labels were parked.
Release conformance now verifies the installed SelfConnect `direct_url.json`
commit against the declared full Git pin and reports version metadata without
using it as source identity.

**Reason:** Live composition review found that BPC shadow mode could cross the
bridge as deceptive `ok=true`, lifecycle secrets had no exercised overlap/
retirement path, recovery tokens did not bind the challenge, TSK replacement
was not restart-safe, and the governed action ledger had no file lifecycle.
The empty package and blanket test wording also implied controls or evidence
that did not exist. Release packing exposed ignored local runtime state, and
idempotency had no recovery after a crash between durable side effect and
response persistence.

**Full actions and links:** `ultra_server/server.js`, `agent-auth.js`,
`recovery-token.js`, `security-boundary.js`, `runtime-stores.js`,
`enterprise/ultra_gate.py`, `enterprise/ledger.py`,
`tools/ultra_rotation_conformance.mjs`,
`tools/ultra_restart_conformance.py`, `.github/workflows/ci.yml`,
`docs/operations/ULTRA_KEY_ROTATION.md`,
`docs/operations/ULTRA_DISASTER_RECOVERY.md`, the executable control catalog,
`GAPS.md`, `SECURITY.md`, and the linked WHY/PARK records.

**Validation:** The complete isolated Python suite passed 1,429 tests with zero
skips and two expected warnings about deliberately absent immutable sinks. A
production-mode drill using real local PostgreSQL 17.5 and Redis 7.4.5 passed
16/16 Node store/auth/package tests, 39/39 live Node contract checks, 84/84
Python live tests, TSK rotation, process stop/restart, and same-identity/HOTP
continuation. The live contract deliberately rewound completed pair, TSK,
binding, and rotation idempotency rows to `processing`; operation-specific
reconciliation restored every response without duplicate resources.
The same contract then made the initial key inactive, rewound its row again,
and confirmed recovery failed closed without creating a replacement.
The first production drill correctly failed before health because its operator
assumed the disposable database password; the successful rerun read the actual
container configuration without printing the secret. The rolling-rotation
drill accepted only current plus immediate previous values during overlap and
only new current values after retirement. Release conformance reported
`PASS_WITH_NAMED_BLIND_SPOTS` with no failed executable controls. Ruff,
compileall, `git diff --check`, actionlint 1.7.12, Python and npm audits, Python
sdist/wheel build, Node syntax checks, and the actual npm pack manifest passed.
The npm manifest contained only eight expected runtime/package entries. The
built wheel installed into a new virtual environment, `pip check` passed, the
packaged CLI started, and the installed SDK commit matched the declared pin.

**Notes:** Off-host immutable retention, an isolated restore of deployment
backups, approved secret custody, external workflow acceptance, and government
authorization remain open. Generic timeout takeover remains prohibited;
operation-specific recovery now closes CC-13 for the implemented lifecycle
routes and fails closed if durable state is ambiguous.

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
