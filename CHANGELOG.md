# Changelog

## Unreleased

### Audit-bound operator approvals

- Added a same-transaction SQLite transition outbox for durable approval
  request, approve, deny, consume, and expiry events.
- Hardened profiles keep transitions in a non-authorizing `audit_pending`
  state until a matching signed-ledger receipt is durable; restart
  reconciliation is idempotent across the append-before-receipt crash window.
- Added decision-writer verification and required the dispatcher to recheck the
  unique ordered request/approval/consumption lineage, each outbox receipt,
  bounded decision-proof envelope, context digest, and signed ledger chain
  before mutation.
- Publish ledger sequence/hash state only after a durable append; partial write
  or `fsync` failure restores and verifies the previous tail before retry.
- Added explicit expiry/backward-clock rejection through a constructor-injected
  validated clock; removed the per-call time override from consume APIs.
- Decision nonces now leave durable tombstones for an explicit retention
  horizon, so purging an approval does not immediately reopen replay.
- Ledger receipt verification reads one exact signature- and chain-verified
  disk snapshot; public values and indexes cannot alias signed nested metadata.
- Approval and outbox schemas are validated independently, rebuilt together
  when either is legacy, and rejected on orphan or foreign-key violations.
- Finalization remains transaction-locked and purge eligibility remains bound
  to terminal and delivered-evidence time.
- Context is represented in evidence only by a canonical SHA-256 digest. This
  supports correlation and integrity checking, not confidentiality against
  low-entropy context guessing.
- Evidence: [LOG-20260717-001](LOG.md#log-20260717-001). Rationale:
  [WHY-20260717-001](WHY.md#why-20260717-001) and
  [WHY-20260717-002](WHY.md#why-20260717-002). Recovery:
  [PARK-20260717-001](PARKED.md#park-20260717-001) and
  [PARK-20260717-002](PARKED.md#park-20260717-002).

### Least-privilege Ultra monitoring

- Replaced administrator-token scraping with a dedicated current/previous
  metrics credential accepted only by `GET /metrics`.
- Bounded route, method, and authentication-failure labels; unknown hostile
  paths now collapse to `__unmatched__`.
- Hardened the Prometheus/Grafana reference stack with digest-pinned current
  images, loopback-only management ports, ignored credential files, persistent
  volumes, and install/verify/rotate/backup/restore/upgrade/rollback/teardown
  procedures.
- Evidence: [LOG-20260716-010](LOG.md#log-20260716-010).
- Rationale: [WHY-20260716-010](WHY.md#why-20260716-010).
- Recovery: [PARK-20260716-010](PARKED.md#park-20260716-010).

### Dedicated provenance service boundary

- Added a restricted `NT SERVICE\SelfConnectProvenance` Windows service, exact
  service-SID filesystem ACLs, a bounded signed named-pipe protocol, durable
  replay/idempotency state, signed high-water recovery, and a fail-closed client
  adapter for Enterprise and Government runtime composition.
- Added administrator enrollment and deployment commands plus an installed,
  distinct-token acceptance drill. Off-host retention and remote-host pipe
  testing remain separate deployment evidence.
- Implemented and exercised one exact-wheel installed-service lifecycle on one
  Windows host: 19/19 lifecycle checks, 19/19 enrolled-agent checks, a
  40-request crash/restart burst, 42 verified session ledgers with 168 signed
  events, 126 verified signed index entries, rollback, and cleanup. The
  [redacted artifact](docs/operations/2026-07-16-provenance-service-acceptance.json)
  explicitly excludes off-host immutability, remote-host rejection, and
  authorization claims.
- Evidence: [LOG-20260716-009](LOG.md#log-20260716-009). Rationale:
  [WHY-20260716-009](WHY.md#why-20260716-009). Recovery:
  [PARK-20260716-009](PARKED.md#park-20260716-009).

### Shared-state Ultra application-node fencing

- Added disabled-by-default, production-only active/passive fencing for two
  Ultra Node processes sharing PostgreSQL and Redis.
- Added admin-authorized, guard-signed monotonic activation/promotion commands,
  current-writer readiness, fail-closed Redis authority handling, concurrent
  shared request locks, and an exclusive PostgreSQL transition/drain boundary.
- Added real two-process CI covering one-writer election, same-principal
  failover, old/restarted-primary fencing without bounded state mutation,
  replay/tamper/stale denial, Redis outage/corruption, and concurrent schema
  initialization.
- Kept independent-state/site replication, convergence, secret unseal, restore,
  and repeated deployment drills explicitly open; this change does not close
  issue #21, and the independent-state/site slice remains issue #28.
- Evidence: [LOG-20260716-005](LOG.md#log-20260716-005), rationale:
  [WHY-20260716-005](WHY.md#why-20260716-005), recovery:
  [PARK-20260716-005](PARKED.md#park-20260716-005), and runbook:
  [ULTRA_SHARED_STATE_HA.md](docs/operations/ULTRA_SHARED_STATE_HA.md).

### Portfolio composition identity

- Closed a post-merge cleanup-conformance blind spot from PR #30. The Windows
  live step now catches stop and log-capture failures separately so cleanup
  cannot replace the primary contract failure. Portfolio conformance parses
  the lifecycle `try` after `Start-Process`, requires its immediately paired
  `finally`, and binds contracts and cleanup to those exact blocks. Negative
  mutations cover cleanup moved outside the lifecycle, cleanup moved to a later
  unreachable `finally`, and weakened guards, while an
  executable PowerShell regression proves the extracted cleanup preserves a
  deliberate primary failure. Hosted run `29479444593` passed all four jobs.
  Evidence: [LOG-20260716-008](LOG.md#log-20260716-008), rationale:
  [WHY-20260716-008](WHY.md#why-20260716-008), and recovery:
  [PARK-20260716-008](PARKED.md#park-20260716-008).
- Made the Windows composition workflow use explicit terminating PowerShell
  errors and fail immediately on nonzero native commands, with executable
  conformance assertions for every critical multi-command step. This follows
  Actions run `29476950456`, whose green
  conclusion masked a failed BPC workspace test and a failed live Node request.
  Follow-up run `29477612730` then failed honestly and exposed that a Windows
  background sidecar did not survive the Actions step boundary. Sidecar start,
  health verification, live contracts, log capture, and shutdown now share one
  `try`/`finally` step, and conformance rejects the former split lifecycle.
  Hosted run `29478571278` passed all four workflow jobs with the final BPC pin.
  Evidence: [LOG-20260716-007](LOG.md#log-20260716-007), rationale:
  [WHY-20260716-007](WHY.md#why-20260716-007), and recovery:
  [PARK-20260716-007](PARKED.md#park-20260716-007).
- Added one machine-readable lock for the exact SelfConnect SDK, BPC, and TSK
  sources consumed by Enterprise.
- Advanced the lock to the canonical merged core, BPC, and TSK security heads
  and required a fresh composed workflow before accepting compatibility.
- Advanced the core pin again to merged SelfConnect
  `5c493300b937a0f912e32a131061a132d2c11fe8` so Enterprise composes against
  the fail-closed `ConsoleWindowClass` transport implemented at ancestor
  `56d5ff1802dca5d4136bcc32fa37aa122d4944dc`, structured caller failure
  propagation, and PR #15's deterministic external-target smoke evidence.
  Evidence: [LOG-20260716-004](LOG.md#log-20260716-004),
  rationale: [WHY-20260716-004](WHY.md#why-20260716-004), recovery:
  [PARK-20260716-004](PARKED.md#park-20260716-004).
- Advanced only the BPC pin to canonical merge
  `772271e174769f91a980cc3ee69a6eb9cc36bf39` after an isolated exact-source
  composition passed BPC, TSK, Ultra Node, and live Python contracts. The TSK
  pin remains the current intentional master commit
  `bc31c234100a6e6432d2ac5de82783fc136bc2ea`.
  The final BPC merge includes PR #17's deterministic exact-horizon evidence,
  cleanup-safe clock restoration, and tested fail-fast workspace runner.
  Evidence: [LOG-20260716-006](LOG.md#log-20260716-006), rationale:
  [WHY-20260716-006](WHY.md#why-20260716-006), and recovery:
  [PARK-20260716-006](PARKED.md#park-20260716-006).
- Made both protocol composition jobs read the lock and verify actual checkout
  commits, package names, and versions before build or execution.
- Added fail-closed tests for missing/invalid pins and checkout mismatch while
  retaining source freshness, deployment, and authorization as separate gates.
- Evidence: [LOG-20260716-001](LOG.md#log-20260716-001).
- Rationale: [WHY-20260716-001](WHY.md#why-20260716-001).
- Parked record:
  [PARK-20260716-001](PARKED.md#park-20260716-001) and
  [PARK-20260716-002](PARKED.md#park-20260716-002).
- Pin-update evidence: [LOG-20260716-002](LOG.md#log-20260716-002) and
  [WHY-20260716-002](WHY.md#why-20260716-002).
- Normalized Enterprise BPC denial codes to the strict bridge's bounded error
  vocabulary after the first merged-pin composition run found the mismatch.
  Evidence: [LOG-20260716-003](LOG.md#log-20260716-003),
  [WHY-20260716-003](WHY.md#why-20260716-003), and
  [PARK-20260716-003](PARKED.md#park-20260716-003).

### Authoritative Ultra enforcement and protocol composition

- Replaced Level 0 local self-check authorization with the live Ultra server's
  BPC/TSK decision and made enforce mode fail closed by default.
- Made `SC_REQUIRE_ULTRA_SERVER=1` an executable runtime requirement, made
  local nonce acceptance atomic, and rejected known or short mesh secrets in
  high-assurance modes.
- Separated software Ed25519 payload signatures from independently verified
  local TPM platform-state claims; neither is described as hardware-bound
  agent signing or remote attestation.
- Pinned the reviewed BPC and TSK commits and immutable release-workflow action
  revisions for reproducible composition testing.
- Evidence: [LOG-20260715-008](LOG.md#log-20260715-008).
- Rationale: [WHY-20260715-008](WHY.md#why-20260715-008).
- Parked record:
  [PARK-20260715-017](PARKED.md#park-20260715-017).

### Claim-boundary and control-map correction

- Separated current-user DPAPI protection, software-KSP signing, platform
  claims, hardware-key custody, and remote attestation into distinct properties.
- Removed owning-client structural-secrecy, model-behavior, hardware birth-ID,
  and TPM-backed payload-signing overclaims; aligned MCP schemas with the
  algorithms and session properties actually implemented.
- Replaced legacy NIST `Satisfied`/`Ready` tables with bounded candidate
  evidence and explicit deployment, assessor, authorization, and retention
  dependencies.
- Corrected the threat model, historical briefing, deployment guide, evidence
  index, and local Win32 probe wording; the TPM hardware-property probe now
  fails closed instead of inferring hardware on query failure.
- Evidence: [LOG-20260715-007](LOG.md#log-20260715-007).
- Rationale: [WHY-20260715-007](WHY.md#why-20260715-007).
- Parked record:
  [PARK-20260715-016](PARKED.md#park-20260715-016).

### Ultra rotation, abuse boundary, and ledger lifecycle

- Added Redis-backed production source-IP and pair rate limits and converted
  BPC shadow/ghost responses to hard Ultra denials before TSK evaluation.
- Added versioned challenge-bound recovery tokens, one bounded previous
  operator/recovery key generation, exercised overlap/retirement, and
  retry-safe TSK prepare/commit/resume rotation.
- Added fsynced, verified AgentLedger segment rotation with cross-segment
  sequence/signature validation and corrupt-resume refusal.
- Added key-rotation and disaster-recovery runbooks while retaining deployment
  custody, actual restore, immutable storage, and authorization as open evidence.
- Removed an empty distillation placeholder and narrowed the test registry's
  false blanket no-mock/exhaustiveness wording.
- Replaced the IRS action-evidence v1 default prompt retention with a v2
  record-kind contract that derives prompt, test, or incident retention.
- Replaced unconditional FIPS/CNSA implementation wording with deployment-
  conditional boundaries and added signed `crypto_backend` evidence plus
  stored-public-key/backend mismatch refusal for CNG identities.
- Made Ultra private while its protocol dependencies remain source-relative,
  added a runtime-only npm package allowlist, and tested the actual pack
  manifest to exclude local logs, restart state, tests, and key-like files.
- Added PostgreSQL advisory-lock and operation-specific reconciliation for
  pair, TSK, binding, and rotation requests stranded in `processing`, with a
  real-store crash-window recovery contract that checks for duplicates.
- Replaced broad `guarantees`/`proven by` security headings with narrowly tested
  component-property language and regression guards against restoration.
- Added a release control that compares the installed SelfConnect VCS
  provenance with the exact declared commit instead of inferring source identity
  from stale or divergent version labels.
- Evidence: [LOG-20260715-006](LOG.md#log-20260715-006).
- Rationale: [WHY-20260715-006](WHY.md#why-20260715-006).
- Parked records: [PARK-20260715-008](PARKED.md#park-20260715-008),
  [PARK-20260715-009](PARKED.md#park-20260715-009), and
  [PARK-20260715-010](PARKED.md#park-20260715-010), and
  [PARK-20260715-011](PARKED.md#park-20260715-011), and
  [PARK-20260715-012](PARKED.md#park-20260715-012), and
  [PARK-20260715-013](PARKED.md#park-20260715-013), and
  [PARK-20260715-014](PARKED.md#park-20260715-014), and
  [PARK-20260715-015](PARKED.md#park-20260715-015).

### Confirmed Win32 delivery and target-path hardening

- Separated Win32 queue acceptance, UIA-confirmed delivery, and independently
  observed execution effects.
- Routed Windows Terminal input to the InputSite child and blocked automatic
  retry after ambiguous delivery.
- Replaced basename-only target checks with protected installation-path policy;
  corrected classic console ownership for the tested `cmd.exe` target.
- Changed watcher WM_CHAR/UIA status from false `OK` to `UNKNOWN` until a live
  target-bound probe runs.
- Evidence: [LOG-20260715-005](LOG.md#log-20260715-005).
- Rationale: [WHY-20260715-005](WHY.md#why-20260715-005).
- Parked record: [PARK-20260715-007](PARKED.md#park-20260715-007).

### Ultra lifecycle, classification, and product-boundary hardening

- Added cryptographic lifecycle authentication, operator-authorized enrollment,
  dual-control recovery, PostgreSQL/Redis production state, and restart proof.
- Fixed HOTP counter rollback and stale idempotent provisioning found by real
  PostgreSQL and process-restart tests.
- Rejected unknown classification strings at label, policy, profile, and
  observer ingress.
- Removed prospective-company material and narrowed TSK disclosure claims to
  the actual reduced provisioning view.
- Added a tiered executable control catalog that reports scope and blind spots
  and never converts deployment/authorization descriptions into test passes.
- Evidence: [LOG-20260715-002](LOG.md#log-20260715-002),
  [LOG-20260715-003](LOG.md#log-20260715-003), and
  [LOG-20260715-004](LOG.md#log-20260715-004).
- Rationale: [WHY-20260715-002](WHY.md#why-20260715-002),
  [WHY-20260715-003](WHY.md#why-20260715-003), and
  [WHY-20260715-004](WHY.md#why-20260715-004).
- Parked records: [PARK-20260715-004](PARKED.md#park-20260715-004),
  [PARK-20260715-005](PARKED.md#park-20260715-005), and
  [PARK-20260715-006](PARKED.md#park-20260715-006).

### Governed runtime and IRS integration evidence

- Added mandatory `GovernedRuntime` composition and fail-closed MCP actuation.
- Added live lease target binding/revalidation and approval binding.
- Blocked reserved ledger metadata from replacing signed core fields.
- Filtered training context with the same allow policy as primary records.
- Started and signed service provenance; added external-key signature verification.
- Added structured IRS integration evidence and a live no-mock conformance tool.
- Added product-neutral sector profiles and explicit external-integration gates.
- Evidence: [LOG-20260715-001](LOG.md#log-20260715-001).
- Rationale: [WHY-20260715-001](WHY.md#why-20260715-001).
- Parked records: [PARK-20260715-001](PARKED.md#park-20260715-001),
  [PARK-20260715-002](PARKED.md#park-20260715-002), and
  [PARK-20260715-003](PARKED.md#park-20260715-003).

### Documentation governance

- Added the chronological [LOG.md](LOG.md) for commit-specific work, audit,
  validation, and decision records.
- Added [WHY.md](WHY.md) for decision rationale, alternatives, consequences, and
  rollback conditions.
- Added the append-only [PARKED.md](PARKED.md) register for wording that is
  removed, superseded, or materially narrowed, plus code and configuration that
  may need to be restored.
- Added structural tests that require unique record IDs and prevent changelog
  references from pointing to nonexistent parked records.
- Evidence: [LOG-20260710-001](LOG.md#log-20260710-001).
- Rationale: [WHY-20260710-001](WHY.md#why-20260710-001).
- Parked records: None. This is an additive documentation change.

Future changelog entries that remove or materially change behavior,
configuration, or a statement must cite the corresponding recovery record using
its stable `PARK-<date>-<sequence>` ID.

---

## v1.2.3 — Protocol Checksum Correctness (2026-05-22)

Patch release fixing a stale checksum-length assumption in local verification.

### Fixed
- `verify_local()` now uses `CHECKSUM_LENGTH` (12) consistently; stale 10-char
  slice assumption removed from the fast-path local check. Regression test added:
  `test_verify_local_uses_protocol_checksum_length`.

---

## v1.2.2 — BPC+TSK Contract Fixes (2026-05-21)

Patch release capturing the BPC+TSK interoperability and release-build fixes.

### Fixed
- **TSK-01:** Corrected checksum contract from 10 to 12 characters and normalized the prefix from `cksum` to `checksum`.
- **TSK-02:** HOTP counters are now committed only after server confirmation, preventing client/server counter drift on failed requests.
- **BPC-07:** Removed the anomaly score `* 100` multiplier that could trigger denial-of-service lockouts from inflated scores.
- **BPC-08:** Replaced `INJECT` with `POST` and added the `X-Target-Path` header for explicit target routing.
- **Build:** Fixed `tsconfig` `rootDirs` output behavior so the server builds to flat `dist/index.js`.

---

## v1.2.1 — Production Hardening: SENTINEL Blockers Closed (2026-05-14)

Closes all five SENTINEL review blockers from the v1.2.0 HOLD verdict. No new features —
this release makes existing claims true at runtime and makes CI authoritative.

### P0: ClassifiedModeProfile enforcement is authoritative
- `require_signed_policy=True` forces signature verification regardless of caller's `require_signature=` arg
- `blocked_apps` / `allowed_apps` enforced before agent lookup
- `require_operator_approval_for` merged with per-agent requirements

### P1: LedgerObserver verified extraction path (G-3 CLOSED)
- `extract()` requires `verifier=<ledger>` (must be bound to same ledger path) in production
- `unsafe_unverified=True` required for offline/research raw access
- `verifier` path binding check prevents cross-ledger misuse

### P1: CNG identity — exact-match enforcement
- `require_cng_identity=True` now requires `identity_type == "cng"` exactly
- Empty string, `"dpapi"`, `"unknown"` all rejected — no pass-through for unrecognized types

### P1: Identity path traversal blocked
- `_SAFE_AGENT_NAME_RE` validates `agent_name` before filesystem use
- Containment check confirms resolved path stays under `data_dir`

### P1: WM_COPYDATA 64 KB ceiling enforced
- `MAX_COPYDATA_BYTES = 64 * 1024` enforced on send (ValueError) and receive (drop + log)

### P2: Lint clean + CI authoritative
- `ruff check enterprise tests tools` passes with 0 errors
- `.github/workflows/ci.yml` runs lint + pytest + test-count gate on every push
- Supply-chain tests: submodule fallback path — works from both source checkout and installed distribution

### Summary

| Metric | v1.2.0 | v1.2.1 |
|--------|--------|--------|
| Tests | 714 | 716 |
| Failures | 0 | 0 |
| Skipped | 2 | 0 |
| Ruff errors | 53 | 0 |
| Open gaps | G-1, G-3, G-4, G-6 | G-1, G-4, G-6 |
| Closed this version | — | G-3 (verified observer) |

---

## v1.2.0 — Hardened Posture: Zero-Day Audit, Fuzz/Stress/Exhaustion Test Suite (2026-05-12)

Historical release note: v1.2.0 expanded adversarial and dependency testing and
did not introduce new user-facing features. The named tests establish only their
specific assertions at that commit; they do not establish universal security,
classified deployment readiness, or authorization.

**What this is not:** The planned v1.2.0 "participant-mode / executor / bridge"
architecture is deferred. That work will be scoped and versioned separately. This
release uses the v1.2.0 slot to capture the security hardening posture milestone,
which is a prerequisite for any further architectural work.

### Security: Zero-Day CVE Audit (G-7 CLOSED)

Active threat sweep against the May 2026 zero-day landscape. Six threats assessed
against the SelfConnect codebase and dependency tree:

- **sonatype-2026-001357 (LiteLLM supply chain):** CI now blocks deployment if
  backdoored versions 1.82.7 or 1.82.8 are installed. The compromise introduced
  a credential stealer and persistent backdoor via poisoned CI tooling.
- **CVE-2026-26007 / CVE-2026-34073 (cryptography):** Minimum version floor raised
  from `>=42` to `>=46.0.6`. Both CVEs are non-exploitable via our code paths (we
  use P-384/ed25519, not SECT curves; we use NCrypt/CNG, not x509.verification).
  Floor raised for scanner compliance and dependency hygiene.
- **CVE-2026-33825 (Windows Defender TOCTOU):** Not applicable to operator-controlled
  .ps1 paths. SHA-256 hash of generated script now printed at generation time with
  `Get-FileHash` verification command — defense-in-depth against file substitution.
- **CVE-2026-32202 / CVE-2026-41089 (Windows NTLM/Netlogon):** OS patch controls.
  No in-app exposure. Documented in operator guide as deployment prerequisites.

Full audit trail: `docs/compliance/gap-analysis.md` §G-7.

### Security: Supply Chain Test (`test_supply_chain.py`, 10 tests)

- LiteLLM backdoored version gate (1.82.7–1.82.8 → hard fail)
- `cryptography >= 46.0.6` version gate
- Static source scan: no SECT curve usage (CVE-2026-26007 scope)
- Static source scan: no `x509.verification` usage (CVE-2026-34073 scope)
- WFP script determinism, hash stability, and tamper detection

### Test Suite: Fuzz, Concurrency Stress, Resource Exhaustion

Three new test files covering attack surfaces that RT-01..RT-20 (logic tests) do not:

- **`test_fuzz.py` (15 tests):** Hypothesis property-based fuzzing — `AllowEntry.parse()`,
  `PolicyBundle.from_dict()`, `WfpProfile._sanitize_ps_string()`. 200+ examples per
  boundary. Never-crash invariants across arbitrary inputs.
- **`test_stress_concurrent.py` (8 tests):** 50–100 thread stress — `ControlPlane`,
  `OperatorQueue`, `AgentLedger`. Exercises the named concurrency scenarios and documents the
  `AgentLedger` single-writer design boundary (G-6).
- **`test_resource_exhaustion.py` (10 tests):** 10k ledger entries, 1k operator queue,
  500-agent bundles, 200 WFP allow entries, 10k action lists. Timing budgets enforced.

### Summary

| Metric | v1.1.1 → v1.2.0 |
|--------|----------------|
| Tests | 632 → **674** |
| Failures | 0 → 0 |
| Coverage | ~90% → ~90% |
| Bandit High/Med | 0 → 0 |
| Open gaps | G-1,G-3,G-4 | G-1,G-3,G-4,G-6 |
| Closed this version | — | G-7 |

---

## v1.1.1 — Security Patch: WFP PowerShell Injection (CWE-93) (2026-05-12)

**FINDING-1 remediated.** `tools/wfp_policy.py` embedded the `--process` value into
generated PowerShell scripts via string interpolation without sanitization. Two injection
classes:

1. **CWE-93 newline injection:** `\n` / `\r\n` broke out of PS string literals, inserting
   bare commands that execute when an admin runs the .ps1 elevated.
2. **CWE-93 subexpression/backtick expansion:** `$(...)` and backtick escapes within
   double-quoted PS string literals could execute arbitrary commands at parse time.

**Fix:** All PS templates changed from double-quoted to single-quoted literals (`'value'`
not `"value"`). Single-quoted PS strings are fully literal — no `$`-expansion, no backtick
sequences. `_sanitize_ps_string()` added: rejects control chars (`\n`, `\r`, `\t`, `\x00`)
at `WfpProfile` construction time. Single quotes in values escaped as `''`.

6 dedicated regression tests. Full suite: **632/632 passing**. Gap G-5 CLOSED.

---

## v1.1.0 — G-2 Remediation: WFP Egress Policy Generator (2026-05-09)

Closes gap G-2 (Network-Layer Egress Not Enforced) from `docs/compliance/gap-analysis.md`.

**Added:** `tools/wfp_policy.py` — Windows Filtering Platform (WFP) egress policy
generator. Produces a PowerShell deployment script that installs deny-by-default
outbound firewall rules for the agent process, with per-entry allow rules for
explicitly allowlisted hosts/ports. Controls addressed: SC-7, SC-8, AC-4.

Four built-in deployment profiles:
- `mode_a` — permissive (dev/simulation, no restriction)
- `mode_b` — CUI (cloud APIs allowlisted, local services)
- `mode_c` — classified (loopback only, any port)
- `mode_c_strict` — classified strict (loopback only, specific ports)

Custom profiles via CLI flags (`--allow host:port/proto`) or JSON config file.
Generated scripts are idempotent, include `-Verify` and `-Remove` modes, and
are validated for injection-safety (no `Invoke-Expression`, `eval`, or shell
execution patterns in output).

36 new tests in `tests/test_wfp_policy.py`. Full suite: **564/564 passing**.

Gap status: G-2 CLOSED. G-1, G-3, G-4 remain open (scheduled).

---

## v1.0.0 — Historical release label (2026-05-08)  `71170e2` → packaging commit

Packaging and verification with no logic changes from v0.9.0. The recorded 528
tests and signed SBOM are commit-specific evidence, not current production,
compliance, or authorization evidence. `docs/verification/` retains the
historical version matrix.

## v0.9.0 — Classified Mode Profile (2026-05-08)  `71170e2`

Introduced `ClassifiedModeProfile`, `EgressGuard`, and `ExportGuard`.
Cloud egress and evidence export are now gated by an immutable frozen profile
loaded at startup. DPAPI identity is rejected in `require_cng_identity=True`
mode at Step 0.5 inside `PolicyEnforcer.check()`. Two hardened baselines ship:
`secret_baseline()` (SECRET ceiling, no egress, no export, CNG required) and
`cui_baseline()` (CUI ceiling, egress and export permitted). 528/528 tests
passing. Both end-to-end classified mode scenarios — SECRET and CUI — verified.

## v0.8.0 — Classification Labels Substrate (2026-05-08)  `8c8ba0f`

Single canonical `enterprise/labels.py` replaces the duplicated
`_CLASSIFICATION_RANK` / `_rank()` that existed independently in both
`policy.py` and `observer.py`. Added `Classification(IntEnum)`,
`LabelEnvelope` (frozen dataclass, Bell-LaPadula lattice dominance, caveat
validation), and `ALLOWED_CAVEATS`. `LabelEnvelope` plumbed through
`PolicyEnforcer.check(label=)`, `AgentLedger.log(label=)`, `CngLedger.log(label=)`,
and `ObserverFilter(allowed_caveats=)`. Named invariant exercised:
`test_observer_never_passes_above_max_classification` — TOP_SECRET entries are
structurally impossible to pass through a SECRET-ceiling filter. 488/488 tests.

## v0.7.0 — Operator Control Plane (2026-05-08)  `d3c9dae` / `5c0d7b3`

Introduced `ControlPlane` with a one-way state machine:
`active → paused → quarantined → revoked`. `kill_all()` revokes all
non-revoked agents in one operation and drains the operator approval queue.
Wired into `PolicyEnforcer` as Step 0 (before all eight policy checks) via
`control_plane=` constructor argument. Red team adversarial suite added:
20 attack categories (RT-01 through RT-20, 59 tests) covering policy bypass,
signature tampering, classification spoofing, training data poisoning, control
plane bypass, hash chain forgery, and concurrent race conditions. 432/432
tests passing. Mypy clean (zero errors).

## v0.6.0 — Policy-Filtered Learning Pipeline (2026-05-07)  `96904d8`

Introduced `ObserverFilter`, `EvidenceRecord`, `LedgerObserver`,
`EvidenceExporter`, `TrainingTrigger`, and `ShadowHook` in `enterprise/observer.py`.
The observer selects entries where `decision=allow` for the named export path.
This is a dataset-filtering property; it does not establish what a model can
learn from other data or that every training path uses the filter. The release
recorded 373/373 tests passing for its source commit.

## v0.5.0 — Signed Policy Bundles and 8-Step Enforcer (2026-05-07)  `ff5f1eb`

Introduced `PolicyBundle` (signed with ECDSA P-384 via `policy_sign.py`),
`PolicyEnforcer` (8-step deny-by-default evaluator), and `OperatorQueue`
(thread-safe human approval gate). Policy bundles are JSON files; no valid
signature means no policy. The evaluator denies by default — every check must
pass or the routed action is blocked. The historical release reported complete
line coverage for `policy_sign.py`; current coverage must be established by a
current run artifact.

## v0.4.0 — CNG Identity and CngLedger (2026-05-06)  `e9793d9`

`CngIdentity` and `CngLedger` replace the DPAPI / Python ed25519 stack with
Windows NCrypt software KSP (ECDSA P-384, SHA-384). Drop-in replacement for
`AgentIdentity` and `AgentLedger` with identical interface. It created a
candidate path for deployment with an appropriately validated Windows
cryptographic module; algorithm/provider selection alone is not a FIPS
validation claim. Both identity types remain available; v0.9.0 adds
profile-level enforcement of which one is required.

## v0.3.1 — NCrypt ECDSA P-384 Crypto Primitives (2026-05-06)  `a6fd49b`

Added `enterprise/crypto.py`: `CngSigner`, `cng_sha384()`, `cng_verify()`,
`cng_key_exists()`, `cng_delete_key()`. All primitives operate through Windows
CNG NCrypt API (ctypes). Foundation for CngIdentity in v0.4.0.

## v0.3.0 — Persistent Agent Identity and Chained Ledger (2026-05-05)  `b16e8ed`

Introduced `AgentIdentity` (DPAPI-protected ed25519 keypair for the current
Windows user context; not hardware-bound)
and `AgentLedger` (append-only JSONL, SHA-256 hash chain, ed25519 signatures).
Every enrolled agent has a permanent `SC-XXXXXXXX` identifier that survives
process restarts. Every entry submitted to `AgentLedger` is signed and chained;
the ledger does not intercept action paths that bypass it.

## v0.2.0 — WM_COPYDATA Receive Layer (2026-05-04)  `7460b44`

Added `CopyDataListener` in `enterprise/transport.py`. A background thread
creates a message-only window and runs a Win32 message pump. On `WM_COPYDATA`,
it deserialises the JSON payload and dispatches to registered callbacks.
The receiver records the sender HWND supplied in `wParam`; this field requires
separate target and identity validation because the caller controls message
parameters. Max payload 64 KB.

## v0.1.0 — SetProp/GetProp Agent Registry + BirthTag (2026-05-03)  `150a5ad`

Initial repo. `enterprise/registry.py` with `stamp_birth_tag()`,
`read_birth_tag()`, `discover_mesh()`, `find_agent()`, `HeartbeatDaemon`.
Every agent stamps an OS-native birth tag at spawn (SCID, SCTYPE, SCBORN,
SCPARENT, SCMODEL, SCHB). When the window dies, the tag vanishes — the OS
handles garbage collection. `send_data()`, `signal_ready()`, `wait_for()`
complete the IPC surface.
