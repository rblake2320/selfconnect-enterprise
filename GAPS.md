# SelfConnect Enterprise — Complete Gap & Limitation Registry

Last updated: 2026-07-31
Scope: all known limitations across the full stack, regardless of severity or prior tracking status.  
Rule: if a limitation is known, it is in this file the first time it is asked about, not when it becomes relevant to something else.

---

## Ultra Server

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| US-1 | BPC verification needed an enforced abuse boundary | Ultra now applies independent source-IP and pair sliding-window limits backed by Redis in production and bounded memory in development. BPC shadow/ghost responses are converted to a hard denial before the TSK bridge; seven forged signatures quarantine the tested tuple without letting an attacker globally revoke the pair. Deployment-specific thresholds and distributed capacity remain operator-owned. | Implemented and live-tested | **CLOSED IN CODE 2026-07-15** |
| US-2 | Production lifecycle state was memory-only | Production mode now requires PostgreSQL for pairs, complete server tumbler records, identity bindings, and idempotency state. A kill/restart conformance probe verifies identity continuity. Development remains explicitly volatile. The owning client still receives the reduced fields and secret required to generate keys. | Implemented and live-tested | **CLOSED 2026-07-15** |
| US-3 | Lifecycle API authentication was incomplete and incompatible | Agent registration, provisioning, and recovery were unauthenticated; binding expected an unrelated bearer; Python-signed headers were not verified. Production now requires body-bound Ed25519 proofs, nonce/timestamp replay checks, ownership checks, operator-authorized enrollment, and dual-authorized recovery. | Implemented and cross-language live-tested | **CLOSED 2026-07-15** |
| US-4 | Redis nonce/anomaly path lacked integration evidence | Production CI uses a real Redis service and the live cross-language suite. Replay checks use Redis in production; memory is development-only. Load capacity for a specific deployment remains benchmark work. | Implemented and live-tested | **CLOSED 2026-07-15** |
| US-5 | Loopback HTTP has no transport encryption | The server binds to `127.0.0.1` and authenticates sensitive routes, but loopback alone does not isolate mutually untrusted processes. Remote/multi-tenant use requires a separately designed protected transport and service identity. | Deployment architecture | Open |
| US-6 | Protocol dependencies use source-relative `file:` paths | CI reproducibly checks out and builds exact BPC/TSK commits, but Ultra does not yet consume published signed packages/SBOM attestations. | Release engineering | Open |
| US-7 | Operator bearer and recovery-HMAC custody are deployment responsibilities | Production validates presence, distinct current/previous values, and minimum length and never logs them. Bounded current/previous overlap, retirement, emergency replacement, and a real PostgreSQL/Redis rotation probe are implemented. Approved secret-manager integration, service-account ACLs, personnel custody, and an actual deployment ceremony remain external. | Code/runbook complete; deployment evidence required | Open deployment boundary |
| US-8 | Ultra npm packing implicitly included ignored local logs and restart-state JSON | The package is now private while source-relative protocol dependencies remain, uses an explicit runtime-only file allowlist, and tests the actual `npm pack --dry-run` manifest. Local logs, restart state, tests, and key-like files are excluded. | Fixed in manifest + executable package test | **CLOSED 2026-07-15** |
| US-9 | Ultra production uses durable single-node stores but does not instantiate the protocol HA wrappers | Upstream BPC/TSK work contains guarded replication and promotion components, but this sidecar still constructs direct PostgreSQL stores. No composed two-node Ultra test proves shared fencing, signed replication, promotion, old-primary exclusion, or resynchronization. | Integration + strongly consistent fencing + live failover evidence | Open; do not claim production HA |

---

## BPC Protocol

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| BPC-1 | Standalone BPC server middleware has no Redis nonce path | Already addressed in Ultra Server via `RedisNonceStore`, but the standalone `@bpc/server` middleware does not wire a Redis nonce path independently. | 1 day | Open |
| BPC-2 | No scope hierarchy | Scopes are exact-match strings. No wildcard or parent/child scope (`read:*` covering `read:quotes`). | Design decision required | Open |

---

## TSK Protocol

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| TSK-1 | HOTP counter exhaustion requires a rotation decision | An authorized client can now rotate explicitly before or after an operator-detected threshold, but the server does not proactively rotate at `maxRequests` or predict exhaustion. Automatic renewal requires a policy for approval, overlap, failure, and abandoned candidates. | Design/policy decision required | Mitigated; proactive renewal open |
| TSK-2 | No restart-safe key rotation ceremony | Ultra now uses prepare, compare-and-swap commit, old-key revocation, and owner-authenticated resume. Prepare and commit retries are idempotent; local state changes only after commit; production restart tests preserve the rotated client and HOTP state. | Implemented and live-tested | **CLOSED IN CODE 2026-07-15** |
| TSK-3 | Durable store could roll HOTP counters back after success | Upstream middleware writes lifecycle metadata from its pre-CAS map. Memory aliasing masked the defect; PostgreSQL exposed it. `PgTumblerStore.set()` now transactionally preserves monotonic counters and request counts, with live concurrent-CAS and 50-request regression coverage. | Fixed and live-tested | **CLOSED 2026-07-15** |
| TSK-4 | Owning-client layout was described as structural secrecy | The client receives the shared secret, ordered segment metadata, lengths, counters, and total length required to assemble keys. Literal server `position` fields are omitted, but the effective client layout is derivable and is not a security claim. | Claim corrected; protocol redesign required for a stronger property | Open design boundary |

---

## AgentLedger

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| AL-1 | JSONL file grew unbounded | `AgentLedger` now seals verified local segments at configurable entry/byte thresholds, fsyncs appends, verifies archives plus the active file as one sequence, resumes across segments, and refuses corrupt startup or rotation. `GovernedRuntime` defaults to 100,000 entries or 128 MiB per segment. | Implemented and tested | **CLOSED IN CODE 2026-07-15** |
| AL-2 | Governed action ledgers are not deployed to a centralized durable authority | Provenance/WORM sink adapters exist, but each governed action ledger still writes local segments and no deployed aggregation/replication service has been exercised. Do not treat the adapters as deployment evidence. | Architectural + deployment | Open |
| AL-3 | Local chain cannot detect tail truncation or complete-file deletion | Interior tampering is detected, but a missing tail/file requires a separately trusted checkpoint. | Deployment + storage | Open |
| AL-4 | Reserved metadata could overwrite signed core fields | Caller-controlled metadata could replace `agent_id`, `action`, timestamps, or chain fields before signing. Both AgentLedger and CngLedger now reject reserved-key collisions. | Fixed in code + adversarial tests | **CLOSED 2026-07-14** |

---

## Delegation Proofs

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| DG-1 | Authorization and authorship existed as separate signed artifacts without one portable delegation chain | `enterprise/delegation.py` now provides an authority-signed exact-scope grant, an agent-signed action proof, and offline verification that binds the full keys, grant, action, target, payload digest, mode, classification, time, revocation checkpoint, and caller-supplied replay/revocation state. | Implemented + 22 real-signature adversarial tests | **CORE CONTRACT CLOSED IN CODE 2026-07-31** |
| DG-2 | The portable delegation proof is not yet mandatory in `GovernedRuntime` or MCP/ACP adapters | Direct use of the new module proves a supplied grant/action pair but does not intercept execution. A later composition must verify before actuation, atomically consume the action ID, persist the proof/receipt, and fail closed on unavailable revocation state. | Runtime integration + durable state + composition tests | Open; do not claim runtime-wide delegation enforcement |
| DG-3 | Classification authorization is exact-match in delegation v1 | The v1 verifier intentionally rejects a classification different from the grant ceiling rather than importing a mutable hierarchy into the portable proof contract. A hierarchy/compartment design requires canonical label semantics and downgrade tests. | Design decision | Open |
| DG-4 | Portable revocation inputs lacked a durable lifecycle authority | `RevocationRegistry` now stores terminal agent/grant revocations with a monotonic epoch and supplies exact ACP snapshots. Agent revocation terminates its ACP session on the next presented action; a host-triggered refresh or bounded shared-SQLite watcher removes already-bound sessions while preserving the human owner trust root. | Implemented + 10 lifecycle/watcher and 2 ACP refresh cases | **LOCAL CORE CLOSED IN CODE 2026-07-31; HA/REMOTE PUSH OPEN** |

---

## Agent Client Protocol Shim

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| ACP-1 | SelfConnect had no ACP boundary | `enterprise/acp_shim.py` now implements ACP v1 core initialization/session/prompt/cancel handling, stdio JSON-RPC, exact signed-call binding, live revocation input, durable replay consumption, agent/session revocation refresh, and a `GovernedRuntime`-only production backend. An end-to-end signed-policy test proves ACP cannot bypass required operator approval or route terminal text when approval is absent. | Implemented + 23 core/composition/refresh tests | **BOUNDED CORE CLOSED IN CODE 2026-07-31** |
| ACP-2 | The shim is not a general coding-agent proxy or complete ACP implementation | It accepts strict governed-action envelopes rather than natural-language coding turns. MCP forwarding, session recovery/lifecycle extensions, filesystem/terminal callbacks, elicitation, media, modes, and configuration are unsupported. | Product/protocol expansion | Open; do not claim complete ACP conformance or registry eligibility |
| ACP-3 | ACP authentication ceremony lacked a possession proof, executable setup path, and active-session revocation behavior | A capable client now receives the Preview terminal-auth method, `scent-acp --setup` requires typed confirmation and fresh-challenge key-possession proof, only the public trust root is stored, and serving fails closed without an active root. Deactivation denies and deletes existing sessions before prompt dispatch; re-enrollment cannot revive them. Local schema validation passed; real-client setup/reconnect acceptance is still absent. | Implemented + 14 auth/entry tests; client acceptance remains | **CORE CLOSED IN CODE 2026-07-31; INTEROP OPEN** |
| ACP-4 | Synchronous stdio cannot interrupt an in-flight backend call | `session/cancel` marks the next turn cancelled. A call already executing cannot be interrupted until dispatch gains an async cancellation contract with safe effect semantics. | Async runtime + cancellation design | Open |
| ACP-5 | No truthful registry distribution artifact exists | The registry requires a published `binary`, `npx`, or `uvx` distribution plus final metadata/icon. The local console entry point is not represented as a published package. A fail-closed preflight exists, but publication remains blocked on release artifacts and registry CI. | Packaging + external acceptance | **HOLD; DO NOT CLAIM REGISTRY ELIGIBILITY** |
| ACP-6 | Ecosystem reach could be misread as authority to replace core protocols | ACP is only the client/session interoperability layer. It must continue to terminate in `GovernedRuntime`; terminal-as-medium injection remains the actuation path and BPC/TSK remain the identity/trust core. Any direct ACP-to-SDK/Win32 backend would violate the architecture. | Permanent architecture invariant | **GUARDRAIL — DO NOT REPLACE OR BYPASS** |

---

## Nostr Evidence Export

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| NE-1 | Signed event interoperability existed only in external systems | `enterprise/nostr_export.py` now renders already-verified evidence into the exact NIP-01 event shape and ID serialization using a deployment-injected Schnorr signer. Its production path requires the canonical verifier-bound `LedgerObserver`, rejects unsafe mode, source tampering, and wrong-ledger verifiers before signing. It has no relay or import path and grants no authority. | Implemented + 13 structural/adversarial tests | **EXPORT CORE CLOSED IN CODE 2026-07-31** |
| NE-2 | No production Nostr signer, kind allocation, or live relay acceptance exists | The repository verifies signer key/signature sizes and exact hashing but does not provide or validate secp256k1 custody, publish events, allocate a collision-safe application kind, or prove external relay acceptance/retention. | Deployment + interoperability test | Open; do not claim live Nostr integration |

---

## SelfConnect Win32 SDK

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| SDK-1 | 6 display-dependent tests skip in headless CI | Requires virtual display or interactive session. | Known, accepted | Open |
| SDK-2 | No code signing on the SDK | Windows Defender and enterprise AV may flag unsigned Python scripts. | Certificate + signing pipeline | Open |
| SDK-3 | Channel watcher treated API presence as live WM_CHAR/UIA health | The watcher returned `OK` without sending or reading a target-bound probe. It now reports `UNKNOWN`; only governed UIA-confirmed delivery may pass. | Fixed in code + regression test | **CLOSED 2026-07-15** |
| SDK-4 | Exact pinning did not prove the interpreter installed that source | `SDK-PIN-001` now compares the full commit in `pyproject.toml` with installed `direct_url.json` and reports the package version separately. The current pin declares version 0.10.0. This closes environment drift, not dependency freshness or completeness; upgrading to later SDK source requires a separate compatibility and packaging review. | Executable provenance gate implemented | **PIN DRIFT CLOSED; REFRESH OPEN** |

---

## EgressGuard

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| EG-1 | `EgressGuard.check_outbound()` destination is cosmetic | The enforcement decision is the global `allow_cloud_egress` boolean; the `destination` string is logged but never checked against an allowlist. With egress on, an agent can reach any host. Root cause: no per-profile destination allowlist exists. This is the exfiltration lane. Fix: add `allowed_destinations: frozenset` to `ClassifiedModeProfile` and check it in `check_outbound()`. | Half day | **CLOSED 2026-07-02** |

---

## Distillation

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| DL-1 | Empty `distillation/` placeholder implied a capability that did not exist | The zero-byte top-level package was removed and parked. No model-extraction or distillation control is claimed. Add a new component only when a scoped requirement, enforcement point, threat model, and executable assertion exist. | False surface removed; capability not implemented | **PLACEHOLDER REMOVED 2026-07-15** |

---

## Deliberate Product Exclusions

| # | Surface | Rationale | Status |
|---|---------|-----------|--------|
| PX-1 | Workspace/community UI, channels, DMs, reactions, presence, canvases, media rooms, and huddles | Collaboration presentation is not the governed-execution thesis and can remain in ACP clients or external systems. | **PERMANENTLY OUT OF SCOPE unless required by a named enforcement boundary** |
| PX-2 | Forge, Git/repository hosting, patch review, merge workflows, issue tracking, CI orchestration, and release management | Mature external systems own these functions; duplicating them would expand scope without strengthening terminal actuation governance. | **PERMANENTLY OUT OF SCOPE unless required by a named enforcement boundary** |

These are not implementation gaps. See [`docs/PRODUCT_SCOPE_BOUNDARY.md`](docs/PRODUCT_SCOPE_BOUNDARY.md).

---

## Cross-cutting

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| CC-1 | No secrets rotation procedure | Current/previous operator and recovery-key overlap, retirement, emergency replacement, TSK rotation, and non-secret evidence requirements are documented and exercised against real local PostgreSQL/Redis. Actual secret-manager custody remains US-7. | Implemented and live-tested | **CLOSED AS PROCEDURE 2026-07-15** |
| CC-2 | No structured runbook for disaster recovery | The protected state, isolated restore sequence, failure conditions, and evidence requirements are documented. Restart continuity is tested, but no backup was restored into an isolated deployment and no external immutable object was recovered. | Runbook complete; restore drill open | Open deployment exercise |
| CC-3 | CI did not test the Redis/PostgreSQL Ultra composition | Dedicated jobs now build pinned BPC/TSK sources, require the live server, test Windows Python-to-Node behavior, run real PostgreSQL/Redis, and prove restart continuity. | Implemented | **CLOSED 2026-07-15** |
| CC-4 | MCP actuation previously required only a lease | Default `sc_inject_text` did not require the signed PolicyEnforcer, operator approval, mandatory live target revalidation, or a persistent signed ledger. `GovernedRuntime` now composes these controls and the dispatcher fails closed when any are absent. | Fixed in code + composition tests | **CLOSED 2026-07-14** |
| CC-5 | Provenance verifier checked hashes but not recorder signatures | A modified `recorder_sig` could pass chain-only verification. `verify_log()` now supports mandatory verification against a separately trusted recorder public key. | Fixed in code + tamper regression | **CLOSED 2026-07-14** |
| CC-6 | No live off-host immutable deployment evidence | S3/R2/file sink code and tests do not establish that a deployed bucket has retention/object-lock policy, correct credentials, independent custody, or a completed restore/verification drill. | Deployment evidence required | Open |
| CC-7 | No IRS/Treasury authorization package | No agency operational approval, PCLIA, AI impact assessment acceptance, ATO/IATT, system boundary, retention implementation, or independent assessment exists in this repository. | External program and assessor work | Open |
| CC-8 | No external workflow adapter has completed live acceptance | A prospective integration remains unverified until its versioned interface, data boundary, callback authentication, error handling, rollback, and end-to-end acceptance evidence exist. | External integration | Open |
| CC-9 | Unknown classification strings previously sorted below UNCLASSIFIED | Unknown labels could pass any ceiling. Label constructors and policy/profile loading now reject unknown values; policy decisions deny them and observers exclude them. | Fixed with adversarial regression | **CLOSED 2026-07-15** |
| CC-10 | PostMessage enqueue was reported as successful delivery | `ChannelRouter` success meant only that Win32 accepted message posts. `MCPDispatcher` now requires a new UIA-visible payload occurrence, rejects unchanged/stale readback, warns against automatic retry after ambiguity, and records separate enqueue/delivery fields. | Fixed in code + adversarial and live Windows tests | **CLOSED 2026-07-15** |
| CC-11 | Target guard discarded the executable directory and rejected legitimate classic `cmd.exe` | Basename-only matching did not enforce the documented protected-path boundary, while `ConsoleWindowClass -> conhost.exe` was false on the tested system. The guard now validates OS-reported full paths against protected Windows/WindowsApps/PowerShell roots and accepts the tested `cmd.exe` owner. | Fixed in code + spoof/load/live tests | **CLOSED 2026-07-15** |
| CC-12 | BPC shadow mode could return deceptive `ok=true` across the Ultra bridge | Ultra now converts any shadow or ghost-alert result to `BPC_SHADOW_QUARANTINED` before TSK evaluation. Unit and live tests prove a quarantined source-IP/pair tuple cannot authorize with a fresh valid credential. | Fixed in code + live adversarial test | **CLOSED 2026-07-15** |
| CC-13 | A production crash could leave an idempotency record in `processing` indefinitely | Lifecycle operations now serialize by durable PostgreSQL advisory lock, inspect the operation-specific pair, TSK, rotation, or binding resource, reconstruct the exact response when it exists, and perform the side effect only when it does not. Ambiguous duplicate state fails closed. A production test rewinds completed rows to `processing` and proves recovery without duplicate resources. | Implemented and real-store live-tested | **CLOSED 2026-07-15** |
| CC-14 | DPAPI/software-KSP identities and the current MCP TPM option were described as hardware-bound signing | DPAPI is current-user OS protection at rest, and the NCrypt software KSP is not a TPM. The current MCP TPM option signs with software Ed25519 and obtains a separate ephemeral platform claim; it does not bind the payload or signing key to that claim. | Documentation corrected; protocol composition required | Open security boundary |
| CC-15 | Legacy control maps used `Satisfied`/`Implemented` as if component evidence established NIST control effectiveness | Repository artifacts are candidate evidence only. Control selection, parameters, inheritance, operating environment, assessment procedures, and authorization decisions remain deployment/assessor work. | Maps superseded by bounded candidate mapping and executable catalog | **CLAIM CLOSED 2026-07-15; assessment open** |
| CC-16 | Ultra previously permitted a repository-known default mesh secret in every mode | Identity enforcement, required-server mode, and production runtime now reject the default and require an explicit secret of at least 32 bytes. Deployment generation, protected distribution, rotation, and recovery evidence are not supplied by the repository. | Code gate implemented; deployment custody required | Open deployment boundary |
| CC-17 | Level 0 previously authorized through a local self-check rather than the authoritative Ultra verifier | The governed Level 0 path now requires the live server decision and strict enforce mode defaults fail closed for rejection and outage. Lower fallback remains available only through explicit `SC_STRICT_ENFORCE=0` compatibility configuration and cannot be cited as strict Level 0. | Fixed in code + concurrency/live regressions | **CLOSED 2026-07-15** |
| CC-18 | Cross-repository source pins were duplicated across jobs and prose | `portfolio-lock.json` now records the exact SDK, BPC, and TSK identities once. Both composition jobs consume it and verify actual checkout commits plus package metadata before build. Pin freshness and security review remain recurring release decisions. | Single lock + executable checkout verification | **CLOSED IN CODE 2026-07-16** |
| CC-19 | Durable approval state could change without an independently chained transition event | Hardened `DurableOperatorQueue` now stages request, approve, deny, consume, and expiry in a same-database outbox, keeps the capability non-authorizing until a receipt is verified from the exact signed-ledger disk snapshot, repeats state validation under a write transaction, retains a bounded nonce-bound decision-proof envelope plus a durable replay tombstone for an explicit horizon, removes per-call expiry-clock overrides, and requires an exact request/approval/consumption lineage before MCP actuation. Approval, outbox, tombstone, index, named-constraint, version, and foreign-key structure is attested and rebuilt as one transaction; duplicate/conflicting replay state or constraint-invalid governed rows fail closed without replacing the source. Ledger append failures restore the prior verified tail and ledger caches cannot alias caller-owned nested metadata. Direct SQLite writes are outside this control and require deployment filesystem/access controls. The selected deployment must still supply and assess its decision-writer credential verifier and trusted clock. | Fixed in code + adversarial disk/restart/TOCTOU/alias/replay-after-purge/clock/schema/comment-spoof/duplicate/conflict/rollback tests; deployment credential, database access control, and clock assessment remain environment-specific | **CLOSED IN CODE 2026-07-17; deployment identity/clock assessment open** |

---

## LedgerObserver

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| OBS-1 | Denied entries could re-enter training exports through `context_before` | The primary record filter was correct, but raw preceding entries were copied into context. Context now uses the same ObserverFilter and a regression test asserts exclusion. | Fixed in code + regression test | **CLOSED 2026-07-14** |

---

## IRS Integration

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| IRS-1 | Agency AI use-case inventory integration | `IRSUseCaseRecord` validates and signs local evidence, but the official IRS/Treasury inventory schema and submission workflow are external. | Partner/agency coordination | Open |
| IRS-2 | Model and data inventory integration | `IRSModelDataRecord` creates signed evidence, but it is not connected to an IRS system of record. | Partner/agency coordination | Open |
| IRS-3 | High-impact assessment and human-review evidence | The evidence contract requires completed review before an executed high-impact action, but accountable-official determination, independent review, risk acceptance, remedies, and appeals remain external. | Program controls | Open |
| IRS-4 | PII/FTI approved boundary and retention implementation | Action records intentionally store hashes and resource identifiers, not raw FTI. The v2 schema requires prompt/test/incident record kind and derives the corresponding IRM 10.24.1.8 retention label. A label does not enforce retention: the approved processing boundary, IRC 6103 controls, provider lifecycle/deletion jobs, and incident response are not deployed. | Schema implemented; security/privacy deployment open | Open deployment boundary |
| IRS-5 | Live no-mock external workflow proof | A local Windows run exercised a real signed policy and identity, protected-path HWND binding, WM_CHAR delivery, independent UIA delivery confirmation, separately observed command output, and signed-ledger verification. It has not been run against an external tax workflow, off-host sink, or IRS-authorized environment. | External live integration test | Open |

---

## Historical Performance Baseline (measured 2026-05-27, Windows 11)

Pending retest on DGX Spark and RTX 5090.

| Operation | Median | p95 | Throughput |
|-----------|--------|-----|------------|
| Policy check (allow/deny) | 0.008ms | 0.009ms | 115,000/sec |
| Ledger write (hash + sign + append) | — | — | 586/sec |
| CNG sign (ECDSA P-384, NCrypt) | 1.05ms | 2.32ms | 582/sec |
| CNG verify (BCrypt) | 0.60ms | 1.37ms | 1,350/sec |
| Full 7-layer HTTP verify (127.0.0.1) | 11.5ms | 13.8ms | 125 req/sec |

This table is retained as dated evidence, not a current release or deployment
claim. Current defaults use `127.0.0.1`. Adversarial live suites intentionally
exercise anomaly/tarpit behavior and are not valid throughput benchmarks.

**Single-machine ceiling estimate:** ~10–15 agents each doing 5–10 verified actions/second before CNG signing (582/sec shared) becomes the bottleneck. Policy enforcer and Ultra Server have headroom well beyond that.

---

## What Was Closed (as of 2026-05-27)

All 19 items from the original gap registry are closed. Specific recent closures:

- US-asyncio: `asyncio_mode = "strict"` removed from `pyproject.toml` — 0 warnings
- CI floor updated to 880 (verified 884-passed baseline)
- Docstring `\S` escapes fixed in `ultra_gate.py`, `identity_gate.py`, `key_recovery.py`
- Redis nonce backend wired in `server.js` (item US-4 partially closed — code wired, CI test still open)
- Prometheus `/metrics` endpoint live with 4 counters
- E2E tests now run automatically via `pytest_sessionstart` Ultra Server auto-start
- Test suite: **905 passed, 0 skipped, 0 failed** (local Windows, 2026-05-27)

---

## What Was Closed (as of 2026-07-02)

- **Gap #2 (composition attacks) closed:** `enterprise/composition_monitor.py` adds a stateful,
  per-agent sliding-window sequence gate that runs *after* `PolicyEnforcer.check()`. It evaluates
  whether a sequence of individually-authorized calls composes into a dangerous shape
  (recon→access→egress, execute→egress, mutate→execute). Wired as `PolicyEnforcer(composition_monitor=...)`
  — optional, fail-closed, non-bypassing. Covered by 12 adversarial tests in
  `tests/test_composition_monitor.py` (12/12 pass, no mocks, real failure injection).
- **EG-1 and DL-1 added** to this registry (surfaced during composition-monitor code audit).

---

## What Was Closed (as of 2026-06-18)

- MCP runtime dispatch: `enterprise/mcp_tools.py` is no longer schema-only.
  `enterprise/mcp_dispatch.py` provides executable handlers for all 20 MCP
  tools with schema validation, lease gating, audit events, channel-router
  delegation, software identity sign/verify, receipt verification, and a
  `scent mcp-call` CLI path. Covered by
  `tests/test_enterprise/test_mcp_dispatch.py`.
- Governance profile separation: normal, enterprise, and government postures
  are documented in `docs/GOVERNANCE_PROFILES.md` and represented in
  `MCPDispatcher(profile=...)`. Normal SelfConnect remains the free-flowing
  day-to-day path; enterprise MCP remains lease/audit governed; government
  profile fails closed for software-only identity/session paths until TPM is
  wired.

---
## What Was Closed (as of 2026-07-02)
- **EG-1 CLOSED:** Added `allowed_destinations: frozenset[str]` field to `ClassifiedModeProfile`.
  `EgressGuard.check_outbound()` now enforces the allowlist: when non-empty, only listed destinations
  are permitted even if `allow_cloud_egress=True`. Empty allowlist preserves backward-compatible
  behavior (any destination allowed). Covered by 5 adversarial tests in
  `tests/test_enterprise/test_classified_mode.py::TestEgressGuard` (allowlist permit, deny,
  empty-list passthrough, deny-reason logging, serialization round-trip). All 12 EgressGuard
  tests pass.
- **US-3 historical note:** The July 2 bearer-only closure was incomplete. It
  did not cover registration, provisioning, or recovery, and it did not verify
  the signed header emitted by the Python client. The authoritative closure is
  the July 15 signed lifecycle, enrollment, ownership, replay, and dual-control
  implementation recorded in the main Ultra Server table above.
