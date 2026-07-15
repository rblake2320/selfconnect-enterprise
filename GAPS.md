# SelfConnect Enterprise — Complete Gap & Limitation Registry

Last updated: 2026-07-15
Scope: all known limitations across the full stack, regardless of severity or prior tracking status.  
Rule: if a limitation is known, it is in this file the first time it is asked about, not when it becomes relevant to something else.

---

## Ultra Server

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| US-1 | No automatic rate limiting / lockout policy | Anomaly data collected but nothing acts on it. Brute-force attacker is slowed by HOTP/TOTP but not hard-blocked. | 1 day | Open |
| US-2 | Production lifecycle state was memory-only | Production mode now requires PostgreSQL for pairs, complete server tumbler records, identity bindings, and idempotency state. A kill/restart conformance probe verifies identity continuity. Development remains explicitly volatile. The owning client still receives the reduced fields and secret required to generate keys. | Implemented and live-tested | **CLOSED 2026-07-15** |
| US-3 | Lifecycle API authentication was incomplete and incompatible | Agent registration, provisioning, and recovery were unauthenticated; binding expected an unrelated bearer; Python-signed headers were not verified. Production now requires body-bound Ed25519 proofs, nonce/timestamp replay checks, ownership checks, operator-authorized enrollment, and dual-authorized recovery. | Implemented and cross-language live-tested | **CLOSED 2026-07-15** |
| US-4 | Redis nonce/anomaly path lacked integration evidence | Production CI uses a real Redis service and the live cross-language suite. Replay checks use Redis in production; memory is development-only. Load capacity for a specific deployment remains benchmark work. | Implemented and live-tested | **CLOSED 2026-07-15** |
| US-5 | Loopback HTTP has no transport encryption | The server binds to `127.0.0.1` and authenticates sensitive routes, but loopback alone does not isolate mutually untrusted processes. Remote/multi-tenant use requires a separately designed protected transport and service identity. | Deployment architecture | Open |
| US-6 | Protocol dependencies use source-relative `file:` paths | CI reproducibly checks out and builds exact BPC/TSK commits, but Ultra does not yet consume published signed packages/SBOM attestations. | Release engineering | Open |
| US-7 | Operator bearer and recovery-HMAC custody are deployment responsibilities | Production validates presence and length and never logs the values. Rotation, service-account ACLs, approved secret manager integration, and emergency recovery ceremony are not yet deployed. | Deployment/runbook | Open |

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
| TSK-1 | HOTP counter exhaustion is a denial-of-service vector | If `maxRequests` is reached, the key expires and the client is locked out until a new key is provisioned. No auto-renewal. | Design decision required | Open |
| TSK-2 | No key rotation ceremony | When a TSK key expires, client must call `/provision-tsk` again. No automatic re-key handshake. | 1–2 days | Open |
| TSK-3 | Durable store could roll HOTP counters back after success | Upstream middleware writes lifecycle metadata from its pre-CAS map. Memory aliasing masked the defect; PostgreSQL exposed it. `PgTumblerStore.set()` now transactionally preserves monotonic counters and request counts, with live concurrent-CAS and 50-request regression coverage. | Fixed and live-tested | **CLOSED 2026-07-15** |

---

## AgentLedger

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| AL-1 | JSONL file grows unbounded | No rotation, no archival, no size cap. Long-running agent accumulates an unbounded ledger file. | 1 day | Open |
| AL-2 | No remote / centralized ledger backend | Each agent writes its own local file. No aggregated audit store. | Architectural — weeks | Open |
| AL-3 | Local chain cannot detect tail truncation or complete-file deletion | Interior tampering is detected, but a missing tail/file requires a separately trusted checkpoint. | Deployment + storage | Open |
| AL-4 | Reserved metadata could overwrite signed core fields | Caller-controlled metadata could replace `agent_id`, `action`, timestamps, or chain fields before signing. Both AgentLedger and CngLedger now reject reserved-key collisions. | Fixed in code + adversarial tests | **CLOSED 2026-07-14** |

---

## SelfConnect Win32 SDK

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| SDK-1 | 6 display-dependent tests skip in headless CI | Requires virtual display or interactive session. | Known, accepted | Open |
| SDK-2 | No code signing on the SDK | Windows Defender and enterprise AV may flag unsigned Python scripts. | Certificate + signing pipeline | Open |
| SDK-3 | Channel watcher treated API presence as live WM_CHAR/UIA health | The watcher returned `OK` without sending or reading a target-bound probe. It now reports `UNKNOWN`; only governed UIA-confirmed delivery may pass. | Fixed in code + regression test | **CLOSED 2026-07-15** |

---

## EgressGuard

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| EG-1 | `EgressGuard.check_outbound()` destination is cosmetic | The enforcement decision is the global `allow_cloud_egress` boolean; the `destination` string is logged but never checked against an allowlist. With egress on, an agent can reach any host. Root cause: no per-profile destination allowlist exists. This is the exfiltration lane. Fix: add `allowed_destinations: frozenset` to `ClassifiedModeProfile` and check it in `check_outbound()`. | Half day | **CLOSED 2026-07-02** |

---

## Distillation

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| DL-1 | `distillation/` is an empty stub | `enterprise/distillation/__init__.py` is 0 bytes. No model-extraction control exists despite distillation being part of the Mythos-class concern (model weights extraction via repeated inference). Fable's own safeguards treat this as a routed-away risk; the enterprise stack has a placeholder and no control. | Design decision required | Open |

---

## Cross-cutting

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| CC-1 | No secrets rotation procedure | Ultra Server generates recovery token HMAC key at startup. No documented procedure for rotating it in a running deployment. | Docs only | Open |
| CC-2 | No structured runbook for disaster recovery | If server crashes and memory store is lost, recovery path is undocumented. | Docs only | Open |
| CC-3 | CI did not test the Redis/PostgreSQL Ultra composition | Dedicated jobs now build pinned BPC/TSK sources, require the live server, test Windows Python-to-Node behavior, run real PostgreSQL/Redis, and prove restart continuity. | Implemented | **CLOSED 2026-07-15** |
| CC-4 | MCP actuation previously required only a lease | Default `sc_inject_text` did not require the signed PolicyEnforcer, operator approval, mandatory live target revalidation, or a persistent signed ledger. `GovernedRuntime` now composes these controls and the dispatcher fails closed when any are absent. | Fixed in code + composition tests | **CLOSED 2026-07-14** |
| CC-5 | Provenance verifier checked hashes but not recorder signatures | A modified `recorder_sig` could pass chain-only verification. `verify_log()` now supports mandatory verification against a separately trusted recorder public key. | Fixed in code + tamper regression | **CLOSED 2026-07-14** |
| CC-6 | No live off-host immutable deployment evidence | S3/R2/file sink code and tests do not establish that a deployed bucket has retention/object-lock policy, correct credentials, independent custody, or a completed restore/verification drill. | Deployment evidence required | Open |
| CC-7 | No IRS/Treasury authorization package | No agency operational approval, PCLIA, AI impact assessment acceptance, ATO/IATT, system boundary, retention implementation, or independent assessment exists in this repository. | External program and assessor work | Open |
| CC-8 | No external workflow adapter has completed live acceptance | A prospective integration remains unverified until its versioned interface, data boundary, callback authentication, error handling, rollback, and end-to-end acceptance evidence exist. | External integration | Open |
| CC-9 | Unknown classification strings previously sorted below UNCLASSIFIED | Unknown labels could pass any ceiling. Label constructors and policy/profile loading now reject unknown values; policy decisions deny them and observers exclude them. | Fixed with adversarial regression | **CLOSED 2026-07-15** |
| CC-10 | PostMessage enqueue was reported as successful delivery | `ChannelRouter` success meant only that Win32 accepted message posts. `MCPDispatcher` now requires a new UIA-visible payload occurrence, rejects unchanged/stale readback, warns against automatic retry after ambiguity, and records separate enqueue/delivery fields. | Fixed in code + adversarial and live Windows tests | **CLOSED 2026-07-15** |
| CC-11 | Target guard discarded the executable directory and rejected legitimate classic `cmd.exe` | Basename-only matching did not enforce the documented protected-path boundary, while `ConsoleWindowClass -> conhost.exe` was false on the tested system. The guard now validates OS-reported full paths against protected Windows/WindowsApps/PowerShell roots and accepts the tested `cmd.exe` owner. | Fixed in code + spoof/load/live tests | **CLOSED 2026-07-15** |

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
| IRS-4 | PII/FTI approved boundary and retention implementation | Action records intentionally store hashes and resource identifiers, not raw FTI. The approved processing boundary, IRC 6103 controls, retention/deletion jobs, and incident response are not deployed. | Security/privacy deployment | Open |
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
