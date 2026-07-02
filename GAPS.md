# SelfConnect Enterprise — Complete Gap & Limitation Registry

Last updated: 2026-05-27  
Scope: all known limitations across the full stack, regardless of severity or prior tracking status.  
Rule: if a limitation is known, it is in this file the first time it is asked about, not when it becomes relevant to something else.

---

## Ultra Server

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| US-1 | No automatic rate limiting / lockout policy | Anomaly data collected but nothing acts on it. Brute-force attacker is slowed by HOTP/TOTP but not hard-blocked. | 1 day | Open |
| US-2 | No PostgreSQL persistence for pairs and TSK keys | Restart = all registered agents must re-register. Memory-only. | 2–3 days | Open |
| US-3 | No authentication on lifecycle API endpoints | `/tsk/keys/:id`, `/bpc/pairs/:id`, `/bind-identity` have no auth guard. Any process that can reach the server can modify or revoke keys. | Half day | **CLOSED 2026-07-02** |
| US-4 | Redis nonce store wired but not tested under load | `RedisNonceStore` code is in `@bpc/server` and wired in `server.js`, but E2E tests run against memory backend only. Redis path has no integration test in CI. | 1 day | Open |
| US-5 | No TLS | Binds to `127.0.0.1` only, so LAN exposure is not the risk — but any process on the same machine can reach it. Matters for multi-tenant or shared machines. | Config only | Open |

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

---

## AgentLedger

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| AL-1 | JSONL file grows unbounded | No rotation, no archival, no size cap. Long-running agent accumulates an unbounded ledger file. | 1 day | Open |
| AL-2 | No remote / centralized ledger backend | Each agent writes its own local file. No aggregated audit store. | Architectural — weeks | Open |

---

## SelfConnect Win32 SDK

| # | Gap | Impact | Effort | Status |
|---|-----|--------|--------|--------|
| SDK-1 | 6 display-dependent tests skip in headless CI | Requires virtual display or interactive session. | Known, accepted | Open |
| SDK-2 | No code signing on the SDK | Windows Defender and enterprise AV may flag unsigned Python scripts. | Certificate + signing pipeline | Open |

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
| CC-3 | CI does not test the Redis nonce path | GitHub Actions CI runs against memory backend only. Redis path untested in CI. | 1 day (add Redis service container to workflow) | Open |

---

## Performance Baseline (measured 2026-05-27, Windows 11, this machine)

Pending retest on DGX Spark and RTX 5090.

| Operation | Median | p95 | Throughput |
|-----------|--------|-----|------------|
| Policy check (allow/deny) | 0.008ms | 0.009ms | 115,000/sec |
| Ledger write (hash + sign + append) | — | — | 586/sec |
| CNG sign (ECDSA P-384, NCrypt) | 1.05ms | 2.32ms | 582/sec |
| CNG verify (BCrypt) | 0.60ms | 1.37ms | 1,350/sec |
| Full 7-layer HTTP verify (127.0.0.1) | 11.5ms | 13.8ms | 125 req/sec |

**Note on localhost vs 127.0.0.1:** On Windows, connecting to `localhost` adds ~200ms due to IPv6 fallback (server is IPv4-only). All production code should use `127.0.0.1` explicitly. The E2E tests use `localhost` — this is the source of the 57-second test run time for 20 tests.

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
- **US-3 CLOSED:** Added `LIFECYCLE_SECRET` env var and `requireLifecycleAuth` middleware to
  `ultra_server/server.js`. Applied to `POST /bind-identity`, `PATCH /tsk/keys/:clientId`,
  `PATCH /bpc/pairs/:pairId`. Middleware is fail-closed: returns 503 if `LIFECYCLE_SECRET` is
  not configured, 401 if wrong token, uses constant-time HMAC comparison to prevent timing
  attacks. Covered by 8 adversarial tests in
  `tests/test_e2e_ultra_gate.py::TestLifecycleAuth` (no-auth → 401/503, wrong token → 401/503,
  empty Bearer, malformed Authorization header — all three endpoints).
