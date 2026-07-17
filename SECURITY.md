# Security Properties

This document states narrowly scoped component properties, their explicit
boundaries, and how each proposition is tested. It is intended for
security reviewers, compliance evaluators, and operators deploying the system
in regulated environments. A passing component test is not a deployed-system
guarantee or an authorization determination.

---

## Narrowly Tested Component Properties

### 1. Classification Ceiling Enforcement

Evidence records above `ObserverFilter.max_classification` are dropped before
reaching the training data exporter. This is a structural property: the filter
is evaluated on every entry before `EvidenceRecord` construction, and there is
no code path from a TOP_SECRET entry to `EvidenceExporter` when the ceiling is
set to SECRET or below.

**Tested by:** `test_observer_never_passes_above_max_classification`
(`tests/test_enterprise/test_labels.py`, v0.8.0+)

**Additional coverage:** RT-04, RT-15 (classification ceiling matrix,
`tests/test_enterprise/test_redteam.py`)

---

### 2. Deny-by-Default Policy Enforcement

`PolicyEnforcer.check()` evaluates nine conditions in order. If any condition
fails, the action is denied and the reason is recorded. No code path returns
`allowed=True` without passing all applicable checks. The enforcer fails
closed: an agent with no policy registration receives an immediate deny.

For MCP actuation, `GovernedRuntime` is the mandatory composition. The default
dispatcher now refuses `sc_inject_text` when a signed policy enforcer,
persistent signed ledger, or live target verifier is absent. Lower-level Python
modules remain callable and must not be described as globally intercepted.

**Evaluation order:**
1. Control plane gate (paused / quarantined / revoked)
2. Agent registered in policy
3. Agent not revoked in policy
4. Policy time window valid
5. Policy signature valid (if `require_signature=True`)
6. Target agent permitted
7. Application permitted
8. Action in `allowed_actions`
9. Classification ceiling not exceeded
10. Caveat validation and composition constraint (when configured)

**Tested by:** `tests/test_enterprise/test_policy.py` (deny-by-default suite),
RT-01 through RT-08 (`tests/test_enterprise/test_redteam.py`)

---

### 3. Signed Policy Enforcement

`PolicyEnforcer` rejects unsigned policies when `require_signature=True`
(the default). The signature is ECDSA P-384 over the canonical JSON
serialisation of the policy bundle (sorted keys, no whitespace), excluding the
`sig` and `signed_by_pub` fields. A tampered or unsigned policy fails closed —
the enforcer will deny every action rather than operate on an unverified policy.

**Tested by:** RT-02 (signature bypass attempts),
`test_enforcer_rejects_missing_sig` (`tests/test_enterprise/test_policy.py`)

---

### 4. Operator Kill-Switch

`ControlPlane.kill_all()` atomically revokes all non-revoked agents and drains
the operator approval queue. The state machine transitions are one-way except
for pause/resume: `active → paused → quarantined → revoked`. There is no
transition from `revoked` or `quarantined` back to `active`. State transitions
are logged when a ledger is configured; `GovernedRuntime` always supplies one.

**Tested by:** `TestKillAll`, `TestEnforcerControlGate`
(`tests/test_enterprise/test_control.py`)

**Concurrent case tested by:**
`test_concurrent_double_revoke_exactly_one_succeeds` (RT-09,
`tests/test_enterprise/test_redteam.py`)

---

### 5. Training Data Isolation

The observer operates only on entries where `decision=allow`. The same filter
is applied to primary records and every `context_before` entry, so denied,
quarantined, and paused entries are excluded from exported training records.

**Narrowly established by:** `test_only_allow_decisions_reach_training_data`
and `test_context_window_does_not_include_denied_in_output`
(`tests/test_enterprise/test_observer.py`)

---

### 6. Egress Gating

When `ClassifiedModeProfile.allow_cloud_egress=False`, outbound calls routed
through `EgressGuard` are denied and logged to the ledger. Direct sockets and
unwrapped libraries are outside this property and require OS/network controls.

**Tested by:** `TestEgressGuard` (`tests/test_enterprise/test_classified_mode.py`)

---

### 7. Export Gating

`ExportGuard.can_export()` returns `False` when:
- `profile.allow_export` is `False` (export disabled by profile), or
- The evidence label classification exceeds the profile ceiling, or
- The evidence label contains caveats not in `profile.allowed_caveats`.

Denial is always logged. No evidence record reaches `EvidenceExporter` without
an explicit `True` from `can_export()` or `check_and_log()`.

**Tested by:** `TestExportGuard` (`tests/test_enterprise/test_classified_mode.py`)

---

### 8. Identity Type Enforcement

When `ClassifiedModeProfile.require_cng_identity=True`, callers that pass
`identity_type="dpapi"` to `PolicyEnforcer.check()` receive an immediate
denial at Step 0.5. CNG (NCrypt ECDSA P-384) identity is required; DPAPI
(Python ed25519) is rejected. When `require_cng_identity=False`, both identity
types are accepted.

**Tested by:** `test_profile_dpapi_rejected_when_cng_required`,
`test_profile_cng_identity_accepted`
(`tests/test_enterprise/test_classified_mode.py`)

---

### 9. Hash Chain Integrity

Every ledger entry (both `AgentLedger` and `CngLedger`) includes a `prev_hash`
field containing the hash of the previous entry. `AgentLedger` uses SHA-256;
`CngLedger` uses SHA-384. `verify()` checks both signature validity and chain
integrity for every entry. Modifying any entry invalidates all subsequent
entries. A genesis constant (`"0" * 64`) anchors the chain.

Interior modification, insertion, and deletion of retained entries are
detectable. Tail truncation and complete-file deletion require a trusted
external checkpoint or WORM/off-host copy; a local chain alone cannot detect
that its final entries or entire file disappeared.

`AgentLedger` can seal verified local segments at entry or byte thresholds.
Verification treats all sealed segments plus the active file as one monotonic
sequence and refuses startup or rotation on corruption. Segmentation controls
local file growth; it does not close the external-checkpoint limitation.

**Tested by:** RT-11 (CNG ledger tamper detection, hash chain forgery),
RT-12 (hash chain insertion) (`tests/test_enterprise/test_redteam.py`)

---

### 10. Caveat Validation

`LabelEnvelope.validate()` returns `False` if any caveat is not in
`ALLOWED_CAVEATS`. When a `LabelEnvelope` with invalid caveats is passed to
`PolicyEnforcer.check()`, the action is denied at Step 8b with the invalid
caveats listed in the reason string.

**Tested by:** `test_check_label_invalid_caveats_denied`
(`tests/test_enterprise/test_labels.py`)

---

### 11. Governed MCP Actuation and Readback

`GovernedRuntime` composes the external policy trust root, active
`ControlPlane`, live HWND/PID/executable/class binding, applicable one-time
operator approval, durable approval store, real UIA output adapter, and
persistent signed ledger. The dispatcher fails closed if those required
components are absent. Approval context includes the action, lease, target
identity, classification, and payload hash, and is consumed once.

Durable approval transitions use a SQLite outbox in the same transaction as
the queue state change. Hardened transitions remain `audit_pending` and cannot
authorize work until their matching receipt passes full signed-ledger
verification. Finalization revalidates the complete queue and outbox state
under a SQLite write transaction. The dispatcher requires one unique ordered
`pending -> approved -> consumed` lineage, with no deny, expiry, duplicate, or
conflicting transition, and rechecks every receipt and the full ledger chain.
The verified operator proof is retained only as a ledger-signed bounded
envelope containing verifier/key identifiers, nonce, verification time, proof
digest, and a digest binding the approval, actor, action, context, decision,
and operator. Raw proof bytes are not stored. Internal `system/` identities may
create safety denials only; that path is explicitly not human attribution and
cannot approve. The SHA-256 context digest prevents raw context from
entering the event, but an unkeyed digest is not confidentiality protection for
guessable context. Deployments select and assess the operator proof verifier;
the repository does not prescribe a CAC, PKI, or personnel-identity system.

Decision nonces are also retained in a separate durable tombstone table for a
configured horizon (24 hours by default). Purging terminal approval and outbox
rows does not remove that replay record before the horizon. This is bounded
replay retention, not indefinite global nonce history. Expiry is evaluated
only through the queue's validated clock dependency; consume APIs do not
accept a caller-supplied current time. Tests may inject a clock at construction,
while production remains responsible for a trustworthy clock source.

The approvals, transition outbox, replay tombstones, required indexes,
schema-version marker, and foreign-key relationship are one migration domain.
Startup checks SQLite metadata and exercises the constraints inside a rolled
back savepoint rather than trusting SQL text. Any legacy member triggers one
transactional rebuild; duplicate or conflicting nonce ownership, forged
governed state, orphan evidence, or a failed integrity check aborts the rebuild
and leaves the source database intact for investigation.
The behavioral probes establish the named invariants; they are not a byte-for-byte
attestation of SQLite's stored DDL text. A current version marker with any missing
governed table and any schema newer than this runtime are rejected without repair
or downgrade.

Ledger append state advances only after append, flush, and `fsync` succeed. A
failed or partial append is truncated to the prior durable length and the tail
is reverified before retry. This is a single-process/thread-safe writer
boundary, not multi-process file locking or off-host immutable custody.
Receipt verification ignores the performance cache and validates the exact
disk snapshot from which the matching signed entry was parsed. Returned ledger
objects and nested indexes are deep copies, preventing caller mutation from
changing the cached interpretation of signed metadata.

This property covers the governed MCP dispatcher. Direct SDK calls and other
repositories are not globally intercepted.

**Narrowly established by:** `tests/test_enterprise/test_governed_runtime.py`,
`tests/test_enterprise/test_mcp_dispatch.py`, and live
`tools/irs_runtime_conformance.py` execution when its real-target prerequisites
are supplied.

---

### 12. Ultra Lifecycle and Restart Durability

Ultra Server agent lifecycle requests use Ed25519 proof over the exact body
hash, timestamp, and nonce. The server derives the agent ID from the public key,
rejects stale/replayed/tampered proofs, binds pairs and tumbler maps to the same
agent, and requires separate operator authorization for first production
enrollment. Recovery issuance requires both operator authorization and the
replacement key proof.

Production mode refuses memory fallback. PostgreSQL persists pair, complete
tumbler, identity-binding, and idempotency state; Redis persists replay and
anomaly state. The store preserves monotonic HOTP counters even when upstream
lifecycle metadata is written from an earlier read. Lifecycle crash recovery
is operation-specific and serialized with PostgreSQL advisory locks. It
reconstructs a response only from the exact owned durable resource and fails
closed on ambiguous duplicates; it is not a generic retry lease. The restart
probe requires a HOTP-bearing map and verifies the same agent, pair, TSK client,
and new request after process restart.

Ultra also applies independent source-IP and pair rate limits. A BPC shadow or
ghost result is converted to a hard denial before the TSK bridge so deceptive
shadow behavior cannot authorize an action. Recovery tokens are versioned and
bind the agent, replacement key, recovery challenge, issuance time, and key ID.
Production may accept one distinct previous operator/recovery secret during a
bounded rotation. TSK client rotation uses prepare, compare-and-swap commit,
old-key revocation, and owner-authenticated resume; local client state changes
only after commit.

**Narrowly established by:** `ultra_server/agent-auth.test.mjs`,
`ultra_server/recovery-token.test.mjs`,
`ultra_server/runtime-stores.test.mjs`, `ultra_server/server.test.mjs`,
`ultra_server/security-boundary.test.mjs`,
`tests/test_e2e_ultra_gate.py`, and
`tools/ultra_restart_conformance.py` against live services.

**TSK disclosure boundary:** the complete stored tumbler record is not returned
verbatim, and literal segment `position` fields are absent from the provisioning
response. The owning client necessarily receives the TSK shared secret plus
segment types, lengths, positional order, initial HOTP counters, and total key
length so it can construct keys. SelfConnect therefore does not claim that the
effective layout is secret from the owning client. The tested properties are
separate key material, rotating values, checksum verification, replay handling,
and server-enforced lifecycle/counter state.

---

## What This System Does Not Guarantee

**This is not a certified MLS system.** SelfConnect Enterprise has not been
evaluated under Common Criteria, DIACAP, RMF, or any other formal assurance
framework. The properties above are software-level propositions backed by tests,
not certified assurance claims.

**This is not IRS-authorized.** No IRS/Treasury operational approval, PCLIA,
ATO/IATT, system boundary, independent assessment, or agency acceptance is
established by this repository. `enterprise/irs_evidence.py` supplies a
structured integration evidence contract; it does not replace agency systems
of record or qualified assessor review.

**This is not DoD Impact Level authorized.** Software tests do not grant a
cloud service offering IL4, IL5, or IL6 status. IL6 is Secret; there is no IL7
in the current DoD Cloud Computing SRG model. The Mission Owner boundary,
authorized cloud service, RMF package, ATO/IATT as applicable, personnel access,
and classified operating environment are separate requirements.

**Network-layer isolation is out of scope.** `EgressGuard` prevents outbound
calls through the Python API call paths it wraps. It does not prevent OS-level
network egress. A process with direct socket access can make outbound calls
regardless of the profile. Network isolation must be enforced at the OS or
infrastructure level (firewall rules, air-gap, etc.).

**Key management is out of scope.** The security of CNG key provisioning
depends entirely on the host environment. Windows NCrypt software KSP stores
keys in the user's key container. If the host environment is compromised,
the keys are compromised. HSM-backed key storage is not implemented.

Ultra production mode checks that independent operator and recovery secrets are
configured and at least 32 bytes, and code/runbooks support bounded rolling
rotation. It does not provide the deployment's secret manager, service-account
isolation, personnel separation, or emergency custody approvals.

**Ledger write access is not restricted.** The system does not protect against
a malicious process with write access to the JSONL ledger file. Tampering is
detectable via `verify()`, but the system does not prevent tampering.

**The SBOM is not exhaustive.** `sbom.json` captures installed Python packages.
It does not enumerate Windows system DLLs, CNG providers, or the Win32 API
surface called by ctypes.

**Coverage is run-specific.** No repository-wide percentage is a standing
release property. Win32 API paths such as live HWND actuation, DPAPI calls, and
NCrypt key persistence require real-Windows probes in addition to portable
tests; a mock-only percentage would not establish those runtime properties.

---

## Test Coverage Summary (v1.2.3)

| Metric | Value |
|--------|-------|
| Current count and result | Commit-specific; use the CI run and local evidence for the exact commit |
| Live Win32 actuation | Run `tools/irs_runtime_conformance.py`; unit adapters do not establish live behavior |
| Authorization/compliance | Not established by test count |

### Test layers

| Layer | File | Count | What it covers |
|-------|------|-------|----------------|
| Logic / unit | `test_policy.py`, `test_observer.py`, `test_ledger.py`, … | Commit-specific | Core invariants, decision paths, edge cases |
| Red team | `test_redteam.py` | 59 | RT-01–RT-20: policy bypass, sig tamper, hash chain forgery, race conditions |
| Adversarial AI | `test_adversarial_ai.py` | 17 | Training data poisoning, ceiling bypass via signed policy, ControlPlane races, approval replay, self-revival |
| Dependency integrity | `test_dependency_integrity.py` | 21 | Axios-style supply chain IOCs, module shadow attack, MCP tool metadata injection scanner, git dep pinning |
| Supply chain / CVE | `test_supply_chain.py` | 10 | LiteLLM backdoor gate, cryptography CVE floor, SECT curve scan, x509.verification scan, WFP integrity, pip-audit hard gate |
| Fuzz (Hypothesis) | `test_fuzz.py` | 15 | 200+ examples per boundary; never-crash invariants |
| Concurrency stress | `test_stress_concurrent.py` | 8 | 50–100 thread stress; documents AgentLedger single-writer contract |
| Resource exhaustion | `test_resource_exhaustion.py` | 10 | 10k entries, 1k queue, 500-agent bundles; timing budgets |

### Critical Invariant Tests

| Test | File | Narrow assertion exercised |
|------|------|----------------|
| `test_only_allow_decisions_reach_training_data` + context test | test_observer.py | Allowed primary records and allowed context only |
| `test_observer_never_passes_above_max_classification` | test_labels.py | Classification ceiling |
| `test_cng_ledger_tampered_entry_detected` (RT-11) | test_redteam.py | Hash chain integrity |
| `test_inserted_entry_breaks_chain` (RT-12) | test_redteam.py | Chain insertion detection |
| `test_concurrent_double_revoke_exactly_one_succeeds` (RT-09) | test_redteam.py | Control plane thread safety |
| `test_classified_mode_full_scenario` | test_classified_mode.py | End-to-end classified mode |
| `test_cui_baseline_full_scenario` | test_classified_mode.py | End-to-end CUI mode |
| `TestClassificationCeilingBypass` | test_adversarial_ai.py | Ceiling survives attacker-signed policy escalation |
| `test_observer_reads_without_verify_documents_gap` | test_adversarial_ai.py | G-3 CLOSED: asserts ValueError when verifier absent; raw path requires `unsafe_unverified=True` |
| `test_policy_id_allowlist_blocks_injected_training_entry` | test_adversarial_ai.py | allowed_policy_ids blocks injected training entries |
| `test_litellm_not_backdoored_version` | test_supply_chain.py | LiteLLM supply chain hard gate |
| `test_cryptography_at_minimum_safe_version` | test_supply_chain.py | deployment environment meets declared cryptography floor |
| `test_direct_deps_no_known_cves` | test_supply_chain.py | pip-audit hard gate on cryptography + selfconnect |

---

## Reporting Security Issues

This is a private research and patent-portfolio repository. Security issues
should be reported directly to the repository owner.
