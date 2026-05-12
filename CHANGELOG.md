# Changelog

## v1.2.0 — Hardened Posture: Zero-Day Audit, Fuzz/Stress/Exhaustion Test Suite (2026-05-12)

This release establishes v1.2.0 as the **first continuously-audited posture release**
of SelfConnect Enterprise. It does not introduce new user-facing features. It proves
that the existing security guarantees hold under adversarial conditions that were not
previously tested, and it locks in the dependency hygiene required for production
classified deployment.

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
  `OperatorQueue`, `AgentLedger`. Confirms thread-safety guarantees and documents the
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

## v1.0.0 — Production Release (2026-05-08)  `71170e2` → packaging commit

Packaging and verification. No logic changes from v0.9.0. All guarantees
formalized in SECURITY.md. 528 tests passing across all modules. Signed SBOM
committed. README updated to reflect the actual module surface as built.
docs/verification/ carries a verification matrix for each version.

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
and `ObserverFilter(allowed_caveats=)`. Critical invariant proven:
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
The observer reads only entries where `decision=allow`, ensuring that a model
fine-tuned on this evidence cannot learn behaviors the policy forbade —
because it was never exposed to them. 373/373 tests passing.

## v0.5.0 — Signed Policy Bundles and 8-Step Enforcer (2026-05-07)  `ff5f1eb`

Introduced `PolicyBundle` (signed with ECDSA P-384 via `policy_sign.py`),
`PolicyEnforcer` (8-step deny-by-default evaluator), and `OperatorQueue`
(thread-safe human approval gate). Policy bundles are JSON files; no valid
signature means no policy. The evaluator denies by default — every check must
pass or the action is blocked. `policy_sign.py` ships at 100% test coverage.

## v0.4.0 — CNG Identity and CngLedger (2026-05-06)  `e9793d9`

`CngIdentity` and `CngLedger` replace the DPAPI / Python ed25519 stack with
Windows NCrypt software KSP (ECDSA P-384, SHA-384). Drop-in replacement for
`AgentIdentity` and `AgentLedger` with identical interface. Provides FIPS 140-2
certification path through the Windows CNG provider. Both identity types remain
available; v0.9.0 adds profile-level enforcement of which one is required.

## v0.3.1 — NCrypt ECDSA P-384 Crypto Primitives (2026-05-06)  `a6fd49b`

Added `enterprise/crypto.py`: `CngSigner`, `cng_sha384()`, `cng_verify()`,
`cng_key_exists()`, `cng_delete_key()`. All primitives operate through Windows
CNG NCrypt API (ctypes). Foundation for CngIdentity in v0.4.0.

## v0.3.0 — Persistent Agent Identity and Chained Ledger (2026-05-05)  `b16e8ed`

Introduced `AgentIdentity` (DPAPI-encrypted ed25519 keypair, machine-bound)
and `AgentLedger` (append-only JSONL, SHA-256 hash chain, ed25519 signatures).
Every agent has a permanent `SC-XXXXXXXX` identifier that survives process
restarts. Every action is a signed, chained ledger entry — retroactive
tampering is detectable because each entry hashes the previous one.

## v0.2.0 — WM_COPYDATA Receive Layer (2026-05-04)  `7460b44`

Added `CopyDataListener` in `enterprise/transport.py`. A background thread
creates a message-only window and runs a Win32 message pump. On `WM_COPYDATA`,
it deserialises the JSON payload and dispatches to registered callbacks.
Sender HWND is OS-verified — peers cannot spoof the origin. Max payload 64 KB.

## v0.1.0 — SetProp/GetProp Agent Registry + BirthTag (2026-05-03)  `150a5ad`

Initial repo. `enterprise/registry.py` with `stamp_birth_tag()`,
`read_birth_tag()`, `discover_mesh()`, `find_agent()`, `HeartbeatDaemon`.
Every agent stamps an OS-native birth tag at spawn (SCID, SCTYPE, SCBORN,
SCPARENT, SCMODEL, SCHB). When the window dies, the tag vanishes — the OS
handles garbage collection. `send_data()`, `signal_ready()`, `wait_for()`
complete the IPC surface.
