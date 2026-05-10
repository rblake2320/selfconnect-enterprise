# Changelog

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
