# Security Properties

This document states what SelfConnect Enterprise guarantees, what it explicitly
does not guarantee, and how each guarantee is verified. It is intended for
security reviewers, compliance evaluators, and operators deploying the system
in classified or regulated environments.

---

## What This System Guarantees

### 1. Classification Ceiling Enforcement

Evidence records above `ObserverFilter.max_classification` are dropped before
reaching the training data exporter. This is a structural property: the filter
is evaluated on every entry before `EvidenceRecord` construction, and there is
no code path from a TOP_SECRET entry to `EvidenceExporter` when the ceiling is
set to SECRET or below.

**Proven by:** `test_observer_never_passes_above_max_classification`
(`tests/test_enterprise/test_labels.py`, v0.8.0+)

**Additional coverage:** RT-04, RT-15 (classification ceiling matrix,
`tests/test_enterprise/test_redteam.py`)

---

### 2. Deny-by-Default Policy Enforcement

`PolicyEnforcer.check()` evaluates nine conditions in order. If any condition
fails, the action is denied and the reason is recorded. No code path returns
`allowed=True` without passing all applicable checks. The enforcer fails
closed: an agent with no policy registration receives an immediate deny.

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
10. Caveat validation (if `LabelEnvelope` provided)

**Proven by:** `tests/test_enterprise/test_policy.py` (deny-by-default suite),
RT-01 through RT-08 (`tests/test_enterprise/test_redteam.py`)

---

### 3. Signed Policy Enforcement

`PolicyEnforcer` rejects unsigned policies when `require_signature=True`
(the default). The signature is ECDSA P-384 over the canonical JSON
serialisation of the policy bundle (sorted keys, no whitespace), excluding the
`sig` and `signed_by_pub` fields. A tampered or unsigned policy fails closed —
the enforcer will deny every action rather than operate on an unverified policy.

**Test coverage:** `enterprise/policy_sign.py` at 100% line coverage.

**Proven by:** RT-02 (signature bypass attempts),
`test_enforcer_rejects_missing_sig` (`tests/test_enterprise/test_policy.py`)

---

### 4. Operator Kill-Switch

`ControlPlane.kill_all()` atomically revokes all non-revoked agents and drains
the operator approval queue. The state machine transitions are one-way except
for pause/resume: `active → paused → quarantined → revoked`. There is no
transition from `revoked` or `quarantined` back to `active`. Every state
transition is logged to the ledger as an `operator_control` entry.

**Proven by:** `TestKillAll`, `TestEnforcerControlGate`
(`tests/test_enterprise/test_control.py`)

**Concurrent safety proven by:**
`test_concurrent_double_revoke_exactly_one_succeeds` (RT-09,
`tests/test_enterprise/test_redteam.py`)

---

### 5. Training Data Isolation

The observer operates only on entries where `decision=allow`. Denied,
quarantined, and paused entries are structurally excluded from the training
data pipeline. A model fine-tuned on observer output cannot learn behaviors
that the policy forbade, because it was never exposed to them.

**Proven by:** `test_only_allow_decisions_reach_training_data`
(`tests/test_enterprise/test_observer.py`)

---

### 6. Egress Gating

When `ClassifiedModeProfile.allow_cloud_egress=False`, all outbound calls
routed through `EgressGuard` are denied and logged to the ledger. There is no
silent bypass path within the Python layer. Every check — allowed or denied —
produces a ledger entry with `action="egress_check"` and `decision=allow|deny`.

**Proven by:** `TestEgressGuard` (`tests/test_enterprise/test_classified_mode.py`)

---

### 7. Export Gating

`ExportGuard.can_export()` returns `False` when:
- `profile.allow_export` is `False` (export disabled by profile), or
- The evidence label classification exceeds the profile ceiling, or
- The evidence label contains caveats not in `profile.allowed_caveats`.

Denial is always logged. No evidence record reaches `EvidenceExporter` without
an explicit `True` from `can_export()` or `check_and_log()`.

**Proven by:** `TestExportGuard` (`tests/test_enterprise/test_classified_mode.py`)

---

### 8. Identity Type Enforcement

When `ClassifiedModeProfile.require_cng_identity=True`, callers that pass
`identity_type="dpapi"` to `PolicyEnforcer.check()` receive an immediate
denial at Step 0.5. CNG (NCrypt ECDSA P-384) identity is required; DPAPI
(Python ed25519) is rejected. When `require_cng_identity=False`, both identity
types are accepted.

**Proven by:** `test_profile_dpapi_rejected_when_cng_required`,
`test_profile_cng_identity_accepted`
(`tests/test_enterprise/test_classified_mode.py`)

---

### 9. Hash Chain Integrity

Every ledger entry (both `AgentLedger` and `CngLedger`) includes a `prev_hash`
field containing the hash of the previous entry. `AgentLedger` uses SHA-256;
`CngLedger` uses SHA-384. `verify()` checks both signature validity and chain
integrity for every entry. Modifying any entry invalidates all subsequent
entries. A genesis constant (`"0" * 64`) anchors the chain.

**Proven by:** RT-11 (CNG ledger tamper detection, hash chain forgery),
RT-12 (hash chain insertion) (`tests/test_enterprise/test_redteam.py`)

---

### 10. Caveat Validation

`LabelEnvelope.validate()` returns `False` if any caveat is not in
`ALLOWED_CAVEATS`. When a `LabelEnvelope` with invalid caveats is passed to
`PolicyEnforcer.check()`, the action is denied at Step 8b with the invalid
caveats listed in the reason string.

**Proven by:** `test_check_label_invalid_caveats_denied`
(`tests/test_enterprise/test_labels.py`)

---

## What This System Does Not Guarantee

**This is not a certified MLS system.** SelfConnect Enterprise has not been
evaluated under Common Criteria, DIACAP, RMF, or any other formal assurance
framework. The guarantees above are software-level properties backed by tests,
not certified assurance claims.

**Network-layer isolation is out of scope.** `EgressGuard` prevents outbound
calls through the Python API call paths it wraps. It does not prevent OS-level
network egress. A process with direct socket access can make outbound calls
regardless of the profile. Network isolation must be enforced at the OS or
infrastructure level (firewall rules, air-gap, etc.).

**Key management is out of scope.** The security of CNG key provisioning
depends entirely on the host environment. Windows NCrypt software KSP stores
keys in the user's key container. If the host environment is compromised,
the keys are compromised. HSM-backed key storage is not implemented.

**Ledger write access is not restricted.** The system does not protect against
a malicious process with write access to the JSONL ledger file. Tampering is
detectable via `verify()`, but the system does not prevent tampering.

**The SBOM is not exhaustive.** `sbom.json` captures installed Python packages.
It does not enumerate Windows system DLLs, CNG providers, or the Win32 API
surface called by ctypes.

**Coverage gaps reflect real limits.** The 12% of code not covered by tests
is primarily Win32 API paths (HWND creation, DPAPI calls, NCrypt key persistence)
that require a live Windows session. These are not mocked because mocking them
at the wrong layer would produce coverage numbers that lie.

---

## Test Coverage Summary (v1.2.1)

| Metric | Value |
|--------|-------|
| Total tests | 716 |
| Passing | 716 |
| Failures | 0 |
| Coverage (overall) | ~90% |
| `enterprise/observer.py` | 100% |
| `enterprise/policy_sign.py` | 100% |
| `enterprise/__init__.py` | 100% |
| Win32 / DPAPI / NCrypt paths | Not covered in CI (requires live session) |

### Test layers

| Layer | File | Count | What it covers |
|-------|------|-------|----------------|
| Logic / unit | `test_policy.py`, `test_observer.py`, `test_ledger.py`, … | ~591 | Core invariants, decision paths, edge cases |
| Red team | `test_redteam.py` | 59 | RT-01–RT-20: policy bypass, sig tamper, hash chain forgery, race conditions |
| Adversarial AI | `test_adversarial_ai.py` | 17 | Training data poisoning, ceiling bypass via signed policy, ControlPlane races, approval replay, self-revival |
| Dependency integrity | `test_dependency_integrity.py` | 21 | Axios-style supply chain IOCs, module shadow attack, MCP tool metadata injection scanner, git dep pinning |
| Supply chain / CVE | `test_supply_chain.py` | 10 | LiteLLM backdoor gate, cryptography CVE floor, SECT curve scan, x509.verification scan, WFP integrity, pip-audit hard gate |
| Fuzz (Hypothesis) | `test_fuzz.py` | 15 | 200+ examples per boundary; never-crash invariants |
| Concurrency stress | `test_stress_concurrent.py` | 8 | 50–100 thread stress; documents AgentLedger single-writer contract |
| Resource exhaustion | `test_resource_exhaustion.py` | 10 | 10k entries, 1k queue, 500-agent bundles; timing budgets |

### Critical Invariant Tests

| Test | File | What it proves |
|------|------|----------------|
| `test_only_allow_decisions_reach_training_data` | test_observer.py | Training data isolation |
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
| `test_cryptography_at_minimum_safe_version` | test_supply_chain.py | cryptography CVE floor ≥46.0.6 |
| `test_direct_deps_no_known_cves` | test_supply_chain.py | pip-audit hard gate on cryptography + selfconnect |

---

## Reporting Security Issues

This is a private research and patent-portfolio repository. Security issues
should be reported directly to the repository owner.

---

## Known Vulnerabilities & Remediation Record

This section documents every CVE and supply-chain advisory identified as relevant to this codebase, the scope assessment, and the remediation or mitigation applied. Each entry is backed by an automated test that acts as a permanent regression gate.

---

### sonatype-2026-001357 — LiteLLM TeamPCP Supply Chain Backdoor

| Field | Value |
|---|---|
| **Advisory** | sonatype-2026-001357 |
| **Affected package** | `litellm` versions 1.82.7 and 1.82.8 |
| **Severity** | Critical |
| **Discovered** | 2026-03-24 (Datadog Security Labs) |
| **Type** | Supply chain — credential stealer + persistent backdoor injected via PyPI |

**Description.** The TeamPCP threat actor (tracked as Sapphire Sleet / UNC1069) published backdoored versions of `litellm` to PyPI. The backdoor injected a new dependency (`plain-crypto-js`) that exfiltrated credentials from the host environment on import. Any environment that ran `pip install litellm` between 2026-03-24 and 2026-03-26 may have installed the backdoored version.

**Scope assessment.** `litellm` is not a direct dependency of this package. If present in the environment (e.g., installed by a co-located agent framework), the backdoored versions are blocked.

**Remediation.** `test_litellm_not_backdoored_version` in `tests/test_enterprise/test_supply_chain.py` is a hard gate: it fails the test suite if `litellm==1.82.7` or `litellm==1.82.8` is installed. Any CI run on a compromised environment will fail immediately.

**Reference.** https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/

---

### CVE-2026-26007 — cryptography < 46.0.5: SECT Curve ECDH Small-Subgroup Attack

| Field | Value |
|---|---|
| **CVE** | CVE-2026-26007 |
| **Affected package** | `cryptography` < 46.0.5 |
| **Severity** | High (CVSS 7.4) |
| **Fixed in** | `cryptography` 46.0.5 |
| **Type** | Cryptographic — small-subgroup ECDH attack on SECT (binary) curves |

**Description.** A small-subgroup attack on SECT elliptic curves (SECT163k1, SECT233k1, SECT283k1, etc.) allowed an attacker to recover private key material from ECDH key exchange operations using a low-order point.

**Scope assessment.** This codebase uses P-384 and Ed25519 exclusively — not SECT curves. The gate is defense-in-depth against a future dependency silently introducing a SECT curve operation.

**Remediation.** Two gates in `tests/test_enterprise/test_supply_chain.py`: (1) `test_cryptography_at_minimum_safe_version` — hard fails if `cryptography < 46.0.6`; (2) `test_cryptography_not_using_sect_curves` — scans all Python source files for SECT curve references.

---

### CVE-2026-34073 — cryptography < 46.0.6: X.509 Name Constraint Bypass

| Field | Value |
|---|---|
| **CVE** | CVE-2026-34073 |
| **Affected package** | `cryptography` < 46.0.6 |
| **Severity** | High (CVSS 7.5) |
| **Fixed in** | `cryptography` 46.0.6 |
| **Type** | Cryptographic — X.509 name constraint bypass in `x509.verification` module |

**Description.** A name constraint bypass in the `x509.verification` module allowed a certificate violating the issuer's name constraints to pass verification, enabling a sub-CA to issue certificates for domains outside its permitted subtree.

**Scope assessment.** This codebase does not use `x509.verification` for TLS/cert validation — that is delegated to the OS TLS stack. The gate prevents a future code change from introducing this path.

**Remediation.** Two gates: (1) `test_cryptography_at_minimum_safe_version` — requires `cryptography >= 46.0.6`; (2) `test_x509_verification_path_not_used` — scans all Python source files for `x509.verification` usage.

---

### CVE-2026-23744 — MCP Tool Metadata Prompt Injection

| Field | Value |
|---|---|
| **CVE** | CVE-2026-23744 |
| **Affected surface** | MCP clients that do not validate server-provided tool metadata |
| **Severity** | High |
| **Reported by** | OX Security; Elastic Security Labs (2026) |
| **Type** | Prompt injection — malicious instructions embedded in MCP tool names/descriptions/schemas |

**Description.** 5 of 7 evaluated MCP clients performed zero static validation of server-provided tool metadata. A malicious MCP server could embed prompt injection payloads in tool names, descriptions, or input schemas that the LLM obeys as system-level directives, enabling credential exfiltration, command execution, and behavioral override.

**Remediation.** `TestMcpToolPoisoningScanner` in `tests/test_enterprise/test_dependency_integrity.py` provides a reusable scanner checking tool description strings against 12 injection pattern categories: authority directives, system instruction claims, ignore-previous injections, forget directives, behavioral overrides, new-instructions claims, role overrides, credential path references, shadow tool references, credential exfiltration attempts, backtick command execution, and Unicode homoglyph attacks.

**Reference.** OX Security CVE-2026-23744; Elastic Security Labs "MCP Tools: Attack Vectors and Defense Recommendations" (2026).

---

### CVE-2026-33825 — BlueHammer: Windows Defender Temp Path TOCTOU

| Field | Value |
|---|---|
| **CVE** | CVE-2026-33825 |
| **Affected surface** | Windows Defender internal temp/staging paths |
| **Severity** | Medium (CVSS 5.9) |
| **Type** | TOCTOU — file substitution between script generation and execution |

**Description.** BlueHammer targets Windows Defender's internal temp/staging paths via a TOCTOU race. A malicious process can substitute a script file between when Defender stages it and when it executes it.

**Scope assessment.** This CVE targets Defender's internal paths, **not** operator-controlled `.ps1` paths generated by this codebase. The mitigation is defense-in-depth for general file substitution scenarios.

**Remediation.** `generate_powershell()` in `enterprise/wfp.py` is deterministic — identical inputs always produce identical output bytes. Operators verify the SHA-256 hash of the generated script before executing it. `TestWfpScriptIntegrity` in `tests/test_enterprise/test_supply_chain.py` verifies determinism and hash stability.

---

## Automated Supply Chain Gate Summary

| Advisory | Test file | Test name | Gate type |
|---|---|---|---|
| sonatype-2026-001357 (LiteLLM) | `test_supply_chain.py` | `test_litellm_not_backdoored_version` | Hard fail if backdoored version installed |
| CVE-2026-26007 | `test_supply_chain.py` | `test_cryptography_at_minimum_safe_version` | Hard fail if `cryptography < 46.0.6` |
| CVE-2026-26007 (scope) | `test_supply_chain.py` | `test_cryptography_not_using_sect_curves` | Hard fail if SECT curve reference found in source |
| CVE-2026-34073 | `test_supply_chain.py` | `test_cryptography_at_minimum_safe_version` | Hard fail if `cryptography < 46.0.6` |
| CVE-2026-34073 (scope) | `test_supply_chain.py` | `test_x509_verification_path_not_used` | Hard fail if `x509.verification` found in source |
| CVE-2026-23744 | `test_dependency_integrity.py` | `TestMcpToolPoisoningScanner` | Reusable scanner on all MCP tool metadata |
| CVE-2026-33825 | `test_supply_chain.py` | `TestWfpScriptIntegrity` | Determinism + hash stability verification |
| pip-audit (all direct deps) | `test_supply_chain.py` | `test_direct_deps_no_known_cves` | Hard fail if pip-audit reports any CVE |
