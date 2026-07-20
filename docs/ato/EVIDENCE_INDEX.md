# SelfConnect Enterprise — ATO Evidence Index

**Version:** 1.2.3  
**Date:** 2026-06-18  
**Purpose:** Traceable developer evidence that may support a future assessment. Each control reference is a preliminary candidate mapping, not a conclusion that the control is satisfied.

---

## Evidence Artifact Table

| # | Artifact | Type | Location | Bounded proposition / status | Candidate NIST controls | Date |
|---|---------|------|----------|----------------|---------------|------|
| 1 | `test_dependency_integrity.py` — AXIOS-1 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | The enumerated dependency graph matched the test's allowlist in that run; novel or undeclared supply-chain paths remain outside scope | SI-3, SI-7, CM-7 | CI run-specific |
| 2 | `test_dependency_integrity.py` — AXIOS-2 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | Declared metadata matched the test's install-hook policy; this is not proof that no installer code can execute in every environment | SI-3, CM-7 | CI run-specific |
| 3 | `test_dependency_integrity.py` — AXIOS-3 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No git dependencies pinned to mutable tags (must use immutable commit hash) | SI-3, CM-9 | CI-continuous |
| 4 | `test_dependency_integrity.py` — AXIOS-4 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No PyPI package name shadows a local module name | SI-3, SI-7 | CI-continuous |
| 5 | `test_dependency_integrity.py` — MCP-1 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | Tool description fields in MCP configuration contain no prompt injection patterns | SI-3 | CI-continuous |
| 6 | `test_dependency_integrity.py` — MCP-2 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No typosquatted package names similar to declared dependencies | SI-3, SI-7 | CI-continuous |
| 7 | WRAITH-003 red-team finding + fix | Red-team finding | `enterprise/identity_gate.py:get_current_mode()` (inline comment) | Default mode was `bypass`; changed to `audit`; bypass now requires dual env-var opt-in | AC-3, IA-2, CA-2 | 2026-06 |
| 8 | Gap 1 mitigation: emergency-bypass interlock | Design + code | `enterprise/identity_gate.py:_emergency_mutex_active()`, `write_bypass_registry_token()` | The mutex alone cannot trigger the downgrade; an expiring DPAPI-protected same-user token is also required. This is not independent authentication because a same-user process may be able to create both | AC-3, IA-5, IR-4 | 2026-06 |
| 9 | Gap 4 fix: strict governed Ultra verification | Design + code | `enterprise/identity_gate.py`, governed send wrapper | The governed path requires authoritative Ultra verification and denies every Level-0 rejection. Alternate/direct send paths require separate inventory | AC-3, SC-8, CA-2 | 2026-07 |
| 10 | WR-001 fix: pre-registered expected_pub | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:role_b()` | Named pipe server pre-pins expected TPM public key blob; self-signed substitution attack rejected | IA-3, SC-8, CA-2 | 2026-06 |
| 11 | WR-003 fix: random pipe name + `FILE_FLAG_FIRST_PIPE_INSTANCE` | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:_unique_pipe_name()`, `role_b()` | Pipe name prediction race mitigated via 128-bit entropy + OS-enforced first-instance flag | SC-4, AC-4 | 2026-06 |
| 12 | WR-005 experiment: `SW_HIDE` on throwaway consoles | Red-team finding + mitigation | `experiments/win32_probe/chained_channel.py:main()` | The throwaway console is launched without a visible window. `SW_HIDE` is not a security boundary and does not prove it is unavailable to same-session UI Automation | SC-4, AU-9 | 2026-06 |
| 13 | WR-009 fix: challenge-response nonce | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:role_b()` (challenge_nonce), `main()` | Server-generated nonce folded into `SHA-256(delta + nonce)`; replay of pre-captured payloads rejected | SC-8, IA-3 | 2026-06 |
| 14 | `AgentIdentity` DPAPI protection | Design document + code | `enterprise/identity.py:_dpapi_encrypt()`, `AgentIdentity.__doc__` | The private key blob uses current-user DPAPI protection. Microsoft describes same-credential/same-computer use as typical and documents exceptions including roaming profiles; this is not hardware binding or non-repudiation | IA-5, SC-28 | 2026-06 |
| 15 | `TargetGuard` protected-path image validation | Code + probe | `experiments/win32_probe/target_guard.py:TERMINAL_CLASS_TO_EXE`, `_exe_path()`, `_trusted_terminal_image()` | Reads the OS-reported image path and accepts supported terminal classes only from protected Windows/package roots; this is not cryptographic process identity | AC-3, AC-4, CM-7 | 2026-07 |
| 16 | `chained_channel.py` — CHAIN COMPLETE exit-0 proof | End-to-end experiment | `experiments/win32_probe/chained_channel.py:main()` | The named experimental chain (UIA read, Platform-KSP signing where the probe confirms it, DACL pipe, challenge-response) completed in the recorded environment; it does not establish production composition or remote attestation | IA-2, IA-3, SC-8, AU-12 | 2026-06 |
| 17 | TPM availability detection + CRITICAL log | Runtime evidence | `enterprise/identity_gate.py:_check_tpm_available()` | The local capability probe records TPM availability/absence. Presence does not prove the AgentIdentity key or DPAPI root is hardware-bound | IA-5, AU-2, CA-7 | 2026-06 |
| 18 | `DegradationCascade` strict enforce boundary | Code + tests | `enterprise/identity_gate.py:DegradationCascade.verify()` | In the current strict configuration, a Level-0 server rejection denies rather than falling through; deployment behavior still depends on using the governed wrapper and verified runtime configuration | AC-3, SI-7 | 2026-07 |
| 19 | BPC ECDSA-P256 body hash binding | Code + design | `enterprise/bpc_crypto.py:body_hash()`, `verify_payload_with_jwk()` | Injection payload content is bound to the signature via `SHA-256(text)`; payload tampering after signing fails Level 0/1 verification | SC-8, SI-7, AU-10 | 2026-06 |
| 20 | `policy_sign.py` — policy integrity | Code | `enterprise/policy_sign.py` | Policy documents are cryptographically signed; unauthorized policy modifications are detectable | SI-7, CM-9, CA-7 | 2026-06 |
| 21 | `egress_guard.py` — data egress control | Code | `enterprise/egress_guard.py` | Outbound data flows are subject to classification and policy checks before egress | AC-4, SC-8 | 2026-06 |
| 22 | `export_guard.py` — classification enforcement | Code | `enterprise/export_guard.py` | Data classification labels (`enterprise/labels.py`) enforced at export boundary | AC-4, AU-10 | 2026-06 |
| 23 | `msg_validator.py` — message validation | Code | `enterprise/msg_validator.py` | Messages routed through the named validator reject the exercised malformed payloads; other parsers and entry points require separate enumeration | SI-3, AC-3 | 2026-06 |
| 24 | `version_gate.py` — minimum version enforcement | Code | `enterprise/version_gate.py` | Callers that invoke the gate reject versions below the configured floor; the module is not global interception of every launch path | SI-7, CM-9 | 2026-06 |
| 25 | `ledger.py` — tamper-evident audit ledger | Code + design | `enterprise/ledger.py` | Interior modification of retained, verified records is detectable. Tail truncation, complete deletion, exclusive key custody, trusted time, and independent anchoring are separate boundaries | AU-9, AU-10, IR-4 | 2026-06 |
| 26 | MCP runtime dispatch | Code + tests | `enterprise/mcp_dispatch.py`, `tests/test_enterprise/test_mcp_dispatch.py` | The 20 MCP schemas have executable, schema-validated handlers; actuating calls are lease-gated, audited, and routed through the governed channel router | AC-3, AU-2, AU-12, SI-10 | 2026-06 |
| 27 | Governance profile split | Design + tests | `docs/GOVERNANCE_PROFILES.md`, `enterprise/mcp_dispatch.py`, `tests/test_enterprise/test_mcp_dispatch.py` | Profile names and fail-closed request gates are explicit. The current MCP TPM option still combines a software signature with a separate platform claim and is not the complete Government product | AC-3, AC-6, IA-2, IA-5, CM-7 | 2026-07 |
| 28 | Immutable-retention wiring | Code + tests; deployment open | `enterprise/audit_config.py`, `enterprise/worm_service.py`, `tests/test_enterprise/test_audit_config.py`, `tests/test_enterprise/test_worm_service.py` | AuditConfig maps runtime settings to a sink. Government posture rejects memory/file replicas. S3/R2 paths require live provider retention configuration; actual deployment evidence remains open. Candidate mappings only. | AU-9, AU-12, AU-5 | 2026-07 |
| 29 | TPM platform-claim probe | Code + tests | `enterprise/tpm_attestation.py`, `tests/test_enterprise/test_tpm_attestation.py` | NCryptCreateClaim platform evidence is attempted with nonce freshness and unsupported hosts return NA. This does not bind the ordinary agent signing key or payload to the claim and is not remote attestation | IA-5, IA-3, SC-28 | 2026-06 |
| 30 | MSI installer (WiX v4) | Deployment artifact | `installer/selfconnect-enterprise.wxs`, `installer/build_installer.py`, `installer/INSTALL.md` | The WiX source can register the Windows service, PATH entry, and ProgramData directory. Reproducibility and Authenticode signing require separate release-run evidence | CM-7, CM-9, SI-7 | 2026-06 |
| 31 | Live AWS S3 Object Lock WORM proof | Live cloud evidence | `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md`, `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.json`, `enterprise/provenance.py:S3ObjectLockSink` | A redacted Merkle-seal event and its stable seal-index were pushed to an Object Lock bucket in `COMPLIANCE` mode; a fresh sink instance rejected a conflicting root from remote seal-index state | AU-9, AU-10, AU-12, AU-5, CA-2 | 2026-06-21 |
| 32 | Live TPM platform attestation probe | Live host evidence | `docs/ato/TPM_LIVE_PROBE_2026-06-21.md`, `docs/ato/TPM_LIVE_PROBE_2026-06-21.json`, `enterprise/tpm_attestation.py` | SDK-correct NCryptCreateClaim ABI and all-PCR platform claim parameters are exercised live; host returns a clean NA (`0x80090026`) rather than malformed-call or fake PASS | IA-5, IA-3, SC-28, CA-2 | 2026-06-21 |
| 33 | MSI build proof | Local release evidence | `docs/ato/MSI_BUILD_PROOF_2026-06-21.md`, `installer/selfconnect-enterprise.wxs` | WiX v4 build produces `selfconnect-enterprise-1.2.3.msi` with recorded SHA-256 and size; installer source schema now compiles under WiX v4 | CM-7, CM-9, SI-7 | 2026-06-21 |
| 34 | Gemini real-agent auth blocker | Provider boundary evidence | `docs/ato/GEMINI_REAL_AGENT_AUTH_BLOCKER_2026-06-21.md` | Gemini CLI cannot join real-agent ladders without interactive login, `GEMINI_API_KEY`, or ADC; documents the non-SelfConnect provider-auth blocker | CA-2, SI-4 | 2026-06-21 |
| 35 | MSI release artifact workflow proof | GitHub Actions evidence | `.github/workflows/release-msi.yml`, `docs/ato/MSI_RELEASE_AUTOMATION_2026-06-21.md` | Manual GitHub Actions run `27897466199` built and uploaded `selfconnect-enterprise-1.2.3.msi` with SHA-256 `9A1CD2F56B6A4CE3AEFC6CC8CF4C5FE09B07F406F6D0E3ED8E62D9591749CF4D`; code signing remains false until certificate secrets are configured | CM-7, CM-9, SI-7 | 2026-06-21 |
| 36 | Live TPM platform attestation PASS | Live host evidence | `docs/ato/TPM_LIVE_PROBE_2026-07-20.md`, `docs/ato/TPM_LIVE_PROBE_2026-07-20.json`, `enterprise/tpm_attestation.py`, SelfConnect `sc_tpm_attestation.py` | The tested Windows TPM 2.0 host issued and locally verified a nonce-bound PCR 0-23 quote under an operator-pinned non-exportable PCP identity key, with durable replay rejection. Manufacturer/EK-chain trust, remote enrollment/revocation, and agent-signing-key binding remain outside this result | IA-5, IA-3, SC-28, CA-2 | 2026-07-20 |

---

## Evidence Coverage by NIST Family

| Family | Evidence Entries | Key Artifacts |
|--------|-----------------|---------------|
| AC | 1, 7, 8, 9, 15, 18, 21, 22, 26, 27 | identity_gate.py, target_guard.py, egress_guard.py, mcp_dispatch.py |
| AU | 7, 12, 17, 19, 22, 25, 26, 28, 31 | ledger.py, identity_gate.py, observer.py, mcp_dispatch.py, worm_service.py, S3ObjectLockSink |
| IA | 7, 8, 10, 14, 16, 17, 27, 29 | identity.py, chained_channel.py, governance profiles, tpm_attestation.py |
| SC | 9, 11, 12, 13, 19, 21, 29 | bpc_crypto.py, chained_channel.py, tpm_attestation.py |
| SI | 1, 2, 3, 4, 5, 6, 18, 19, 20, 24, 26, 30, 35 | test_dependency_integrity.py, version_gate.py, mcp_dispatch.py, installer/ |
| CM | 1, 3, 9, 15, 20, 24, 27, 30, 35 | test_dependency_integrity.py, version_gate.py, governance profiles, installer/ |
| CA | 7, 8, 9, 10, 17, 20, 31 | identity_gate.py (inline WRAITH references), WORM_LIVE_AWS_PROOF_2026-06-21.md |
| IR | 8, 25 | identity_gate.py:emergency_bypass(), ledger.py |

---

## Evidence Gaps and Unaccepted/Open Risks

| Gap | Description | Candidate compensating measure | Recorded date |
|-----|------------|----------------------|-----------------|
| Gap 3 | DPAPI-protected key exposure after user/SYSTEM compromise | Startup warning; a separately designed hardware-key and attestation path remains open | 2026-06 |
| WR-005 (prod) | UIA TextChanged eavesdropping on production terminal windows | UIAccess process isolation (OS configuration, outside codebase scope) | 2026-06 |
| Level 2 payload binding | ed25519 birth tag does not bind to specific payload content | SC_STRICT_ENFORCE=1 prevents degradation to Level 2 in high-assurance deployments | 2026-06 |

---

## Evidence Collection Procedure

For each CI run, the following artifacts must be collected and retained:

1. Full pytest output from `tests/test_enterprise/test_dependency_integrity.py` — all 6 AXIOS/MCP tests must show `PASSED`.
2. Exit code 0 from `python experiments/win32_probe/chained_channel.py` — records that the exact local experimental chain completed in that environment.
3. Startup log output recording the TPM capability result. Do not convert the
   result into AgentIdentity hardware-binding evidence or risk acceptance.
4. Hash of `enterprise/identity_gate.py`, `enterprise/identity.py`, `experiments/win32_probe/target_guard.py`, and `experiments/win32_probe/chained_channel.py` — to detect post-deployment modification.
5. For AU-9 evidence, retain the live S3 Object Lock receipt and `head-object` output showing `ObjectLockMode=COMPLIANCE` for both the event record and the stable seal-index object.

Evidence retention: configure and test the organization-defined period required
by the applicable records schedule, contract, legal hold, and authorization
boundary. NIST SP 800-53 AU-11 does not prescribe a universal three-year
period.
