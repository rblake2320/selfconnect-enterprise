# SelfConnect Enterprise — ATO Evidence Index

**Version:** 1.2.3  
**Date:** 2026-06-18  
**Purpose:** This index provides a traceable record of all security evidence artifacts for the Authority to Operate (ATO) review. Each entry links a specific artifact to the security claim it substantiates and the NIST SP 800-53 Rev 5 controls it satisfies.

---

## Evidence Artifact Table

| # | Artifact | Type | Location | What It Proves | NIST Controls | Date |
|---|---------|------|----------|----------------|---------------|------|
| 1 | `test_dependency_integrity.py` — AXIOS-1 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No unexpected subdependencies injected into the install graph (defends against axios/Sapphire Sleet supply chain pattern) | SI-3, SI-7, CM-7 | CI-continuous |
| 2 | `test_dependency_integrity.py` — AXIOS-2 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No postinstall/build hooks execute during `pip install` | SI-3, CM-7 | CI-continuous |
| 3 | `test_dependency_integrity.py` — AXIOS-3 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No git dependencies pinned to mutable tags (must use immutable commit hash) | SI-3, CM-9 | CI-continuous |
| 4 | `test_dependency_integrity.py` — AXIOS-4 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No PyPI package name shadows a local module name | SI-3, SI-7 | CI-continuous |
| 5 | `test_dependency_integrity.py` — MCP-1 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | Tool description fields in MCP configuration contain no prompt injection patterns | SI-3 | CI-continuous |
| 6 | `test_dependency_integrity.py` — MCP-2 pass | Test result | `tests/test_enterprise/test_dependency_integrity.py` | No typosquatted package names similar to declared dependencies | SI-3, SI-7 | CI-continuous |
| 7 | WRAITH-003 red-team finding + fix | Red-team finding | `enterprise/identity_gate.py:get_current_mode()` (inline comment) | Default mode was `bypass`; changed to `audit`; bypass now requires dual env-var opt-in | AC-3, IA-2, CA-2 | 2026-06 |
| 8 | Gap 1 fix: dual-factor emergency bypass | Design + code | `enterprise/identity_gate.py:_emergency_mutex_active()`, `write_bypass_registry_token()` | Unprivileged mutex alone cannot trigger bypass downgrade; DPAPI Registry token required as second factor | AC-3, IA-5, IR-4 | 2026-06 |
| 9 | Gap 4 fix: `SC_STRICT_ENFORCE` | Design + code | `enterprise/identity_gate.py:_STRICT_ENFORCE`, `DegradationCascade.verify()` | Network failure at Level 0 fails closed under `SC_STRICT_ENFORCE=1`; prevents forced degradation attack | AC-3, SC-8, CA-2 | 2026-06 |
| 10 | WR-001 fix: pre-registered expected_pub | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:role_b()` | Named pipe server pre-pins expected TPM public key blob; self-signed substitution attack rejected | IA-3, SC-8, CA-2 | 2026-06 |
| 11 | WR-003 fix: random pipe name + `FILE_FLAG_FIRST_PIPE_INSTANCE` | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:_unique_pipe_name()`, `role_b()` | Pipe name prediction race mitigated via 128-bit entropy + OS-enforced first-instance flag | SC-4, AC-4 | 2026-06 |
| 12 | WR-005 fix: `SW_HIDE` on throwaway consoles | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:main()` | Throwaway console hidden from UIA enumeration by other same-session processes | SC-4, AU-9 | 2026-06 |
| 13 | WR-009 fix: challenge-response nonce | Red-team finding + fix | `experiments/win32_probe/chained_channel.py:role_b()` (challenge_nonce), `main()` | Server-generated nonce folded into `SHA-256(delta + nonce)`; replay of pre-captured payloads rejected | SC-8, IA-3 | 2026-06 |
| 14 | `AgentIdentity` DPAPI key binding proof | Design document + code | `enterprise/identity.py:_dpapi_encrypt()`, `AgentIdentity.__doc__` | Private key DPAPI blob cannot be decrypted on a different machine or by a different Windows user | IA-5, SC-28, AU-10 | 2026-06 |
| 15 | `TargetGuard` protected-path image validation | Code + probe | `experiments/win32_probe/target_guard.py:TERMINAL_CLASS_TO_EXE`, `_exe_path()`, `_trusted_terminal_image()` | Reads the OS-reported image path and accepts supported terminal classes only from protected Windows/package roots; this is not cryptographic process identity | AC-3, AC-4, CM-7 | 2026-07 |
| 16 | `chained_channel.py` — CHAIN COMPLETE exit-0 proof | End-to-end test | `experiments/win32_probe/chained_channel.py:main()` | Full 4-leg chain (UIA read + TPM identity + OS-verified DACL pipe + challenge-response) completes successfully; exit code 0 | IA-2, IA-3, SC-8, AU-12 | 2026-06 |
| 17 | TPM availability detection + CRITICAL log | Runtime evidence | `enterprise/identity_gate.py:_check_tpm_available()` | Systems without TPM receive a CRITICAL log at startup documenting the DPAPI offline extraction risk (Gap 3 acknowledgement) | IA-5, AU-2, CA-7 | 2026-06 |
| 18 | `DegradationCascade` enforce-mode floor | Code proof | `enterprise/identity_gate.py:DegradationCascade.verify()` (Level 2 block) | In `enforce` mode, cascade halts at Level 2; Levels 3/4 are audit-only and never reached in production | AC-3, SI-7 | 2026-06 |
| 19 | BPC ECDSA-P256 body hash binding | Code + design | `enterprise/bpc_crypto.py:body_hash()`, `verify_payload_with_jwk()` | Injection payload content is bound to the signature via `SHA-256(text)`; payload tampering after signing fails Level 0/1 verification | SC-8, SI-7, AU-10 | 2026-06 |
| 20 | `policy_sign.py` — policy integrity | Code | `enterprise/policy_sign.py` | Policy documents are cryptographically signed; unauthorized policy modifications are detectable | SI-7, CM-9, CA-7 | 2026-06 |
| 21 | `egress_guard.py` — data egress control | Code | `enterprise/egress_guard.py` | Outbound data flows are subject to classification and policy checks before egress | AC-4, SC-8 | 2026-06 |
| 22 | `export_guard.py` — classification enforcement | Code | `enterprise/export_guard.py` | Data classification labels (`enterprise/labels.py`) enforced at export boundary | AC-4, AU-10 | 2026-06 |
| 23 | `msg_validator.py` — message validation | Code | `enterprise/msg_validator.py` | All inbound messages are validated before processing; malformed payloads rejected | SI-3, AC-3 | 2026-06 |
| 24 | `version_gate.py` — minimum version enforcement | Code | `enterprise/version_gate.py` | System refuses to operate below a minimum version, preventing downgrade attacks | SI-7, CM-9 | 2026-06 |
| 25 | `ledger.py` — tamper-evident audit ledger | Code + design | `enterprise/ledger.py` | Audit records written to tamper-evident store; supports post-incident review | AU-9, AU-10, IR-4 | 2026-06 |
| 26 | MCP runtime dispatch | Code + tests | `enterprise/mcp_dispatch.py`, `tests/test_enterprise/test_mcp_dispatch.py` | The 20 MCP schemas have executable, schema-validated handlers; actuating calls are lease-gated, audited, and routed through the governed channel router | AC-3, AU-2, AU-12, SI-10 | 2026-06 |
| 27 | Governance profile split | Design + tests | `docs/GOVERNANCE_PROFILES.md`, `enterprise/mcp_dispatch.py`, `tests/test_enterprise/test_mcp_dispatch.py` | Normal, enterprise, and government postures are explicit. Normal SelfConnect remains free-flowing; enterprise defaults to lease/audit controls; government denies software-only identity/session paths until TPM is wired | AC-3, AC-6, IA-2, IA-5, CM-7 | 2026-06 |
| 28 | Immutable-retention wiring | Code + tests; deployment open | `enterprise/audit_config.py`, `enterprise/worm_service.py`, `tests/test_enterprise/test_audit_config.py`, `tests/test_enterprise/test_worm_service.py` | AuditConfig maps runtime settings to a sink. Government posture rejects memory/file replicas. S3/R2 paths require live provider retention configuration; actual deployment evidence remains open. Candidate mappings only. | AU-9, AU-12, AU-5 | 2026-07 |
| 29 | TPM platform attestation | Code + tests | `enterprise/tpm_attestation.py`, `tests/test_enterprise/test_tpm_attestation.py` | IA-5 hardware identity foundation: NCryptCreateClaim platform PCR evidence is attempted with nonce freshness; downgrade guards reject empty/small blobs and tpm_probe() provides NA-safe runtime detection without fake PASS | IA-5, IA-3, SC-28 | 2026-06 |
| 30 | MSI installer (WiX v4) | Deployment artifact | `installer/selfconnect-enterprise.wxs`, `installer/build_installer.py`, `installer/INSTALL.md` | Deployment hardening: Windows service registered with auto-start, PATH entry, and ProgramData directory; reproducible signed build via WiX toolset | CM-7, CM-9, SI-7 | 2026-06 |
| 31 | Live AWS S3 Object Lock WORM proof | Live cloud evidence | `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md`, `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.json`, `enterprise/provenance.py:S3ObjectLockSink` | A redacted Merkle-seal event and its stable seal-index were pushed to an Object Lock bucket in `COMPLIANCE` mode; a fresh sink instance rejected a conflicting root from remote seal-index state | AU-9, AU-10, AU-12, AU-5, CA-2 | 2026-06-21 |
| 32 | Live TPM platform attestation probe | Live host evidence | `docs/ato/TPM_LIVE_PROBE_2026-06-21.md`, `docs/ato/TPM_LIVE_PROBE_2026-06-21.json`, `enterprise/tpm_attestation.py` | SDK-correct NCryptCreateClaim ABI and all-PCR platform claim parameters are exercised live; host returns a clean NA (`0x80090026`) rather than malformed-call or fake PASS | IA-5, IA-3, SC-28, CA-2 | 2026-06-21 |
| 33 | MSI build proof | Local release evidence | `docs/ato/MSI_BUILD_PROOF_2026-06-21.md`, `installer/selfconnect-enterprise.wxs` | WiX v4 build produces `selfconnect-enterprise-1.2.3.msi` with recorded SHA-256 and size; installer source schema now compiles under WiX v4 | CM-7, CM-9, SI-7 | 2026-06-21 |
| 34 | Gemini real-agent auth blocker | Provider boundary evidence | `docs/ato/GEMINI_REAL_AGENT_AUTH_BLOCKER_2026-06-21.md` | Gemini CLI cannot join real-agent ladders without interactive login, `GEMINI_API_KEY`, or ADC; documents the non-SelfConnect provider-auth blocker | CA-2, SI-4 | 2026-06-21 |
| 35 | MSI release artifact workflow proof | GitHub Actions evidence | `.github/workflows/release-msi.yml`, `docs/ato/MSI_RELEASE_AUTOMATION_2026-06-21.md` | Manual GitHub Actions run `27897466199` built and uploaded `selfconnect-enterprise-1.2.3.msi` with SHA-256 `9A1CD2F56B6A4CE3AEFC6CC8CF4C5FE09B07F406F6D0E3ED8E62D9591749CF4D`; code signing remains false until certificate secrets are configured | CM-7, CM-9, SI-7 | 2026-06-21 |

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

## Evidence Gaps and Accepted Risks

| Gap | Description | Compensating Control | Acceptance Date |
|-----|------------|----------------------|-----------------|
| Gap 3 | DPAPI root key offline extraction without TPM (Mimikatz at SYSTEM) | CRITICAL log at startup; TPM migration roadmap | 2026-06 |
| WR-005 (prod) | UIA TextChanged eavesdropping on production terminal windows | UIAccess process isolation (OS configuration, outside codebase scope) | 2026-06 |
| Level 2 payload binding | ed25519 birth tag does not bind to specific payload content | SC_STRICT_ENFORCE=1 prevents degradation to Level 2 in high-assurance deployments | 2026-06 |

---

## Evidence Collection Procedure

For each CI run, the following artifacts must be collected and retained:

1. Full pytest output from `tests/test_enterprise/test_dependency_integrity.py` — all 6 AXIOS/MCP tests must show `PASSED`.
2. Exit code 0 from `python experiments/win32_probe/chained_channel.py` — proves the 4-leg chain functions end-to-end.
3. Startup log output confirming `IdentityGate: TPM detected` (or documenting the accepted CRITICAL log if no TPM).
4. Hash of `enterprise/identity_gate.py`, `enterprise/identity.py`, `experiments/win32_probe/target_guard.py`, and `experiments/win32_probe/chained_channel.py` — to detect post-deployment modification.
5. For AU-9 evidence, retain the live S3 Object Lock receipt and `head-object` output showing `ObjectLockMode=COMPLIANCE` for both the event record and the stable seal-index object.

Evidence retention: minimum 3 years per NIST SP 800-53 AU-11 guidance.
