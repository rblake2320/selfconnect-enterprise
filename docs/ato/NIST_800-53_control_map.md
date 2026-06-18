# NIST SP 800-53 Rev 5 — Security Control Mapping

**System:** SelfConnect Enterprise v1.2.3  
**Date:** 2026-06-18  
**Framework:** NIST SP 800-53 Rev 5  
**Impact Level:** Moderate  

This document maps each applicable NIST SP 800-53 Rev 5 security control to the specific
implementation in the SelfConnect Enterprise codebase. Evidence files are listed with the
relevant class, function, or constant that implements or satisfies the control.

---

## Control Families

### AC — Access Control

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| AC-3 | Access Enforcement | `gated_send_string()` enforces injection authorization via `DegradationCascade.verify()`. In `enforce` mode, a failed verification raises `InjectionDeniedError` before any Win32 call is made. Deny-by-default: the default mode is `audit` (not `bypass`), ensuring that unconfigured systems never silently allow unverified injection. The `bypass` mode requires BOTH `SC_IDENTITY_MODE=bypass` AND `SC_IDENTITY_BYPASS_CONFIRMED=1` — a single env var is not sufficient. | `enterprise/identity_gate.py:get_current_mode()`, `enterprise/identity_gate.py:gated_send_string()` | Implemented |
| AC-4 | Information Flow Enforcement | `TargetGuard.verify_target()` enforces that injection only flows to ConPTY terminal windows (`CASCADIA_HOSTING_WINDOW_CLASS`, `ConsoleWindowClass`). Non-terminal window classes are refused regardless of identity verification result. Information flow is further restricted by DPAPI scope — DPAPI blobs cannot be decrypted in a different Windows user session, preventing cross-session leakage. | `experiments/win32_probe/target_guard.py:verify_target()`, `enterprise/identity.py:_dpapi_encrypt()` | Implemented |
| AC-6 | Least Privilege | Agent identities use standard user DPAPI scope (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`). The system requires only `PROCESS_QUERY_LIMITED_INFORMATION` (0x1000) to read the owning executable path of a target window — the minimum privilege needed. Named pipe DACL restricts connections to the creating user's SID. `ImpersonateNamedPipeClient` is used to verify the OS-reported caller identity, then `RevertToSelf()` is called immediately after the token query. | `enterprise/identity.py:_dpapi_encrypt()`, `experiments/win32_probe/target_guard.py:_exe()`, `experiments/win32_probe/chained_channel.py:role_b()` | Implemented |
| AC-17 | Remote Access | The system operates localhost-only. The Ultra Server is bound to `127.0.0.1:7777`. No remote access paths exist. If the Ultra Server is unreachable, `SC_STRICT_ENFORCE=1` fails closed rather than degrading to a lower verification level (Gap 4 fix). | `enterprise/identity_gate.py:_STRICT_ENFORCE`, `enterprise/identity_gate.py:DegradationCascade.verify()` | Implemented |

---

### AU — Audit and Accountability

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| AU-2 | Event Logging | Every call to `gated_send_string()` emits a structured log record. Log levels are calibrated to severity: `DEBUG` for authorized injections, `WARNING` for degraded-level passes, `ERROR` for blocked injections, `CRITICAL` for emergency bypass activation. TPM absence is logged at `CRITICAL` on startup. Emergency bypass activation is logged at `CRITICAL` with PID. Every degradation level transition is logged with level number and reason string. | `enterprise/identity_gate.py:gated_send_string()`, `enterprise/identity_gate.py:DegradationCascade.verify()`, `enterprise/identity_gate.py:_check_tpm_available()` | Implemented |
| AU-9 | Protection of Audit Information | `enterprise/ledger.py` maintains tamper-evident audit records. Logs are emitted via the Python `logging` framework at named logger `__name__` — operators must configure the handler to a tamper-evident store (e.g., append-only file, SIEM). The bypass token TTL (3600s) and DPAPI binding prevent retroactive manipulation of bypass evidence. | `enterprise/ledger.py`, `enterprise/identity_gate.py:_BYPASS_TOKEN_TTL_SEC` | Implemented |
| AU-10 | Non-Repudiation | Every injection is associated with a cryptographic identity: the `agent_id` is `"SC-" + SHA-256(public_key)[:8]`, derived from the DPAPI-bound ed25519 key pair. Because the private key is machine-and-user bound, a signed action cannot be disavowed — only the holder of the specific DPAPI key can produce a valid signature for that `agent_id`. Birth tags (`enterprise/birth_tag_v2.py`) provide a per-session non-repudiation anchor. | `enterprise/identity.py:AgentIdentity.sign()`, `enterprise/identity.py:AgentIdentity.verify()`, `enterprise/birth_tag_v2.py` | Implemented |
| AU-12 | Audit Record Generation | `enterprise/observer.py` and `enterprise/provenance.py` generate provenance records for each action. The `DegradationCascade` returns `(ok, reason, level)` on every call, and `gated_send_string()` records all three fields in the audit trail. Supply chain audit records are generated by `test_dependency_integrity.py` at CI time. | `enterprise/observer.py`, `enterprise/provenance.py`, `enterprise/identity_gate.py:gated_send_string()` | Implemented |

---

### IA — Identification and Authentication

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| IA-2 | Identification and Authentication (Organizational Users) | `AgentIdentity.init()` generates a unique ed25519 key pair on first boot. The `agent_id` (`"SC-" + SHA-256(public_key)[:8].upper()`) is a stable, collision-resistant identifier derived solely from the public key — it cannot be assumed by a different key pair. Agent names are validated against a slug regex (`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`) to prevent path traversal in identity storage. | `enterprise/identity.py:AgentIdentity.init()`, `enterprise/identity.py:_SAFE_AGENT_NAME_RE` | Implemented |
| IA-3 | Device Identification and Authentication | The Named Pipe transport (`chained_channel.py`) uses `ImpersonateNamedPipeClient` + `GetTokenInformation(TokenUser)` to obtain the OS-verified caller SID before accepting any payload. This is kernel-enforced — the target process cannot forge a different SID. The DACL on the pipe additionally restricts who can connect at the OS level. | `experiments/win32_probe/chained_channel.py:role_b()` | Implemented |
| IA-5 | Authenticator Management | Private keys are stored as DPAPI-encrypted blobs at `%APPDATA%\SelfConnect\<agent_name>\identity.dpapi`. The DPAPI binding is to the current user SID + machine SID — the blob cannot be decrypted on another machine or by another account even if copied. `AgentIdentity.init()` enforces `overwrite=False` by default, preventing accidental key rotation. The bypass token uses a separate DPAPI call with custom entropy (`SC-EmergencyBypass-Entropy-v1`) and a 1-hour TTL. TPM absence is flagged at CRITICAL log level at startup. | `enterprise/identity.py:_dpapi_encrypt()`, `enterprise/identity_gate.py:_BYPASS_TOKEN_ENTROPY`, `enterprise/identity_gate.py:_BYPASS_TOKEN_TTL_SEC`, `enterprise/identity_gate.py:_check_tpm_available()` | Implemented (TPM gap documented) |

---

### SC — System and Communications Protection

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| SC-4 | Information in Shared Resources | The Named Pipe server uses `FILE_FLAG_FIRST_PIPE_INSTANCE` to ensure only the creating process can hold the server end — a race-condition attacker cannot hijack the pipe even if they guess the name (WR-003 fix). The pipe name includes a 128-bit random suffix (`secrets.token_hex(16)`) to prevent name prediction. The throwaway console used in testing is launched with `SW_HIDE` to prevent cross-process UIA enumeration of the window (WR-005 fix). | `experiments/win32_probe/chained_channel.py:_unique_pipe_name()`, `experiments/win32_probe/chained_channel.py:role_b()` | Implemented |
| SC-8 | Transmission Confidentiality and Integrity | BPC (Bearer Protocol Crypto) uses ECDSA-P256 signatures and body hashing to provide integrity guarantees on every injection payload. The `body_hash` function and `verify_payload_with_jwk` in `enterprise/bpc_crypto.py` ensure that the payload received matches what was signed. The WR-009 challenge-response (server-generated nonce folded into `SHA-256(delta + nonce)`) binds each signed payload to a unique server interaction, preventing replay. | `enterprise/bpc_crypto.py:body_hash()`, `enterprise/bpc_crypto.py:verify_payload_with_jwk()`, `experiments/win32_probe/chained_channel.py:role_b()` | Implemented |
| SC-13 | Cryptographic Protection | ed25519 (RFC 8032) for agent identity signatures; ECDSA-P256 for BPC payload signing; SHA-256 for body hashing and agent ID fingerprinting; DPAPI (`CryptProtectData`/`CryptUnprotectData`) for private key at-rest protection; TPM Platform KSP (NCrypt `ECDSA_P256`) for hardware-attested signing in `tpm_identity`. The `cryptography` library is used for ed25519 operations — pinned in `requirements.txt` and verified via supply chain integrity tests. | `enterprise/identity.py`, `enterprise/bpc_crypto.py`, `experiments/win32_probe/tpm_identity.py`, `enterprise/_portable_crypto.py` | Implemented |
| SC-28 | Protection of Information at Rest | Agent private keys are never stored in plaintext. `_dpapi_encrypt()` calls `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN` before writing the blob to disk. The public key is stored in plaintext (it is public). The bypass token is also DPAPI-encrypted before writing to the Registry. | `enterprise/identity.py:_dpapi_encrypt()`, `enterprise/identity_gate.py:write_bypass_registry_token()` | Implemented |

---

### SI — System and Information Integrity

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| SI-3 | Malware Protection | Supply chain integrity tests (`test_dependency_integrity.py`) defend against the AXIOS-1 pattern (unexpected subdependency injection), AXIOS-2 (postinstall hook execution), AXIOS-3 (mutable git tag pinning), AXIOS-4 (module name shadowing), MCP-1 (tool description prompt injection), and MCP-2 (typosquatted package names). These tests run at every CI invocation and are required to pass before deployment. | `tests/test_enterprise/test_dependency_integrity.py` | Implemented |
| SI-7 | Software, Firmware, and Information Integrity | `enterprise/version_gate.py` enforces minimum version requirements before allowing operation. BPC payload signing (ECDSA-P256 + body hash) ensures injection payloads cannot be tampered in transit. Birth tags (`enterprise/birth_tag_v2.py`) provide a signed anchor for the target window's identity at session start. The `_peer_public_keys` dict in `DegradationCascade` is populated from completed `HandshakePeer` records — never from attacker-controlled window properties. | `enterprise/version_gate.py`, `enterprise/birth_tag_v2.py`, `enterprise/identity_gate.py:DegradationCascade._level2_enterprise()` | Implemented |

---

### CM — Configuration Management

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| CM-7 | Least Functionality | The system uses Win32 user-mode APIs exclusively — no kernel drivers, no network listeners (beyond localhost Ultra Server), no COM servers, no browser extensions. The TargetGuard enforces that injection is only valid for two terminal window classes (`CASCADIA_HOSTING_WINDOW_CLASS`, `ConsoleWindowClass`, `PseudoConsoleWindow`, `mintty`). Any other window class is refused. Self-injection (target PID == own PID) is explicitly refused. | `experiments/win32_probe/target_guard.py:TERMINAL_CLASSES`, `experiments/win32_probe/target_guard.py:verify_target()` | Implemented |
| CM-9 | Configuration Management Plan | Operating mode is controlled by `SC_IDENTITY_MODE` (bypass / audit / enforce). `SC_STRICT_ENFORCE=1` enables strict network-fail-closed behavior. `SC_IDENTITY_BRIDGE_TIMEOUT_MS` controls bridge timeout (default 500ms). `DPAPI_RISK_ACKNOWLEDGED=1` suppresses TPM warning (must be explicitly set by operator). All configuration is via environment variables read per-call, enabling live reconfiguration without restart. Unknown values for `SC_IDENTITY_MODE` raise `IdentityGateError` instead of silently falling back (fail-safe). | `enterprise/identity_gate.py:get_current_mode()`, `enterprise/identity_gate.py:BRIDGE_TIMEOUT_MS`, `enterprise/identity_gate.py:_STRICT_ENFORCE` | Implemented |

---

### CA — Assessment, Authorization, and Monitoring

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| CA-2 | Control Assessments | Red-team findings are tracked with WRAITH-NNN identifiers. WRAITH-003 (identity bypass via default mode), WR-001 (self-signed key substitution), WR-003 (pipe name race), WR-005 (UIA eavesdrop), WR-009 (replay) are all documented with inline comments referencing the finding ID and the specific code change that mitigated them. | `enterprise/identity_gate.py` (WRAITH-003), `experiments/win32_probe/chained_channel.py` (WR-001, WR-003, WR-005, WR-009) | Implemented |
| CA-7 | Continuous Monitoring | `enterprise/observer.py` implements continuous monitoring of gate decisions. The degradation cascade level is recorded on every injection. TPM availability is checked at startup and re-checked on each bypass token verification. The audit ledger (`enterprise/ledger.py`) provides a persistent record for post-incident review. | `enterprise/observer.py`, `enterprise/ledger.py`, `enterprise/identity_gate.py:_check_tpm_available()` | Implemented |

---

### IR — Incident Response

| Control ID | Control Name | Implementation | Evidence File | Status |
|------------|-------------|----------------|---------------|--------|
| IR-4 | Incident Handling | Emergency bypass (`emergency_bypass()`) provides a controlled incident-response path that degrades enforce mode to audit (not full bypass) while maintaining full logging. The bypass requires dual-factor authorization (Named Mutex + DPAPI Registry token). `release_bypass()` restores enforce mode immediately. The bypass token has a 1-hour TTL to ensure automatic expiry if the operator forgets to call `release_bypass()`. | `enterprise/identity_gate.py:emergency_bypass()`, `enterprise/identity_gate.py:release_bypass()`, `enterprise/identity_gate.py:write_bypass_registry_token()` | Implemented |

---

## Summary Statistics

| Family | Controls Mapped | Status: Implemented | Status: Partial | Status: Not Applicable |
|--------|----------------|---------------------|-----------------|------------------------|
| AC | 4 | 4 | 0 | 0 |
| AU | 4 | 4 | 0 | 0 |
| IA | 3 | 2 | 1 | 0 |
| SC | 4 | 4 | 0 | 0 |
| SI | 2 | 2 | 0 | 0 |
| CM | 2 | 2 | 0 | 0 |
| CA | 2 | 2 | 0 | 0 |
| IR | 1 | 1 | 0 | 0 |
| **Total** | **22** | **21** | **1** | **0** |

**Partial:** IA-5 — TPM-backed key storage is available (`tpm_identity.py`) but not enforced by default. Systems without TPM receive a CRITICAL log warning. Full TPM enforcement is on the roadmap (Gap 3 in `identity_gate.py` header).
