# SelfConnect Enterprise — STRIDE Threat Model

**Version:** 1.2.3  
**Date:** 2026-06-18  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**Assessment Team:** WRAITH Red-Team + FORGE Architecture Review  
**Scope:** SelfConnect Enterprise v1.2.3, Windows 10/11 x64, same-user-session deployment

---

## Trust Boundary Map

```
[Agent Process A] ──── IdentityGate ──── [Agent Process B]
       │                   │                    │
       │              [Ultra Server]             │
       │               localhost:7777            │
       │                                        │
       └───── Win32 Named Pipe (DACL) ──────────┘
       │
[Windows Kernel / DPAPI / Named Mutex / Registry]
       │
[TPM 2.0] (optional hardware boundary)
```

Trust boundaries:
- **Process boundary** — two processes running as the same Windows user
- **DPAPI boundary** — encrypted blobs are user+machine bound
- **Named Pipe DACL boundary** — OS-enforced connection restriction
- **TPM boundary** — hardware attestation (optional, recommended)

---

## STRIDE Threat Analysis

### S — Spoofing

---

#### THREAT-S-001: Identity Spoofing via Window Class Registration
**Finding Reference:** WRAITH-001 (inline: `target_guard.py`)  
**Actor:** Malicious process running as the same Windows user  
**Vector:** `RegisterClassExW` with a fake `CASCADIA_HOSTING_WINDOW_CLASS` name, then creates a window with that class to receive injected text meant for a legitimate terminal  
**Attack Detail:**  
Any process in the same Windows session can call `RegisterClassExW` with any class name string, including `CASCADIA_HOSTING_WINDOW_CLASS`. `GetClassNameW` returns the class name as a string — it does not verify the owning executable. An attacker who registers a fake terminal class and creates a visible window could receive injection payloads intended for the legitimate terminal.

**Mitigated By:**  
`target_guard.py:TERMINAL_CLASS_TO_EXE` and `_trusted_terminal_image()` — when
`require_terminal=True`, `QueryFullProcessImageNameW` obtains the OS-reported
owning image path. Supported classes are accepted only for named executables in
protected Windows, WindowsApps, or PowerShell installation roots. A matching
basename in a user-writable directory is refused:
```python
if not _trusted_terminal_image(cls, exe_path):
    r.append("...possible class-name spoof (WRAITH-001)")
```

**Residual Risk:** LOW within the tested local-user threat model. The check does
not validate an Authenticode signer and does not protect a compromised trusted
binary, administrator-controlled protected directory, or kernel.

---

#### THREAT-S-002: Agent Identity Spoofing (WRAITH-003)
**Finding Reference:** WRAITH-003 (inline: `identity_gate.py:get_current_mode()`)  
**Actor:** Local process or malware in the same user session  
**Vector:** Rely on the default gate mode being `bypass`, allowing injection without identity verification  
**Attack Detail:**  
Prior to the WRAITH-003 fix, if `SC_IDENTITY_MODE` was not set, the gate defaulted to `bypass` mode, meaning any caller could inject without any identity verification. An attacker who could launch a process in the same session would have unconstrained injection capability.

**Mitigated By:**  
`identity_gate.py:get_current_mode()` — the default is now `MODE_AUDIT`, not `MODE_BYPASS`. Bypass requires both `SC_IDENTITY_MODE=bypass` AND `SC_IDENTITY_BYPASS_CONFIRMED=1`. An unrecognised value raises `IdentityGateError`. Production deployments set `SC_IDENTITY_MODE=enforce`.
```python
raw = os.environ.get("SC_IDENTITY_MODE", MODE_AUDIT).strip().lower()
```

**Residual Risk:** LOW — Default-safe configuration ensures unconfigured systems are never silently bypassed.

---

#### THREAT-S-003: Emergency Bypass via Unprivileged Mutex (Gap 1 Fix)
**Finding Reference:** Gap 1 (inline: `identity_gate.py` header)  
**Actor:** Malware running as the current Windows user (no elevation needed)  
**Vector:** Create `Global\SelfConnect_IdentityBypass_<SID>` Named Mutex to force enforce mode to downgrade to audit  
**Attack Detail:**  
Named Mutex creation requires no special privilege. Any user-mode process can call `CreateMutexW` with any name. Prior to the Gap 1 fix, the presence of the mutex alone was sufficient to trigger the emergency bypass downgrade.

**Mitigated By:**  
Dual-factor emergency bypass: `_emergency_mutex_active()` requires BOTH the mutex AND a valid DPAPI-signed Registry token. The token is created by `write_bypass_registry_token()` via `CryptProtectData` — only a process with access to the user's DPAPI key (i.e., a legitimate process running as that user, not an unprivileged malware process that has only created a mutex) can write a valid token. Additionally, the token has a 1-hour TTL enforced by comparing against a DPAPI-decrypted timestamp.

**Residual Risk:** LOW — An attacker running as the same user with full session access could potentially write a valid DPAPI token, but at that point the attacker already has full user-session control; the bypass downgrade provides no additional attack surface.

---

### T — Tampering

---

#### THREAT-T-001: Injection Payload Tampering
**Finding Reference:** BPC design (`enterprise/bpc_crypto.py`)  
**Actor:** Man-in-the-middle within the same process or via shared memory  
**Vector:** Modify the `text` parameter between the `gated_send_string()` call and the Win32 `PostMessage` call  
**Attack Detail:**  
If an attacker can inject into the calling process's address space (e.g., via DLL injection), they could potentially modify the `text` argument after identity verification but before the Win32 call.

**Mitigated By:**  
BPC `body_hash` binds the ECDSA-P256 signature to the specific `text` content via `SHA-256(text)`. The `verify_payload_with_jwk` check confirms the body hash matches before the injection is considered verified. Any modification of `text` after signing produces a hash mismatch that fails Level 0 and Level 1 verification. At Level 2, the birth tag is signed over the session identity, not the specific payload — this is a known limitation of Level 2 and is documented in the degradation cascade design.

**Residual Risk:** MEDIUM (Level 2 only) — Level 2 (`ed25519` birth tag) does not bind to specific payload content. If an attacker forces degradation to Level 2, they may be able to substitute payload content. Mitigated by `SC_STRICT_ENFORCE=1` which fails closed rather than degrading.

---

#### THREAT-T-002: Supply Chain Tampering (AXIOS-1/2/3/4)
**Finding Reference:** `tests/test_enterprise/test_dependency_integrity.py`  
**Actor:** Compromised PyPI package maintainer or typosquatter  
**Vector:** Publish backdoored version of a dependency (axios pattern: inject `plain-crypto-js` equivalent) or use a postinstall hook to drop malware  
**Attack Detail:**  
Modeled on the March 2026 axios/Sapphire Sleet attack. A compromised dependency could inject a new subdependency with a postinstall RAT dropper, use a mutable git tag instead of a pinned commit hash, or shadow a local module name with a PyPI package.

**Mitigated By:**  
`test_dependency_integrity.py` runs four AXIOS checks and two MCP checks at every CI invocation. AXIOS-1 detects unexpected subdependencies. AXIOS-2 detects postinstall hooks. AXIOS-3 detects mutable tag pinning. AXIOS-4 detects PyPI module name shadowing. These tests must pass before deployment.

**Residual Risk:** LOW — Tests cover known attack patterns. Novel supply chain attacks not matching these patterns may evade detection. Mitigation: pin all dependencies to exact versions with hashes in `requirements.txt`.

---

### R — Repudiation

---

#### THREAT-R-001: Agent Denying Performed Action
**Finding Reference:** `enterprise/identity.py:AgentIdentity.sign()`  
**Actor:** Agent operator claiming an injection was performed by a different agent  
**Vector:** Claim the `agent_id` was shared, or that the DPAPI blob was stolen  
**Attack Detail:**  
Without non-repudiation, an agent could deny performing an injection by claiming another process used the same identity.

**Mitigated By:**  
`agent_id` is derived from `SHA-256(public_key_bytes)[:8]` — it is unique to the specific ed25519 key pair. The private key is DPAPI-encrypted and bound to the user SID + machine SID. A valid signature on an action record can only have been produced by the process holding that DPAPI-encrypted private key on that specific machine as that specific user. The `AgentIdentity.sign()` output is stored in the audit ledger with timestamp.

**Residual Risk:** LOW — If an attacker gains SYSTEM-level access, they could potentially extract DPAPI root keys via Mimikatz (documented Gap 3). TPM backing eliminates this residual risk.

---

#### THREAT-R-002: Operator Denying Emergency Bypass Activation
**Finding Reference:** `enterprise/identity_gate.py:emergency_bypass()`  
**Actor:** Operator claiming they did not activate emergency bypass  
**Vector:** Emergency bypass activated without logging, or logs tampered after the fact  
**Attack Detail:**  
Emergency bypass downgrades security posture. Without a clear record, an operator could deny activating it.

**Mitigated By:**  
`emergency_bypass()` emits a `CRITICAL` log with PID and timestamp. The DPAPI Registry token records the activation timestamp (encrypted). `_check_tpm_available()` emits a `CRITICAL` log if TPM is absent. The 1-hour token TTL creates a time-bounded audit window.

**Residual Risk:** LOW — Requires tamper-evident log storage to be configured by the operator (out of scope for this codebase, required by deployment policy).

---

### I — Information Disclosure

---

#### THREAT-I-001: Private Key Exfiltration
**Finding Reference:** `enterprise/identity.py`, Gap 3  
**Actor:** Malware with SYSTEM-level access (e.g., Mimikatz)  
**Vector:** Extract the DPAPI master key from LSASS memory (offline) and decrypt `identity.dpapi`  
**Attack Detail:**  
DPAPI root keys can be extracted from LSASS by a SYSTEM-privileged attacker using tools like Mimikatz. If the DPAPI master key is extracted offline, all `identity.dpapi` blobs for that user on that machine can be decrypted, and all agent keys can be derived.

**Mitigated By:**  
`_check_tpm_available()` emits a CRITICAL log at startup when no TPM is detected, requiring operator acknowledgement (`DPAPI_RISK_ACKNOWLEDGED=1`). When TPM 2.0 is present, DPAPI root keys are backed by the TPM and cannot be extracted offline. The Gap 3 roadmap item calls for migrating to TPM-backed key storage (`tpm_identity.py` via Platform KSP).

**Residual Risk:** MEDIUM (no TPM) / LOW (with TPM) — Systems without TPM must treat this as an accepted risk with compensating controls (endpoint EDR, LSASS protection, Windows Credential Guard).

---

#### THREAT-I-002: UIA TextChanged Eavesdropping (WR-005)
**Finding Reference:** WR-005 (inline: `chained_channel.py`)  
**Actor:** Same-session process with UIAccess privileges  
**Vector:** Enumerate all ConPTY terminal windows via `EnumWindows` and register a `TextChanged` event handler on the target terminal's UIA element to read terminal output without injection  
**Attack Detail:**  
UI Automation is accessible to any process running in the same Windows session with UIAccess. An attacker could enumerate terminal windows and subscribe to `TextChanged` events to eavesdrop on agent communications.

**Mitigated By:**  
Throwaway consoles used in testing and probing are created with `SW_HIDE` (`STARTF_USESHOWWINDOW + SW_HIDE`) so that `EnumWindows` (which filters by visibility) will not enumerate them for other processes. For production windows, this threat is inherent to the Windows UIA model and requires UIAccess restrictions at the OS configuration level.

**Residual Risk:** MEDIUM — Production terminal windows are visible. Full mitigation requires UIAccess process isolation at the OS level, which is outside the scope of this codebase.

---

### D — Denial of Service

---

#### THREAT-D-001: Ultra Server Blocking to Force Degradation (Gap 4 Fix)
**Finding Reference:** Gap 4 (inline: `identity_gate.py:_STRICT_ENFORCE`)  
**Actor:** Local attacker who can block loopback connections (e.g., via firewall rule or process killing)  
**Vector:** Block `localhost:7777` to force the `DegradationCascade` to fall from Level 0 (full BPC+TSK) to Level 2 (ed25519 only), bypassing the more stringent verification layers  
**Attack Detail:**  
If Level 0 fails with an `OSError` (network failure), the cascade degrades to Level 2. An attacker who can block the Ultra Server connection forces permanent Level 2 operation, reducing verification strength without triggering an outright block.

**Mitigated By:**  
`SC_STRICT_ENFORCE=1` causes `OSError` exceptions at Level 0 to fail CLOSED instead of degrading. The cascade returns `(False, "strict_enforce: Ultra Server unreachable: ...", 0)` and `gated_send_string()` raises `InjectionDeniedError`.
```python
if _STRICT_ENFORCE and self.mode == MODE_ENFORCE:
    return False, f"strict_enforce: Ultra Server unreachable: {exc}", 0
```

**Residual Risk:** LOW (with `SC_STRICT_ENFORCE=1`) / MEDIUM (without) — Default deployment should enable `SC_STRICT_ENFORCE=1` in high-assurance environments.

---

#### THREAT-D-002: Pipe Name Prediction Race (WR-003)
**Finding Reference:** WR-003 (inline: `chained_channel.py:_unique_pipe_name()`)  
**Actor:** Same-user process racing to create a named pipe server  
**Vector:** Predict the named pipe name and call `CreateNamedPipe` before the legitimate server, causing `ConnectNamedPipe` to succeed for the attacker  
**Attack Detail:**  
If the pipe name is predictable (e.g., a fixed string), an attacker can race to create the server end first and intercept communications.

**Mitigated By:**  
`_unique_pipe_name()` appends `secrets.token_hex(16)` (128-bit random) to the base name. `role_b()` uses `FILE_FLAG_FIRST_PIPE_INSTANCE` which causes the OS to return `ERROR_ACCESS_DENIED` to any second `CreateNamedPipe` call for the same name, even if the attacker guesses the random suffix.

**Residual Risk:** LOW — 128-bit entropy makes prediction computationally infeasible. `FILE_FLAG_FIRST_PIPE_INSTANCE` provides a second layer.

---

### E — Elevation of Privilege

---

#### THREAT-E-001: Injection into Non-Terminal Windows (Notepad Overwrite Lesson)
**Finding Reference:** `target_guard.py` header comment ("Lesson from the 2026-06-16 Notepad overwrite")  
**Actor:** Misconfigured agent or attacker who has obtained a valid HWND for a non-terminal window  
**Vector:** Pass a Notepad or other application's HWND to `gated_send_string()`, causing arbitrary text injection into a sensitive document  
**Attack Detail:**  
WM_CHAR injection is semantically valid for ConPTY terminals but destructive in other window types. The 2026-06-16 Notepad overwrite incident demonstrated that an allow-flag alone is insufficient — the live window must be verified before injection.

**Mitigated By:**  
`verify_target()` in `target_guard.py` checks `cls in allow_classes` (the set of ConPTY terminal classes). Any non-terminal class produces `reasons.append(f"class {cls!r} is not a ConPTY terminal")` and `ok=False`. `assert_safe_target()` raises `PermissionError` on failure.

**Residual Risk:** LOW for supported protected-path terminal images. Unmapped
terminal classes fail closed; deployment-specific terminal variants require a
reviewed protected-path policy and live delivery confirmation.

---

#### THREAT-E-002: Self-Signed Key Substitution (WR-001)
**Finding Reference:** WR-001 (inline: `chained_channel.py:role_b()`)  
**Actor:** Attacker intercepting the Named Pipe transport  
**Vector:** Substitute their own TPM public key blob (`pub`) alongside a valid self-signature (`sig`) in the transport payload — since `_verify(pub, digest, sig)` returns True for any self-consistent (pub, sig) pair  
**Attack Detail:**  
Without pre-registration of the expected public key, the server verifies that the signature is consistent with the provided public key — but does not verify that the public key belongs to the expected agent. An attacker could supply their own key pair and produce a valid signature.

**Mitigated By:**  
`role_b()` takes `expected_pub: bytes` from the pre-registration step (before the server thread starts). The server compares `pub != expected_pub` byte-for-byte and sets `result["sig_valid"] = False` and `result["pub_mismatch"] = True` if they differ. The expected public key is established before any client interaction begins.
```python
if pub != expected_pub:
    result["sig_valid"] = False
    result["pub_mismatch"] = True
    return
```

**Residual Risk:** LOW — Pre-registration pins the expected key. This requires that the handshake (key exchange) channel itself be trusted; see `enterprise/handshake.py` for the handshake protocol.

---

## Red-Team Finding Registry

| ID | Category | Finding | Fixed In | Residual Risk |
|----|----------|---------|----------|---------------|
| WRAITH-001 | Spoofing | Class name spoof — any process can register fake terminal class | `target_guard.py:TERMINAL_CLASS_TO_EXE` | LOW |
| WRAITH-003 | Spoofing | Default mode was `bypass`; unconfigured systems allowed unverified injection | `identity_gate.py:get_current_mode()` default = `audit` | LOW |
| Gap 1 | Spoofing | Unprivileged mutex sufficient to trigger emergency bypass downgrade | `identity_gate.py:_emergency_mutex_active()` dual-factor | LOW |
| Gap 3 | Info Disclosure | DPAPI root key offline extraction without TPM | TPM roadmap; CRITICAL log emitted at startup | MEDIUM (no TPM) |
| Gap 4 | DoS | Ultra Server blocking forces cascade degradation | `identity_gate.py:_STRICT_ENFORCE` | LOW |
| WR-001 | Elevation | Self-signed key substitution in Named Pipe transport | `chained_channel.py:role_b()` pre-registered `expected_pub` | LOW |
| WR-003 | DoS | Named pipe name prediction race | `_unique_pipe_name()` + `FILE_FLAG_FIRST_PIPE_INSTANCE` | LOW |
| WR-005 | Info Disclosure | UIA TextChanged eavesdrop on hidden console | `SW_HIDE` on throwaway consoles | MEDIUM (prod) |
| WR-009 | Spoofing/Replay | Replay attack — pre-captured (sig, delta_hash, pub) replayed to server | Challenge-response nonce in `chained_channel.py:role_b()` | LOW |

---

## Residual Risk Summary

| Risk Level | Count | Items |
|------------|-------|-------|
| LOW | 7 | WRAITH-001, WRAITH-003, Gap 1, Gap 4, WR-001, WR-003, WR-009 |
| MEDIUM | 2 | Gap 3 (no TPM), WR-005 (production UIA) |
| HIGH | 0 | — |
| CRITICAL | 0 | — |

**Overall residual risk: MEDIUM** (driven by the TPM gap on systems without hardware TPM).
