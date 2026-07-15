# SelfConnect Enterprise — Deployment Guide

**Version:** 1.2.3  
**Date:** 2026-06-18  
**Platform:** Windows 10 22H2+ / Windows 11, x64  
**Privilege Required:** Standard user (no Administrator required for runtime; Administrator required for service install)

---

## Prerequisites

### Hardware

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| CPU | x64, any | x64 with TPM 2.0 |
| TPM | Not required by the Enterprise prototype | TPM 2.0 where selected by the deployment; a live probe does not establish IA-5 compliance |
| RAM | 512 MB available | 1 GB+ |
| Disk | 50 MB for identity blobs + logs | 500 MB for audit ledger |

> **TPM Note:** Systems without TPM 2.0 are supported but receive a CRITICAL log at startup documenting the DPAPI offline extraction risk (Gap 3). Set `DPAPI_RISK_ACKNOWLEDGED=1` only after documenting acceptance of this risk in your system security plan.

### Software

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| Windows | 10 22H2 (build 19045) | Windows 11 recommended |
| Python | 3.11.0 | 3.12.x recommended |
| pip | 23.0+ | |
| Windows Terminal | 1.18+ | For `CASCADIA_HOSTING_WINDOW_CLASS` injection targets |
| Visual C++ Redistributable | 2019+ | Required by `cryptography` wheel |

### Python Package Dependencies

Install exact versions from `requirements.txt`:

```powershell
pip install --require-hashes -r requirements.txt
```

Core runtime dependencies:
- `cryptography` — ed25519 and ECDSA-P256 operations
- `pywin32` — Win32 API bindings (Named Pipe, window management, DACL)
- `pythoncom` — COM/UIA event loop
- `comtypes` — UIA text pattern access

---

## Installation

### Step 1 — Clone and verify the repository

```powershell
git clone https://github.com/your-org/selfconnect-enterprise.git
cd selfconnect-enterprise

# Verify the commit hash against the release manifest before proceeding
git log --oneline -5
```

### Step 2 — Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3 — Install dependencies (hash-pinned)

```powershell
pip install --require-hashes -r requirements.txt
```

If `requirements.txt` does not yet include hashes, generate them:

```powershell
pip install pip-tools
pip-compile --generate-hashes requirements.in -o requirements.txt
```

### Step 4 — Run supply chain integrity tests

**This step is mandatory before any deployment.**

```powershell
python -m pytest tests/test_enterprise/test_dependency_integrity.py -v
```

All 6 AXIOS/MCP tests must show `PASSED`. A failure is a real security finding that must be remediated before proceeding.

### Step 5 — Initialize agent identity

On first boot for each agent, generate and store the ed25519 key pair:

```python
from enterprise.identity import AgentIdentity

# Run once per agent per machine
identity = AgentIdentity.init("my-agent-name")
print(f"Agent ID: {identity.agent_id}")  # SC-A7F3B2E1 (example)
```

The key pair is stored at `%APPDATA%\SelfConnect\<agent_name>\identity.dpapi` (encrypted) and `identity.pub` (public key, plaintext).

On subsequent boots, load the existing identity:

```python
identity = AgentIdentity.load("my-agent-name")
```

### Step 6 — Set operating mode

Set the environment variable before starting the agent process:

```powershell
# Production (recommended)
$env:SC_IDENTITY_MODE = "enforce"
$env:SC_STRICT_ENFORCE = "1"

# High-assurance production (fails closed on Ultra Server unreachable)
$env:SC_IDENTITY_MODE = "enforce"
$env:SC_STRICT_ENFORCE = "1"

# Validation / pre-production (logs but does not block)
$env:SC_IDENTITY_MODE = "audit"

# Explicit bypass (requires both vars; not for production)
$env:SC_IDENTITY_MODE = "bypass"
$env:SC_IDENTITY_BYPASS_CONFIRMED = "1"
```

### Step 7 — Verify the end-to-end chain

Run the chain proof (requires a live Windows session with a console window):

```powershell
python experiments/win32_probe/chained_channel.py
```

Expected output (exit code 0):

```
[READ] TextChanged delta carried the token; delta='SC_CHAIN_...'
[TRANSPORT] received server challenge nonce (32 bytes)
[IDENTITY] signed SHA-256(delta+nonce) with Platform-KSP key; sig_len=64
[TRANSPORT] OS-verified caller=DOMAIN\user SID=S-1-5-21-...
[IDENTITY ] Platform-KSP signature valid=True
CHAIN COMPLETE — UIA read + Platform-KSP key proof + OS-verified DACL pipe verified.
```

If exit code is 1, diagnose using the `FAIL:` line in the output before proceeding.

---

## Configuration Reference

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SC_IDENTITY_MODE` | string | `audit` | Gate mode: `bypass`, `audit`, or `enforce`. Unknown values raise `IdentityGateError`. |
| `SC_IDENTITY_BYPASS_CONFIRMED` | string | `""` | Must be `"1"` when `SC_IDENTITY_MODE=bypass`. Otherwise gate raises `IdentityGateError`. |
| `SC_STRICT_ENFORCE` | string | `"0"` | Set to `"1"` to fail closed on Ultra Server network errors (Gap 4 fix). Recommended for production. |
| `SC_IDENTITY_BRIDGE_TIMEOUT_MS` | integer | `500` | Timeout in milliseconds for Ultra Server BPC verification bridge. |
| `DPAPI_RISK_ACKNOWLEDGED` | string | `"0"` | Set to `"1"` to suppress CRITICAL log when no TPM is detected. Must be documented in the system security plan. |

### Identity Storage

| Path | Content | Protected |
|------|---------|-----------|
| `%APPDATA%\SelfConnect\<agent_name>\identity.dpapi` | DPAPI-encrypted ed25519 private key | Yes — user+machine SID bound |
| `%APPDATA%\SelfConnect\<agent_name>\identity.pub` | Raw 32-byte ed25519 public key (hex) | No — public |

### Registry Keys

| Key | Value | Purpose |
|-----|-------|---------|
| `HKCU\Software\SelfConnect\EmergencyBypass` | `REG_BINARY` DPAPI blob | Emergency bypass token (1-hour TTL). Written by `write_bypass_registry_token()`, verified by `_verify_bypass_registry_token()`. |

### Named Mutex

| Mutex Name | Scope | Purpose |
|------------|-------|---------|
| `Global\SelfConnect_IdentityBypass_<UserSID>` | All terminals of the current Windows user | Emergency bypass signal. Requires DPAPI token in Registry to take effect (Gap 1 fix). Auto-releases on process exit. |

---

## Windows Service Installation

To run SelfConnect Enterprise as a Windows service (optional, for server-side agents):

### Install NSSM (Non-Sucking Service Manager)

```powershell
# Download NSSM and place at D:\tools\nssm\nssm.exe (or your preferred path)
# Run as Administrator:

$nssm = "D:\tools\nssm\nssm.exe"
$serviceName = "SelfConnectAgent"
$pythonExe = "C:\path\to\.venv\Scripts\python.exe"
$script = "C:\path\to\selfconnect-enterprise\your_agent_entry.py"

& $nssm install $serviceName $pythonExe $script
& $nssm set $serviceName AppDirectory "C:\path\to\selfconnect-enterprise"
& $nssm set $serviceName AppEnvironmentExtra "SC_IDENTITY_MODE=enforce" "SC_STRICT_ENFORCE=1"
& $nssm set $serviceName Start SERVICE_AUTO_START
& $nssm set $serviceName ObjectName ".\YourServiceUser" "YourPassword"
```

> **Important:** The service must run as the same Windows user account whose DPAPI key protects the `identity.dpapi` blob. Running as SYSTEM will cause `CryptUnprotectData` to fail.

### Start the service

```powershell
& $nssm start SelfConnectAgent
```

### Verify service health

```powershell
& $nssm status SelfConnectAgent
# Expected: SERVICE_RUNNING
```

### Uninstall the service

```powershell
# Run as Administrator:
& $nssm stop SelfConnectAgent
& $nssm remove SelfConnectAgent confirm
```

---

## Hardening Checklist

Before declaring the deployment production-ready, verify each item:

- [ ] **1. SC_IDENTITY_MODE=enforce** — Confirmed set in the service/process environment. Never use `audit` or `bypass` in production without documented exception.
- [ ] **2. SC_STRICT_ENFORCE=1** — Confirmed set. Prevents forced degradation via Ultra Server blocking.
- [ ] **3. Hardware identity decision recorded** — If TPM-backed identity is required, verify the exact key provider, key, attestation/binding protocol, and live deployment evidence. TPM presence alone is insufficient.
- [ ] **4. Supply chain tests pass** — `pytest tests/test_enterprise/test_dependency_integrity.py` all 6 tests PASSED in this deployment's CI run.
- [ ] **5. Identity files ACL-restricted** — `%APPDATA%\SelfConnect\` directory is readable only by the owning user account. Verify: `Get-Acl "%APPDATA%\SelfConnect"`.
- [ ] **6. Audit log handler configured** — Python `logging` for the `enterprise` logger namespace is directed to a tamper-evident store (e.g., Windows Event Log, SIEM, append-only file). Never rely on stdout alone in production.
- [ ] **7. DPAPI_RISK_ACKNOWLEDGED not set to 1 without documentation** — If set, the system security plan must document the accepted risk and compensating controls (EDR, Credential Guard, LSASS protection).
- [ ] **8. Ultra Server reachable** — Verify `localhost:7777` is accessible before starting the agent. `Test-NetConnection -ComputerName 127.0.0.1 -Port 7777`.
- [ ] **9. Windows Terminal version verified** — `WindowsTerminal.exe` version 1.18+ present if terminal injection is required. Older versions may not support the `CASCADIA_HOSTING_WINDOW_CLASS` class name reliably.
- [ ] **10. chained_channel.py exit-0 confirmed** — Run the chain proof once per deployment environment to confirm the full 4-leg chain functions correctly.
- [ ] **11. No bypass env vars in production config** — Confirm `SC_IDENTITY_BYPASS_CONFIRMED` is NOT set in the production environment. Scan with: `[System.Environment]::GetEnvironmentVariables()`.
- [ ] **12. Log retention policy configured** — Set and test the organization-defined period required by the applicable records schedule, legal hold, contract, and authorization boundary. AU-11 does not prescribe a universal three-year period.

---

## Rollback Procedure

If a deployment must be rolled back:

### Step 1 — Stop the agent process or service

```powershell
& $nssm stop SelfConnectAgent
# or kill the process:
Stop-Process -Name "python" -Force  # only if safe
```

### Step 2 — Restore the previous version

```powershell
cd selfconnect-enterprise
git checkout v1.2.2  # or the last known-good tag
pip install --require-hashes -r requirements.txt
```

### Step 3 — Verify identity files are intact

```powershell
# Preserve identity.dpapi during rollback. Reinitializing creates a different
# key pair and therefore a different agent_id. DPAPI protection is normally
# tied to the current Windows credentials/computer but has documented recovery
# and roaming exceptions; it is not hardware binding.
Test-Path "$env:APPDATA\SelfConnect\<agent_name>\identity.dpapi"
# Must return: True
```

### Step 4 — Re-run supply chain integrity tests on the rolled-back version

```powershell
python -m pytest tests/test_enterprise/test_dependency_integrity.py -v
```

### Step 5 — Restart the service

```powershell
& $nssm start SelfConnectAgent
& $nssm status SelfConnectAgent
```

### Step 6 — Verify chain proof

```powershell
python experiments/win32_probe/chained_channel.py
# Must exit 0
```

### Emergency rollback (all crypto down)

If the identity gate is blocking all operations in enforce mode and the issue cannot be resolved quickly:

```powershell
# Step 1: Write the DPAPI bypass token (operator must run this)
python -c "from enterprise.identity_gate import write_bypass_registry_token; print(write_bypass_registry_token())"

# Step 2: Activate the emergency bypass mutex
python -c "from enterprise.identity_gate import emergency_bypass; emergency_bypass(); input('Press Enter when crisis resolved...')"
# This requests the documented emergency audit downgrade for call paths that
# support it. The governed strict wrapper still requires authoritative Ultra
# verification; do not use this interlock as a substitute for authorization.

# Step 3: Resolve the root cause, then release the bypass:
python -c "from enterprise.identity_gate import release_bypass; release_bypass()"
```

> **Note:** Emergency bypass automatically expires when the process holding the
> mutex exits. The Registry token expires after one hour. Both must be present
> simultaneously. Because a same-user process may be able to create both, this
> is an operational interlock, not independent operator authentication.

---

## Known Issues

| Issue | Affected Versions | Workaround |
|-------|-------------------|------------|
| TPM not detected on VMs | All | Record the actual key-storage boundary and obtain deployment-owner review; TPM presence alone would not prove AgentIdentity hardware binding |
| Ultra Server on port 7777 blocked by corporate firewall | All | Restore the local Ultra dependency and keep the governed wrapper fail-closed; disabling strict enforcement is outside the high-assurance profile |
| `chained_channel.py` fails on RDP session without audio | All | This is a UIA accessibility limitation in headless RDP sessions. Use a local console session for chain proof. |
| `identity.dpapi` unavailable after host/profile migration | Deployment-dependent | Preserve and test the supported Windows recovery/migration path, or initialize a new identity and explicitly re-register its new public key/agent ID |
