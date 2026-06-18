# SelfConnect Enterprise — Authority to Operate (ATO) Package

**Version:** 1.2.3  
**Date:** 2026-06-18  
**Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY  
**Prepared by:** UltraSecure Developer Team  
**ATO Sponsor:** [Authorizing Official Placeholder]

---

## Executive Summary

SelfConnect Enterprise is an OS-native AI peer mesh communication system for Windows 10/11
(x64). It enables authenticated, audited, policy-controlled inter-process messaging between
AI agent processes running within the same Windows user session, using only kernel-verified
OS primitives — no network stack, no third-party middleware, no kernel drivers.

The system provides three core security guarantees that differentiate it from conventional
message-passing frameworks:

**Kernel-verified identity.** Every message sender is authenticated via a 7-layer cascade:
full BPC+TSK cryptographic verification at Layer 0, degrading under controlled conditions to
ed25519 birth-tag verification (Layer 2) as the worst-case in enforce mode. Agent identities
are ed25519 key pairs stored as DPAPI-encrypted blobs bound to the Windows user SID and
machine SID — they cannot be decrypted on any other machine or by any other account. The
`AgentIdentity` class (`enterprise/identity.py`) implements this binding; the
`DegradationCascade` class (`enterprise/identity_gate.py`) enforces that production enforce
mode never falls below Layer 2. Emergency bypass requires BOTH a Named Mutex AND a valid
DPAPI-signed Registry token with a 1-hour TTL, preventing unprivileged malware from
triggering a downgrade by simply creating a mutex.

**Fail-closed actuation.** The `IdentityGate` (`enterprise/identity_gate.py`) operates in
one of three modes — `bypass`, `audit`, `enforce` — with `audit` as the safe default. In
`enforce` mode, any injection that fails verification raises `InjectionDeniedError` and is
blocked before it reaches the target window. The `SC_STRICT_ENFORCE=1` flag eliminates the
degradation-to-Level-2 path on network failure, preventing an attacker from forcing a
downgrade by blocking the local Ultra Server on port 7777. The `TargetGuard`
(`experiments/win32_probe/target_guard.py`) adds a second fail-closed layer: it verifies the
live window's class, owning process image path (via kernel `QueryFullProcessImageNameW`, not
spoofable), PID, and title substring before any injection is attempted.

**Per-action audit receipts.** Every call to `gated_send_string()` emits structured log
records at DEBUG (pass), WARNING (degraded), ERROR (blocked), or CRITICAL (emergency bypass)
severity. The audit ledger (`enterprise/ledger.py`) maintains tamper-evident records. The
dependency integrity test suite (`tests/test_enterprise/test_dependency_integrity.py`)
verifies supply chain integrity against the AXIOS-1 through MCP-2 attack patterns at every
CI run.

This ATO package covers the Windows 10/11 x64 deployment surface, with and without TPM 2.0.
The known gap when TPM is absent (DPAPI root key offline extraction risk) is documented,
actively monitored via `_check_tpm_available()`, and logged at CRITICAL severity at startup
to ensure operator awareness.

---

## System Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     AUTHORIZATION BOUNDARY                                  │
│                     Windows 10/11 x64 User Session                         │
│                                                                             │
│  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────┐   │
│  │  Agent Process A │   │  Agent Process B │   │  Ultra Server        │   │
│  │  (Sender)        │   │  (Receiver)      │   │  localhost:7777      │   │
│  │                  │   │                  │   │  (BPC/TSK verify)    │   │
│  │  AgentIdentity   │   │  AgentIdentity   │   │                      │   │
│  │  ed25519 DPAPI   │   │  ed25519 DPAPI   │   │                      │   │
│  └────────┬─────────┘   └────────▲─────────┘   └──────────▲───────────┘   │
│           │                      │                         │               │
│           │ gated_send_string()  │                         │               │
│           ▼                      │                         │               │
│  ┌──────────────────────────────────────────┐             │               │
│  │         IdentityGate                     │             │               │
│  │  Mode: bypass | audit | enforce          │             │               │
│  │  ┌─────────────────────────────────┐    │             │               │
│  │  │  DegradationCascade             │    │─────────────┘               │
│  │  │  L0: BPC+TSK (UltraGate)        │    │  BPC verify request         │
│  │  │  L1: BPC-only                   │    │                             │
│  │  │  L2: ed25519 birth tag (min)    │    │                             │
│  │  │  L3+: audit-only pass-through   │    │                             │
│  │  └─────────────────────────────────┘    │                             │
│  │  InjectionDeniedError (enforce fail)     │                             │
│  └─────────────────────────┬────────────────┘                             │
│                            │ WM_CHAR PostMessage                          │
│                            ▼                                               │
│  ┌──────────────────────────────────────────┐                             │
│  │         TargetGuard                      │                             │
│  │  IsWindow / GetClassNameW /              │                             │
│  │  QueryFullProcessImageNameW              │                             │
│  │  (kernel path — not spoofable)           │                             │
│  │  Checks: is_terminal, exe match,         │                             │
│  │          pid match, title substr         │                             │
│  └─────────────────────────┬────────────────┘                             │
│                            │                                               │
│                            ▼ Win32 PostMessage                             │
│  ┌───────────────────────────────────────────────────────────────────┐    │
│  │  Target Window (ConPTY — WindowsTerminal.exe / conhost.exe)       │    │
│  └───────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Audit / Ledger Layer  (enterprise/ledger.py)                        │  │
│  │  Structured log records for every gate decision                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

  OUTSIDE BOUNDARY:
  - Network interfaces (system is localhost-only)
  - Other Windows user sessions (DPAPI isolates per SID)
  - Kernel/driver layer (system uses Win32 user-mode APIs only)
```

---

## Data Flow Diagram

```
[Operator sets SC_IDENTITY_MODE=enforce]
          │
          ▼
[gated_send_string(target, text, gate=ultra_gate)]
          │
          ▼
[get_current_mode()]
  ├── Checks Named Mutex + DPAPI Registry token (emergency bypass check)
  ├── Reads SC_IDENTITY_MODE env var
  └── Returns: bypass | audit | enforce
          │
          ▼ (enforce path)
[DegradationCascade.verify(hwnd, text)]
  │
  ├──[L0] UltraGate.authorize_injection(hwnd, text)
  │         BPC ECDSA-P256 self-sign + body hash
  │         TSK checksum verification via Ultra Server
  │         → PASS → inject (Level 0)
  │
  ├──[L1] BPC-only: verify ECDSA sig + body_hash (skip TSK)
  │         → PASS → inject (Level 1, warning logged)
  │
  ├──[L2] Birth-tag verification: read_birth_tag(hwnd)
  │         verify_signed_birth_tag(hwnd, trusted_pub_key)
  │         Key sourced from HandshakePeer record (NOT window properties)
  │         → PASS → inject (Level 2, warning logged)
  │
  └──[L2 FAIL in enforce] → raise InjectionDeniedError ──────► BLOCKED
          │
          ▼ (on PASS)
[TargetGuard.verify_target(hwnd)]
  ├── IsWindow(hwnd)
  ├── GetClassNameW → must be ConPTY terminal class
  ├── QueryFullProcessImageNameW → must match expected exe
  ├── GetWindowThreadProcessId → must match expected PID
  └── GetWindowTextW → must contain expected title substring
          │
          ├── FAIL → PermissionError raised ─────────────────► BLOCKED
          │
          ▼ PASS
[Win32 PostMessage(hwnd, WM_CHAR, ...)]
          │
          ▼
[Ledger.write_receipt(hwnd, text, level, agent_id, timestamp)]
          │
          ▼
[Structured log record emitted at DEBUG level]
```

---

## Security Claim

> **OS-native AI peer mesh with kernel-verified identity, fail-closed actuation, and per-action audit receipts.**

This claim is substantiated by:

1. **Kernel-verified identity** — `QueryFullProcessImageNameW` (kernel image path) is used in `target_guard.py` for exe verification; DPAPI binds agent keys to machine + user SID at the OS level; TPM-backed signing is available via `tpm_identity` and demonstrated in `chained_channel.py`.

2. **Fail-closed actuation** — `get_current_mode()` defaults to `audit` (never `bypass`) when `SC_IDENTITY_MODE` is unset (WRAITH-003 fix); `enforce` mode blocks injection on any verification failure; `SC_STRICT_ENFORCE=1` fails closed on network errors (Gap 4 fix); emergency bypass requires dual-factor (mutex + DPAPI token, Gap 1 fix).

3. **Per-action audit receipts** — every `gated_send_string()` call produces a structured log entry; `enterprise/ledger.py` maintains tamper-evident records; supply chain integrity is verified at CI time via `test_dependency_integrity.py`.

---

## Scope of ATO

| Dimension | In Scope | Out of Scope |
|-----------|----------|--------------|
| OS | Windows 10 22H2+, Windows 11 | Linux, macOS |
| Architecture | x64 | x86, ARM64 |
| TPM | With TPM 2.0 (nominal), Without TPM (with DPAPI risk warning) | Network HSM |
| Session | Interactive Windows user session | Service account (SYSTEM) |
| Network | Localhost only (Ultra Server on 127.0.0.1:7777) | Remote network |
| Privilege | Standard user | Administrator / SYSTEM |
| Transport | Win32 PostMessage (WM_CHAR), Named Pipe (DACL) | Network sockets, COM |
| Terminals | WindowsTerminal.exe, conhost.exe | All other window classes |
