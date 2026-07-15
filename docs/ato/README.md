# SelfConnect Enterprise — ATO Evidence Support Package

**Version:** 1.2.3  
**Date:** 2026-06-18  
**Repository data marking:** UNCLASSIFIED
**Authorization status:** Engineering evidence only; no ATO, IATT, PA, or Impact Level authorization

---

## Executive Summary

SelfConnect Enterprise contains engineering controls and evidence artifacts that can
support a future authorization package for an explicitly defined Windows deployment.
Repository tests do not create an authorization, approve a system boundary, establish a
cloud Impact Level, or authorize processing of government data.

The strongest current composed path is `GovernedRuntime`: it requires an externally pinned
signed policy, persistent cryptographic identity and signed ledger, active ControlPlane,
live HWND/PID/class/protected-image binding, applicable one-time operator approval, and UIA
confirmation of newly visible injected text. A full live conformance PASS additionally
requires an execution-output token that is absent from the injected command and appears
only after the target executes it.

Other modules, including `IdentityGate`, `DegradationCascade`, and low-level SDK send
functions, have narrower contracts. Their component tests do not imply that every caller
uses the complete governed composition. DPAPI-backed keys are scoped to the Windows user
and machine mechanisms used by the implementation; TPM/CNG and deployment-specific FIPS
claims require separate configuration and evidence.

`TargetGuard` reads the owning image path through `QueryFullProcessImageNameW` and restricts
supported Windows Terminal and classic-console classes to protected installation roots.
This raises the cost of class-name spoofing but is not a kernel identity or non-repudiation
claim. The remaining gaps and external evidence requirements are tracked in `GAPS.md` and
`docs/compliance/gap-analysis.md`.

---

## System Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CANDIDATE ENGINEERING BOUNDARY                          │
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
│  │  (protected image-path policy)            │                             │
│  │  Checks: is_terminal, exe match,         │                             │
│  │          pid match, title substr         │                             │
│  └─────────────────────────┬────────────────┘                             │
│                            │                                               │
│                            ▼ Win32 PostMessage                             │
│  ┌───────────────────────────────────────────────────────────────────┐    │
│  │  Target Window (approved protected terminal image)                │    │
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

## Bounded Engineering Claims

The repository implements and exercises OS-native terminal routing, cryptographic agent
identities, policy and operator gates, protected-path target validation, and signed
hash-chained audit records. The mandatory `GovernedRuntime` composition is the only path in
this repository that may be described as governed actuation without further qualification.

`QueryFullProcessImageNameW` supplies the OS-reported owning image path; SelfConnect then
checks that path against protected installation roots. This is target validation, not
cryptographic identity. `gated_send_string()` logging is also not equivalent to a confirmed
delivery receipt. Confirmed delivery requires a new UIA-visible payload occurrence, and
confirmed execution requires a separately observed effect.

---

## Evidence Scope

| Dimension | In Scope | Out of Scope |
|-----------|----------|--------------|
| OS | Windows 10 22H2+, Windows 11 | Linux, macOS |
| Architecture | x64 | x86, ARM64 |
| TPM | With TPM 2.0 (nominal), Without TPM (with DPAPI risk warning) | Network HSM |
| Session | Interactive Windows user session | Service account (SYSTEM) |
| Network | Localhost only (Ultra Server on 127.0.0.1:7777) | Remote network |
| Privilege | Standard user | Administrator / SYSTEM |
| Transport | Win32 PostMessage (WM_CHAR), Named Pipe (DACL) | Network sockets, COM |
| Terminals | Protected Windows Terminal package; protected classic console images | Unmapped or user-writable terminal images |
