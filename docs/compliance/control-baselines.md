# Control Baseline Targets
## SelfConnect Enterprise v1.0.0

**Reference:** NIST SP 800-53 Rev 5 — Low, Moderate, and High baselines  
**Date:** 2026-05-08

This document maps each control in `nist-800-53-mapping.md` to the baseline
at which it is required (Low / Moderate / High) and states the current
implementation status for that baseline level.

---

## Reading this document

| Symbol | Meaning |
|--------|---------|
| ✅ | Control satisfied at this baseline level |
| ⚠️ | Control partially satisfied; documented gap exists |
| 🔲 | Planned for v1.1.0 |
| — | Control not required at this baseline level |

---

## Baseline Coverage

| Control | Low | Moderate | High | Notes |
|---------|-----|----------|------|-------|
| **AC-2** Account Management | ✅ | ⚠️ | ⚠️ | Low: revocation satisfied. Mod/High: no inventory, no rotation |
| **AC-3** Access Enforcement | ✅ | ✅ | ✅ | 9-step deny-by-default pipeline |
| **AC-4** Info Flow Enforcement | — | ⚠️ | ⚠️ | Process layer satisfied; OS layer gap (SC-7) |
| **AC-6** Least Privilege | ✅ | ✅ | ✅ | Empty `allowed_actions` = no permissions |
| **AC-16** Security Attributes | — | ✅ | ✅ | LabelEnvelope, Classification enum, ALLOWED_CAVEATS |
| **AU-2** Event Logging | ✅ | ✅ | ✅ | All decision paths log unconditionally |
| **AU-3** Audit Record Content | ✅ | ✅ | ✅ | Full entry schema with all required fields |
| **AU-9** Audit Protection | ✅ | ⚠️ | ⚠️ | Tamper-detectable; not tamper-preventable (no WORM) |
| **AU-12** Audit Generation | ✅ | ✅ | ✅ | Synchronous, append-only, unconditional |
| **IA-3** Device I&A | — | ✅ | ✅ | Machine-bound NCrypt / DPAPI keys |
| **IA-5** Authenticator Mgmt | ✅ | ⚠️ | ⚠️ | CNG enforcement satisfied; no rotation protocol |
| **SC-7** Boundary Protection | — | ⚠️ | ⚠️ | Process layer only; OS enforcement gap |
| **SC-8** Transmission Integrity | — | 🔲 | 🔲 | Planned v1.1.0 |
| **SC-28** Info at Rest | — | ⚠️ | ⚠️ | Keys protected; ledger content plaintext |
| **SI-3** Malicious Code | ✅ | ✅ | ✅ | 59 adversarial tests across 20 attack categories |
| **SI-7** Software Integrity | ✅ | ✅ | ✅ | ECDSA P-384 signed policies, fail-closed unsigned |
| **SI-10** Input Validation | ✅ | ✅ | ✅ | ALLOWED_CAVEATS validation, deny on invalid |
| **PM-9** Risk Management | ✅ | ✅ | ✅ | Documented gaps, scheduled remediation |

---

## Baseline Readiness Summary

### Low Baseline
**Status: Substantially satisfied.**  
All Low baseline controls are satisfied or partially satisfied. The one gap
(AU-9 tamper-prevention) does not block Low baseline ATO — the control at Low
requires protection of audit information, which the hash-chain + signature
approach satisfies. WORM storage is a High enhancement, not a Low requirement.

### Moderate Baseline
**Status: Satisfied for core controls; 5 documented gaps.**

| Gap | Control | Severity | Remediation |
|-----|---------|----------|-------------|
| No OS-layer egress enforcement | SC-7, AC-4 | Medium | v1.1.0 WFP / AppContainer |
| No WORM ledger backend | AU-9 | Low-Medium | v1.1.0 append-only store |
| No key rotation protocol | IA-5, AC-2 | Medium | v1.1.0 rotation workflow |
| Ledger content plaintext | SC-28 | Low | Host-level BitLocker / NTFS ACL |
| SC-8 not implemented | SC-8 | Medium | v1.1.0 Named Pipes + TLS |

These gaps are formally documented in `gap-analysis.md` with remediation
schedules. A Moderate ATO package would present these as POA&M items with
v1.1.0 milestone dates.

### High Baseline
**Status: Requires v1.1.0 completion + external assessment.**

High baseline adds enhanced requirements for SC-7 (boundary protection with
managed interfaces), SC-8 (cryptographic protection of transmissions),
AU-9 (hardware-protected audit), and IA-5 (PIV/PKI authenticators).
The v1.1.0 roadmap addresses SC-7 and SC-8. AU-9 at High requires WORM
hardware or a write-once backend. IA-5 at High requires PIV/CAC or equivalent
hardware authenticator — outside the current Windows NCrypt software KSP scope.

---

## Deployment Mode Baseline Alignment

| Deployment Mode | Target Baseline | Current Readiness |
|----------------|----------------|-------------------|
| Mode A — Commercial | Low | ✅ Ready |
| Mode B — High-Assurance | Moderate | ⚠️ 5 POA&M items |
| Mode C — Classified (`secret_baseline`) | Moderate-High | ⚠️ v1.1.0 required for full Moderate |

---

*This baseline assessment is a self-assessment and has not been validated
by an accredited third-party assessor (3PAO).*
