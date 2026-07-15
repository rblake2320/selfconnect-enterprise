# Gap Analysis — Open Security Items
## SelfConnect Enterprise v1.2.3

**Date:** 2026-07-14
**Prepared against:** NIST SP 800-53 Rev 5 Moderate Baseline  
**Status:** Self-assessment in progress. `GAPS.md` is the canonical cross-component registry.

This document is a Plan of Action and Milestones (POA&M) precursor, not an
approved POA&M or assessor determination.
Each gap is documented with: what the gap is, why it exists, what controls it
affects, the risk posture, and the remediation plan.

**Control mapping qualifier:** Candidate controls affected are preliminary and
pending review by a qualified assessor. They do not constitute a legal or
compliance determination.

Known gaps must be named, tested where possible, and linked to remediation or an
explicitly accepted limitation. This file is not evidence that undiscovered
gaps do not exist.

---

## G-1 — Training Data Isolation: Deny Entries Visible in Ledger

**What the gap is:**  
Denied and quarantined ledger entries are excluded from primary training
records and `context_before` windows by `ObserverFilter`, as narrowly
established by `test_only_allow_decisions_reach_training_data` and
`test_context_window_does_not_include_denied_in_output`. However, the raw ledger
JSONL file contains all entries including denied decisions. An operator with
read access to the ledger file can observe what actions were denied and for
whom, potentially revealing policy configuration details.

**Why it exists:**  
The ledger is append-only and intentionally stores all decisions for auditability.
The training pipeline filter is a read-time exclusion, not a write-time exclusion.

**Controls affected:** AC-4 (information flow — ledger read access), SI-12 (info retention)

**Risk posture:** Low-Medium. Ledger read access should be restricted to
administrators. The policy configuration itself is not exposed — only the fact
that a specific action by a specific agent was denied, and the denial reason.

**Remediation plan:**  
- v1.1.0: Role-based ledger read access control (separate read key from write key)
- Alternatively: Write denied entries with a redacted metadata field (classification
  of the reason string itself, not the action record)
- WORM backend integration (see G-3) addresses the write-protection aspect but
  not the read-access aspect

**Milestone:** v1.1.0

---

## G-2 — Network-Layer Egress Not Enforced ✓ CLOSED (v1.1.0)

**What the gap is:**  
`EgressGuard` enforces the `allow_cloud_egress=False` restriction at the Python
process layer — it intercepts outbound calls routed through the guard. A Python
process with direct `socket` access, or any process outside the SelfConnect
runtime, can make outbound network calls regardless of the profile setting.

**Why it exists:**  
Process-layer enforcement is what a Python library can do. OS-layer network
isolation requires Windows Filtering Platform (WFP), AppContainer, or physical
air-gap — infrastructure controls outside the scope of a Python package.

**Controls affected:** SC-7 (boundary protection), SC-8 (transmission confidentiality),
AC-4 (information flow enforcement)

**Risk posture:** Medium for Mode C (classified) deployments. In a correctly
configured classified environment, the host would be on an isolated network with
no internet routing regardless of process behaviour. `EgressGuard` is a defence-
in-depth control, not a primary boundary. The gap is in the depth layer, not the
primary perimeter.

**Remediation delivered (v1.1.0):**  
- `tools/wfp_policy.py` — WFP egress policy generator. Produces a PowerShell
  deployment script (`New-NetFirewallRule`) that installs a deny-by-default
  outbound block rule for the agent process and per-entry allow rules for
  explicitly allowlisted hosts/ports. Idempotent install; includes `-Verify`
  and `-Remove` modes.
- Four built-in profiles: `mode_a` (permissive/dev), `mode_b` (CUI/SaaS),
  `mode_c` (classified/loopback-only), `mode_c_strict` (classified/port-specific).
- Custom profiles via `--allow host:port/proto` flags or JSON config file.
- 36 tests in `tests/test_wfp_policy.py` — all pass.
- **Residual:** AppContainer isolation for sub-processes deferred. Physical host
  isolation remains the primary perimeter for Mode C.

**Milestone:** v1.1.0 — CLOSED

---

## G-3 — Ledger Write Protection Not Enforced

**What the gap is:**  
`AgentLedger` and `CngLedger` detect interior modification, insertion, and
deletion of retained entries through signature and hash-chain verification.
Tampering is detectable but not prevented. Tail truncation and complete-file
deletion are not detectable from the local file alone because no later retained
entry remains to expose the missing tail. Those cases require a trusted external
checkpoint or off-host immutable copy. The earlier statement that every
truncate/delete would be detected by the next `verify()` call was incorrect.

**Why it exists:**  
Filesystem write protection is an OS/storage concern. The Python ledger
implementation provides cryptographic tamper-evidence; it does not provide
physical write protection.

**Controls affected:** AU-9 (protection of audit information), AU-10 (non-repudiation)

**Risk posture:** Low-Medium. In practice, ledger files should be written to
an ACL-restricted path (e.g., accessible only to the agent process UID and the
audit review role). Physical modification is an insider threat scenario.

**Remediation implemented:** S3 Object Lock and R2 bucket-lock adapters verify
provider retention configuration and per-object retention readback. Local file
replication is explicitly a replica, not WORM, and government mode rejects it
as the immutable sink.

**Remaining deployment proof:** Select an independently controlled provider,
configure credentials and retention/legal-hold policy, run a live write/readback,
delete/corrupt local state, restore from the independent copy, verify signatures
and the chain, and retain the provider configuration evidence. Until then this
gap remains open for a deployed system.

**Milestone:** Deployment-specific

---

## G-4 — No Key Rotation or Expiry Protocol

**What the gap is:**  
`CngIdentity` and `AgentIdentity` keypairs are generated once at agent
provisioning (`init()`) and used indefinitely. There is no key rotation
workflow, no key expiry, no certificate-based lifecycle management. Revocation
via `ControlPlane.revoke()` terminates the agent's ability to act but does not
rotate the underlying cryptographic key.

**Why it exists:**  
Key lifecycle management (rotation schedules, expiry enforcement, OCSP/CRL
distribution) is a PKI concern. Implementing a full PKI is out of scope for
v1.0.0; the design provides the cryptographic primitives on which a PKI can
be layered.

**Controls affected:** IA-5 (authenticator management), AC-2 (account management),
SC-12 (cryptographic key management)

**Risk posture:** Low for most deployments. Key rotation matters most when keys
have long exposure windows or when a key compromise is suspected. The NCrypt
software KSP provides OS-level key protection; the risk of undetected key
compromise is low on a correctly configured host.

**Remediation plan:**  
- v1.1.0: Key rotation protocol — `CngIdentity.rotate()` method that generates
  a new keypair, re-signs the agent's birth tag with the new key, and writes a
  rotation entry to the ledger. The old key is preserved for verification of
  historical ledger entries but disabled for new signing.
- v1.1.0: Key expiry field in `BirthTag` — agents with expired keys are denied
  by the enforcer (Step 0.5 gate, same pattern as `identity_type="dpapi"` rejection)
- Document key rotation procedure in the operator guide

**Milestone:** v1.1.0

---

## G-5 — WFP Generator: PowerShell Script Injection ✓ CLOSED (v1.1.1)

**What the gap is:**  
`tools/wfp_policy.py` embedded the `--process` value into generated PowerShell
scripts via string interpolation without sanitization. Two injection classes:
(1) CWE-93: newline characters (`\n`, `\r\n`) broke out of PS string literals,
inserting bare commands that execute when an admin runs the .ps1 elevated.
(2) CWE-93: `$(...)` subexpression expansion and backtick escapes within
double-quoted PS string literals could execute arbitrary commands at parse time.

**Why it existed:**  
The initial generator did not anticipate control character injection in an
operator-supplied `--process` argument.  The double-quoted PS string context
was carried over from template construction without considering PS parse rules.

**Controls affected:** SI-3 (malicious code protection), SA-11 (developer testing),
CM-7 (least functionality — script generator must not amplify attack surface)

**Risk posture:** HIGH for environments where the generator is used in any
pipeline or where `--process` is not strictly operator-controlled.  Generated
.ps1 scripts are executed with administrator privileges.

**Remediation delivered (v1.1.1):**  
- `_sanitize_ps_string()` rejects control characters (`\n`, `\r`, `\t`, `\x00`)
  at `WfpProfile` construction time (fail-closed, no script generated)
- All interpolated values in PS templates changed from double-quoted to
  single-quoted literals (`'value'` not `"value"`); single-quoted PS strings
  are fully literal — no `$`-expansion, no backtick escape sequences
- Single quotes in values are escaped as `''` (PS standard)
- 6 dedicated regression tests: newline-LF, newline-CRLF, `$(cmd)` expansion,
  backtick injection, `"` injection, `'` escaping — all pass
- Full suite: 632/632 passing

**Milestone:** v1.1.1 — CLOSED

---

## G-6 — AgentLedger Concurrent Write Safety (Design Boundary)

**What the boundary is:**
Base `AgentLedger.log()` and `CngLedger.log()` retain a documented single-writer
contract. `ThreadSafeAgentLedger` provides the locked adapter, and
`GovernedRuntime` requires that adapter for its persistent action path.

**Why it exists:**
The ledger is designed as a single-writer component — one agent process, one ledger
instance, sequential calls. The contract is enforced at the architecture level, not
the code level.

**Controls affected:** AU-9 (protection of audit information), AU-10 (non-repudiation)

**Risk posture:** Low on `GovernedRuntime`; caller-controlled on direct base-class
use. `verify()` detects resulting corruption but does not prevent it.

**Status:** Mitigated for the governed runtime; direct base-class use remains a
documented design boundary and cannot inherit the thread-safe claim.

**Milestone:** Governed path implemented 2026-07-15

---

## G-7 — Dependency and Vulnerability Release Gate

**What is implemented:** `pyproject.toml` declares `cryptography>=48.0.1`.
Supply-chain tests check the installed environment, direct dependencies, pinned
Git dependencies, prohibited code patterns, and selected historical indicators.
CI pins third-party GitHub Actions by full commit and Ultra protocol sources by
full commit.

**What this does not establish:** A historical scan is not a current
vulnerability determination. A dependency declaration does not prove the
deployed environment installed it. Claims about a specific CVE or installed
version are valid only for the report, lock/input set, and timestamp attached to
that run.

**Controls affected:** SA-10, SA-15, SI-2, SR-11

**Release rule:** The isolated release environment must install the declared
floor, run the full suite and Ruff, and pass a current dependency audit. A
shared developer environment below the floor is a release-gate failure, not
evidence that the declaration is absent.

**Status:** Control implemented; result is build-specific and must be rerun.

---

## G-8 through G-20 — Deployment and Composition Register

These entries prevent component evidence from being mistaken for deployment or
authorization evidence. Each control mapping below is a candidate control
affected, pending qualified assessor review.

| Gap | Description | Candidate controls | Risk | Status |
|---|---|---|---|---|
| G-8 | No selected authorization track, authorization boundary, PA/ATO/IATT package, or accountable authorizing official. A cloud service offering path and a Mission Owner component path are different. | CA-1, CA-2, CA-6, CA-7 | Blocker | Open |
| G-9 | Installed dependency state is environment-specific. The declared `cryptography>=48.0.1` floor must be enforced in every release/deployment environment. | SI-2, SR-11 | High | Release gate |
| G-10 | No verified SelfConnect-specific FIPS 140-3 deployment path, approved module/configuration inventory, or certificate-condition evidence exists. CNG algorithm use alone is not a FIPS claim. | SC-13, IA-7 | High | Open |
| G-11 | Unknown classifications previously sorted below UNCLASSIFIED. All current label, profile, policy, and observer ingress now fails closed and named adversarial tests cover the prior bypass. | AC-4, SC-16 | High | **Closed in code 2026-07-15** |
| G-12 | `EgressGuard` and `ExportGuard` govern calls routed through them; they are not OS/network interception boundaries. WFP/infrastructure controls and live route enumeration remain required. | SC-7, AC-4 | High | Open deployment boundary |
| G-13 | `GovernedRuntime` requires an external policy trust root. Lower-level `PolicyEnforcer` can still use an embedded signing key for compatibility and is outside that stronger claim. | IA-3, SC-12 | High | Open compatibility boundary |
| G-14 | Interior ledger changes are detectable; local tail truncation or complete deletion is not. Provider-verified immutable adapters exist, but no partner deployment/restore evidence exists. | AU-9, AU-10 | High | Open; same root issue as G-3 |
| G-15 | TPM/CNG capability probes and software identities do not establish mandatory TPM attestation on every governed frame or remote attestation. | IA-3, SC-17 | Medium | Open |
| G-16 | Core SelfConnect raw-send, cross-machine relay, and other repositories are separate boundaries. Enterprise composition does not globally intercept them. | AC-3, SC-8 | Medium | Open cross-repository conformance |
| G-17 | No completed STIG/SRG assessment, inheritance matrix, configuration baseline, POA&M approval, continuous-monitoring plan, incident evidence, or independent assessment exists. | CA-2, CA-7, CM-2, IR-1 | Blocker | Open |
| G-18 | Ultra lifecycle authentication and durability were inconsistent across Python and Node. Signed body-bound agent proofs, operator-authorized production enrollment, dual-control recovery, PostgreSQL/Redis stores, and mandatory live CI now cover the composition. | IA-3, IA-5, AU-9 | High | **Closed in code and live local test 2026-07-15; CI publication pending** |
| G-19 | No external workflow adapter has completed a live approved-tenant test with a versioned callback contract, rollback evidence, and integrator acceptance. | SA-9, CA-3, AC-20 | High | Open |
| G-20 | No live off-host immutable evidence deployment, independent custody decision, retention/legal-hold policy, or restore drill has been completed for the proposed partner boundary. | AU-9, CP-9, CP-10 | Blocker | Open |

---

## Gap Summary

| Gap ID | Description | Controls | Risk | Status |
|--------|-------------|----------|------|--------|
| G-1 | Deny entries visible in raw ledger | AC-4, SI-12 | Low-Medium | Open — v1.3.0 |
| G-2 | No OS-layer egress enforcement | SC-7, SC-8, AC-4 | Medium | **CLOSED v1.1.0** |
| G-3 | Ledger write not protected | AU-9, AU-10 | Low-Medium | Open — v1.3.0 |
| G-4 | No key rotation protocol | IA-5, AC-2, SC-12 | Low | Open — v1.3.0 |
| G-5 | WFP generator PS injection (CWE-93) | SI-3, SA-11, CM-7 | High | **CLOSED v1.1.1** |
| G-6 | Base ledger single-writer boundary | AU-9, AU-10 | Low | Mitigated on GovernedRuntime |
| G-7 | Dependency/vulnerability release gate | SA-10, SA-15, SI-2, SR-11 | High | Implemented; rerun per build |
| G-8–G-20 | Deployment, authorization, FIPS, cross-path, Ultra, partner, and immutable-evidence boundaries | See register above | Medium–Blocker | Mixed; G-11 and code portion of G-18 closed |

G-2, G-5, G-11, and the implementation portion of G-18 are closed. G-7 is a
recurring release gate, not a permanent closure. Other open items require code,
deployment evidence, partner integration, assessment, or authorization. Additional
cross-component, deployment, and IRS-integration details are tracked in `GAPS.md`.
Component tests do not establish that every runtime path or deployment boundary
uses those components.

---

*This gap analysis was produced as a self-assessment. It has not been reviewed
by an accredited third-party assessor (3PAO).*
