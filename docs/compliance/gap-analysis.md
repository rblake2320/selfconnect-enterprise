# Gap Analysis — Open Security Items
## SelfConnect Enterprise v1.0.0

**Date:** 2026-05-08  
**Prepared against:** NIST SP 800-53 Rev 5 Moderate Baseline  
**Status:** 4 open gaps. All acknowledged in `SECURITY.md`. All scheduled for remediation.

This document is the system's Plan of Action and Milestones (POA&M) precursor.
Each gap is documented with: what the gap is, why it exists, what controls it
affects, the risk posture, and the remediation plan.

The existence of this document is itself a security signal. A system that cannot
name its gaps cannot remediate them. These four gaps are known, bounded, and
scheduled. They are not surprises.

---

## G-1 — Training Data Isolation: Deny Entries Visible in Ledger

**What the gap is:**  
Denied and quarantined ledger entries are excluded from the training data
pipeline by `ObserverFilter` — this is a proven invariant
(`test_only_allow_decisions_reach_training_data`). However, the raw ledger
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
`AgentLedger` and `CngLedger` detect retroactive tampering via hash chain
verification — any modified entry breaks all subsequent entry hashes.
Tampering is detectable but not prevented. A malicious process with write
access to the JSONL ledger file can modify, delete, or truncate entries.
The modification will be detected by the next `verify()` call, but if all
copies of the ledger are compromised before verification, the chain is broken
without recovery.

**Why it exists:**  
Filesystem write protection is an OS/storage concern. The Python ledger
implementation provides cryptographic tamper-evidence; it does not provide
physical write protection.

**Controls affected:** AU-9 (protection of audit information), AU-10 (non-repudiation)

**Risk posture:** Low-Medium. In practice, ledger files should be written to
an ACL-restricted path (e.g., accessible only to the agent process UID and the
audit review role). Physical modification is an insider threat scenario.

**Remediation plan:**  
- v1.1.0: WORM backend adapter — abstract the ledger write path behind a
  `LedgerBackend` protocol; provide a `WormFileLedgerBackend` that opens the
  file with `FILE_FLAG_WRITE_THROUGH` and appends to an OS-level append-only
  log. On Windows, this maps to NTFS append-only attribute or Event Log backend.
- Separately: Document NTFS ACL configuration for the ledger directory in the
  deployment guide (least-privilege path — read/append for agent, read-only for
  audit reviewer, no delete permission for either)

**Milestone:** v1.1.0

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

**What the gap is:**
`AgentLedger.log()` (and `CngLedger.log()`) have no threading lock. The `_seq`,
`_prev_hash`, and JSONL file write are not protected against concurrent callers.
Concurrent writes corrupt the hash chain.

**Why it exists:**
The ledger is designed as a single-writer component — one agent process, one ledger
instance, sequential calls. The contract is enforced at the architecture level, not
the code level.

**Controls affected:** AU-9 (protection of audit information), AU-10 (non-repudiation)

**Risk posture:** Low. Exploitation requires two threads sharing the same AgentLedger
instance and calling log() simultaneously — a usage pattern that violates the stated
single-writer contract. `verify()` correctly detects corruption after the fact.

**Remediation plan:**
- v1.3.0: Optional `threading.Lock` wrapper — `ThreadSafeAgentLedger(AgentLedger)`
  that wraps log() with a lock, for callers who cannot guarantee single-writer usage.
  The base class stays lockless (fast path for the common case).
- Document single-writer contract explicitly in class docstring.

**Status:** Documented (v1.2.0). Discovered by concurrency stress test `test_concurrent_writes_documented_unsafe`.

**Milestone:** v1.3.0

---

## G-7 — May 2026 Zero-Day CVE Audit ✓ CLOSED (v1.2.0)

**What the audit covered:**
Proactive sweep of the May 2026 zero-day threat landscape against the SelfConnect
Enterprise codebase and dependency tree.

**Threats assessed:**

| CVE / Threat | Attack Class | Our Exposure | Disposition |
|---|---|---|---|
| sonatype-2026-001357 (LiteLLM 1.82.7–1.82.8) | Supply chain — credential stealer + backdoor | litellm not a direct dep; env has 1.82.5 (safe) | CI gate added in `test_supply_chain.py` |
| CVE-2026-26007 (cryptography < 46.0.5) | ECDH small-subgroup — SECT curves | We use P-384/ed25519 (not exploitable via our paths) | Version floor raised to >=46.0.6; static scan added |
| CVE-2026-34073 (cryptography < 46.0.6) | X.509 name constraint bypass | We use Windows NCrypt/CNG, not x509.verification (not exploitable) | Version floor >=46.0.6; static x509.verification scan added |
| CVE-2026-33825 / BlueHammer (Defender TOCTOU) | NTFS junction redirect → SYSTEM | Affects Defender's internal staging paths, not .ps1 output paths | SHA-256 integrity hash added to wfp_policy.py output |
| CVE-2026-32202 (Windows NTLM coercion) | Net-NTLMv2 hash capture | We use NCrypt ECDSA, no NTLM auth paths | OS patch control (not in-app) |
| CVE-2026-41089 (Windows Netlogon heap RCE) | Unauthenticated domain controller RCE | No Netlogon usage | OS patch control (not in-app) |

**Controls affected:** SA-10 (developer security testing), SA-15 (development process), SI-2 (flaw remediation), SR-11 (component authenticity)

**Deliverables (v1.2.0):**
- `tests/test_enterprise/test_supply_chain.py` — 10 tests: LiteLLM backdoor version gate,
  cryptography version floor, SECT curve static scan, x509.verification static scan,
  WFP script determinism and tamper detection.
- `pyproject.toml` — `cryptography>=46.0.6` (was `>=42`)
- `tools/wfp_policy.py` — SHA-256 hash printed to console at script generation time
- Installed version upgraded to `cryptography==48.0.0`

**Residual:** OS CVEs (CVE-2026-32202, CVE-2026-41089) are environment/OS patch controls.
Not tracked as SelfConnect code gaps — tracked as deployment requirements in the operator
guide.

**Milestone:** v1.2.0 — CLOSED

---

## Gap Summary

| Gap ID | Description | Controls | Risk | Status |
|--------|-------------|----------|------|--------|
| G-1 | Deny entries visible in raw ledger | AC-4, SI-12 | Low-Medium | Open — v1.3.0 |
| G-2 | No OS-layer egress enforcement | SC-7, SC-8, AC-4 | Medium | **CLOSED v1.1.0** |
| G-3 | Ledger write not protected | AU-9, AU-10 | Low-Medium | Open — v1.3.0 |
| G-4 | No key rotation protocol | IA-5, AC-2, SC-12 | Low | Open — v1.3.0 |
| G-5 | WFP generator PS injection (CWE-93) | SI-3, SA-11, CM-7 | High | **CLOSED v1.1.1** |
| G-6 | AgentLedger single-writer contract undocumented | AU-9, AU-10 | Low | Open — v1.3.0 |
| G-7 | May 2026 CVE audit | SA-10, SA-15, SI-2, SR-11 | — | **CLOSED v1.2.0** |

G-2, G-5, and G-7 are closed. G-1, G-3, G-4, G-6 remain open for v1.3.0.
None of the open gaps represent an exploitable vulnerability in the primary
security controls — classification ceiling enforcement, deny-by-default policy,
signed policy verification, and training data isolation are all fully satisfied.

---

*This gap analysis was produced as a self-assessment. It has not been reviewed
by an accredited third-party assessor (3PAO).*
