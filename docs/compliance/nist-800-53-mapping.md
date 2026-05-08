# NIST SP 800-53 Rev 5 Control Mapping
## SelfConnect Enterprise v1.0.0

**Date:** 2026-05-08  
**System:** SelfConnect Enterprise — Win32-native AI agent policy enforcement substrate  
**Prepared against:** NIST SP 800-53 Rev 5 (Final, September 2020)  
**Baseline target:** Moderate (with selected High controls noted)

This document maps SelfConnect Enterprise's verified security properties to
NIST 800-53 Rev 5 controls. Each row identifies the control, how the system
satisfies it (or partially satisfies it), and the test evidence that proves
the claim. Documented gaps reference `gap-analysis.md` and the v1.1.0 roadmap.

---

## Access Control (AC)

### AC-2 — Account Management
**Status:** Partial  
**How satisfied:** Agent identities are provisioned via `CngIdentity.init()` and stored
in the Windows NCrypt key container. `ControlPlane.revoke()` provides a terminal
account revocation path — revoked agent IDs are denied by the enforcer and the
state is permanent. There is no self-service account creation path; identity
provisioning is a manual administrative act.  
**Gaps:** No centralised account inventory or automated provisioning workflow. Agent
identity lifecycle (rotation, expiry) is a documented gap. See `gap-analysis.md §G-4`.  
**Evidence:** `tests/test_enterprise/test_control.py::TestRevoke`,
`enterprise/identity_cng.py`

---

### AC-3 — Access Enforcement
**Status:** Satisfied  
**How satisfied:** `PolicyEnforcer.check()` enforces access decisions on every agent
action. The 9-step deny-by-default pipeline requires an explicit `allow` on all
applicable conditions before any action proceeds. No code path returns
`allowed=True` without passing every check. Unregistered agents receive an
immediate deny. Actions not in `allowed_actions` are denied at Step 8.  
**Evidence:** `tests/test_enterprise/test_policy.py` (deny-by-default suite),
`SECURITY.md §2`, commit `ff5f1eb`

---

### AC-4 — Information Flow Enforcement
**Status:** Satisfied (process layer); OS layer is a documented gap  
**How satisfied:** `ObserverFilter` enforces classification ceiling on information flow
into the training data pipeline. `ExportGuard` enforces the ceiling on evidence
export. `EgressGuard` blocks outbound information flow when `allow_cloud_egress=False`.
LabelEnvelope carries classification and caveats on every evidence record; the
Bell-LaPadula `le()` comparator enforces the lattice at each gate.  
**Gaps:** Network-layer information flow enforcement (SC-7) is not implemented in
process code. See `gap-analysis.md §G-2`.  
**Evidence:** `tests/test_enterprise/test_labels.py::TestLabelDominance`,
`tests/test_enterprise/test_classified_mode.py::TestExportGuard`,
`SECURITY.md §1`, `SECURITY.md §6`, `SECURITY.md §7`

---

### AC-6 — Least Privilege
**Status:** Satisfied  
**How satisfied:** Every agent has an explicit `allowed_actions` list in its policy
record. The list defaults to empty — agents have no permissions unless
explicitly granted. Actions not in the list are denied at Step 8 of
`PolicyEnforcer.check()`. `allowed_targets`, `allowed_apps`, and
`blocked_apps` provide additional least-privilege scoping.  
**Evidence:** `enterprise/policy.py::AgentPolicy`, `tests/test_enterprise/test_policy.py`,
`SECURITY.md §2`

---

### AC-16 — Security Attributes
**Status:** Satisfied  
**How satisfied:** `LabelEnvelope` is the system's security attribute carrier.
Every ledger entry carries `classification`, `caveats`, `originator`, and `label_ts`
fields. Labels flow from `PolicyEnforcer.check(label=)` through
`AgentLedger.log(label=)` to `ObserverFilter.matches()`. The `Classification`
enum and `ALLOWED_CAVEATS` frozenset form a bounded, validated attribute vocabulary.  
**Evidence:** `tests/test_enterprise/test_labels.py`,
`enterprise/labels.py`, `SECURITY.md §6`, `SECURITY.md §10`

---

## Audit and Accountability (AU)

### AU-2 — Event Logging
**Status:** Satisfied  
**How satisfied:** Every `PolicyEnforcer.check()` call produces a `PolicyDecision`
that is logged to `AgentLedger` or `CngLedger` via `to_ledger_metadata()`. Every
`EgressGuard.check_outbound()` call produces an `egress_check` entry.
Every `ExportGuard.check_and_log()` call produces an `export_check` entry.
Every `ControlPlane` state transition produces an `operator_control` entry.
Logging is unconditional — allowed and denied decisions are both recorded.  
**Evidence:** `enterprise/ledger.py`, `enterprise/egress_guard.py`,
`enterprise/export_guard.py`, `enterprise/control.py::_log()`

---

### AU-3 — Content of Audit Records
**Status:** Satisfied  
**How satisfied:** Every ledger entry includes: `seq` (sequence number),
`agent_id`, `action`, `result`, `ts` (timestamp), `prev_hash` (chain integrity),
`sig` (digital signature), `classification`, `policy_id`, `approval_mode`,
`decision`. `operator_control` entries additionally carry `command`,
`operator_id`, `reason`, `prev_state`, `new_state`.  
**Evidence:** `enterprise/ledger.py` (entry schema), `enterprise/policy.py::PolicyDecision.to_ledger_metadata()`

---

### AU-9 — Protection of Audit Information
**Status:** Partial  
**How satisfied:** Ledger entries are signed with ECDSA P-384 (CngLedger) or
ed25519 (AgentLedger). Every entry hashes the previous entry. `verify()` detects
retroactive modification of any entry. A tampered entry is detectable; it is not
preventable at the Python layer.  
**Gaps:** No WORM storage backend. A process with write access to the JSONL file
can modify entries (tampering is detectable, not prevented). See `gap-analysis.md §G-3`.  
**Evidence:** `tests/test_enterprise/test_redteam.py::RT-11` (tamper detection),
`tests/test_enterprise/test_redteam.py::RT-12` (insertion detection),
`SECURITY.md §9`

---

### AU-12 — Audit Record Generation
**Status:** Satisfied  
**How satisfied:** `AgentLedger.log()` and `CngLedger.log()` are the only write
paths to the audit chain. Both are synchronous and append-only.
Every policy decision, control plane action, egress check, and export check
produces a ledger entry. The chain is linear and monotonically sequenced.  
**Evidence:** `enterprise/ledger.py`, `enterprise/identity_cng.py::CngLedger`,
`tests/test_enterprise/test_identity_cng.py`

---

## Identification and Authentication (IA)

### IA-3 — Device Identification and Authentication
**Status:** Satisfied  
**How satisfied:** Every agent has a permanent `SC-XXXXXXXX` identifier derived
from a machine-bound keypair. `CngIdentity` stores the key in the Windows NCrypt
software KSP — the private key cannot be exported from the key container.
`AgentIdentity` uses DPAPI-encrypted ed25519 — the key is machine-bound and
decryptable only on the originating machine. `verify_tag()` validates the agent's
hardware binding (PID + OS creation time).  
**Evidence:** `enterprise/identity_cng.py::CngIdentity`,
`enterprise/identity.py::verify_tag()`, `SECURITY.md §8`

---

### IA-5 — Authenticator Management
**Status:** Satisfied  
**How satisfied:** When `ClassifiedModeProfile.require_cng_identity=True`,
`PolicyEnforcer.check()` at Step 0.5 rejects any caller that passes
`identity_type="dpapi"`. Only CNG-backed (ECDSA P-384, NCrypt) identities are
accepted. Key provisioning is performed once by an administrator via
`CngIdentity.init()`; subsequent boots use `CngIdentity.load()`. Key rotation
is a documented gap.  
**Gaps:** No automated key rotation or expiry protocol. See `gap-analysis.md §G-4`.  
**Evidence:** `tests/test_enterprise/test_classified_mode.py::test_profile_dpapi_rejected_when_cng_required`,
`SECURITY.md §8`

---

## System and Communications Protection (SC)

### SC-7 — Boundary Protection
**Status:** Partial — process layer only  
**How satisfied:** `EgressGuard.check_outbound()` blocks outbound API calls at the
Python process layer when `ClassifiedModeProfile.allow_cloud_egress=False`. Every
check is logged. There is no silent bypass path through `EgressGuard`.  
**Gaps:** OS-level network boundary enforcement is not implemented. A process with
raw socket access can make outbound calls. Network isolation requires OS-layer
controls (Windows Filtering Platform, AppContainer, firewall rules, or physical
air-gap). See `gap-analysis.md §G-2`.  
**Evidence:** `tests/test_enterprise/test_classified_mode.py::TestEgressGuard`,
`SECURITY.md §6`, `SECURITY.md non-guarantee §2`

---

### SC-8 — Transmission Confidentiality and Integrity
**Status:** Planned (v1.1.0)  
**How satisfied:** In scope for v1.1.0. Current scope is process-layer only.
The WM_COPYDATA transport is same-machine only. Cross-machine transport
(Named Pipes, HTTPS) is not yet implemented.  
**Gaps:** See `gap-analysis.md §G-2`. Planned for v1.1.0.  
**Evidence:** `enterprise/transport.py` (WM_COPYDATA, same-machine only)

---

### SC-28 — Protection of Information at Rest
**Status:** Partial  
**How satisfied:** Agent private keys are protected by Windows NCrypt software
KSP (CNG) or DPAPI (legacy) — both provide OS-level key protection at rest.
Ledger JSONL files are written to disk in plaintext; content protection is
host-environment dependent (BitLocker, NTFS ACLs).  
**Gaps:** Ledger content is not encrypted at rest. See `gap-analysis.md §G-3`.  
**Evidence:** `enterprise/identity_cng.py`, `enterprise/identity.py`

---

## System and Information Integrity (SI)

### SI-3 — Malicious Code Protection
**Status:** Satisfied (adversarial testing coverage)  
**How satisfied:** The red team suite exercises 20 attack categories including
policy bypass, signature tampering, classification spoofing, training data
poisoning, control plane bypass, hash chain forgery, and concurrent race
conditions. All 59 red team tests pass. The system is actively tested against
adversarial inputs, not just expected inputs.  
**Evidence:** `tests/test_enterprise/test_redteam.py` (RT-01 through RT-20),
`SECURITY.md §2` (deny-by-default), `SECURITY.md §3` (signed policy)

---

### SI-7 — Software, Firmware, and Information Integrity
**Status:** Satisfied  
**How satisfied:** Policy bundles are signed with ECDSA P-384 via
`enterprise/policy_sign.py`. `PolicyEnforcer` rejects unsigned policies when
`require_signature=True` (the default). A tampered policy bundle fails the
signature check and every subsequent action is denied. `policy_sign.py` ships
at 100% test coverage.  
**ClassifiedModeProfile** can also be loaded from a signed JSON file via
`from_file(verify_signature=True)` — a tampered or unsigned profile fails closed
with a `RuntimeError`.  
**Evidence:** `tests/test_enterprise/test_policy_sign.py` (100% coverage),
`tests/test_enterprise/test_redteam.py::RT-02` (signature bypass),
`SECURITY.md §3`

---

### SI-10 — Information Input Validation
**Status:** Satisfied  
**How satisfied:** `LabelEnvelope.validate()` enforces membership in
`ALLOWED_CAVEATS` before any label is acted on. Invalid caveats cause denial at
Step 8b of `PolicyEnforcer.check()` with the disallowed caveats listed in the
reason string. `ClassifiedModeProfile.validate()` similarly enforces
`allowed_caveats ⊆ ALLOWED_CAVEATS` at profile construction.
Policy bundle fields are validated on load via `AgentPolicy.from_dict()`.  
**Evidence:** `tests/test_enterprise/test_labels.py::TestLabelEnvelope::test_validate_invalid_caveat`,
`tests/test_enterprise/test_labels.py::test_check_label_invalid_caveats_denied`,
`SECURITY.md §10`

---

## Program Management (PM)

### PM-9 — Risk Management Strategy
**Status:** Documented  
**How satisfied:** `SECURITY.md` explicitly documents both what the system
guarantees and what it does not guarantee. The four non-guarantees are
formally identified as open items in `gap-analysis.md` with v1.1.0 milestone
references. This constitutes a documented risk management posture: known gaps
are owned, scoped, and scheduled — not ignored.  
**Evidence:** `SECURITY.md §non-guarantees`, `docs/compliance/gap-analysis.md`

---

## Control Summary Table

| Control | Family | Status | Primary Evidence |
|---------|--------|--------|-----------------|
| AC-2 | Access Control | Partial | test_control.py::TestRevoke |
| AC-3 | Access Control | **Satisfied** | test_policy.py, SECURITY.md §2 |
| AC-4 | Access Control | Partial (process layer) | test_labels.py, test_classified_mode.py |
| AC-6 | Access Control | **Satisfied** | policy.py::AgentPolicy, test_policy.py |
| AC-16 | Access Control | **Satisfied** | test_labels.py, labels.py |
| AU-2 | Audit | **Satisfied** | ledger.py, egress_guard.py, control.py |
| AU-3 | Audit | **Satisfied** | ledger.py entry schema |
| AU-9 | Audit | Partial | test_redteam.py RT-11/RT-12, SECURITY.md §9 |
| AU-12 | Audit | **Satisfied** | ledger.py, identity_cng.py |
| IA-3 | Identity | **Satisfied** | identity_cng.py, identity.py::verify_tag() |
| IA-5 | Identity | Partial (no rotation) | test_classified_mode.py |
| SC-7 | Comms | Partial (process layer) | test_classified_mode.py::TestEgressGuard |
| SC-8 | Comms | Planned v1.1.0 | gap-analysis.md §G-2 |
| SC-28 | Comms | Partial | identity_cng.py, identity.py |
| SI-3 | Integrity | **Satisfied** | test_redteam.py RT-01–RT-20 |
| SI-7 | Integrity | **Satisfied** | test_policy_sign.py (100%), RT-02 |
| SI-10 | Integrity | **Satisfied** | test_labels.py::test_validate |
| PM-9 | Program Mgmt | Documented | SECURITY.md, gap-analysis.md |

**Satisfied: 9 controls | Partial: 6 controls | Planned: 1 control | Documented: 1 control**

---

*This mapping is a system-level narrative for ATO support purposes. It is not a
formal assessment and has not been reviewed by an accredited third-party
assessor (3PAO). See `gap-analysis.md` for open items and remediation schedule.*
