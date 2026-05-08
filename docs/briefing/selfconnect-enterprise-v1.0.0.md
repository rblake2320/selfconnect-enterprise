# SelfConnect Enterprise v1.0.0
## Executive Security Briefing

**Date:** 2026-05-08
**Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY
**Audience:** CISO, Contracting Officer, AO/ISSM
**Prepared by:** SelfConnect Engineering

---

## 1. The Problem

Autonomous AI agents are deploying into enterprise Windows environments
today. They read files, inject keystrokes, call APIs, and interact with
desktop applications — all without a human approving each action in real
time. Every compliance framework from FedRAMP to NIST RMF assumes that
actions on a system are attributable, bounded, and auditable. Autonomous
agents break all three assumptions simultaneously.

**The audit gap is structural, not procedural.** Traditional access control
logs record that a user launched a process. They do not record that the
process decided to read a classified document, summarise it, and send the
summary to an external API. The decision — and the classification of the
data it touched — are invisible to the audit chain.

No Windows-native substrate exists to enforce policy on agent decisions,
log those decisions to a tamper-evident chain, filter training data by
classification, and gate egress and export by deployment profile. Agents
either operate ungoverned or they do not deploy.

SelfConnect Enterprise closes this gap. It is a deny-by-default policy
enforcement and audit substrate for AI agent meshes on Windows. It is
not an agent. It is not an LLM. It is the governance layer that makes
agents deployable in regulated environments.

---

## 2. Threat Scenario

An adversarial agent sends an `execute_shell` action with a forged
classification header claiming UNCLASSIFIED on a payload that references
SECRET-level content. Here is what happens at each layer of the
SelfConnect Enterprise enforcement pipeline:

**Step 0 — ControlPlane gate.** If the system is paused, quarantined,
or the agent is revoked, the action is denied before any evaluation
begins. `ControlPlane` state transitions are one-way: there is no path
from `revoked` back to `active`.

**Step 0.5 — ClassifiedModeProfile gate.** If the deployment profile
ceiling is SECRET and the agent presents a DPAPI identity instead of CNG,
the action is denied. The profile also enforces the classification ceiling:
a request classified above the profile maximum is rejected here.

**Steps 1-7 — Policy bundle checks.** The agent must be registered,
not revoked in policy, within the policy time window, presenting a valid
signature, targeting a permitted agent, operating in a permitted
application, and requesting a permitted action. Failure at any step
produces a deny with a specific reason string.

**Step 8 — Action and classification check.** `execute_shell` must be
in the agent's `allowed_actions` list. The effective classification
(from `LabelEnvelope` or the `classification` string) must not exceed
the policy ceiling.

**Step 8b — Caveat validation.** If the label carries caveats not in
`ALLOWED_CAVEATS`, the action is denied with the invalid caveats named.

**Step 9 — Operator approval gate.** If the action requires human
approval (configurable per profile), it enters the `OperatorQueue` and
blocks until an operator approves or denies.

**After the decision:** The `PolicyDecision` is logged to the hash-chained
ledger with full metadata including classification, caveats, agent ID,
action, target, timestamp, sequence number, and digital signature (ECDSA
P-384 or ed25519). Every decision — allowed or denied — is recorded.

**Training data isolation:** `ObserverFilter` reads the ledger but only
passes entries where `decision=allow` AND `classification <= max_classification`
AND `caveats <= allowed_caveats`. The denied adversarial action never
reaches the training data pipeline. A model fine-tuned on observer output
cannot learn the behavior because it was never exposed to it.

**Egress and export gating:** Even if the action were somehow allowed,
`EgressGuard` blocks outbound calls when `allow_cloud_egress=False`, and
`ExportGuard` blocks evidence export when the label exceeds the profile
ceiling. Both log every check to the ledger.

The forged classification header is irrelevant. The system does not trust
the agent's self-declared classification — it evaluates every condition
independently and denies on the first failure.

---

## 3. Architecture

```
                    +-------------------------------------+
                    |        ClassifiedModeProfile         |
                    |  ceiling . caveats . egress . export |
                    +-----------------+-------------------+
                                      |
              +-----------------------v------------------------+
              |              PolicyEnforcer                     |
              |  Step 0:   ControlPlane gate                    |
              |  Step 0.5: Profile ceiling + identity type      |
              |  Steps 1-8: Bundle checks + classification      |
              |  Step 8b:  Caveat validation                    |
              |  Step 9:   Operator approval gate               |
              +-----------------------+------------------------+
                                      | PolicyDecision
              +-----------------------v------------------------+
              |         AgentLedger / CngLedger                 |
              |  Signed, hash-chained JSONL entry               |
              |  + LabelEnvelope (classification + caveats)     |
              +-----------------------+------------------------+
                                      |
              +-----------------------v------------------------+
              |          LedgerObserver / ObserverFilter        |
              |  decision=allow only                            |
              |  classification <= max_classification            |
              |  caveats <= allowed_caveats                      |
              +-----------------------+------------------------+
                                      |
              +-----------------------v------------------------+
              |    ExportGuard -> EvidenceExporter              |
              |  allow_export=True AND label <= ceiling         |
              +------------------------------------------------+
```

### Per-Layer Threat Coverage

| Layer | What it stops | NIST Control |
|-------|--------------|-------------|
| ClassifiedModeProfile | Wrong identity type, above-ceiling requests | IA-5, AC-3 |
| PolicyEnforcer | Unregistered agents, revoked agents, unsigned policies, forbidden actions | AC-2, AC-3, AC-6, SI-7 |
| LabelEnvelope | Forged classification, invalid caveats | AC-16, SI-10 |
| AgentLedger / CngLedger | Retroactive audit tampering (detection) | AU-9, AU-12 |
| ObserverFilter | Denied actions reaching training data, above-ceiling evidence | SI-3, AC-4 |
| EgressGuard | Unauthorized outbound network calls | SC-7 |
| ExportGuard | Evidence export above classification ceiling | AC-4, SC-28 |
| ControlPlane | Continued operation after kill-switch | AC-2 |

---

## 4. Deployment Profiles and Control Posture

### Pre-Built Deployment Profiles

| Profile | Ceiling | CNG Required | Cloud Egress | Export | Operator Approval |
|---------|---------|-------------|-------------|--------|-------------------|
| `secret_baseline()` | SECRET | Yes | No | No | `export_content`, `write_file` |
| `cui_baseline()` | CUI | No | Yes | Yes | None |
| Custom | Any | Configurable | Configurable | Configurable | Configurable |

### Deployment Mode Baseline Alignment

| Mode | Environment | Target Baseline | Readiness |
|------|------------|----------------|-----------|
| Mode A — Commercial | SaaS, hybrid cloud | NIST Low | Ready |
| Mode B — High-Assurance | On-premises, signed policies | NIST Moderate | 5 POA&M items (v1.1.0) |
| Mode C — Classified | Air-gapped, CNG-only | NIST Moderate-High | Requires v1.1.0 |

### NIST SP 800-53 Rev 5 Control Posture (v1.0.0)

| Status | Count | Controls |
|--------|-------|----------|
| **Satisfied** | 9 | AC-3, AC-6, AC-16, AU-2, AU-3, AU-12, SI-3, SI-7, SI-10 |
| **Partial** | 6 | AC-2, AC-4, AU-9, IA-5, SC-7, SC-28 |
| **Planned (v1.1.0)** | 1 | SC-8 |
| **Documented** | 1 | PM-9 |

Partial controls have formally documented gaps with v1.1.0 remediation
milestones. In FedRAMP terms, these are POA&M items — not findings.

### v1.1.0 Remediation Targets

| Gap | Description | Risk | Remediation |
|-----|-------------|------|-------------|
| G-1 | Deny entries visible in raw ledger | Low-Medium | Role-based ledger read access |
| G-2 | No OS-layer egress enforcement | Medium | WFP policy generation utility |
| G-3 | Ledger write not protected | Low-Medium | WORM backend adapter |
| G-4 | No key rotation protocol | Low | CngIdentity.rotate() + expiry |

---

## 5. What This System Is Not

SelfConnect Enterprise states its limits explicitly. The following are
not guaranteed and are documented as open items with remediation plans.

**This is not a certified MLS system.** SelfConnect Enterprise has not been
evaluated under Common Criteria, DIACAP, RMF, or any other formal assurance
framework. The guarantees are software-level properties backed by 528
passing tests and 88% code coverage, not certified assurance claims.

**Network-layer isolation is out of scope.** `EgressGuard` prevents outbound
calls through the Python API call paths it wraps. It does not prevent
OS-level network egress. A process with direct socket access can make
outbound calls regardless of the profile. Network isolation must be
enforced at the OS or infrastructure level (WFP, AppContainer, air-gap).

**Key management is out of scope.** The security of CNG key provisioning
depends on the host environment. Windows NCrypt software KSP stores keys
in the user's key container. There is no key rotation, expiry, or
PKI lifecycle management in v1.0.0. HSM-backed key storage is not
implemented.

**Ledger write access is not restricted.** The system detects retroactive
tampering via hash chain verification. It does not prevent a malicious
process with write access to the JSONL file from modifying entries.
WORM storage is planned for v1.1.0.

### Why the limits are stated here

A system that cannot name its gaps cannot remediate them. These four items
are known, bounded, and scheduled — not surprises. They are documented in
`docs/compliance/gap-analysis.md` with NIST control references and v1.1.0
milestone dates. A Moderate ATO package would present them as POA&M items.

---

## Test Evidence Summary

| Metric | Value |
|--------|-------|
| Total tests | 528 |
| Passing | 528 |
| Coverage | 88% |
| Red team tests | 59 (20 adversarial attack categories) |
| Critical invariant tests | 7 |
| Ruff (linter) | Clean |
| SBOM | Signed, committed (`sbom.json`) |

---

## Data Rights

SelfConnect Enterprise was developed entirely at private expense with no
government funding, contract, or CRADA. All intellectual property rights
are retained under DFARS 252.227-7014 (Rights in Noncommercial Computer
Software and Noncommercial Computer Software Documentation). Seven patent
claims are documented and proved by test evidence.

---

## Contact

Repository: [github.com/rblake2320/selfconnect-enterprise](https://github.com/rblake2320/selfconnect-enterprise)
Release: v1.0.0 (2026-05-08)

---

*This briefing is derived from verified system documentation and test
evidence. It has not been reviewed by an accredited third-party assessor.
See `SECURITY.md`, `docs/compliance/nist-800-53-mapping.md`, and
`docs/compliance/gap-analysis.md` for full technical detail.*
