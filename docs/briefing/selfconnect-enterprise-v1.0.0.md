# SelfConnect Enterprise v1.0.0
## Executive Security Briefing

> **Historical snapshot — superseded.** This file preserves the wording of an
> early engineering briefing. It is not current release evidence, a deployment
> readiness statement, a control assessment, an authorization package, or a
> competitive-market finding. Current claim boundaries are in `SECURITY.md`,
> `GAPS.md`, and `docs/ato/NIST_800-53_control_map.md`.

**Date:** 2026-05-08
**Document marking:** Repository documentation; no government classification or
CUI determination is asserted
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

SelfConnect Enterprise implements a Windows-oriented candidate substrate for
policy decisions, tamper-evident local records, training-export filtering, and
profile-aware egress/export decisions. This briefing does not establish that
no comparable system exists or that these components alone close an
authorization or deployment gap.

SelfConnect Enterprise is designed as a deny-by-default policy
enforcement and audit substrate for AI agent meshes on Windows. It is
not an agent. It is not an LLM. It is the governance layer that makes
selected agent workflows governable through the integrated paths described
below. Regulated deployment requires boundary integration and assessment.

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

**After the decision:** In the integrated governed runtime, the
`PolicyDecision` is logged to the hash-chained
ledger with full metadata including classification, caveats, agent ID,
action, target, timestamp, sequence number, and digital signature (ECDSA
P-384 or ed25519). This statement does not cover direct calls that bypass the
governed runtime or deployment-specific tools not wired to the ledger.

**Training export filtering:** `ObserverFilter` reads the ledger but only
passes entries where `decision=allow` AND `classification <= max_classification`
AND `caveats <= allowed_caveats`. The denied adversarial action never
becomes the selected training record through that filter. This establishes a
dataset-path property only; it does not prove that a model cannot learn similar
behavior from other data or that every training path uses this filter.

**Egress and export gating:** Even if the action were somehow allowed,
`EgressGuard` blocks outbound calls when `allow_cloud_egress=False`, and
`ExportGuard` blocks evidence export when the label exceeds the profile
ceiling. Both log every check to the ledger.

The governed path evaluates the supplied label and configured policy
conditions and denies on the first failed check. It cannot independently know
the semantic classification of arbitrary content merely from a caller-provided
label; trusted labeling and ingestion remain deployment responsibilities.

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
| Mode A — Commercial | SaaS, hybrid cloud | NIST Low candidate mapping | Engineering profile; not assessed |
| Mode B — High-Assurance | On-premises, signed policies | NIST Moderate candidate mapping | Engineering profile; open gaps |
| Mode C — Classified | Air-gapped, CNG-only | Deployment-specific | Not authorized or assessed |

### NIST SP 800-53 Rev 5 Candidate Evidence (v1.0.0 snapshot)

The v1.0.0 implementation referenced candidate controls including AC-2, AC-3,
AC-4, AC-6, AC-16, AU-2, AU-3, AU-9, AU-12, IA-5, PM-9, SC-7, SC-28, SI-3,
SI-7, and SI-10. This is a preliminary developer mapping, not a determination
that a control is satisfied. A POA&M is part of an authorization process and
requires the responsible system owner/authorization boundary; repository gaps
must not be represented as approved POA&M items.

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
framework. Named tests may narrowly establish particular software behaviors;
they are not certified assurance claims. The 528-test/88%-coverage figures
below are retained only as historical, run-specific figures whose source
commit and evidence artifact are not recorded in this briefing.

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
were identified as engineering gaps at the time. They are documented in
`docs/compliance/gap-analysis.md` with NIST control references and v1.1.0
milestone dates. The current gap register supersedes this snapshot.

---

## Historical Test Summary (not current release evidence)

| Metric | Value |
|--------|-------|
| Total tests | 528 |
| Passing | 528 |
| Coverage | 88% |
| Red team tests | 59 (20 adversarial attack categories) |
| Critical invariant tests | 7 |
| Ruff (linter) | Clean |
| SBOM | v1.0.0 briefing stated committed; signing/current verification not established here |

---

## Data Rights

The developer records this work as privately developed. Government contract
data-rights treatment is contract- and funding-specific and requires qualified
legal review; this briefing does not determine rights under DFARS clauses.
Candidate claim sets may cite implementation and named-test artifacts, while
patent scope, validity, ownership, and enforceability are not proved by software
tests.

---

## Contact

Repository: [github.com/rblake2320/selfconnect-enterprise](https://github.com/rblake2320/selfconnect-enterprise)
Release: v1.0.0 (2026-05-08)

---

*This historical briefing was derived from the engineering documentation and
test results available at the time. It has not been reviewed by an accredited
third-party assessor and must not be cited as current verification.
See `SECURITY.md`, `docs/compliance/nist-800-53-mapping.md`, and
`docs/compliance/gap-analysis.md` for full technical detail.*
