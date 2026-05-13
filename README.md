# SelfConnect Enterprise

**Win32-native AI agent infrastructure for government and regulated enterprise deployment.**

Built on the [SelfConnect SDK](https://github.com/rblake2320/selfconnect) — the OS-native bridge
between AI agents and Windows desktop applications using Win32 IPC primitives.

**v1.2.0 — 714 tests passing — 0 failures — Continuously audited posture release**

---

## What This Is

A production-grade policy enforcement and audit substrate for AI agent meshes running on
Windows. Every agent action passes through a deny-by-default policy evaluator. Every decision
is logged to a tamper-evident hash chain. Evidence is filtered by classification label before
it reaches the training data pipeline. Classified deployments enforce egress restrictions,
export gating, and CNG identity requirements through an immutable deployment profile.

---

## Module Surface

| Module | Purpose |
|--------|---------|
| `enterprise/registry.py` | SetProp/GetProp agent registry, BirthTag, `discover_mesh()`, heartbeat |
| `enterprise/transport.py` | WM_COPYDATA structured payload transport (64KB atomic JSON, OS-verified sender) |
| `enterprise/identity.py` | Persistent machine-bound ed25519 agent identity (DPAPI) |
| `enterprise/identity_cng.py` | CNG-backed identity + CngLedger (ECDSA P-384, SHA-384, FIPS 140-2) |
| `enterprise/ledger.py` | AgentLedger — tamper-evident action log (SHA-256 hash chain) |
| `enterprise/crypto.py` | NCrypt ECDSA P-384 / SHA-384 primitives via Windows CNG |
| `enterprise/policy.py` | PolicyEnforcer — 9-step deny-by-default decision pipeline |
| `enterprise/policy_sign.py` | ECDSA P-384 policy bundle signing and verification (100% coverage) |
| `enterprise/operator.py` | Thread-safe operator approval queue for human-in-the-loop gates |
| `enterprise/control.py` | ControlPlane — pause / quarantine / revoke / kill_all state machine |
| `enterprise/observer.py` | LedgerObserver, ObserverFilter, EvidenceExporter, training pipeline |
| `enterprise/labels.py` | Classification enum, LabelEnvelope, rank(), le(), ALLOWED_CAVEATS |
| `enterprise/classified_mode.py` | ClassifiedModeProfile — immutable deployment profile |
| `enterprise/egress_guard.py` | Outbound call gating (enforces allow_cloud_egress) |
| `enterprise/export_guard.py` | Evidence export gating (enforces allow_export + ceiling check) |

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │        ClassifiedModeProfile         │
                    │  ceiling · caveats · egress · export │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────▼────────────────────────┐
              │              PolicyEnforcer                  │
              │  Step 0:   ControlPlane gate                 │
              │  Step 0.5: Profile ceiling + identity type   │
              │  Steps 1–8: Bundle checks + classification   │
              │  Step 8b:  Caveat validation                 │
              │  Step 9:   Operator approval gate            │
              └────────────────────┬────────────────────────┘
                                   │ PolicyDecision
              ┌────────────────────▼────────────────────────┐
              │         AgentLedger / CngLedger              │
              │  Signed, hash-chained JSONL entry            │
              │  + LabelEnvelope (classification + caveats)  │
              └────────────────────┬────────────────────────┘
                                   │
              ┌────────────────────▼────────────────────────┐
              │          LedgerObserver / ObserverFilter     │
              │  decision=allow only                         │
              │  classification ≤ max_classification         │
              │  caveats ⊆ allowed_caveats                   │
              └────────────────────┬────────────────────────┘
                                   │
              ┌────────────────────▼────────────────────────┐
              │    ExportGuard → EvidenceExporter            │
              │  allow_export=True AND label ≤ ceiling       │
              └─────────────────────────────────────────────┘
```

---

## Security Properties (summary)

The system enforces classification ceilings, signs and verifies policies, isolates training data
from denied actions, gates cloud egress and evidence export, and provides an operator kill-switch.
Full details, non-guarantees, and test references in [SECURITY.md](SECURITY.md).

---

## Deployment Profiles

Two hardened baselines are provided. Construct custom profiles via `ClassifiedModeProfile(...)`.

| Profile | Ceiling | CNG Required | Cloud Egress | Export | Operator Approval |
|---------|---------|-------------|-------------|--------|-------------------|
| `secret_baseline()` | SECRET | Yes | No | No | `export_content`, `write_file` |
| `cui_baseline()` | CUI | No | Yes | Yes | — |

```python
from enterprise.classified_mode import ClassifiedModeProfile
from enterprise.egress_guard import EgressGuard
from enterprise.export_guard import ExportGuard
from enterprise.policy import PolicyEnforcer

profile  = ClassifiedModeProfile.secret_baseline()
enforcer = PolicyEnforcer(bundle, require_signature=True, profile=profile)
egress   = EgressGuard(profile, ledger=ledger)
export   = ExportGuard(profile, ledger=ledger)

# All actions, egress, and exports are now profile-gated
decision = enforcer.check("SC-AGENT1", "read_text", identity_type="cng")
ok       = egress.check_outbound("api.anthropic.com", "SC-AGENT1")
can_exp  = export.check_and_log(label, "SC-AGENT1")
```

---

## Test Suite

```
528 tests   0 failures   88% coverage   ruff clean
```

| Test file | Count | What it covers |
|-----------|-------|----------------|
| `test_registry.py` | — | BirthTag, discover_mesh, heartbeat |
| `test_identity.py` | — | AgentIdentity, ledger chains |
| `test_identity_cng.py` | — | CngIdentity, CngLedger, SHA-384 |
| `test_policy.py` | — | 9-step enforcer, deny-by-default |
| `test_observer.py` | 81 | Training data isolation, filter |
| `test_control.py` | 59 | ControlPlane state machine |
| `test_redteam.py` | 59 | 20 adversarial attack categories |
| `test_labels.py` | 56 | Classification enum, LabelEnvelope, Bell-LaPadula |
| `test_classified_mode.py` | 40 | Profile, EgressGuard, ExportGuard, end-to-end |

---

## Relationship to SelfConnect SDK

```
selfconnect (SDK)                    selfconnect-enterprise
─────────────────────────────────    ──────────────────────────────────────
WM_CHAR injection          →         Foundation transport (submodule)
UIA text readback          →         Foundation receive channel (submodule)
list_windows()             →         Used by discover_mesh()
send_string()              →         Used for legacy compat
submit_claude_input()      →         Used by agent briefing scripts
```

The SDK is the foundation. This repo builds the enterprise governance layer on top of it.

---

## Patent Coverage

| Claim Set | Primitive | Status |
|---|---|---|
| Claim 1 (core) | WM_CHAR background injection → ConPTY | PROVED (selfconnect) |
| Claim 2 (new) | SetProp/GetProp zero-infra agent registry | PROVED (this repo) |
| Claim 3 (upgraded) | HWND + BirthTag structured self-discovery | PROVED (this repo) |
| Claim 4 (new) | WM_COPYDATA OS-verified structured transport | PROVED (this repo) |
| Claim 5 (new) | Deny-by-default signed policy enforcement | PROVED (v0.5.0+) |
| Claim 6 (new) | Policy-filtered training data pipeline | PROVED (v0.6.0+) |
| Claim 7 (new) | Classification-gated evidence export | PROVED (v0.8.0+) |

---

## Quick Start

```bash
git clone --recurse-submodules https://github.com/rblake2320/selfconnect-enterprise
cd selfconnect-enterprise
pip install -e .
python -m pytest tests/ -q
```

SDK submodule pinned to commit hash: `8cf151dbc5f312ce888e51aa429f62960e1a2ee6`

---

## Security & Testing Overview

The security posture is verified continuously — not claimed. Every guarantee
listed in [SECURITY.md](SECURITY.md) has a named test that proves it.

### Test pyramid (714 tests, 0 failures)

| Layer | File(s) | What it covers |
|-------|---------|----------------|
| Logic / unit | `test_policy.py`, `test_observer.py`, `test_ledger.py`, … | Core invariants, decision paths, edge cases |
| Red team (adversarial) | `test_redteam.py` (RT-01–RT-20, 59 tests) | 20 attack categories: policy bypass, sig tamper, classification spoof, training poisoning, control plane bypass, hash chain forgery, race conditions |
| Adversarial AI | `test_adversarial_ai.py` (17 tests) | AI-specific attacks: training data poisoning via LedgerObserver, classification ceiling bypass via signed policy escalation, ControlPlane race conditions, approval token replay, agent self-revival |
| Dependency integrity | `test_dependency_integrity.py` (21 tests) | Axios-style supply chain (IOC registry, install hooks), module shadow attack, MCP tool metadata injection scanner, git dep commit-hash pinning |
| Supply chain / zero-day | `test_supply_chain.py` (10 tests) | LiteLLM backdoor gate, `cryptography>=46.0.6` floor, SECT curve static scan, `x509.verification` static scan, WFP script determinism + tamper detection, pip-audit hard gate on direct deps |
| Property-based fuzz | `test_fuzz.py` (15 tests, Hypothesis) | 200+ examples per boundary across `AllowEntry.parse()`, `PolicyBundle.from_dict()`, `WfpProfile._sanitize_ps_string()` |
| Concurrency stress | `test_stress_concurrent.py` (8 tests) | 50–100 thread stress on ControlPlane, OperatorQueue, AgentLedger; documents single-writer contract |
| Resource exhaustion | `test_resource_exhaustion.py` (10 tests) | 10k ledger entries, 1k queue, 500-agent bundles, 200 WFP rules — timing budgets enforced |

### Compliance documentation

| Document | What it contains |
|----------|-----------------|
| [`docs/compliance/gap-analysis.md`](docs/compliance/gap-analysis.md) | POA&M: 7 gaps identified, G-2/G-5/G-7/G-8 closed, G-1/G-3/G-4/G-6 scheduled for v1.3.0 |
| [`SECURITY.md`](SECURITY.md) | Guarantees, explicit non-guarantees, test citations |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-version security deliverables and gap status |

### Key invariants (each proved by a named test)

| Guarantee | Proved by |
|-----------|-----------|
| Training data isolation — denied decisions never reach training pipeline | `test_only_allow_decisions_reach_training_data` |
| Classification ceiling — entries above max never reach EvidenceExporter | `test_observer_never_passes_above_max_classification` |
| Hash chain integrity — retroactive modification detected | RT-11, RT-12 |
| Control plane thread safety — exactly one revoke wins under contention | RT-09 |
| Classification ceiling bypass via signed policy blocked | `TestClassificationCeilingBypass` |
| LedgerObserver gap documented — injected entries leak without verify() | `test_observer_reads_without_verify_documents_gap` |
| allowed_policy_ids allowlist blocks injected training entries | `test_policy_id_allowlist_blocks_injected_training_entry` |
