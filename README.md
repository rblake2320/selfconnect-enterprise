# SelfConnect Enterprise

**Win32-native AI governance components for regulated enterprise integration.**

Built on the [SelfConnect SDK](https://github.com/rblake2320/selfconnect) — the OS-native bridge
between AI agents and Windows desktop applications using Win32 IPC primitives.

**v1.2.3 — engineering prototype; test and runtime evidence are commit- and deployment-specific**

---

## What This Is

SelfConnect Enterprise provides policy, identity, operator-control, target-validation, and
audit components for AI agent meshes on Windows. `GovernedRuntime` composes those controls so
MCP text actuation fails closed unless a live target binding, externally pinned signed policy,
required operator approval, and persistent signed ledger are present. Direct use of lower-level
modules is not automatically intercepted by that runtime.

This repository is not an IRS authorization, ATO, IATT, FIPS validation, or legal compliance
determination. Deployment claims require live conformance evidence and review in the actual
system boundary.

---

## Module Surface

| Module | Purpose |
|--------|---------|
| `enterprise/registry.py` | SetProp/GetProp agent registry, BirthTag, `discover_mesh()`, heartbeat |
| `enterprise/transport.py` | WM_COPYDATA structured payload transport (64KB atomic JSON; sender HWND is caller-supplied and requires separate validation) |
| `enterprise/identity.py` | Persistent ed25519 identity with current-user DPAPI protection at rest; not hardware-bound |
| `enterprise/identity_cng.py` | CNG-backed identity + CngLedger (ECDSA P-384, SHA-384); FIPS status depends on the validated Windows module and configuration |
| `enterprise/ledger.py` | AgentLedger — signed, tamper-evident SHA-256 chain with verified local segment lifecycle; external witnessing remains separate |
| `enterprise/provenance_service.py` | Dedicated service-SID provenance writer for hardened profiles; installed-service evidence is deployment-specific |
| `enterprise/crypto.py` | NCrypt ECDSA P-384 / SHA-384 primitives via Windows CNG |
| `enterprise/policy.py` | PolicyEnforcer — deny-by-default decision pipeline plus composition gate |
| `enterprise/policy_sign.py` | ECDSA P-384 policy bundle signing and verification; coverage is run-specific |
| `enterprise/operator.py` | One-time context-bound approvals; SQLite WAL durable queue for governed runtime |
| `enterprise/control.py` | ControlPlane — pause / quarantine / revoke / kill_all state machine |
| `enterprise/governed_runtime.py` | Mandatory enterprise composition for policy, approval, target binding, identity, and signed audit |
| `enterprise/irs_evidence.py` | Structured IRS integration evidence records; not an IRS system-of-record submission |
| `enterprise/uia_output.py` | Fail-closed UIA TextPattern output adapter used by governed MCP readback |
| `ultra_server/` | Signed BPC+TSK lifecycle sidecar; fail-closed shadow boundary, bounded rate limits, key rotation, development memory mode, and PostgreSQL/Redis production mode |
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

Enterprise and Government runtime evidence is written through the dedicated
Windows service described in [docs/PROVENANCE_SERVICE.md](docs/PROVENANCE_SERVICE.md).
There is no automatic in-process fallback for those profiles.

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

# These calls are profile-gated; direct paths remain outside this boundary.
decision = enforcer.check("SC-AGENT1", "read_text", identity_type="cng")
ok       = egress.check_outbound("api.anthropic.com", "SC-AGENT1")
can_exp  = export.check_and_log(label, "SC-AGENT1")
```

---

## Test Suite

```bash
python -m ruff check .
python -m pytest -q
```

Results are evidence for the exact commit and environment in which they ran. Do not reuse a
historical count as a release-wide or deployed-runtime claim.

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

### Ultra identity sidecar

Ultra Server 1.3 verifies body-bound Ed25519 lifecycle proofs, derived agent
identity, timestamp/nonce freshness, ownership, and operator-authorized first
enrollment. Its production mode refuses to start without PostgreSQL, Redis,
operator authorization, and a distinct recovery HMAC key. Live CI builds exact
BPC/TSK source commits, exercises Python-to-Node verification, tests concurrent
HOTP replay protection, restarts the process, and verifies identity continuity.
See [`ultra_server/README.md`](ultra_server/README.md).

This establishes the tested sidecar propositions only. It does not establish
TPM attestation, approved secret custody, a partner deployment, an ATO, or a DoD
Impact Level authorization.

---

## Implementation Evidence

| Claim Set | Primitive | Status |
|---|---|---|
| Claim 1 (core) | WM_CHAR background injection → ConPTY | Implemented in SelfConnect; cite a dated live artifact for reduction-to-practice |
| Claim 2 (new) | SetProp/GetProp zero-infra agent registry | Implemented and exercised by named registry tests |
| Claim 3 (upgraded) | HWND + BirthTag structured self-discovery | Implemented and exercised by named discovery tests |
| Claim 4 (new) | WM_COPYDATA structured transport | Implemented and exercised; OS sender identity alone does not make application-level spoofing impossible |
| Claim 5 (new) | Deny-by-default signed policy enforcement | Narrowly established for `PolicyEnforcer` and mandatory `GovernedRuntime` paths by named tests |
| Claim 6 (new) | Policy-filtered training data pipeline | Narrowly established for primary records and filtered context windows by named tests |
| Claim 7 (new) | Classification-gated evidence export | Narrowly established for calls routed through `ExportGuard` |

---

## Quick Start

```bash
git clone --recurse-submodules https://github.com/rblake2320/selfconnect-enterprise
cd selfconnect-enterprise
pip install -e .
python -m pytest tests/ -q
```

The canonical SDK, BPC, and TSK source identities are recorded in
[`portfolio-lock.json`](portfolio-lock.json). Release conformance verifies the
installed SDK's `direct_url.json` commit and the checked-out protocol commits
and package metadata against that lock. It does not infer source identity from
tags, branch names, release titles, or feature documents.

---

## Security & Testing Overview

Named tests establish specific component propositions. They do not establish an authorization,
an entire deployed-system posture, or behavior on paths outside their scope. Live Windows
actuation can be assessed with `tools/irs_runtime_conformance.py` without mock targets.

### Test pyramid

| Layer | File(s) | What it covers |
|-------|---------|----------------|
| Logic / unit | `test_policy.py`, `test_observer.py`, `test_ledger.py`, … | Core invariants, decision paths, edge cases |
| Red team (adversarial) | `test_redteam.py` (RT-01–RT-20, 59 tests) | 20 attack categories: policy bypass, sig tamper, classification spoof, training poisoning, control plane bypass, hash chain forgery, race conditions |
| Adversarial AI | `test_adversarial_ai.py` (17 tests) | AI-specific attacks: training data poisoning via LedgerObserver, classification ceiling bypass via signed policy escalation, ControlPlane race conditions, approval token replay, agent self-revival |
| Dependency integrity | `test_dependency_integrity.py` (21 tests) | Axios-style supply chain (IOC registry, install hooks), module shadow attack, MCP tool metadata injection scanner, git dep commit-hash pinning |
| Supply chain / zero-day | `test_supply_chain.py` | LiteLLM backdoor gate, declared `cryptography>=48.0.1` environment gate, SECT curve static scan, `x509.verification` static scan, WFP script determinism + tamper detection, pip-audit hard gate on direct deps |
| Property-based fuzz | `test_fuzz.py` (15 tests, Hypothesis) | 200+ examples per boundary across `AllowEntry.parse()`, `PolicyBundle.from_dict()`, `WfpProfile._sanitize_ps_string()` |
| Concurrency stress | `test_stress_concurrent.py` (8 tests) | 50–100 thread stress on ControlPlane, OperatorQueue, AgentLedger; documents single-writer contract |
| Resource exhaustion | `test_resource_exhaustion.py` (10 tests) | 10k ledger entries, 1k queue, 500-agent bundles, 200 WFP rules — timing budgets enforced |

### Compliance documentation

| Document | What it contains |
|----------|-----------------|
| [`GAPS.md`](GAPS.md) | Canonical cross-component gap and limitation registry |
| [`docs/compliance/gap-analysis.md`](docs/compliance/gap-analysis.md) | Preliminary control mapping and remediation record; not an assessed POA&M |
| [`docs/assurance/SECTOR_PROFILES.md`](docs/assurance/SECTOR_PROFILES.md) | Product-neutral government, tax, healthcare, and financial-services claim boundaries |
| [`docs/assurance/CONTROL_CATALOG.md`](docs/assurance/CONTROL_CATALOG.md) | Tiered executable assertions, evidence locations, and named blind spots |
| [`SECURITY.md`](SECURITY.md) | Bounded component properties, explicit non-guarantees, test citations |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-version security deliverables and gap status |
| [`LOG.md`](LOG.md) | Chronological, commit-specific work and validation evidence |
| [`WHY.md`](WHY.md) | Decision rationale, alternatives, consequences, and rollback triggers |
| [`PARKED.md`](PARKED.md) | Restorable prior wording, code, configuration, and behavior |

### Key invariants (each narrowly established by a named test)

| Tested proposition | Established by |
|-----------|-----------|
| Observer export filtering — denied primary records and denied context are excluded on this path | `test_only_allow_decisions_reach_training_data`, `test_context_window_does_not_include_denied_in_output` |
| Observer classification ceiling — entries above max do not reach EvidenceExporter on this path | `test_observer_never_passes_above_max_classification` |
| Hash chain integrity — retroactive modification detected | RT-11, RT-12 |
| Control plane thread safety — exactly one revoke wins under contention | RT-09 |
| Classification ceiling bypass via signed policy blocked | `TestClassificationCeilingBypass` |
| LedgerObserver G-3 closed — extract() requires verifier bound to ledger | `test_observer_reads_without_verify_documents_gap` |
| allowed_policy_ids allowlist blocks injected training entries | `test_policy_id_allowlist_blocks_injected_training_entry` |
