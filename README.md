# SelfConnect Enterprise

**Win32-native AI agent infrastructure for government and regulated enterprise deployment.**

Built on the [SelfConnect SDK](https://github.com/rblake2320/selfconnect) — the OS-native bridge
between AI agents and Windows desktop applications using Win32 IPC primitives.

---

## What This Is

SelfConnect Enterprise extends the core SDK with capabilities required for production,
air-gapped, and compliance-regulated environments:

| Capability | What It Solves |
|---|---|
| **SetProp/GetProp Agent Registry** | Zero-infrastructure mesh discovery — no config files, no stale entries |
| **Terminal Birth Tags** | OS-native agent identity certificates anchored to live window handles |
| **WM_COPYDATA Transport** | 64KB atomic JSON payloads with OS-verified sender identity |
| **Named Event Coordination** | Zero-polling agent synchronization — sub-millisecond latency |
| **Hidden Desktop Execution** | Invisible agent mesh for production deployment |
| **BEA Compliance Layer** | DoD Business Enterprise Architecture alignment artifacts |
| **JSONL Observer Logging** | Structured execution evidence for distillation pipeline ingestion |
| **Multi-Teacher Distillation** | Continuous local model improvement from verified agent interactions |

---

## Architecture

```
selfconnect-enterprise/
├── sdk/                    ← selfconnect SDK (git submodule, pinned to v1.0.0-session15)
│   └── self_connect.py     ← Core: WM_CHAR injection, UIA readback, mesh spawn
│
├── enterprise/             ← Enterprise layer (this repo)
│   ├── registry.py         ← SetProp/GetProp agent registry + BirthTag
│   ├── transport.py        ← WM_COPYDATA structured payload transport
│   ├── coordination.py     ← Named Events zero-polling sync
│   ├── hidden_desktop.py   ← CreateDesktop invisible execution environment
│   └── observer_jsonl.py   ← Structured JSONL event logging for distillation
│
├── compliance/             ← Government/DoD deployment
│   ├── bea_mapping.py      ← BEA reference model alignment artifacts
│   └── audit_export.py     ← Tamper-evident log export in BEA-compatible format
│
├── distillation/           ← Multi-teacher training pipeline
│   ├── formatter.py        ← Observer JSONL → LoRA training rows
│   └── trainer.py          ← Nightly LoRA fine-tune job on local model
│
└── tests/
    └── test_enterprise/    ← All tests, no live desktop required
```

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

sc_enterprise.py           →         Promoted here as enterprise/registry.py
                                      + enterprise/transport.py
                                      + enterprise/coordination.py
```

The SDK is the foundation. This repo builds the enterprise floor on top of it.

---

## Patent Coverage

This codebase contributes evidence for the following claims:

| Claim Set | Primitive | Status |
|---|---|---|
| Claim 1 (core) | WM_CHAR background injection → ConPTY | PROVED (selfconnect) |
| Claim 2 (new) | SetProp/GetProp zero-infra agent registry | PROVED (this repo) |
| Claim 3 (upgraded) | HWND + BirthTag structured self-discovery | PROVED (this repo) |
| Claim 4 (new) | WM_COPYDATA OS-verified structured transport | PROVED (this repo) |
| Claim 5 (pending) | Named Events zero-polling coordination | In progress |
| Claim 6 (pending) | CreateDesktop hidden execution environment | Planned |
| Claim 7 (pending) | BEA-compliant federated agent architecture | Planned |

---

## Government Deployment Story

SelfConnect Enterprise maps directly to DoD Business Enterprise Architecture (BEA) reference models:

- **Air-gap capable** — complete Win32 capability surface, zero external runtime dependencies
- **OS-attested identity** — HWND + PID + process creation time as unforgeable agent identity
- **Tamper-evident audit** — append-only JSONL event logs with execution evidence
- **Federated architecture** — orchestrator/domain/observer layers match BEA federated framework
- **Policy-gated approvals** — allow/deny/escalate rules engine on every tool call

---

## Quick Start

```bash
git clone --recurse-submodules https://github.com/rblake2320/selfconnect-enterprise
cd selfconnect-enterprise
pip install -e sdk/[full]
python -m enterprise.registry   # discover live mesh agents
```

---

## Status

| Module | Status |
|---|---|
| `enterprise/registry.py` | ✅ Built, 26 tests passing |
| `enterprise/transport.py` | ✅ Built, tests passing |
| `enterprise/coordination.py` | ✅ Built, tests passing |
| `enterprise/hidden_desktop.py` | 🔲 Planned |
| `compliance/bea_mapping.py` | 🔲 Planned |
| `distillation/formatter.py` | 🔲 Planned |

SDK submodule pinned to: `v1.0.0-session15`
