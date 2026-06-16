# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, Cursor, etc.) working in this
repository. This is the tool-agnostic source of truth; `CLAUDE.md` points here.

## What this repo is

**SelfConnect Enterprise** — a Win32-native policy enforcement and audit substrate
for AI agent meshes on Windows. It is the **governance/security layer** built on top
of the [SelfConnect SDK](https://github.com/rblake2320/selfconnect) (vendored as the
`sdk/` submodule).

Every agent action passes through a **deny-by-default** policy evaluator, every
decision is written to a **tamper-evident SHA-256 hash chain**, and evidence is
**filtered by classification label** before it can reach a training pipeline or be
exported. Classified deployments enforce egress restrictions, export gating, and CNG
identity requirements through an immutable deployment profile.

> **This repo is NOT for keystroke injection.** WM_CHAR/PostMessage injection lives in
> the original SelfConnect SDK. Enterprise has diverged and will fail for injection
> tasks — never add injection logic here.

## Layout

| Path | What lives there |
|------|------------------|
| `enterprise/` | The product. Policy, identity, ledger, transport, classification, guards. |
| `tests/test_enterprise/` | The full test suite (~35 modules incl. red-team, fuzz, supply-chain). |
| `tests/test_e2e_ultra_gate.py` | E2E tests that need a live Ultra Server — **skip cleanly** without one (the 21 known CI skips). |
| `sdk/` | SelfConnect SDK submodule, pinned to commit `8cf151d` (v1.0.0-session15). |
| `tools/wfp_policy.py` | Windows Filtering Platform policy generator. |
| `bench/` | Signing benchmarks. |
| `docs/`, `SECURITY.md`, `GAPS.md`, `TEST_REGISTRY.md` | Security guarantees, POA&M gap analysis, test registry. |
| `compliance/`, `distillation/`, `ultra_server/` | Supporting packages. |
| `.github/workflows/ci.yml` | Authoritative lint + test + count gate. |

### Key modules (`enterprise/`)

`policy.py` (9-step deny-by-default enforcer) · `policy_sign.py` (ECDSA P-384 bundle
signing) · `ledger.py` / `identity_cng.py` (hash-chained, CNG-backed ledgers) ·
`identity.py` (DPAPI ed25519 identity) · `crypto.py` (NCrypt P-384/SHA-384) ·
`labels.py` (classification enum + Bell-LaPadula) · `classified_mode.py` (immutable
deployment profile) · `egress_guard.py` / `export_guard.py` (outbound + export gating)
· `control.py` (pause/quarantine/revoke/kill_all) · `observer.py` (training-data
isolation) · `registry.py` / `transport.py` (SetProp registry, WM_COPYDATA transport)
· `provenance.py`, `ultra_gate.py`, `version_gate.py` (v1.4.0 hardening).

## Build & test commands

```bash
pip install -e .[dev]        # Python >= 3.10 (CI uses 3.12); also: pip install pywin32
python -m ruff check enterprise tests tools   # lint — must be clean
python -m pytest -q --tb=short                 # full suite
python scripts/run_all_tests.py                # convenience runner
```

CI (`.github/workflows/ci.yml`, `windows-latest`) is authoritative. Its count gate
requires **≥ 880 passing, 0 failed, and exactly 21 skipped** — those 21 are the
`test_e2e_ultra_gate.py` cases that need a live Ultra Server. Any other skip fails CI.
Run the full suite locally on Windows before claiming a change is done; many tests
exercise Windows CNG/NCrypt/DPAPI and are platform-specific.

Ruff config (`pyproject.toml` / `ruff.toml`): line length 120, target py310,
rules `E,F,I,RUF` (ignore `RUF022`).

## Non-negotiable rules for agents

1. **Never weaken a security invariant to make a test pass.** Each guarantee in
   `SECURITY.md` is backed by a named test (training-data isolation, classification
   ceiling, hash-chain integrity, control-plane thread safety, signed-policy ceiling
   bypass). If a change touches these, add/extend a test that proves the property
   still holds — don't loosen the assertion.
2. **Deny-by-default stays default.** The policy pipeline denies unless explicitly
   allowed. Do not invert that, and do not add allow-by-default fast paths.
3. **Classification isolation is absolute.** Denied decisions and entries above the
   ceiling must never reach the training pipeline or `EvidenceExporter`. Egress and
   export only through `EgressGuard` / `ExportGuard`.
4. **No injection code here.** See the note above — injection belongs in the SDK.
5. **Don't bump the `sdk/` submodule pin** (`8cf151d`) unless explicitly asked; it's
   pinned by commit hash on purpose.
6. **Keep claims true.** This project's posture is "verified, not claimed" — if you
   say something is tested, point to the test. Match the README/CHANGELOG/SECURITY
   numbers to reality (note: the README prose still cites the older 716-test figure;
   trust the CI gate, not stale prose).
7. **Match surrounding style** — small, focused diffs; every changed line traces to
   the request; no opportunistic refactors of adjacent code.

## Gotchas

- **Windows-only.** CNG/NCrypt/DPAPI/WM_COPYDATA paths require Windows + `pywin32`.
- The repo has shipped past the README's headline version — current release tag is
  **v1.4.0** (`pyproject.toml` may lag at `1.2.3`; the git tag is authoritative).
- `tmp_path` retention is off (`pyproject.toml`), so test temp dirs are cleaned each run.
