# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in this repository.

**The full, tool-agnostic guidance lives in [`AGENTS.md`](AGENTS.md). Read it first.**
It covers what this repo is, the module map, build/test commands, and the
non-negotiable security rules. Everything below is Claude-Code-specific and additive.

## TL;DR

SelfConnect Enterprise is the **Win32 governance/security layer** (deny-by-default
policy, tamper-evident ledger, classification-gated evidence) built on the SelfConnect
SDK (`sdk/` submodule). **It is not for keystroke injection** — that lives in the SDK.

## Quick commands

```bash
pip install -e .[dev]                          # + pip install pywin32 on Windows
python -m ruff check enterprise tests tools    # lint (must be clean)
python -m pytest -q --tb=short                 # full suite
```

CI gate (`.github/workflows/ci.yml`): **≥ 880 passing, 0 failed, exactly 21 skipped**
(the 21 are `test_e2e_ultra_gate.py`, which need a live Ultra Server). Run the suite on
**Windows** — most tests touch CNG/NCrypt/DPAPI and are platform-specific.

## Hard rules (see AGENTS.md for the full list)

- Never weaken a security invariant to make a test pass; prove the property with a test instead.
- Deny-by-default and classification isolation are absolute — don't add allow-by-default paths or export bypasses.
- No injection code here. Don't move the `sdk/` submodule pin (`8cf151d`) unless asked.
- Small, focused diffs; every changed line traces to the request.

## Relationship to the parent PKA workspace

This repo is a submodule of the PKA testing workspace. When the parent workspace's
rules conflict with engineering work *inside this repo*, this file and `AGENTS.md`
govern the code here; the parent `CLAUDE.md` still governs workspace-level routing and
delivery conventions.
