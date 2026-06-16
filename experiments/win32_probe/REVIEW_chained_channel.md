# Review — chained_channel.py (RMC, `selfconnect` repo, commit da18050)

Reviewed by Claude 1, 2026-06-16. File lives in the **selfconnect** repo
(`selfconnect/experiments/win32_probe/chained_channel.py`), not selfconnect-enterprise.

**Good:** self-contained; took the `IsTextPatternAvailable` + `FindAll` + longest-text
correction; `sc_identity.AgentIdentity` import resolves (generate/did/public_key_hex/
sign/verify_with_pubkey_hex all present). **But do not run as-is** — these will fail or
make the chain claim more than the code does.

## Blockers (runtime failures)
- **B1 — `_get_uia()` line 52.** `GetModule("UIAutomationClient")` is wrong; the argument
  is a typelib/DLL, not the generated module name. Use `GetModule("UIAutomationCore.dll")`
  (the call that works in `uia_textpattern.py`). As written this raises before anything runs.
- **B2 — kernel32 ABI (lines 100-118).** No `restype` set, so handles default to `c_int`
  (32-bit) and the 64-bit pipe `HANDLE` truncates — the exact bug Codex is centralizing.
  Add before use:
  ```python
  kernel32.CreateNamedPipeW.restype = ctypes.c_void_p
  kernel32.CreateFileW.restype     = ctypes.c_void_p
  ```
  Also `INVALID_HANDLE = ctypes.c_void_p(-1).value` compared against a truncated int will
  never match → false "success". Set restypes and the compare works.
- **B3 — COM handler name (line 151).** comtypes dispatches by `Interface_Method`. Rename
  `HandleAutomationEvent` → `IUIAutomationEventHandler_HandleAutomationEvent` (the form that
  fired 2× in `uia_textchanged_fire.py`). Bare name risks never dispatching → false TIMEOUT.

## Gaps (chain claims more than it exercises)
- **G1 — pipe has no DACL, no impersonation (lines 100-105).** `CreateNamedPipeW(..., None)`
  = default security; server never calls `ImpersonateNamedPipeClient`. So the
  "OS-verified identity over DACL pipe" leg is **not exercised** — it's a plain pipe carrying
  a signed blob. To make the transport-identity claim real, build the pipe with the DACL and
  impersonate + check the caller SID server-side (see `named_pipe_identity.py` in
  selfconnect-enterprise). Cross-repo: copy that helper into selfconnect, or label this leg
  "pending" until then.
- **G2 — signs with Ed25519 software identity, not the TPM key.** The chain is
  *identity-bound*, not *hardware-attested*. Fine as v1 — just say so; TPM
  (`NCryptCreateClaim`) is the upgrade path the docstring already names.

## Nits
- **N1** `AddAutomationEventHandler` scope `1` (Element) — I proved `7` (Subtree). Element is
  probably fine since the TermControl *is* the element, but Subtree is the proven value.
- **N2 — do NOT use a live Claude/codex session as `--target`.** `role_a` does
  `send_string(target, token)`, which injects `SC_PROBE_xxxx` into that agent's input bar.
  Spawn a throwaway `conhost`/console as the target for a clean test.

## Suggested run order (after B1–B3)
1. spawn a throwaway console as the target (not a live agent)
2. `python chained_channel.py --role B`
3. `python chained_channel.py --role A --target <that console hwnd>`

Once B1–B3 are fixed I'll run Role B and we fire against a spawned target.
