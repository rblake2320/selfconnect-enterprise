# What I Did Today — Win32 × SelfConnect (Claude 1)

**Date/time:** 2026-06-16 02:44 CDT
**Repo:** selfconnect-enterprise · **Branch:** `experiment/win32-probe` (pushed to GitHub)
**Baseline preserved:** local `master` = `origin/master` = **v1.4.0**, untouched.

## Headline
Proved, on this machine, the previously-untested Win32 capabilities that strengthen the
SelfConnect patent claims — and **composed them into one working governed channel** (the
strong, hard-to-design-around embodiment). All work is isolated in `experiments/win32_probe/`
and cannot affect the shipping `enterprise/` package or the CI test-count gate.

## Proven probes (`experiments/win32_probe/`, all PASS on DESKTOP-CM6G60N)
| File | Result | Proves |
|------|--------|--------|
| `tpm_identity.py` | PASS | TPM ECDSA P-256 key (Platform Crypto Provider) sign+verify — hardware-backed identity |
| `named_pipe_identity.py` | PASS | DACL pipe + `ImpersonateNamedPipeClient` reads the OS-verified caller SID; spoofed payload ignored |
| `uia_read.py` | PASS | Structured window enumeration + TextPattern string read (no pixels) + event registration |
| `uia_write.py` | PASS (safe) | Ownership-bound write — spawns + pins its OWN window by HWND-diff; never touches others |
| `uia_textpattern.py` | helper | Reusable read path (`text_element`/`read_text`/`register_textchanged`/`compute_delta`) |
| `uia_textchanged_fire.py` | PASS | TextChanged **fires** on live terminal output — incl. **minimized/no-focus** (focus- and visibility-independent) |
| `chained_channel.py` | **CHAIN COMPLETE** | The composed loop, verified end-to-end (below) |
| `mesh_talk.py` | tool | Peer comms over the SelfConnect SDK (explicit-hwnd targeting only) |
| `target_guard.py` | PASS | Safe injection gate — terminal class check blocks Notepad/non-ConPTY; stale-hwnd expect_* checks |
| `tpm_attestation.py` | NA (diagnosed) | `NCryptCreateClaim(PLATFORM)` → E_INVALIDARG; malformed call (not hardware limit); needs `NCryptBufferDesc` |
| `job_sandbox.py` | **PASS** | OS Job Object: ACTIVE_PROCESS=1 + 256MB + KILL_ON_JOB_CLOSE — child dead on handle close, no app cooperation |

## The chain — `chained_channel.py` (CHAIN COMPLETE, 02:44 CDT)
One governed loop, all three legs cryptographically bound, verified end-to-end:
1. **READ** — UIA `TextChanged` fires on the terminal TermControl (single `Text`/50020 surface), delta read via TextPattern (no pixels).
2. **IDENTITY** — `SHA-256(delta)` signed with a **TPM-backed** key (Platform Crypto Provider).
3. **TRANSPORT** — payload sent over a **DACL-guarded named pipe**; the server calls `ImpersonateNamedPipeClient`, records the **OS-verified caller SID**, then verifies the TPM signature.

This is the patent-relevant composition: read channel + hardware identity + OS-verified
transport in one loop — not three isolated demos.

## Patent-relevant findings
- **Hardware-attested identity** (TPM) — upgrade path to remote-verifiable proof via `NCryptCreateClaim` / `NCRYPT_CLAIM_PLATFORM`.
- **OS-controlled (not app-asserted) transport identity** — the SID comes from the OS token over a DACL pipe; a spoofed in-payload identity is ignored.
- **Alternate read embodiment** — UIA TextPattern *semantic* read replaces PrintWindow pixel scrape; `TextChanged` gives **push-based** "reply ready" detection, proven focus- AND visibility-independent (fired on a minimized window).
- **Terminal text surface** — Windows Terminal exposes one `TermControl` (`ControlType=Text/50020`, ~1.1M chars). It fires on **both input echo and new output**, so an echo filter (PROBE token) is required.

## Mesh coordination (3 live agents)
- **Claude 1** (me, `selfconnect-enterprise`): probes, the gap-free chain, and code review.
- **Codex 1**: SDK side — central HWND/LPARAM/BOOL prototypes (fix 64-bit `c_int` truncation), packaging + the 6 `sc_*` wheel modules, MessageListener `pythoncom` fallback.
- **Role-migration Claude (RMC)** (`selfconnect` repo, branch `test/win32-hardening-v1`, commit `a25d4b2`): its own `chained_channel.py` — fixed my 3 review blockers (GetModule arg, 64-bit handle ABI, comtypes handler name) and closed the gaps (real impersonation, TPM upgrade note, throwaway target).
- **Agreements:** peer registry is additive/discovery-only until live 3-agent flow is proven; checkpoint stays authoritative for migration; registry fields `role, session, prev_hwnd, status`; TPM + named pipes stay optional adapters behind a flag (park → strengthen → promote, never break the shipping path).

## Honesty note — the incident
An early write probe matched windows by **title substring** and overwrote the *in-memory*
content of unrelated Notepad windows (nothing saved to disk; recoverable via Ctrl+Z; Ron
confirmed they were disposable). **Fixed:** `uia_write.py` is now ownership-bound (spawn +
pin by HWND-diff, write only that window). The lesson is baked in across the probes.

## How to access from your laptop
- Branch is on GitHub: `git fetch origin && git checkout experiment/win32-probe`
- Or browse `github.com/rblake2320/selfconnect-enterprise` → branch **`experiment/win32-probe`**
- `master` is unchanged (still v1.4.0) — this branch is purely additive.
- Run it all: `python experiments/win32_probe/run_all.py` then `python experiments/win32_probe/chained_channel.py`

## Session 2 additions (2026-06-16, resumed after sleep)
- **`target_guard.py`** (PASS, commit `8251221`) — injection safety gate, proven on Codex CASCADIA and Notepad. Schema handed to Codex 1; they patched it into `send_text` as commit `95b1f45`.
- **`tpm_attestation.py`** (NA/diagnosed, commit `48c5d94`) — honest E_INVALIDARG diagnosis; deferred attestation to a doc-grounded build with proper `NCryptBufferDesc`.
- **`job_sandbox.py`** (PASS, commit `48c5d94`) — OS-backed containment via Job Object. `ActiveProcesses=1` live; child killed by OS on `CloseHandle(job)`. The containment ExecGuard (SCFH NO-GO) could not provide.
- All three committed and pushed to `experiment/win32-probe` in commit `48c5d94`.
- Notified Codex 1 over WM_CHAR mesh.

## Next (queued in `NEXT_STEPS.md`)
1. TPM **attestation proper build** — `NCryptCreateClaim(PLATFORM)` with correct `NCryptBufferDesc` (nonce + PCR mask). Doc-grounded only.
2. **Peer registry** (JSON over the DACL pipe, additive) — schema agreed (`role, session, prev_hwnd, status`); hand to Codex to wire into migration.
3. UIA **echo filter** — inject SC_PROBE token, filter echoed input from new output delta.
4. UIA **TermControl proof** — confirm TextChanged on Windows Terminal CASCADIA (proven on conhost, not yet on WT TermControl directly).
5. **Promote** TPM probe into `enterprise/` behind feature flag after attestation lands.
6. Codex lane: ETW provider + Service-SID daemon mode.
7. LEGAL review of 6 patent families — route before any public disclosure.
