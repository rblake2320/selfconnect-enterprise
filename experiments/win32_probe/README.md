# Win32 capability probes — `experiments/win32_probe/`

Throwaway-safe proofs that the **unexplored Win32 capabilities** from the
"Win32 × SelfConnect" map actually work **on this machine**, prioritized by patent
strength. Each probe is self-contained, creates/deletes its own resources, and is
**not imported by the shipping `enterprise/` package** — so it cannot affect the CI
test-count gate or shipping behavior.

> **Isolation / version control (per Ron's constraint):**
> - `master` (local) is pinned to `origin/master` = the GitHub release (v1.4.0). It is
>   **untouched** — the "go back to how it started" anchor.
> - All experimental work lives on the local branch **`experiment/win32-probe`** and is
>   **never pushed**. GitHub does not change.
> - **Roll back everything:** `git checkout master`  (delete the branch with
>   `git branch -D experiment/win32-probe`).
> - **Restore from GitHub even if master got dirty:** `git fetch && git checkout master && git reset --hard origin/master`.

## Run

```bash
C:/Python312/python.exe experiments/win32_probe/run_all.py
# or individually:
C:/Python312/python.exe experiments/win32_probe/tpm_identity.py
```

Requires: Windows, `pywin32`, `comtypes` (all already installed under Python 3.12).

## Results on this machine (DESKTOP-CM6G60N, 2026-06-16)

| Probe | Result | What was proven |
|-------|--------|-----------------|
| `tpm_identity.py` | **PASS** | ECDSA **P-256** key created in the **Microsoft Platform Crypto Provider (TPM)**, signed an audit-style payload, verified OK. Hardware-backing inferred from the provider (`Impl Type` query returned `NTE_NOT_SUPPORTED` on this TPM — best-effort). |
| `named_pipe_identity.py` | **PASS** | DACL-guarded named pipe; server called `ImpersonateNamedPipeClient` and read the **OS-verified caller SID** (`S-1-5-21-…-1001`). The client's spoofed `identity=I-AM-ROOT` payload was **ignored** — identity came from the OS token, not the application. |
| `uia_read.py` | **PASS** | Enumerated **40 top-level windows** structurally (incl. 16 terminals — the live Claude sessions), read **text as strings via TextPattern (no pixels)** from 5 targets, and registered/removed a UIA event handler (push-based reply detection path). |
| `uia_write.py` | **PASS (safe)** | Rewritten after the 2026-06-16 overwrite incident: spawns Notepad, pins the single NEW window by HWND set-diff, verifies the UIA element handle matches, writes **only** that window, read-back verified. Never touches a window it didn't create. |
| `uia_textpattern.py` | **helper** | Reusable read path for `chained_channel.py`: `get_uia / text_element / read_text / register_textchanged / compute_delta`. Descend to the TermControl (longest-text TextPattern descendant), v1 `IUIAutomationTextPattern`. |
| `uia_textchanged_fire.py` | **PASS** | Live-fire proof: spawns a console (conhost), registers TextChanged on its text element, pumps the COM loop — event **fired 2× on streamed output**, delta read returned the real new line. Push-based read validated (Notepad RichEditD2DPT does NOT raise it; terminals do). |
| `mesh_talk.py` | **tool** | Peer comms (`list` / `send` / `read`) via the SelfConnect SDK; explicit-hwnd targeting only. |

## Patent mapping

| Probe | Claim family it strengthens | Why it's a distinct/stronger embodiment |
|-------|------------------------------|------------------------------------------|
| TPM identity | Machine-bound agent identity | Private key sealed to the TPM — a captured ledger/identity file **cannot forge signatures on another machine** (defeats cross-machine replay). Stronger than software-KSP/DPAPI keys. |
| Named-pipe identity | OS-verified transport / agent identity | Caller identity established by the **OS access-control layer** (pipe ACL + impersonation token), not application-asserted. The "OS-controlled vs app-controlled" distinction reviewers look for during an ATO. Complements the existing WM_COPYDATA OS-verified-*sender* claim. |
| UIA structured read | Read channel (alternate embodiment) | Replaces injection-+-visual-scrape with injection-+-**semantic structured read**: text-as-string via TextPattern + event-driven "reply ready" detection instead of a screenshot/poll loop. A documented alternate embodiment widens the claim. |

> Patent framing is for engineering record only — route claim language to LEGAL.

## Honest caveats

- **TPM curve:** this TPM accepted **P-256**, not the P-384 the software path ships.
  Production would store the algorithm id (crypto-agility is already designed into
  `enterprise/crypto.py`) and accept whichever curve the hardware supports.
- **UIA depth:** `TextPattern` returned real strings (tab titles + Notepad content),
  proving semantic extraction works. Reading the **full terminal scrollback** means
  targeting Windows Terminal's "Text Area" element specifically rather than the first
  TextPattern descendant — a refinement, not a blocker.
- **Nothing here is production code.** If a capability proves out, the next step is a
  proper module in `enterprise/` with tests, behind a feature flag (park/disable, never
  break the existing path).

## Deferred (not probed here, with reason)

| Capability | Why deferred |
|------------|--------------|
| ETW provider | Product/SIEM value, not a patent claim (standard MS facility). Worth doing for enterprise visibility, lower priority. |
| Windows ODR / MCP proxy | Needs verification of the Ignite-2025 product claims + MSIX packaging; can't validate the platform here. |
| DirectComposition overlay | UIA delivers most of the same benefit (delta/event-driven read) with far less complexity. |
| Arm64EC / Phi Silica | Need preview SDKs / Arm or Copilot+ hardware to test meaningfully; Phi Silica is a local-model concern, orthogonal to the governance layer. |
