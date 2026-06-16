# Win32 probe — status & planned changes (2026-06-16)

Saved end of session, before bed. Nothing here is pushed; all on local branch
`experiment/win32-probe`. `master` = `origin/master` = v1.4.0, untouched.

## Mesh context
The only agents/windows that matter for this work:
- **Claude 1** (me)
- **Codex 1**
- **Role-migration Claude**

Every other Notepad window on the desktop is legacy/unrelated — **never a target**.

## Done this session (all green unless noted)
| File | Status | Notes |
|------|--------|-------|
| `tpm_identity.py` | ✅ PASS | TPM ECDSA P-256 create → sign → verify; hardware-backed. |
| `named_pipe_identity.py` | ✅ PASS | OS-verified caller SID via `ImpersonateNamedPipeClient`; spoofed payload ignored. **Hardened**: explicit `HANDLE`/`BOOL` argtypes (applied Codex's ctypes ABI finding). |
| `uia_read.py` | ✅ PASS | Structured window enumeration + TextPattern string read (no pixels) + UIA event-handler registration. |
| `run_all.py` | ✅ | Summary runner. |
| `uia_write.py` | ⛔ QUARANTINED | Write/inject worked via `ValuePattern.SetValue`, but targeting was unsafe — see incident. Disabled at `__main__`. |
| `_check_state.py` | ✅ | Read-only Notepad content inspector (used for incident triage). |

## Incident — must fix before re-enabling any write
`uia_write.py` selected targets by **title substring** ("Untitled"/"Notepad") and called
`SetValue` on **every** match, overwriting the in-memory contents of unrelated user
Notepad windows (including one holding an API key and various notes). **Nothing was saved
to disk** (all windows kept their unsaved `*` marker); files intact, Ctrl+Z restores.
User confirmed the affected windows were legacy and disposable.

**Root cause:** target selection by title, not by ownership.
**Fix (item 1 below):** only ever touch a window this probe spawned, pinned by PID/HWND;
refuse to write to any window it didn't create; refuse if more than one candidate.

## Planned changes (to do together next session)
1. ✅ **DONE — Safe write rewrite** (`uia_write.py`): snapshot Notepad HWNDs → spawn →
   diff to the single new HWND → pin → write/read **only** that handle; verified.
2. **UIA upgrade**: ✅ live `TextChanged` delivery **PROVEN** (`uia_textchanged_fire.py` —
   fired 2× on streamed terminal output, delta returned the real new line; reusable path
   in `uia_textpattern.py`). ✅ **background/no-focus PROVEN** — fires 2× even with the
   console MINIMIZED (focus- and visibility-independent; ConPTY buffer is process-level).
   Remaining: select the scrollback by **ControlType=Text(50020)** rather than the
   longest-text heuristic; add **echo filtering** (PROBE-token: inject `SC_PROBE_xxxx`,
   ignore delta if it starts with the token); confirm on Windows Terminal TermControl
   (proven on conhost).
3. **TPM attestation**: `NCryptCreateClaim` (`NCRYPT_CLAIM_PLATFORM`) for a
   remote-verifiable hardware-residency proof; persist algo id for P-256/P-384 agility.
4. **Named pipe**: add a **negative DACL test** (deny → `ERROR_ACCESS_DENIED`); capture
   client integrity level / AppContainer SID, not just user SID.
5. **`chained_channel.py`**: UIA read → TPM-sign `(caller-SID, msg-hash)` → verify over
   the DACL pipe. The strong combined patent embodiment.
6. **`capability_matrix.json`**: machine-readable probe results for the mesh to consume.
7. **Regression guard** that does **not** break the CI `≥880` count gate (separate runner
   / pytest marker excluded from the gate — not dropped into `tests/`).
8. **Promote TPM probe into `enterprise/`** behind a feature flag (disabled by default) —
   only after attestation (item 3) lands. Park, strengthen, then promote; never break the
   existing path.
9. **Capability registry + read waterfall** (from Codex / mesh convergence): a
   `probe_capabilities()` that returns a dict (`uia_text`, `uia_events`, `printwindow`,
   `tpm_identity`, …) so each Win32 capability is a **probed adapter, not a hardcoded
   dependency**. Read path degrades gracefully: UIA TextChanged event → UIA text poll →
   `WM_GETTEXT` children → PrintWindow/OCR → screenshot. This is the cross-machine /
   cross-config robustness layer; `capability_matrix.json` (item 6) is its serialized form.
10. **Mesh routing table off WM_CHAR** (from Role-migration Claude / mesh): peer
    announcements and hwnd updates must NOT travel over `WM_CHAR` — that's the user-facing
    terminal input channel, and it also tripped the Claude Code auto-mode classifier.
    Move routing metadata to a shared **JSON routing table** updated over the DACL named
    pipe (item 4): each agent writes its own entry `{hwnd, pipe, last_seen}`, reads
    others'. Migration becomes a file/pipe write, not an injection. Relevant agents:
    Claude 1, Codex 1, Role-migration Claude.

## Rollback (unchanged)
- Abandon everything: `git checkout master`
- Restore from GitHub even if master got dirty: `git fetch && git checkout master && git reset --hard origin/master`
