# SelfConnect Enterprise — Rollback Procedures

Every flag introduced in Tier 2 has a documented rollback path. This document is the
authoritative reference. It lands with Tier 1 so it exists before any flag-gated code ships.

**Every rollback activation must:**
1. Set the override env var (documented below per flag)
2. Restart the affected agent process
3. Emit a ledger event with action `emergency_override_activated` and reason
4. Notify operator (log at WARN level, or via OperatorQueue if available)
5. File a root-cause task before re-enabling the flag

---

## Flag: `SC_HANDSHAKE=v2` (Tier 2a — Challenge-Response)

**Symptom requiring rollback:** Agents reject legitimate peers due to clock skew,
TPM contention under load, or WM_COPYDATA delivery failure.

**Rollback:**
```bash
# Set flag to v1 (trust-the-tag, original behavior) and restart agent
SC_HANDSHAKE=v1 python -m enterprise.agent_runner
```

**What v1 restores:** Discovery trusts SCID property at face value. No handshake.
Full functionality of pre-Tier-2 system.

**Root-cause checklist before re-enabling v2:**
- [ ] NTP synchronized across all mesh machines (skew must be <10s)
- [ ] Confirmed WM_COPYDATA delivery works between affected agents
- [ ] TPM not under sustained load (bench p95 < 50ms on affected machine)
- [ ] No UIPI integrity level mismatch between challenger and responder

---

## Flag: `SC_DISABLE_SIG_VERIFY=1` (Emergency — Signed Birth Tag Verifier)

**When to use:** Signed-tag verifiers are hard-rejecting legitimate v2 peers.
Common cause: clock skew causing tag freshness check to fail (tags older than 60s
are rejected even during grace period).

**Rollback:**
```bash
# Disable sig verification entirely — falls back to v1 trust model
SC_DISABLE_SIG_VERIFY=1 python -m enterprise.agent_runner
```

**Security impact:** Disabling sig verify returns to the pre-Tier-1 trust model.
No cryptographic verification of birth tags. Document in ledger immediately.

**Ledger entry to emit manually:**
```python
ledger.log(
    action="emergency_override_activated",
    result="SC_DISABLE_SIG_VERIFY=1",
    metadata={"reason": "<describe root cause>", "operator": "<name>"}
)
```

**Root-cause checklist before re-enabling:**
- [ ] Identify which agents were generating stale tags (>60s freshness violation)
- [ ] Fix clock sync or birth-tag re-sign cadence
- [ ] Re-run WRAITH red-team against the fixed configuration
- [ ] Set SC_SUNSET_V1 deadline forward by 14 days to allow clean re-rollout

---

## Flag: `SC_SUNSET_V1=<date>` (Tier 2c — v1 Peer Rejection)

**Symptom requiring rollback:** Sunset date hit but one or more nodes still running
v1 (not yet upgraded). Mesh fragments — v2 nodes hard-reject v1 peers.

**Rollback option A — Grace extension (preferred):**
```bash
# Push sunset date forward 14 days from today
SC_SUNSET_V1=2026-09-15 python -m enterprise.agent_runner
```
This keeps enforcement active but gives the stuck v1 node time to upgrade.

**Rollback option B — Disable sunset entirely:**
```bash
# Unset SC_SUNSET_V1 — falls back to warn-only mode, never hard-rejects
SC_SUNSET_V1="" python -m enterprise.agent_runner
```

**Root-cause checklist:**
- [ ] Identify the stuck v1 node and reason it hasn't upgraded
- [ ] Document the node in ledger: action=`v1_node_exception`, metadata includes hostname and reason
- [ ] Set a concrete upgrade deadline in the task tracker
- [ ] Re-enable sunset after that node is confirmed upgraded

---

## Flag: `SC_HARDENING=on` (Tier 2d — Process Mitigation Policies)

**Symptom requiring rollback:** A plugin or dependency fails to load after hardening
is applied. Common: ProcessImageLoadPolicy blocks a legitimate DLL from a network path.

**Important:** Mitigation policies are kernel-enforced and **cannot be unapplied** in
a running process. The only rollback is process restart with the flag off.

**Rollback:**
```bash
# Restart agent WITHOUT hardening flag
# (SC_HARDENING defaults to off if unset)
python -m enterprise.agent_runner
```

**Root-cause checklist before re-enabling:**
- [ ] Run `Process Monitor` during startup with `SC_HARDENING=on` to identify blocked DLL
- [ ] Determine if the DLL load is legitimate (if yes, whitelist via policy exception)
- [ ] If DLL comes from a UNC/network path: relocate it to local disk before re-enabling
- [ ] Re-run bootstrap test: clean agent + policy-enabled agent must both complete startup

**Re-enable one flag at a time:**
```bash
# Start with ASLR only (lowest risk)
SC_HARDENING_ASLR=on python -m enterprise.agent_runner

# Then add ExtensionPoint disable
SC_HARDENING_ASLR=on SC_HARDENING_EXT=on python -m enterprise.agent_runner

# Finally add ImageLoad policy
SC_HARDENING=on python -m enterprise.agent_runner
```

---

## Option B Identity Packet Fields (Gap C Closure — `SC_HANDSHAKE=v2`)

Introduced 2026-05-16. When `SC_HANDSHAKE=v2`, the responder emits an extended
identity packet with two additional fields beyond the original `ed25519_sig` /
`ed25519_pubkey` pair:

| Field | Type | Contents |
|-------|------|----------|
| `ed25519_pubkey` | hex str | 32-byte ed25519 public key |
| `ed25519_sig` | hex str | 64-byte ed25519 signature over `nonce:initiator_hwnd` |
| `platform_ksp_pubkey` | hex str | 97-byte P-384 public key (uncompressed point) |
| `platform_ksp_sig` | hex str | ECDSA P-384 / SHA-384 signature over `nonce ‖ ed25519_pubkey` |

Provider: **Microsoft Software Key Storage Provider** (NCrypt, user-bound).
NOT TPM-backed (Platform Crypto Provider is a separate future upgrade).

**What these fields narrowly establish:**
- a valid `platform_ksp_sig` over `(nonce || ed25519_pubkey)` establishes:
  1. **Fresh exchange binding** — nonce ties the signature to this handshake
  2. **Cross-key possession** — the responder had access to both private keys
     during the exchange; this does not identify a human or prove hardware custody

**`verify_peer()` enforcement steps:**
1. `agent_id == "SC-" + SHA384(platform_ksp_pubkey)[:8].upper()` — ID fingerprint check
2. `cng_verify(nonce ‖ ed25519_pubkey, platform_ksp_sig, platform_ksp_pubkey)` — Gap C closure
3. `ed25519_verify(nonce:initiator_hwnd, ed25519_sig, ed25519_pubkey)` — liveness check

**Rollback if `platform_ksp_*` fields cause peer rejection:**
```bash
# Disable v2 handshake entirely — falls back to v1 (trust-the-tag)
SC_HANDSHAKE=v1 python -m enterprise.agent_runner
```
v1 peers do not send `platform_ksp_*` fields; `verify_peer()` is only invoked
under `SC_HANDSHAKE=v2`. Downgrading to v1 fully bypasses Gap C verification.

**Root-cause checklist before re-enabling:**
- [ ] Confirm responder is a v2-capable agent (has `CngIdentity` initialized)
- [ ] Verify the P-384 key exists in KSP: `certutil -csp "Microsoft Software Key Storage Provider" -key`
- [ ] Check agent_id derivation matches: `SC-` + SHA384(p384_pubkey).hex()[:8].upper()
- [ ] Re-run `TestGapCBinding` integration tests on the affected machine

---

## Flag: `SC_VALIDATE_BIRTH=1` (Tier 2b — Per-Message Birth Time Validation)

**Symptom requiring rollback:** False rejections on messages from legitimate agents
whose PIDs were reused within the 1s cache TTL window.

**Rollback:**
```bash
# Disable birth-time validation — falls back to no per-message verification
SC_VALIDATE_BIRTH=0 python -m enterprise.agent_runner
```

**Root-cause checklist:**
- [ ] Check ledger for `birth_time_mismatch` events — confirm they're false positives
- [ ] If PID recycling is confirmed: reduce cache TTL via `SC_BIRTH_CACHE_TTL_SEC` (default 1)
- [ ] Or enable WMI process watcher plugin for immediate invalidation on process exit
- [ ] Re-enable after confirming no false rejections in 24h test run

---

## Flag: `SC_KEY_ROTATION_DAYS=<N>` (Tier 2e — Key Rotation)

**Symptom requiring rollback:** Key rotation disrupts active mesh sessions (peers
haven't received the new public key mapping yet).

**Rollback:**
```bash
# Disable rotation scheduler — keys remain as-is
# (SC_KEY_ROTATION_DAYS defaults to off if unset)
python -m enterprise.agent_runner
```

**Note:** Rotation cannot be un-done once a new key is finalized. Rollback here means
"stop future rotations" not "restore old key." The old key is gone.

**Root-cause checklist:**
- [ ] Confirm all mesh peers have received the new public key (check ledger for `key_rotation_ack`)
- [ ] If peers are missing the new key: manually distribute via out-of-band channel
- [ ] Re-enable after all peers are synchronized

---

## AXIOM Verdict Review Protocol

Per the process failure documented 2026-05-16: any subagent verdict containing
GO / READY / PASS / COMPLETE / APPROVED must be dispatched to an adversarial reviewer
with instruction: "Find one reason this verdict is wrong. Return CONFIRM or CHALLENGE."

The verdict is blocked from surfacing until the reviewer returns CONFIRM.

This applies to: benchmark results driving design decisions, test pass/fail verdicts,
security assessment conclusions, and deployment GO signals.

---

*Last updated: 2026-05-16. Owner: AXIOM. Review cadence: after each Tier 2 flag flip.*
