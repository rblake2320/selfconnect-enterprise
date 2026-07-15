# SelfConnect Enterprise - Live TPM Platform Attestation Probe

**Date:** 2026-06-21  
**Verdict:** NA on this machine  
**Scope:** Live `enterprise.tpm_attestation` probe after SDK-correct ABI repair.

## Summary

The TPM attestation path was updated to match the installed Windows SDK:

- `NCRYPT_CLAIM_PLATFORM = 0x00010000`
- `NCRYPTBUFFER_TPM_PLATFORM_CLAIM_PCR_MASK = 80`
- `NCRYPTBUFFER_TPM_PLATFORM_CLAIM_NONCE = 81`
- `NCryptCreateClaim` uses the documented two-call `pbClaimBlob/cbClaimBlob/pcbResult` pattern.
- `NCRYPT_CLAIM_PLATFORM` is invoked as platform PCR evidence with `hSubjectKey = NULL`.

The live probe no longer fails with the earlier malformed call shape. It now returns:

```text
NCryptCreateClaim -> 0x80090026
```

That is recorded as a platform attestation NA condition for this machine, not a fake PASS.

## Live Result

| Field | Value |
|---|---|
| supported | `false` |
| claim_size | `0` |
| pcr_mask | `0x00FFFFFF` |
| verify | `false` |
| status | `TPM not available or Platform Crypto Provider unsupported (NCryptCreateClaim -> 0x80090026)` |
| Raw artifact | `docs/ato/TPM_LIVE_PROBE_2026-06-21.json` |

## Fresh Recheck

Rechecked on 2026-06-21 using `enterprise.tpm_attestation.tpm_probe()`.

| Field | Value |
|---|---|
| supported | `false` |
| claim_size | `0` |
| status | `TPM not available or Platform Crypto Provider unsupported (NCryptCreateClaim -> 0x80090026)` |

The recheck confirms the same boundary: the code path executes, but this host
does not produce a platform claim blob.

## Boundary

This probe exercised the Windows ABI and recorded the fail-closed NA behavior on
this host. It did not validate the successful claim path or establish a hardware
attestation PASS because this machine produced no platform claim blob. A machine
with provisioned TPM platform-attestation material is still required for that
separate result.
