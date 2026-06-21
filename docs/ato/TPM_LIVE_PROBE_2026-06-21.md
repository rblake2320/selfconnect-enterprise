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

## Boundary

This probe proves the Windows ABI and downgrade behavior are correct on this host. It does not prove a hardware attestation PASS because this machine did not produce a platform claim blob. A separate machine with provisioned TPM platform attestation material is still required for a PASS artifact.
