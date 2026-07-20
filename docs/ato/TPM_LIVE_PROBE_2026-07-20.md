# SelfConnect Enterprise - Live TPM Platform Attestation PASS

**Date:** 2026-07-20
**Verdict:** PASS on the tested Windows TPM 2.0 host
**Scope:** Enterprise composition over SelfConnect commit
`787a6b88d9ff4a79917ebba94bffc7fe38d700d2`.

## Result

The default Enterprise probe used the operator-pinned
`SelfConnectPlatformAIK-v1` identity key in the Microsoft Platform Crypto
Provider. The key is machine-scoped, hardware-backed, PCP identity marked, and
non-exportable.

The probe generated a fresh nonce, issued an `NCRYPT_CLAIM_PLATFORM` quote,
verified the pinned-key RSA signature, verified the PCR 0-23 selection and PCR
digest, and consumed the nonce in a durable replay store.

| Field | Result |
|---|---|
| supported / verified | `true` / `true` |
| claim size | `1187` bytes |
| PCR mask | `0x00FFFFFF` |
| platform key bound | `true` |
| nonce replay checked | `true` |
| manufacturer/EK chain verified | `false` |
| Raw claim, nonce, or public key retained | `false` |

The redacted machine-readable receipt is
`docs/ato/TPM_LIVE_PROBE_2026-07-20.json`.

## Configuration

The Enterprise process must receive the reviewed public-key digest through
`SELFCONNECT_TPM_PUBLIC_KEY_SHA256`. It does not trust a digest supplied by the
attestation artifact itself. `SELFCONNECT_TPM_KEY_NAME` may select a governed
replacement key; the default is `SelfConnectPlatformAIK-v1`.

## Boundary

This closes the local platform-claim mechanism gate on the tested host. It does
not bind the existing DPAPI software agent-signing key to the quote and does not
establish manufacturer or endorsement-key certificate-chain trust, remote fleet
enrollment, verifier-policy distribution, revocation, independent assessment,
FedRAMP authorization, or an authorization to operate.

The June 21 NA artifact remains valid historical evidence for the earlier probe
and key configuration; it is not rewritten or relabeled.
