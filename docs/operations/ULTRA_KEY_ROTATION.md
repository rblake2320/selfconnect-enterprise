# Ultra Key Rotation Runbook

This runbook covers the Ultra operator bearer, recovery-token HMAC key, and TSK
client keys. It is an engineering procedure, not evidence that a deployment's
secret manager, personnel, or authorization boundary has been approved.

## Preconditions

1. Run Ultra in `production` mode with PostgreSQL and Redis healthy.
2. Store secrets in the deployment's approved secret manager. Do not place
   values in Git, command history, tickets, screenshots, evidence bundles, or
   application logs.
3. Confirm the service account alone can read the injected secret values.
4. Preserve the current values until the overlap verification succeeds.
5. Choose an operator and independent reviewer for the change record.

## Operator And Recovery Keys

Ultra accepts one current value and at most one previous value:

- `ULTRA_ADMIN_TOKEN` and `ULTRA_ADMIN_TOKEN_PREVIOUS`
- `ULTRA_RECOVERY_HMAC_KEY` and `ULTRA_RECOVERY_HMAC_KEY_PREVIOUS`

Generate new independent random values of at least 32 bytes. Never reuse an
operator token as a recovery key.

1. Move the existing current values into the corresponding `*_PREVIOUS`
   secrets.
2. Install the new values as the current secrets.
3. Restart one instance and verify `/health` plus authenticated `/status`.
4. Confirm `keyRotation.adminVerificationKeys == 2` and
   `keyRotation.recoveryVerificationKeys == 2`. These are counts, not secrets.
5. Prove the new and immediately previous operator tokens work and an older
   retired token fails. Use `tools/ultra_rotation_conformance.mjs` for the
   recovery-token overlap proof.
6. Update every authorized operator client to the new current token.
7. Wait at least the configured recovery-token TTL and the deployment's client
   drain window.
8. Remove both previous secrets and restart.
9. Confirm both key counts equal one, the previous operator token fails, and a
   token issued under the retired recovery key no longer verifies.

The production CI job performs this overlap, restart, and retirement sequence
against real PostgreSQL and Redis on every change.

## TSK Rotation

Call `UltraGate.rotate_tsk()` on a bootstrapped identity. The method performs:

1. `POST /rotate-tsk/prepare`: creates one idempotent unbound replacement.
2. `POST /rotate-tsk/commit`: compare-and-swaps the pair binding to the new
   client and revokes the old client.
3. Local state changes only after the commit response is valid.

Both routes require a body-bound agent signature. Production also requires the
operator bearer. A lost prepare response returns the same prepared key on retry.
A lost commit response is safe to retry because the binding swap is idempotent.
`POST /resume-identity` returns the currently bound active key to the proven
owner after a process restart; production also requires operator authorization.

After rotation, prove all of the following:

- the client ID changed;
- the old key status is `revoked`;
- the new key status is `active`;
- a new request verifies with the new key;
- a fresh client instance resumes the new key; and
- a service restart preserves the new binding and HOTP counter.

## Emergency Revocation

If an operator token is suspected compromised, replace the current token
without configuring it as previous. Restart, verify that the suspected token is
rejected, and record the incident. If the recovery key is suspected compromised,
replace it without overlap; all outstanding recovery tokens become invalid.
Rotate affected TSK clients and agent identities separately as required.

Evidence must contain timestamps, service version, non-secret key counts,
accepted/rejected status codes, and the commit SHA. It must not contain any
token, recovery key, shared secret, private key, or complete authentication
header.
