# Nostr-Shaped Evidence Export

`enterprise.nostr_export` is a one-way export adapter for verified SelfConnect
evidence. It produces the seven-field NIP-01 event shape and computes the event
ID from the exact NIP-01 serialization:

```text
[0, pubkey, created_at, kind, tags, content]
```

The recommended `export_from_verified_observer()` path requires two
deployment-owned inputs:

1. A source verifier that accepts the exact record. Production callers should
   use records obtained through the verified `LedgerObserver` path or an
   equivalent verifier bound to the source ledger.
2. A dedicated NIP-01 signer exposing a 32-byte x-only secp256k1 public key and
   a 64-byte Schnorr signature. SelfConnect Ed25519 and P-384 keys are not
   relabeled as Nostr identities.

```python
from enterprise.nostr_export import export_verified_record

event = export_verified_record(
    verified_record,
    source_verifier=verify_exact_source_record,
    signer=deployment_nostr_signer,
    created_at=unix_seconds,
    kind=deployment_allocated_kind,
    tags=[["classification", "CUI"]],
)
```

For production use, prefer:

```python
events = export_from_verified_observer(
    LedgerObserver(ledger_path, verifier=ledger),
    signer=deployment_nostr_signer,
    kind=deployment_allocated_kind,
)
```

This path accepts only the exact `LedgerObserver` type, requires its verifier,
rejects `unsafe_unverified=True`, and runs ledger verification before rendering
any event. Tampered source content and a verifier bound to a different ledger
both fail before the Nostr signer is called. `export_verified_record()` remains the lower-level adapter for
deployments with an equivalent exact-record verifier.

The content contains canonical JSON with the source record and its SHA-256
digest. Authoritative schema and source-digest tags cannot be overridden by the
caller.

## Hard boundary

- This module does not open WebSockets, publish to relays, subscribe, or import
  events.
- A Nostr event is never authorization to execute a SelfConnect action.
- Nostr does not replace ACP, terminal-as-medium injection, `GovernedRuntime`,
  BPC/TSK, the native signed ledger, revocation, or approval.
- Event-kind allocation, relay selection, key custody, retention, and external
  acceptance are deployment responsibilities.
- Structural tests exercise serialization and signer contracts; no production
  secp256k1 signer or live relay has been validated in this repository.

Primary references inspected 2026-07-31:

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [Buzz protocol vision](https://github.com/block/buzz/blob/main/VISION.md)
