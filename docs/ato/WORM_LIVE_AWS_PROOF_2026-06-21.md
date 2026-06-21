# SelfConnect Enterprise - Live AWS S3 Object Lock WORM Proof

**Date:** 2026-06-21  
**Verdict:** PASS  
**Scope:** Live off-host WORM replication proof for `enterprise.provenance.S3ObjectLockSink`.

## Summary

The live AWS proof created a dedicated S3 bucket with Object Lock enabled, pushed a redacted Merkle-seal audit record through `S3ObjectLockSink`, confirmed both the seal-index object and event object were retained in `COMPLIANCE` mode, and verified that a fresh sink instance rejects a conflicting root for the same `(session_id, segment_no)` using the remote seal-index state.

This proves the shipped sink path can produce real AWS WORM receipts and can detect remote fork attempts after service restart, not only in local process memory.

## Environment

| Field | Value |
|---|---|
| Bucket | `selfconnect-worm-proof-723013807658-20260621013523` |
| Region | `us-east-1` |
| Prefix | `scent/audit/live-proof/20260621T063604Z` |
| Session | `selfconnect-worm-live-20260621T063604Z` |
| Retention | `COMPLIANCE` until `2026-06-22 06:36:05+00:00` |
| Raw artifact | `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.json` |

## Receipt

```text
s3://selfconnect-worm-proof-723013807658-20260621013523/scent/audit/live-proof/20260621T063604Z/selfconnect-worm-live-20260621T063604Z/seg-000000/seq-000000000100-ffffffffffffffff.json#817a32c3310dbb57a0815d0dd6d32d37
```

## Locked Objects

| Object | Key | ObjectLockMode | Retention |
|---|---|---|---|
| Event record | `scent/audit/live-proof/20260621T063604Z/selfconnect-worm-live-20260621T063604Z/seg-000000/seq-000000000100-ffffffffffffffff.json` | `COMPLIANCE` | `2026-06-22 06:36:05+00:00` |
| Seal index | `scent/audit/live-proof/20260621T063604Z/selfconnect-worm-live-20260621T063604Z/seg-000000/seal-index.json` | `COMPLIANCE` | `2026-06-22 06:36:05+00:00` |

## Remote Fork Check

Second sink instance attempted to push a different Merkle root for the same session and segment. The sink rejected it from remote seal-index state:

```text
fork_detected: session=selfconnect-worm-live-20260621T063604Z segment=0 existing_root=ffffffffffffffff... new_root=eeeeeeeeeeeeeeee...
```

## Boundary

All pre-existing AWS buckets available to this account returned `ObjectLockConfigurationNotFoundError`, so they were not suitable WORM targets. S3 Object Lock must be enabled when the bucket is created. This proof therefore uses a dedicated proof bucket created only for this evidence run.

No raw prompts, local paths, credentials, or private transcripts are included in this artifact.
