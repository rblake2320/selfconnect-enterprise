# Immutable Evidence Routing — Owner Input Checklist

**Matrix level:** `immutable-evidence-deployment` in
`docs/assurance/ha_test_coverage.json` (status: `partial`). This checklist is
exactly what remains before an owner can move that level to `pass`. Nothing
here should be treated as done until the owner has executed it and retained
evidence.

## What this change already delivers (repo-verifiable, no owner input needed)

- `enterprise/evidence_worm_router.py`: routes the exact named HA
  acceptance/incident evidence artifacts
  (`enterprise.evidence_worm_router.DEFAULT_EVIDENCE_ARTIFACTS`) through the
  same `ReplicationSink` contract (`enterprise/provenance.py`) already proven
  live against AWS in `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md`. Fail-closed:
  a missing artifact or fork-detected tamper stops the run instead of
  silently truncating the routed set.
- `scripts/route_ha_evidence_to_worm.py`: a fail-closed CLI that verifies live
  immutable-retention configuration, routes every named artifact, and prints
  receipts — non-zero exit and an explicit reason on any failure.
- `S3ObjectLockSink.attempt_delete()` / `CloudflareR2Sink.attempt_delete()`
  (`enterprise/provenance.py`) plus
  `enterprise.evidence_worm_router.verify_deletion_denied()`: a live
  deletion-denial exercise — attempts to delete a routed evidence object and
  raises unless the provider actually refuses.
- `tests/test_enterprise/test_evidence_worm_router.py`: 16 tests, all running
  without AWS credentials (mocked boto3, exactly like the existing
  `test_worm_service.py` pattern), including a fork-detection test that
  mirrors the exact "second sink instance rejects a conflicting root from
  remote seal-index state" scenario proven live in
  `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md`.
- `tests/test_enterprise/test_worm_evidence_live.py`: the live drill test.
  With no live sink configured it skips with a fixed, reviewed reason
  (`tools/ci_test_gate.py`'s `ALLOWED_SKIPS`). With
  `SCENT_REQUIRE_WORM_LIVE=1` set but no live sink configured, it raises at
  collection time — a hard failure, never a silent skip or a false pass —
  exactly mirroring the existing `SC_REQUIRE_ULTRA_SERVER=1` convention in
  `tests/test_e2e_ultra_gate.py`.

## What remains — owner inputs required for PASS

1. **A dedicated evidence bucket with Object Lock enabled at creation.**
   S3 Object Lock cannot be enabled after bucket creation (see the boundary
   note in `docs/ato/WORM_LIVE_AWS_PROOF_2026-06-21.md`). Create a bucket
   specifically for HA evidence, e.g.
   `selfconnect-ha-evidence-<account-id>-<date>`, with:
   - Object Lock enabled at creation, default retention mode `COMPLIANCE`.
   - Versioning enabled (required by Object Lock).
   - Bucket policy denying public access.
2. **IAM permissions** for the identity that will run the routing job:
   `s3:PutObject`, `s3:GetObject`, `s3:HeadObject`, `s3:ListBucket`,
   `s3:GetObjectLockConfiguration`, `s3:GetObjectRetention`. For the
   deletion-denial drill specifically: `s3:DeleteObject` (yes — the IAM
   policy must *allow* the API call so Object Lock's own denial is what's
   being tested, not an IAM-level 403). For future legal-hold/custody
   ceremonies: `s3:PutObjectLegalHold`, `s3:GetObjectLegalHold`.
3. **Environment configuration** for `enterprise/audit_config.py`:
   ```
   SCENT_AUDIT_MODE=enterprise           # or government
   SCENT_WORM_SINK=s3                    # or r2
   SCENT_WORM_BUCKET=<dedicated bucket>
   SCENT_WORM_REGION=<region>
   SCENT_WORM_PREFIX=scent/audit/ha-evidence/
   SCENT_WORM_MIN_RETENTION_DAYS=<owner-approved retention>
   ```
   plus AWS credentials resolvable by boto3 (environment variables, a named
   profile, or an assumed role — never hardcoded).
4. **Run the routing job for real:**
   ```bash
   python scripts/route_ha_evidence_to_worm.py
   ```
   Retain its JSON output (bucket, keys, sha256 per artifact) as the routing
   receipt.
5. **Run the live pytest drill and retain the result:**
   ```bash
   SCENT_REQUIRE_WORM_LIVE=1 python -m pytest -q tests/test_enterprise/test_worm_evidence_live.py
   ```
   This exercises retention verification, idempotent re-routing, and
   deletion-denial against the real bucket.
6. **Ongoing custody/legal-hold operations.** Routing artifacts once is not
   the same as "continuing custody operations" named in the matrix
   requirement. Define and exercise: who can place/remove a legal hold, how
   retention extensions are authorized, and how routing failures are
   detected in production (not just at drill time).
7. **Update `docs/assurance/ha_test_coverage.json`.** Once 1–6 are complete,
   change `immutable-evidence-deployment.status` to `pass`, add the real
   routing/drill evidence references (bucket, receipt hashes, drill output),
   and clear `closure`.

Until all seven are done, `immutable-evidence-deployment` must remain
`partial` — the routing and deletion-denial *code* is now real and tested,
but no evidence has actually been routed to a real bucket by an owner yet.
