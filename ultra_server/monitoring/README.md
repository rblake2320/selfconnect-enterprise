# Ultra monitoring reference stack

This directory provides a reproducible, local-only Prometheus and Grafana
reference deployment for Ultra Server. It is not a universal production
monitoring configuration. Alert routing, remote access, TLS termination,
enterprise SSO, retention sizing, and deployment authorization remain
environment decisions.

The stack uses Prometheus 3.12.0 and Grafana 13.1.0 multi-platform images pinned
to registry manifest digests. Both management interfaces bind to loopback.
Prometheus receives a dedicated read-only metrics credential from an ignored
file; it never receives the Ultra administrator token. Grafana reads its
administrator password from a separate ignored file.

## Install

1. Install a current Docker Engine with Compose v2.
2. Start Ultra Server on the host at `127.0.0.1:7777`.
3. Generate independent random values containing at least 32 bytes for:
   - `ULTRA_METRICS_TOKEN` in the Ultra Server environment.
   - `secrets/ultra_metrics_token` with the same value.
   - `secrets/grafana_admin_password` with a different value.
4. Restrict both files to the deployment service account.
5. Validate before starting:

```bash
docker compose config --quiet
docker compose pull
docker compose up -d
```

The dashboard is provisioned under the **Ultra** folder:

- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:9090`

Do not publish either port without a separately reviewed authentication, TLS,
and network-boundary design.

## Verify

These checks use status codes and metadata only; do not print credentials.

1. `GET http://127.0.0.1:7777/metrics` without a bearer returns `401`.
2. A wrong bearer returns `401`.
3. `Authorization: Bearer <ULTRA_METRICS_TOKEN>` returns `200`.
4. That same metrics token returns `401` from `GET /status`.
5. Prometheus `GET /api/v1/targets` reports the `ultra-server` target with
   `health: "up"`.
6. Prometheus queries return the named `ultra_*` series after exercising
   registration, provisioning, verification, and denial paths.
7. Grafana `GET /api/health` succeeds and dashboard UID `ultra-server` loads.

The dashboard covers request rate by bounded route, authentication failures by
bounded reason, TSK provisioning, BPC registration, Node memory, and Node CPU.
Unknown request paths are exported only as `__unmatched__`; raw paths never
become metric labels.

## Rotate the metrics token

1. Generate a new independent random token.
2. Restart Ultra with the new value as `ULTRA_METRICS_TOKEN` and the old value
   as `ULTRA_METRICS_TOKEN_PREVIOUS`.
3. Replace `secrets/ultra_metrics_token` atomically with the new value.
4. Restart Prometheus and verify the target is up.
5. Remove `ULTRA_METRICS_TOKEN_PREVIOUS` and restart Ultra.
6. Verify the old token is rejected and the target remains up.

Only one previous metrics token is accepted. It is verification-only and must
be removed immediately after the scraper transition.

## Backup and restore

The named volumes `prometheus-data` and `grafana-data` hold the time series and
Grafana database. Stop both containers before taking a storage-consistent
volume snapshot. Back up this versioned configuration separately, but never
put the secret files in source control or an unencrypted artifact.

For a restore drill:

1. Start from an empty Docker host.
2. Restore both named volumes using the deployment platform's volume procedure.
3. Restore this exact configuration revision.
4. Re-provision fresh secret files through approved custody.
5. Start the stack and repeat every verification check above.

A backup is not treated as usable until this isolated restore succeeds.

## Upgrade

1. Review upstream release and security notes.
2. Resolve the new image tag to its multi-platform manifest digest.
3. Update tag and digest together.
4. Back up both volumes.
5. Run `docker compose pull` and `docker compose up -d`.
6. Repeat target, query, dashboard, restart, and persistence verification.
7. Record the source commit, image digests, commands, timestamps, and
   non-secret results.

## Rollback

Restore the prior tag-and-digest pair and, if the upgrade changed persistent
storage incompatibly, restore the pre-upgrade volume snapshots. Then repeat the
verification procedure. Do not point an older image at data it cannot read.

## Restart and persistence

Run `docker compose restart`, then verify the Prometheus target and Grafana
dashboard. Confirm a pre-restart time series remains queryable and the
provisioned dashboard still loads.

## Teardown

`docker compose down` stops the stack while retaining data. Use
`docker compose down -v` only after an approved retention decision and verified
backup; it permanently removes both named volumes. Securely delete local secret
files when decommissioning the deployment.

## Source mapping

| Panel | Source metric |
|---|---|
| Request rate | `ultra_http_requests_total{method,route,status}` |
| Authentication failures | `ultra_auth_failures_total{reason}` |
| TSK provisioning | `ultra_tsk_provisions_total` |
| BPC registration | `ultra_bpc_registrations_total` |
| Process memory | `ultra_node_process_resident_memory_bytes`, `ultra_node_nodejs_heap_size_used_bytes` |
| Process CPU | `ultra_node_process_cpu_seconds_total` |
