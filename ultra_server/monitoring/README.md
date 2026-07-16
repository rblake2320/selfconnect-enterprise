# Ultra Server Monitoring (Prometheus + Grafana)

Issue #14. The Ultra server exposes Prometheus metrics at `GET /metrics`
(`localhost:7777` by default, `ULTRA_SERVER_PORT`). This stack scrapes and
graphs them.

## Start

From this directory:

```bash
docker compose up -d
```

- **Grafana** → http://localhost:3000 (login `admin` / `admin`, then set a new
  password). The **Ultra Server** dashboard is auto-provisioned under the
  *Ultra* folder.
- **Prometheus** → http://localhost:9090 (check *Status → Targets*: the
  `ultra-server` target should be **UP**).

The Ultra server must be running on the host at `:7777` before or shortly after
`compose up`. Prometheus scrapes `host.docker.internal:7777/metrics` every 15s.

Stop with `docker compose down` (add `-v` to also drop stored metrics).

## What is graphed

| Panel | Query | Source metric |
|-------|-------|---------------|
| Request rate (by route) | `sum by (route) (rate(ultra_http_requests_total[5m]))` | `ultra_http_requests_total{method,route,status}` |
| Auth failure rate (by reason) | `sum by (reason) (rate(ultra_auth_failures_total[5m]))` | `ultra_auth_failures_total{reason}` |
| TSK provisioning rate | `rate(ultra_tsk_provisions_total[5m])` | `ultra_tsk_provisions_total` |
| BPC registration rate | `rate(ultra_bpc_registrations_total[5m])` | `ultra_bpc_registrations_total` |
| Process memory | `ultra_node_process_resident_memory_bytes`, `ultra_node_nodejs_heap_size_used_bytes` | prom-client defaults (`ultra_node_` prefix) |
| Process CPU | `rate(ultra_node_process_cpu_seconds_total[5m])` | prom-client defaults |

## Files

```
monitoring/
  docker-compose.yml                                  Prometheus + Grafana
  prometheus.yml                                      scrape config (15s)
  grafana/provisioning/datasources/prometheus.yml     auto-wired datasource
  grafana/provisioning/dashboards/dashboards.yml      dashboard provider
  grafana/dashboards/ultra-server.json                the dashboard
```

## Notes

- On Linux the compose file maps `host.docker.internal` via `host-gateway`;
  on Docker Desktop (macOS/Windows) it resolves automatically.
- If the Ultra server binds a non-default port, update the target in
  `prometheus.yml`.
- The dashboard queries only metrics the server actually exports (verified
  against `ultra_server/server.js`).
