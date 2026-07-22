# Ultra Alert Fault-Injection Drill

**Scope:** Proves the local reference monitoring stack (`ultra_server/monitoring/`)
actually detects a fault, fires a Prometheus alert, and delivers it through
Alertmanager to a receiver — not just that the YAML parses.

**Not in scope / boundary:** This is a synthetic single-host drill. It stands
up Prometheus and Alertmanager from the exact committed
`ultra_server/monitoring/{prometheus,alertmanager,alert_rules}.yml`, but the
`/metrics` target is a small synthetic exporter (`ultra_server/alert-fault-drill.mjs`)
standing in for a live Ultra Server, not a real multi-host Ultra deployment.
It is **not** the "independently observed deployment alerting drill for the
exact multi-host topology" that
`docs/assurance/ha_test_coverage.json`'s `monitoring-alerting` level requires
to move from `partial` to `pass` — see
`docs/ato/MONITORING_ALERTING_OWNER_CHECKLIST.md` for that remaining gap.

## What it proves

1. `ultra_server/monitoring/alert_rules.yml` loads into a real Prometheus
   3.12.0 and its `expr` fields evaluate against a live-scraped metric.
2. A fault (`ultra_ha_authority_loss_total` going from `0` to `1`) makes the
   `UltraHaAuthorityLoss` alert transition to `firing` within Prometheus's own
   rule evaluator.
3. `ultra_server/monitoring/alertmanager.yml` loads into a real Alertmanager
   0.28.1, receives the firing alert from Prometheus over the real
   Prometheus -> Alertmanager wire protocol, and routes it.
4. Alertmanager delivers a webhook POST containing the alert to the receiver
   URL configured via the `alertmanager_webhook_url` secret file — proving
   the whole pipeline is live-wired, not just declared.

## How to run it

Requires a working Docker Engine with Compose v2 reachable as `docker`. Not
run by default — explicit invocation only:

```bash
cd ultra_server
ULTRA_ALERT_DRILL_LIVE=1 npm run test:alert-drill
```

The script stands up `prometheus` and `alertmanager` under a dedicated
Compose project (`ultra-alert-fault-drill`), starts a synthetic bearer-gated
exporter on `127.0.0.1:7777` and a local webhook receiver, injects the fault,
polls Prometheus's and Alertmanager's own HTTP APIs and the receiver until all
three confirm the alert, then tears everything down (`docker compose down -v`)
and restores any pre-existing local secret files. It never touches a real
Ultra Server, a real bucket, or real credentials.

If Docker is not available, the script fails with a non-zero exit and an
explicit "Docker Engine is not reachable" message — it does not silently skip
or report success.

## Real local run

```
Starting Prometheus + Alertmanager (docker compose)...
Prometheus is scraping the synthetic exporter.
Injecting fault: ultra_ha_authority_loss_total 0 -> 1 ...
Prometheus rule evaluation confirmed: alert is firing.
Alertmanager confirmed: alert received and routed.
Receiver confirmed: webhook POST delivered.
PASS: fault metric -> Prometheus rule -> Alertmanager -> webhook receiver, proven end to end against the committed monitoring config.
Tearing down drill stack...
```

SHA-256 of the transcript above (UTF-8, no trailing newline):
`e7f679c12d76c24b23730f8bfee838786fef87b4b81c272e3c6a76537dea0e3a`

- **Date:** 2026-07-22
- **Images:** `prom/prometheus:v3.12.0@sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac`,
  `prom/alertmanager:v0.28.1@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba`
  (both verified as the multi-platform manifest-list digest via
  `docker buildx imagetools inspect`).
- Post-run verification: `docker ps -a` and `docker volume ls` filtered on the
  drill's Compose project name showed no leftover containers or volumes;
  `ultra_server/monitoring/secrets/` contained only `README.md` afterward.
- `ultra_server/monitoring/alert_rules.yml` and `alertmanager.yml` were also
  independently validated with the upstream tools before this run:
  `promtool check rules` (8 rules found) and `promtool check config`
  (prometheus.yml + alert_rules.yml, SUCCESS), and `amtool check-config`
  (1 receiver, SUCCESS).

## Closure toward PASS

See `docs/ato/MONITORING_ALERTING_OWNER_CHECKLIST.md` for the exact remaining
owner inputs: a real receiver (PagerDuty/Slack/email) behind
`alertmanager_webhook_url`, the dedicated multi-host deployment, and an
independently observed drill against that exact topology.
