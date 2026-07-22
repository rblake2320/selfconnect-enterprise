# Monitoring secret files

Create these extensionless files locally before starting the stack:

- `ultra_metrics_token` — the same random value configured as the Ultra
  server's current `ULTRA_METRICS_TOKEN`.
- `grafana_admin_password` — an independent random Grafana administrator
  password.
- `alertmanager_webhook_url` — the real receiver URL Alertmanager delivers
  alerts to (e.g. a PagerDuty Events API v2 integration URL, a Slack
  incoming-webhook URL, or an internal relay). There is no reviewed default:
  provisioning a real receiver is an owner decision — see
  docs/ato/MONITORING_ALERTING_OWNER_CHECKLIST.md.

The parent directory is ignored except for this file. Each secret file should
contain exactly one value with no trailing newline or surrounding whitespace.
Restrict all files to the deployment service account. Never commit, print, or
include them in support bundles.
