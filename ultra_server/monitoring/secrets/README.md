# Monitoring secret files

Create these two extensionless files locally before starting the stack:

- `ultra_metrics_token` — the same random value configured as the Ultra
  server's current `ULTRA_METRICS_TOKEN`.
- `grafana_admin_password` — an independent random Grafana administrator
  password.

The parent directory is ignored except for this file. Each secret file should
contain exactly one value with no trailing newline or surrounding whitespace.
Restrict both files to the deployment service account. Never commit, print, or
include them in support bundles.
