# Monitoring & Alerting — Owner Input Checklist

**Matrix level:** `monitoring-alerting` in `docs/assurance/ha_test_coverage.json`
(status: `partial`). This checklist is exactly what remains before an owner
can move that level to `pass`. Nothing here should be treated as done until
the owner has executed it and retained evidence.

## What this change already delivers (repo-verifiable, no owner input needed)

- Real Prometheus counters/gauge for the five required signals — authority
  loss, denied promotion, stale-writer denial, recovery failure, and a
  replication-lag proxy — emitted by `ultra_server/server.js` at the exact
  call sites where `ha-controller.js` and `independent-state.js` already
  return those outcomes (`ultra_server/ha-metrics.js` bounds every label set).
- `ultra_server/monitoring/alert_rules.yml`: 8 Prometheus alert rules
  covering all five signals plus target-down and an auth-failure-rate alert.
  Cross-checked against `server.js` by
  `ultra_server/monitoring-alerting-config.test.mjs` so a renamed metric
  fails CI instead of an alert going silently dark.
- `ultra_server/monitoring/alertmanager.yml` + a new `alertmanager` service in
  `docker-compose.yml`, digest-pinned and loopback-only like the existing
  Prometheus/Grafana services.
- `ultra_server/alert-fault-drill.mjs`: a real, runnable, Docker-based
  end-to-end drill (fault metric -> Prometheus rule -> Alertmanager ->
  webhook receiver), executed successfully in this environment — see
  `docs/operations/ULTRA_ALERT_FAULT_DRILL.md` for the run transcript and
  its boundary.

## What remains — owner inputs required for PASS

1. **A real receiver.** `alertmanager.yml` routes every alert to
   `secrets/alertmanager_webhook_url` — currently unset in any real
   deployment. Provision one of:
   - A PagerDuty Events API v2 integration URL, or
   - A Slack incoming-webhook URL, or
   - An internal relay that forwards to your paging/chat system.
   Populate `ultra_server/monitoring/secrets/alertmanager_webhook_url` with
   it on the deployment host (never commit it).
2. **The exact multi-host production topology.** The fault-injection drill in
   this change runs against a synthetic single-host stack. Deploy Prometheus,
   Alertmanager, and Grafana against the real multi-host Ultra deployment
   (the same topology used for `docs/operations/ULTRA_FINAL_HA_ACCEPTANCE.md`
   and `docs/operations/SPARK2_HOST_ACCEPTANCE.md`).
3. **An independently observed drill on that topology.** Have someone other
   than the implementer inject each of the five named faults (kill the
   fencing authority, force a stale-writer denial, force a promotion denial,
   force a TSK reprovision/reload failure, stall independent-state
   readiness) against the real deployment, confirm timely alert delivery and
   operator acknowledgement, and retain the resulting evidence (timestamps,
   screenshots or API responses from Prometheus/Alertmanager, the
   acknowledging operator's identity).
4. **Retention/ownership of that evidence.** Route the retained drill
   evidence through the WORM sink described in
   `docs/ato/WORM_EVIDENCE_ROUTING_OWNER_CHECKLIST.md` once produced, so the
   alerting drill evidence itself is tamper-evident.
5. **Update `docs/assurance/ha_test_coverage.json`.** Once 1–4 are complete,
   change `monitoring-alerting.status` to `pass`, add the real drill's
   evidence references, and clear `closure`.

Until all five are done, `monitoring-alerting` must remain `partial` — a
locally-validated pipeline is real progress, not a substitute for a real
receiver and a real multi-host, independently observed drill.
