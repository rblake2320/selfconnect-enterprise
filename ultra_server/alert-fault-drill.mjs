#!/usr/bin/env node
// ultra_server/alert-fault-drill.mjs — Local end-to-end alert-firing drill.
//
// Proves the real deployed pipeline in ultra_server/monitoring/ works:
//   fault metric -> Prometheus rule evaluation -> Alertmanager routing ->
//   webhook delivery to a receiver.
//
// This is NOT the "independently observed deployment alerting drill for the
// exact multi-host topology" required to move docs/assurance/ha_test_coverage.json's
// monitoring-alerting level from PARTIAL to PASS (see
// docs/ato/MONITORING_ALERTING_OWNER_CHECKLIST.md for that boundary). It uses
// a synthetic single-host Prometheus+Alertmanager stack and a synthetic
// metrics exporter standing in for Ultra Server, not a live multi-host Ultra
// deployment. What it DOES prove, for real, against the exact committed
// ultra_server/monitoring/{prometheus,alertmanager,alert_rules}.yml: the
// alert actually fires and actually gets delivered to a receiver — not just
// that the YAML parses.
//
// Not run by default (not part of `npm test`). Requires explicit invocation:
//   ULTRA_ALERT_DRILL_LIVE=1 npm run test:alert-drill
// Requires a working Docker Engine with Compose v2 reachable as `docker`.
// Fails loudly (non-zero exit, explicit reason) if invoked without Docker
// available, rather than silently skipping or reporting success.

import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MONITORING_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'monitoring');
const COMPOSE_PROJECT = 'ultra-alert-fault-drill';
const RECEIVER_PORT = 18990;
const EXPORTER_PORT = 7777; // must match ultra_server/monitoring/prometheus.yml target
const METRICS_TOKEN = randomBytes(24).toString('hex');

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
  throw new Error(message);
}

if (process.env.ULTRA_ALERT_DRILL_LIVE !== '1') {
  console.log(
    'Not run: this is an explicit, opt-in local drill. Set '
    + 'ULTRA_ALERT_DRILL_LIVE=1 to run it (requires Docker).',
  );
  process.exit(0);
}

const dockerCheck = spawnSync('docker', ['info'], { stdio: 'ignore' });
if (dockerCheck.status !== 0) {
  fail(
    'ULTRA_ALERT_DRILL_LIVE=1 but a working Docker Engine is not reachable as '
    + '`docker`. Install/start Docker Desktop (or the Docker Engine) and retry.',
  );
}

async function waitFor(label, checkFn, { timeoutMs = 90_000, intervalMs = 2_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await checkFn();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  fail(`timed out waiting for: ${label}${lastError ? ` (last error: ${lastError})` : ''}`);
}

// The compose file mounts these two fixed relative paths; write drill values
// there, remembering any pre-existing content so a developer's real local
// secrets are restored afterward rather than clobbered.
function stageSecret(secretsDir, name, value) {
  const target = path.join(secretsDir, name);
  const previous = existsSync(target) ? readFileSync(target) : null;
  writeFileSync(target, value);
  return () => {
    if (previous === null) rmSync(target, { force: true });
    else writeFileSync(target, previous);
  };
}

async function main() {
  const secretsDir = path.join(MONITORING_DIR, 'secrets');
  mkdirSync(secretsDir, { recursive: true });
  const restoreMetricsToken = stageSecret(secretsDir, 'ultra_metrics_token', METRICS_TOKEN);
  const restoreWebhookUrl = stageSecret(
    secretsDir,
    'alertmanager_webhook_url',
    `http://host.docker.internal:${RECEIVER_PORT}/webhook`,
  );

  const received = [];
  const receiver = createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(404).end();
      return;
    }
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      received.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.writeHead(200).end();
    });
  });
  await new Promise((resolve) => receiver.listen(RECEIVER_PORT, '0.0.0.0', resolve));

  let authorityLossCount = 0;
  const exporter = createServer((req, res) => {
    if (req.url !== '/metrics') {
      res.writeHead(404).end();
      return;
    }
    if (req.headers.authorization !== `Bearer ${METRICS_TOKEN}`) {
      res.writeHead(401).end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
    res.end(
      `# HELP ultra_ha_authority_loss_total drill\n`
      + `# TYPE ultra_ha_authority_loss_total counter\n`
      + `ultra_ha_authority_loss_total ${authorityLossCount}\n`,
    );
  });
  await new Promise((resolve) => exporter.listen(EXPORTER_PORT, '0.0.0.0', resolve));

  const compose = (...args) => spawnSync(
    'docker',
    ['compose', '-p', COMPOSE_PROJECT, '-f', path.join(MONITORING_DIR, 'docker-compose.yml'), ...args],
    { cwd: MONITORING_DIR, env: { ...process.env, }, encoding: 'utf8' },
  );

  try {
    console.log('Starting Prometheus + Alertmanager (docker compose)...');
    const up = compose('up', '-d', '--quiet-pull', 'prometheus', 'alertmanager');
    if (up.status !== 0) {
      fail(`docker compose up failed: ${up.stderr || up.stdout}`);
    }

    await waitFor('Prometheus target ultra-server up', async () => {
      const response = await fetch('http://127.0.0.1:9090/api/v1/targets');
      const body = await response.json();
      return body.data.activeTargets.some(
        (t) => t.labels.job === 'ultra-server' && t.health === 'up',
      );
    });
    console.log('Prometheus is scraping the synthetic exporter.');

    console.log('Injecting fault: ultra_ha_authority_loss_total 0 -> 1 ...');
    authorityLossCount = 1;

    await waitFor('UltraHaAuthorityLoss alert firing in Prometheus', async () => {
      const response = await fetch('http://127.0.0.1:9090/api/v1/rules');
      const body = await response.json();
      const group = body.data.groups.find((g) => g.name === 'ultra-ha-fault-signals');
      const rule = group?.rules?.find((r) => r.name === 'UltraHaAuthorityLoss');
      return rule?.alerts?.some((a) => a.state === 'firing');
    });
    console.log('Prometheus rule evaluation confirmed: alert is firing.');

    await waitFor('UltraHaAuthorityLoss alert visible in Alertmanager', async () => {
      const response = await fetch('http://127.0.0.1:9093/api/v2/alerts');
      const alerts = await response.json();
      return alerts.some((a) => a.labels.alertname === 'UltraHaAuthorityLoss');
    });
    console.log('Alertmanager confirmed: alert received and routed.');

    await waitFor('webhook delivery to the local receiver', () => received.some(
      (payload) => payload.alerts?.some((a) => a.labels.alertname === 'UltraHaAuthorityLoss'),
    ));
    console.log('Receiver confirmed: webhook POST delivered.');

    console.log(
      'PASS: fault metric -> Prometheus rule -> Alertmanager -> webhook receiver, '
      + 'proven end to end against the committed monitoring config.',
    );
  } finally {
    console.log('Tearing down drill stack...');
    compose('down', '-v');
    await new Promise((resolve) => receiver.close(resolve));
    await new Promise((resolve) => exporter.close(resolve));
    restoreMetricsToken();
    restoreWebhookUrl();
  }
}

await main();
