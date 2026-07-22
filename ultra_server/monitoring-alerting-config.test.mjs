import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parse } from 'yaml';

const monitoring = new URL('./monitoring/', import.meta.url);
const server = new URL('./server.js', import.meta.url);

async function read(relativePath) {
  return readFile(new URL(relativePath, monitoring), 'utf8');
}

// Metric names prom-client's own default collector produces, plus Prometheus's
// own built-in `up` meta-metric. These are legitimate to alert on even though
// they are never `new Counter(...)`-defined in server.js.
const BUILTIN_METRIC_NAMES = new Set(['up']);

function extractMetricNames(promQlExpr) {
  const matches = promQlExpr.match(/\b(?:ultra_[a-z0-9_]+|up)\b/g) ?? [];
  return [...new Set(matches)];
}

test('alert_rules.yml only alerts on metrics server.js actually emits', async () => {
  const rules = parse(await read('alert_rules.yml'));
  const serverSource = await readFile(server, 'utf8');

  assert.ok(Array.isArray(rules.groups) && rules.groups.length > 0);
  const group = rules.groups.find((g) => g.name === 'ultra-ha-fault-signals');
  assert.ok(group, 'expected the ultra-ha-fault-signals rule group');
  assert.ok(group.rules.length >= 7);

  const definedMetricNames = new Set(
    [...serverSource.matchAll(/name:\s*'(ultra_[a-z0-9_]+)'/g)].map((m) => m[1]),
  );

  for (const rule of group.rules) {
    assert.ok(rule.alert, 'every rule must be a named alert');
    assert.ok(rule.expr, `${rule.alert} has no expr`);
    assert.ok(rule.labels?.severity, `${rule.alert} has no severity label`);
    assert.ok(rule.annotations?.summary, `${rule.alert} has no summary annotation`);
    assert.ok(typeof rule.for === 'string', `${rule.alert} has no 'for' duration`);

    const referenced = extractMetricNames(rule.expr);
    assert.ok(referenced.length > 0, `${rule.alert} expr references no ultra_* metric`);
    for (const name of referenced) {
      assert.ok(
        BUILTIN_METRIC_NAMES.has(name) || definedMetricNames.has(name),
        `${rule.alert} references undefined metric ${name}`,
      );
    }
  }
});

test('alert names are unique', async () => {
  const rules = parse(await read('alert_rules.yml'));
  const names = rules.groups.flatMap((g) => g.rules.map((r) => r.alert));
  assert.equal(new Set(names).size, names.length);
});

test('every HA fault-signal category required by the coverage matrix has an alert', async () => {
  const rules = parse(await read('alert_rules.yml'));
  const names = rules.groups.flatMap((g) => g.rules.map((r) => r.alert));
  // docs/assurance/ha_test_coverage.json: monitoring-alerting requires
  // authority loss, replication lag, denied promotion, stale writers, and
  // recovery failure.
  for (const expected of [
    'UltraHaAuthorityLoss',
    'UltraHaReplicationLagHigh',
    'UltraHaPromotionDenied',
    'UltraHaStaleWriterDenied',
    'UltraHaRecoveryFailure',
  ]) {
    assert.ok(names.includes(expected), `missing required alert: ${expected}`);
  }
});

test('alertmanager routes to a single webhook receiver whose URL is a mounted secret file', async () => {
  const config = parse(await read('alertmanager.yml'));
  assert.equal(config.route.receiver, 'operator-webhook');
  const receiver = config.receivers.find((r) => r.name === 'operator-webhook');
  assert.ok(receiver, 'expected the operator-webhook receiver');
  const webhook = receiver.webhook_configs[0];
  assert.equal(webhook.url_file, '/run/secrets/alertmanager_webhook_url');
  assert.equal('url' in webhook, false, 'webhook URL must come from url_file, never inline');
});

test('docker-compose wires alertmanager digest-pinned, loopback-only, persistent, and dependent on it from prometheus', async () => {
  const compose = parse(await read('docker-compose.yml'));
  const alertmanager = compose.services.alertmanager;
  assert.ok(alertmanager, 'expected an alertmanager service');
  assert.match(alertmanager.image, /^prom\/alertmanager:[^@\s]+@sha256:[0-9a-f]{64}$/);
  for (const port of alertmanager.ports ?? []) {
    assert.match(String(port), /^127\.0\.0\.1:/);
  }
  assert.ok(alertmanager.volumes.includes('alertmanager-data:/alertmanager'));
  assert.ok(
    alertmanager.volumes.some((v) => v.endsWith('/run/secrets/alertmanager_webhook_url:ro')),
  );
  assert.ok(Object.hasOwn(compose.volumes, 'alertmanager-data'));
  assert.ok(compose.services.prometheus.depends_on?.includes('alertmanager'));
  assert.ok(
    compose.services.prometheus.volumes.some((v) => v.endsWith('/etc/prometheus/alert_rules.yml:ro')),
  );
});

test('prometheus.yml points at the alert rules file and a loopback alertmanager target', async () => {
  const prometheus = parse(await read('prometheus.yml'));
  assert.ok(prometheus.rule_files.includes('/etc/prometheus/alert_rules.yml'));
  const [alertmanagerConfig] = prometheus.alerting.alertmanagers;
  assert.deepEqual(alertmanagerConfig.static_configs[0].targets, ['alertmanager:9093']);
});
