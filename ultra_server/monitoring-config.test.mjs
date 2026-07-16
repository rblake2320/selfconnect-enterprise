import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parse } from 'yaml';

const monitoring = new URL('./monitoring/', import.meta.url);

async function read(relativePath) {
  return readFile(new URL(relativePath, monitoring), 'utf8');
}

test('monitoring compose is digest-pinned, loopback-only, persistent, and file-secret based', async () => {
  const composeText = await read('docker-compose.yml');
  const compose = parse(composeText);

  for (const [name, service] of Object.entries(compose.services)) {
    assert.match(
      service.image,
      /^[^@\s]+@sha256:[0-9a-f]{64}$/,
      `${name} image is not digest-pinned`,
    );
    for (const port of service.ports ?? []) {
      assert.match(String(port), /^127\.0\.0\.1:/, `${name} port is not loopback-only`);
    }
  }

  assert.equal(composeText.includes('ULTRA_ADMIN_TOKEN'), false);
  assert.equal(
    compose.services.grafana.environment.GF_SECURITY_ADMIN_PASSWORD__FILE,
    '/run/secrets/grafana_admin_password',
  );
  assert.ok(compose.services.prometheus.volumes.includes('prometheus-data:/prometheus'));
  assert.ok(compose.services.grafana.volumes.includes('grafana-data:/var/lib/grafana'));
  assert.ok(Object.hasOwn(compose.volumes, 'prometheus-data'));
  assert.ok(Object.hasOwn(compose.volumes, 'grafana-data'));
});

test('Prometheus reads a dedicated bearer from a mounted credential file', async () => {
  const prometheus = parse(await read('prometheus.yml'));
  const [scrape] = prometheus.scrape_configs;
  assert.equal(scrape.metrics_path, '/metrics');
  assert.equal(scrape.authorization.type, 'Bearer');
  assert.equal(
    scrape.authorization.credentials_file,
    '/run/secrets/ultra_metrics_token',
  );
  assert.equal('credentials' in scrape.authorization, false);
});

test('dashboard and provisioning files parse and secrets are actually ignored', async () => {
  const dashboard = JSON.parse(await read('grafana/dashboards/ultra-server.json'));
  assert.equal(dashboard.uid, 'ultra-server');
  assert.ok(dashboard.panels.length >= 6);
  const dashboardProvisioning = await read(
    'grafana/provisioning/dashboards/dashboards.yml',
  );
  const datasourceProvisioning = await read(
    'grafana/provisioning/datasources/prometheus.yml',
  );
  assert.doesNotThrow(() => parse(dashboardProvisioning));
  assert.doesNotThrow(() => parse(datasourceProvisioning));

  const git = process.platform === 'win32' ? 'git.exe' : 'git';
  const ignored = execFileSync(
    git,
    ['check-ignore', '--no-index', 'ultra_server/monitoring/secrets/ultra_metrics_token'],
    {
      cwd: new URL('..', import.meta.url),
      encoding: 'utf8',
    },
  ).trim();
  assert.equal(ignored, 'ultra_server/monitoring/secrets/ultra_metrics_token');
});
