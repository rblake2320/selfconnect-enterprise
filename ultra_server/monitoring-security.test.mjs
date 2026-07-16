import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createMetricsAuthMiddleware,
  METRIC_ROUTE_LABEL_LIMIT,
  metricAuthFailureLabel,
  metricMethodLabel,
  metricRouteLabel,
  validateMetricsTokenConfiguration,
} from './monitoring-security.js';

function invoke(middleware, authorization) {
  let nextCalled = false;
  const response = {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
  middleware(
    { get: () => authorization },
    response,
    () => { nextCalled = true; },
  );
  return { nextCalled, response };
}

test('metrics bearer accepts current and one previous token only', () => {
  const middleware = createMetricsAuthMiddleware(['current-metrics-token', 'previous-metrics-token']);

  for (const token of ['current-metrics-token', 'previous-metrics-token']) {
    const result = invoke(middleware, `Bearer ${token}`);
    assert.equal(result.nextCalled, true);
  }
  for (const header of [undefined, '', 'Basic current-metrics-token', 'Bearer wrong']) {
    const result = invoke(middleware, header);
    assert.equal(result.nextCalled, false);
    assert.equal(result.response.statusCode, 401);
    assert.equal(result.response.body.error, 'METRICS_AUTH_REQUIRED');
  }
});

test('unconfigured metrics bearer fails closed', () => {
  const result = invoke(createMetricsAuthMiddleware([]), 'Bearer anything');
  assert.equal(result.nextCalled, false);
  assert.equal(result.response.statusCode, 503);
  assert.equal(result.response.body.error, 'METRICS_AUTH_UNCONFIGURED');
});

test('production metrics configuration is mandatory, strong, separate, and rotation-bounded', () => {
  const strong = 'm'.repeat(32);
  assert.doesNotThrow(() => validateMetricsTokenConfiguration({
    runtimeMode: 'production',
    current: strong,
    previous: 'p'.repeat(32),
    adminTokens: [['ULTRA_ADMIN_TOKEN', 'a'.repeat(32)]],
  }));

  for (const config of [
    { current: null },
    { current: 'short' },
    { current: strong, previous: 'short' },
    { current: strong, previous: strong },
    {
      current: strong,
      adminTokens: [['ULTRA_ADMIN_TOKEN', strong]],
    },
    {
      current: strong,
      previous: 'p'.repeat(32),
      adminTokens: [['ULTRA_ADMIN_TOKEN_PREVIOUS', 'p'.repeat(32)]],
    },
  ]) {
    assert.throws(() => validateMetricsTokenConfiguration({
      runtimeMode: 'production',
      adminTokens: [],
      ...config,
    }));
  }
});

test('hostile request paths collapse to one bounded route label', () => {
  const labels = new Set();
  for (let index = 0; index < 10_000; index += 1) {
    labels.add(metricRouteLabel(`/attacker/${index}/${'x'.repeat(index % 128)}`));
  }
  assert.deepEqual([...labels], ['__unmatched__']);

  const allKnownAndHostile = new Set([
    metricRouteLabel('/health'),
    metricRouteLabel('/pubkeys/:pairId'),
    ...labels,
  ]);
  assert.equal(allKnownAndHostile.size, 3);
  assert.ok(METRIC_ROUTE_LABEL_LIMIT < 32);
});

test('method and authentication failure labels use closed sets', () => {
  assert.equal(metricMethodLabel('GET'), 'GET');
  assert.equal(metricMethodLabel('TRACE'), 'OTHER');
  assert.equal(metricMethodLabel(`HOSTILE-${'x'.repeat(1_000)}`), 'OTHER');

  assert.equal(metricAuthFailureLabel('bpc'), 'bpc');
  assert.equal(metricAuthFailureLabel('tsk'), 'tsk');
  assert.equal(metricAuthFailureLabel('BPC: INVALID_SIGNATURE'), 'bpc');
  assert.equal(metricAuthFailureLabel('TSK: INVALID_KEY'), 'tsk');
  assert.equal(metricAuthFailureLabel('IDENTITY_BINDING_MISMATCH'), 'identity');
  assert.equal(metricAuthFailureLabel('arbitrary-attacker-reason'), 'unknown');
});
