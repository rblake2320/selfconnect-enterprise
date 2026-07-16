import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { MemoryFencingStore, signGuardCommand } from '@tsk/server';

import { UltraHaController, loadUltraHaConfig } from './ha-controller.js';

const GUARD = 'ultra-ha-guard-secret-at-least-32-bytes';
const NOW = 1_750_000_000_000;

function command({
  clusterId = 'cluster-a',
  command: action,
  expiresAt = NOW + 60_000,
  fenceEpoch,
  issuedAt = NOW,
  nodeId,
}) {
  return signGuardCommand({
    by: 'fleet-guard',
    clusterId,
    command: action,
    expiresAt,
    fenceEpoch,
    issuedAt,
    nodeId,
    reason: 'controlled test transition',
  }, GUARD);
}

function controller(role, nodeId, fenceStore, overrides = {}) {
  return new UltraHaController({
    clusterId: 'cluster-a',
    fenceStore,
    guardSecret: GUARD,
    nodeId,
    now: () => NOW,
    role,
    ...overrides,
  });
}

test('HA configuration is disabled by default and fails closed when incomplete', () => {
  assert.deepEqual(loadUltraHaConfig({}, 'development'), { enabled: false });
  assert.throws(
    () => loadUltraHaConfig({ ULTRA_HA_ENABLED: '1' }, 'production'),
    /ULTRA_HA_ENABLED must be true or false/,
  );
  assert.throws(
    () => loadUltraHaConfig({ ULTRA_HA_ENABLED: 'true' }, 'development'),
    /requires ULTRA_RUNTIME_MODE=production/,
  );
  assert.throws(
    () => loadUltraHaConfig({
      ULTRA_HA_ENABLED: 'true',
      ULTRA_HA_NODE_ID: 'node-a',
      ULTRA_HA_NODE_ROLE: 'primary',
      ULTRA_HA_CLUSTER_ID: 'cluster-a',
    }, 'production'),
    /ULTRA_HA_GUARD_SECRET/,
  );
  assert.throws(
    () => loadUltraHaConfig({
      ULTRA_ADMIN_TOKEN_PREVIOUS: GUARD,
      ULTRA_HA_CLUSTER_ID: 'cluster-a',
      ULTRA_HA_ENABLED: 'true',
      ULTRA_HA_GUARD_SECRET: GUARD,
      ULTRA_HA_NODE_ID: 'node-a',
      ULTRA_HA_NODE_ROLE: 'primary',
    }, 'production'),
    /must differ from ULTRA_ADMIN_TOKEN_PREVIOUS/,
  );
});

test('HA configuration binds the fence and advisory lock to the cluster', () => {
  const config = loadUltraHaConfig({
    ULTRA_ADMIN_TOKEN: 'admin-token-distinct-at-least-32-bytes',
    ULTRA_HA_CLUSTER_ID: 'cluster-a',
    ULTRA_HA_ENABLED: 'true',
    ULTRA_HA_GUARD_SECRET: GUARD,
    ULTRA_HA_NODE_ID: 'node-a',
    ULTRA_HA_NODE_ROLE: 'primary',
    ULTRA_RECOVERY_HMAC_KEY: 'recovery-key-distinct-at-least-32-bytes',
  }, 'production');
  assert.equal(config.enabled, true);
  assert.equal(config.fenceKey, 'ultra:ha:cluster-a:writer');
  assert.equal(config.advisoryLockKey, 'ultra-ha:cluster-a:transition');
});

test('higher-epoch replica promotion fences the old primary', async () => {
  const fence = new MemoryFencingStore();
  const primary = controller('primary', 'primary-a', fence);
  const replica = controller('replica', 'replica-a', fence);

  assert.equal((await primary.applyCommand(command({
    command: 'activate', fenceEpoch: 10, nodeId: 'primary-a',
  }))).status, 200);
  assert.equal((await primary.assertWritable()).ok, true);

  assert.equal((await replica.applyCommand(command({
    command: 'promote', fenceEpoch: 11, nodeId: 'replica-a',
  }))).status, 200);
  assert.equal((await replica.assertWritable()).ok, true);
  assert.equal((await primary.assertWritable()).ok, false);
});

test('role mismatch, stale command, tamper, and replay are rejected', async () => {
  const fence = new MemoryFencingStore();
  const primary = controller('primary', 'primary-a', fence);
  const wrongRole = await primary.applyCommand(command({
    command: 'promote', fenceEpoch: 1, nodeId: 'primary-a',
  }));
  assert.equal(wrongRole.status, 409);
  assert.equal(wrongRole.result.error, 'wrong_command_for_role');

  const stale = await primary.applyCommand(command({
    command: 'activate',
    expiresAt: NOW + 1,
    fenceEpoch: 1,
    issuedAt: NOW - 60_001,
    nodeId: 'primary-a',
  }));
  assert.equal(stale.status, 401);
  assert.equal(stale.result.error, 'command_stale');

  const valid = command({ command: 'activate', fenceEpoch: 2, nodeId: 'primary-a' });
  const tampered = await primary.applyCommand({ ...valid, fenceEpoch: 3 });
  assert.equal(tampered.status, 401);
  assert.equal(tampered.result.error, 'signature_invalid');
  assert.equal((await primary.applyCommand(valid)).status, 200);
  assert.equal((await primary.applyCommand(valid)).status, 409);
});

test('commands are cluster- and node-bound by the signature', async () => {
  const fence = new MemoryFencingStore();
  const primary = controller('primary', 'primary-a', fence);
  const wrongCluster = await primary.applyCommand(command({
    clusterId: 'cluster-b', command: 'activate', fenceEpoch: 1, nodeId: 'primary-a',
  }));
  assert.equal(wrongCluster.status, 409);
  assert.equal(wrongCluster.result.error, 'wrong_cluster_or_node');
  const wrongNode = await primary.applyCommand(command({
    command: 'activate', fenceEpoch: 1, nodeId: 'primary-b',
  }));
  assert.equal(wrongNode.status, 409);
  assert.equal(wrongNode.result.error, 'wrong_cluster_or_node');
});

test('fence outage and corrupt authority fail closed', async () => {
  const broken = controller('primary', 'primary-a', {
    claim: async () => { throw new Error('down'); },
    current: async () => { throw new Error('corrupt'); },
    release: async () => false,
  });
  const result = await broken.applyCommand(command({
    command: 'activate', fenceEpoch: 1, nodeId: 'primary-a',
  }));
  assert.equal(result.status, 503);
  assert.equal((await broken.assertWritable()).ok, false);
});

test('a restarted process has no local lease and remains fenced', async () => {
  const fence = new MemoryFencingStore();
  const first = controller('primary', 'primary-a', fence);
  assert.equal((await first.applyCommand(command({
    command: 'activate', fenceEpoch: 1, nodeId: 'primary-a',
  }))).status, 200);
  assert.equal((await first.assertWritable()).ok, true);

  const restarted = controller('primary', 'primary-a', fence);
  assert.equal((await restarted.assertWritable()).ok, false);
});

test('readiness drains before expiry while an admitted epoch remains current', async () => {
  let now = NOW;
  const fence = new MemoryFencingStore();
  const primary = controller('primary', 'primary-a', fence, {
    minLeaseRemainingMs: 5_000,
    now: () => now,
  });
  const grant = command({
    command: 'activate',
    expiresAt: NOW + 10_000,
    fenceEpoch: 1,
    nodeId: 'primary-a',
  });
  assert.equal((await primary.applyCommand(grant)).status, 200);
  now += 5_001;
  assert.equal((await primary.assertWritable()).ok, true);
  assert.equal((await primary.assertWritable({ minRemainingMs: 5_000 })).ok, false);
  const snapshot = await primary.snapshot();
  assert.equal(snapshot.writable, true);
  assert.equal(snapshot.acceptingWrites, false);
});

test('every state-mutating HTTP route declares the HA writer boundary', async () => {
  const source = await readFile(new URL('./server.js', import.meta.url), 'utf8');
  const routes = [...source.matchAll(/app\.(post|put|patch|delete)\('([^']+)',\s*([^,\n)]+)/g)]
    .map((match) => ({ method: match[1], path: match[2], firstGuard: match[3].trim() }));
  assert.ok(routes.length > 0);
  for (const route of routes) {
    if (route.path === '/verify-recovery-token') {
      assert.equal(route.firstGuard, '(req', 'token verification is the only read-only POST');
    } else if (route.path === '/ha/command') {
      assert.equal(route.firstGuard, 'requireAdminAuth');
      assert.match(source, /app\.post\('\/ha\/command', requireAdminAuth, serializeHaTransition,/);
    } else {
      assert.equal(
        route.firstGuard,
        'requireWriterLease',
        `${route.method.toUpperCase()} ${route.path} is missing the writer boundary`,
      );
    }
  }
  assert.match(
    source,
    /await idempotencyStore\.withLock\(bpcActivityLock\(pairId\), verifyRequest\)/,
    'BPC verification activity must be cross-process serialized per pair',
  );
  assert.match(
    source,
    /idempotencyStore\.withLock\(bpcActivityLock\(req\.params\.pairId\)/,
    'BPC lifecycle updates must share the per-pair activity lock',
  );
});
