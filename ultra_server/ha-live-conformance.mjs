import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';

import Redis from 'ioredis';
import { Pool } from 'pg';
import { signGuardCommand } from '@tsk/server';
import {
  createUltraRedisClient,
  loadUltraRedisAuthorityConfig,
} from './ultra-redis-authority.js';

const PHASE = process.argv[2];
const STATE_PATH = process.argv[3];
const PRIMARY_URL = process.env.ULTRA_PRIMARY_URL ?? 'http://127.0.0.1:7777';
const REPLICA_URL = process.env.ULTRA_REPLICA_URL ?? 'http://127.0.0.1:7778';
const ADMIN_TOKEN = process.env.ULTRA_ADMIN_TOKEN ?? '';
const GUARD_SECRET = process.env.ULTRA_HA_GUARD_SECRET ?? '';
const CLUSTER_ID = process.env.ULTRA_HA_CLUSTER_ID ?? 'ci-shared-state';
const PRIMARY_ID = process.env.ULTRA_HA_PRIMARY_ID ?? 'primary-a';
const REPLICA_ID = process.env.ULTRA_HA_REPLICA_ID ?? 'replica-a';
const LEASE_MS = 240_000;

if (!ADMIN_TOKEN || Buffer.byteLength(GUARD_SECRET, 'utf8') < 32) {
  throw new Error('ULTRA_ADMIN_TOKEN and a 32-byte ULTRA_HA_GUARD_SECRET are required');
}

async function request(base, method, path, body, headers = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(10_000),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

function command(action, nodeId, fenceEpoch, overrides = {}) {
  const issuedAt = overrides.issuedAt ?? Date.now();
  return signGuardCommand({
    by: 'ci-fleet-guard',
    clusterId: overrides.clusterId ?? CLUSTER_ID,
    command: action,
    expiresAt: overrides.expiresAt ?? issuedAt + LEASE_MS,
    fenceEpoch,
    issuedAt,
    nodeId,
    reason: 'two-process shared-state conformance',
  }, GUARD_SECRET);
}

async function sendCommand(base, body) {
  return request(base, 'POST', '/ha/command', body, {
    Authorization: `Bearer ${ADMIN_TOKEN}`,
  });
}

async function ready(base) {
  return request(base, 'GET', '/ready');
}

async function preflight() {
  for (const base of [PRIMARY_URL, REPLICA_URL]) {
    const health = await request(base, 'GET', '/health');
    assert.equal(health.status, 200);
    assert.equal((await ready(base)).status, 503);
  }

  const primaryCandidate = command('activate', PRIMARY_ID, 10);
  const replicaCandidate = command('promote', REPLICA_ID, 10);
  const candidates = await Promise.all([
    sendCommand(PRIMARY_URL, primaryCandidate),
    sendCommand(REPLICA_URL, replicaCandidate),
  ]);
  assert.deepEqual(candidates.map(({ status }) => status).sort(), [200, 409]);
  const initialReady = await Promise.all([ready(PRIMARY_URL), ready(REPLICA_URL)]);
  assert.equal(initialReady.filter(({ status }) => status === 200).length, 1);

  const primaryActivationCommand = command('activate', PRIMARY_ID, 11);
  const activatePrimary = await sendCommand(PRIMARY_URL, primaryActivationCommand);
  assert.equal(activatePrimary.status, 200, JSON.stringify(activatePrimary));
  assert.equal((await ready(PRIMARY_URL)).status, 200);
  assert.equal((await ready(REPLICA_URL)).status, 503);

  const replay = await sendCommand(PRIMARY_URL, primaryActivationCommand);
  assert.equal(replay.status, 409);

  const validForTamper = command('activate', PRIMARY_ID, 13);
  const tampered = await sendCommand(PRIMARY_URL, { ...validForTamper, fenceEpoch: 14 });
  assert.equal(tampered.status, 401);
  assert.equal(tampered.body.error, 'signature_invalid');

  const staleIssued = Date.now() - 60_001;
  const stale = await sendCommand(PRIMARY_URL, command('activate', PRIMARY_ID, 13, {
    expiresAt: Date.now() + 1_000,
    issuedAt: staleIssued,
  }));
  assert.equal(stale.status, 401);
  assert.equal(stale.body.error, 'command_stale');

  const replicaMutation = await request(REPLICA_URL, 'POST', '/verify', {});
  assert.equal(replicaMutation.status, 503);
  assert.equal(replicaMutation.body.error, 'ULTRA_WRITER_FENCED');
}

async function promote() {
  const result = await sendCommand(REPLICA_URL, command('promote', REPLICA_ID, 13));
  assert.equal(result.status, 200, JSON.stringify(result));
  assert.equal((await ready(PRIMARY_URL)).status, 503);
  assert.equal((await ready(REPLICA_URL)).status, 200);
  const oldMutation = await request(PRIMARY_URL, 'POST', '/verify', {});
  assert.equal(oldMutation.status, 503);
  assert.equal(oldMutation.body.error, 'ULTRA_WRITER_FENCED');
}

async function stateSnapshot(pool, state) {
  const [pair, tumbler, binding] = await Promise.all([
    pool.query(
      `SELECT status, requests, failed_sigs, cumulative_failures, first_failure_at,
              last_active, max_requests, expires_at
       FROM bpc_pairs WHERE id=$1`,
      [state.pair_id],
    ),
    pool.query('SELECT map FROM ultra_tumbler_maps WHERE client_id=$1', [state.tsk_client_id]),
    pool.query(
      `SELECT pair_id, tsk_client_id, agent_id, canonical_id, agent_public_key_hex
         FROM ultra_identity_bindings WHERE pair_id=$1`,
      [state.pair_id],
    ),
  ]);
  return JSON.stringify({ pair: pair.rows, tumbler: tumbler.rows, binding: binding.rows });
}

async function assertOldFenced() {
  if (!STATE_PATH) throw new Error('state path is required');
  const state = JSON.parse(await readFile(STATE_PATH, 'utf8'));
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const before = await stateSnapshot(pool, state);
    const python = process.env.PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
    const attempt = spawnSync(python, [
      '-m', 'tools.ultra_restart_conformance', 'verify',
      '--state', STATE_PATH,
      '--server-url', PRIMARY_URL,
    ], {
      cwd: new URL('..', import.meta.url),
      encoding: 'utf8',
      env: process.env,
    });
    assert.notEqual(attempt.status, 0, 'old primary unexpectedly completed a governed verification');
    const after = await stateSnapshot(pool, state);
    assert.equal(after, before, 'fenced old-primary request changed governed state');
  } finally {
    await pool.end();
  }
}

async function corruptFence() {
  const redis = createUltraRedisClient(Redis,
    loadUltraRedisAuthorityConfig(process.env, { haEnabled: true }));
  try {
    await redis.connect();
    await redis.set(`ultra:ha:${CLUSTER_ID}:writer`, '{bad-json');
  } finally {
    await redis.quit().catch(() => undefined);
  }
  assert.equal((await ready(PRIMARY_URL)).status, 503);
  assert.equal((await ready(REPLICA_URL)).status, 503);
  const denied = await sendCommand(REPLICA_URL, command('promote', REPLICA_ID, 14));
  assert.equal(denied.status, 503);
  assert.equal(denied.body.error, 'fencing_authority_unavailable');
}

switch (PHASE) {
  case 'preflight': await preflight(); break;
  case 'promote': await promote(); break;
  case 'assert-old-fenced': await assertOldFenced(); break;
  case 'corrupt-fence': await corruptFence(); break;
  default: throw new Error('phase must be preflight, promote, assert-old-fenced, or corrupt-fence');
}

console.log(JSON.stringify({ ok: true, phase: PHASE }));
