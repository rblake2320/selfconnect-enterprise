import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { Pool } from 'pg';

import {
  MemoryIdempotencyStore,
  MemoryIdentityBindingStore,
  PgIdempotencyStore,
  PgIdentityBindingStore,
  PgTumblerStore,
  ULTRA_PG_SCHEMA,
  initializePgSchemas,
} from './runtime-stores.js';

test('memory idempotency completion and operation locks are retry safe', async () => {
  const store = new MemoryIdempotencyStore();
  const key = randomUUID();
  assert.deepEqual(await store.claim(key, 'operation', 'agent'), { kind: 'claimed' });
  await store.complete(key, { ok: true, nested: { a: 1, b: 2 } });
  await store.complete(key, { nested: { b: 2, a: 1 }, ok: true });
  await assert.rejects(store.complete(key, { ok: false }), /response conflict/);

  let active = 0;
  let maximum = 0;
  const enter = async () => store.withLock('same-resource', async () => {
    active += 1;
    maximum = Math.max(maximum, active);
    await new Promise((resolve) => setTimeout(resolve, 10));
    active -= 1;
  });
  await Promise.all([enter(), enter(), enter()]);
  assert.equal(maximum, 1);
});

test('memory identity binding compare-and-swap is idempotent and conflict aware', async () => {
  const store = new MemoryIdentityBindingStore();
  await store.set('pair-1', { tskClientId: 'old', agentId: 'agent-1' });
  assert.equal(await store.compareAndSwap(
    'pair-1', 'old', { tskClientId: 'new', agentId: 'agent-1' },
  ), 'updated');
  assert.equal(await store.compareAndSwap(
    'pair-1', 'old', { tskClientId: 'new', agentId: 'agent-1' },
  ), 'already');
  assert.equal(await store.compareAndSwap(
    'pair-1', 'other', { tskClientId: 'wrong', agentId: 'agent-1' },
  ), 'conflict');
  assert.equal(await store.compareAndSwap(
    'missing', 'old', { tskClientId: 'new', agentId: 'agent-1' },
  ), 'missing');
});

const connectionString = process.env.DATABASE_URL;

function deferred() {
  let resolve;
  const promise = new Promise((accept) => { resolve = accept; });
  return { promise, resolve };
}

async function waitForAdvisoryWaiter(pool) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const { rows } = await pool.query(
      "SELECT COUNT(*)::int AS count FROM pg_locks WHERE locktype='advisory' AND NOT granted",
    );
    if (rows[0].count > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('exclusive advisory-lock waiter did not appear');
}

test('PostgreSQL HA shared holders overlap and queued transition is exclusive', {
  skip: !connectionString,
}, async () => {
  const pool = new Pool({ connectionString, max: 8 });
  const store = new PgIdempotencyStore(pool);
  const key = `ha-lock-test:${randomUUID()}`;
  const releaseShared = deferred();
  const releaseExclusive = deferred();
  const bothSharedEntered = deferred();
  const exclusiveEntered = deferred();
  let sharedActive = 0;
  let sharedMaximum = 0;
  let lateSharedEntered = false;

  const sharedHolder = () => store.withSharedLock(key, async () => {
    sharedActive += 1;
    sharedMaximum = Math.max(sharedMaximum, sharedActive);
    if (sharedActive === 2) bothSharedEntered.resolve();
    await releaseShared.promise;
    sharedActive -= 1;
  });

  const first = sharedHolder();
  const second = sharedHolder();
  let exclusive;
  let lateShared;
  try {
    await bothSharedEntered.promise;
    assert.equal(sharedMaximum, 2);

    exclusive = store.withLock(key, async () => {
      exclusiveEntered.resolve();
      await releaseExclusive.promise;
    });
    await waitForAdvisoryWaiter(pool);

    lateShared = store.withSharedLock(key, async () => {
      lateSharedEntered = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(lateSharedEntered, false, 'late shared holder bypassed queued transition');

    releaseShared.resolve();
    await exclusiveEntered.promise;
    assert.equal(sharedActive, 0);
    assert.equal(lateSharedEntered, false);
    releaseExclusive.resolve();
    await Promise.all([first, second, exclusive, lateShared]);
    assert.equal(lateSharedEntered, true);
  } finally {
    releaseShared.resolve();
    exclusiveEntered.resolve();
    releaseExclusive.resolve();
    await Promise.allSettled([first, second, exclusive, lateShared].filter(Boolean));
    await pool.end();
  }
});

test('PostgreSQL stores preserve monotonic counters and atomic idempotency', {
  skip: !connectionString,
}, async () => {
  const pool = new Pool({ connectionString });
  const concurrentInitializer = new Pool({ connectionString });
  await Promise.all([
    initializePgSchemas(pool, ULTRA_PG_SCHEMA),
    initializePgSchemas(concurrentInitializer, ULTRA_PG_SCHEMA),
  ]);
  await concurrentInitializer.end();
  const tumblerStore = new PgTumblerStore(pool);
  const idempotency = new PgIdempotencyStore(pool);
  const bindings = new PgIdentityBindingStore(pool);
  const suffix = randomUUID();
  const clientId = `tsk_test_${suffix}`;
  const rotatedClientId = `tsk_rotated_${suffix}`;
  const pairId = `pair_test_${suffix}`;
  const idemKey = randomUUID();
  const map = {
    clientId,
    sharedSecret: 'ab'.repeat(32),
    keyLength: 32,
    segments: [
      { segmentId: 'id_test', type: 'static', position: [0, 8] },
      { segmentId: 'hotp_test', type: 'hotp', counter: 0, position: [8, 20] },
    ],
    checksum: { position: [20, 32] },
    createdAt: Date.now(),
    version: '1',
    status: 'active',
    requestCount: 0,
    lastUsedAt: null,
  };

  try {
    await tumblerStore.set(clientId, map);
    const concurrent = await Promise.all([
      tumblerStore.consumeCounter(clientId, 'hotp_test', 0),
      tumblerStore.consumeCounter(clientId, 'hotp_test', 0),
    ]);
    assert.deepEqual(concurrent.sort(), [false, true]);

    await tumblerStore.set(clientId, {
      ...map,
      requestCount: 1,
      lastUsedAt: Date.now(),
    });
    const persisted = await tumblerStore.get(clientId);
    assert.equal(persisted.segments.find((segment) => segment.segmentId === 'hotp_test').counter, 1);
    assert.equal(persisted.requestCount, 1);

    const validationCommits = await Promise.all([
      tumblerStore.commitValidation(clientId, {
        counterMatches: [{ segmentId: 'hotp_test', matchedCounter: 1 }],
        usedAt: Date.now(),
      }),
      tumblerStore.commitValidation(clientId, {
        counterMatches: [{ segmentId: 'hotp_test', matchedCounter: 1 }],
        usedAt: Date.now(),
      }),
    ]);
    assert.equal(validationCommits.filter((result) => result.ok).length, 1);
    assert.equal(
      validationCommits.filter((result) => result.error === 'TSK_HOTP_REPLAY_DETECTED').length,
      1,
    );
    const committed = await tumblerStore.get(clientId);
    assert.equal(committed.segments.find((segment) => segment.segmentId === 'hotp_test').counter, 2);
    assert.equal(committed.requestCount, 2);

    const replacement = {
      ...map,
      clientId: rotatedClientId,
      segments: map.segments.map((segment) => ({ ...segment })),
    };
    assert.equal(await tumblerStore.replaceCredential(clientId, replacement), true);
    assert.equal((await tumblerStore.get(clientId)).status, 'revoked');
    assert.equal((await tumblerStore.get(rotatedClientId)).status, 'active');
    assert.equal(await tumblerStore.replaceCredential(clientId, replacement), false);

    const claims = await Promise.all([
      idempotency.claim(idemKey, 'test-operation', 'SC-12345678'),
      idempotency.claim(idemKey, 'test-operation', 'SC-12345678'),
    ]);
    assert.deepEqual(claims.map((claim) => claim.kind).sort(), ['claimed', 'processing']);
    await idempotency.complete(idemKey, { clientId, ok: true });
    await idempotency.complete(idemKey, { ok: true, clientId });
    await assert.rejects(
      idempotency.complete(idemKey, { clientId: 'different' }),
      /response conflict/,
    );
    assert.deepEqual(
      await idempotency.claim(idemKey, 'test-operation', 'SC-12345678'),
      { kind: 'complete', response: { ok: true, clientId } },
    );

    let active = 0;
    let maximum = 0;
    const lockKey = `test-lock:${suffix}`;
    const enter = async () => idempotency.withLock(lockKey, async () => {
      active += 1;
      maximum = Math.max(maximum, active);
      await new Promise((resolve) => setTimeout(resolve, 25));
      active -= 1;
    });
    await Promise.all([enter(), enter(), enter()]);
    assert.equal(maximum, 1);

    await bindings.set(pairId, { tskClientId: clientId, agentId: 'SC-12345678' });
    const secondBindingInstance = new PgIdentityBindingStore(pool);
    assert.deepEqual(
      await secondBindingInstance.get(pairId),
      { tskClientId: clientId, agentId: 'SC-12345678' },
    );
    assert.equal(await bindings.compareAndSwap(
      pairId,
      clientId,
      { tskClientId: rotatedClientId, agentId: 'SC-12345678' },
    ), 'updated');
    assert.equal(await secondBindingInstance.compareAndSwap(
      pairId,
      clientId,
      { tskClientId: rotatedClientId, agentId: 'SC-12345678' },
    ), 'already');
    assert.equal(await bindings.compareAndSwap(
      pairId,
      clientId,
      { tskClientId: 'wrong', agentId: 'SC-12345678' },
    ), 'conflict');
  } finally {
    await pool.query('DELETE FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]);
    await pool.query('DELETE FROM ultra_idempotency WHERE idempotency_key=$1', [idemKey]);
    await tumblerStore.delete(clientId);
    await tumblerStore.delete(rotatedClientId);
    await pool.end();
  }
});
