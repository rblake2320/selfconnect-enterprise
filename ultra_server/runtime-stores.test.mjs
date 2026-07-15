import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { Pool } from 'pg';

import {
  PgIdempotencyStore,
  PgIdentityBindingStore,
  PgTumblerStore,
  ULTRA_PG_SCHEMA,
} from './runtime-stores.js';

const connectionString = process.env.DATABASE_URL;

test('PostgreSQL stores preserve monotonic counters and atomic idempotency', {
  skip: !connectionString,
}, async () => {
  const pool = new Pool({ connectionString });
  await pool.query(ULTRA_PG_SCHEMA);
  const tumblerStore = new PgTumblerStore(pool);
  const idempotency = new PgIdempotencyStore(pool);
  const bindings = new PgIdentityBindingStore(pool);
  const suffix = randomUUID();
  const clientId = `tsk_test_${suffix}`;
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

    const claims = await Promise.all([
      idempotency.claim(idemKey, 'test-operation', 'SC-12345678'),
      idempotency.claim(idemKey, 'test-operation', 'SC-12345678'),
    ]);
    assert.deepEqual(claims.map((claim) => claim.kind).sort(), ['claimed', 'processing']);
    await idempotency.complete(idemKey, { clientId });
    assert.deepEqual(
      await idempotency.claim(idemKey, 'test-operation', 'SC-12345678'),
      { kind: 'complete', response: { clientId } },
    );

    await bindings.set(pairId, { tskClientId: clientId, agentId: 'SC-12345678' });
    const secondBindingInstance = new PgIdentityBindingStore(pool);
    assert.deepEqual(
      await secondBindingInstance.get(pairId),
      { tskClientId: clientId, agentId: 'SC-12345678' },
    );
  } finally {
    await pool.query('DELETE FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]);
    await pool.query('DELETE FROM ultra_idempotency WHERE idempotency_key=$1', [idemKey]);
    await tumblerStore.delete(clientId);
    await pool.end();
  }
});
