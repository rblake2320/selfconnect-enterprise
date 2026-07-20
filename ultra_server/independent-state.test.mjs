import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import test from 'node:test';

import { Pool } from 'pg';

import {
  PgNonceTombstoneStore,
  ULTRA_INDEPENDENT_STATE_SCHEMA,
  assertIndependentStateReady,
  exportIndependentState,
  guardCountersignIndependentState,
  importIndependentState,
  verifyIndependentStateBundle,
} from './independent-state.js';
import { ULTRA_PG_SCHEMA, initializePgSchemas } from './runtime-stores.js';

const urlA = process.env.ULTRA_TEST_POSTGRES_URL_A;
const urlB = process.env.ULTRA_TEST_POSTGRES_URL_B;
if (!urlA || !urlB) throw new Error(
  'ULTRA_TEST_POSTGRES_URL_A and ULTRA_TEST_POSTGRES_URL_B are required (this drill never skips)',
);

test('signed independent-state handoff is atomic, redacted, replay-safe, and rollback-safe', async () => {
  const a = new Pool({ connectionString: urlA });
  const b = new Pool({ connectionString: urlB });
  const source = generateKeyPairSync('ed25519');
  const guard = generateKeyPairSync('ed25519');
  const suffix = randomUUID();
  const clusterId = `ha-${suffix}`;
  const commandId = `promote-${suffix}`;
  const pairId = `pair-${suffix}`;
  const safeKey = randomUUID();
  const secretKey = randomUUID();
  const lockKey = `ultra-ha:${clusterId}:transition`;
  const bpcPromotionDigest = 'a'.repeat(64);
  const tskActivationDigest = 'b'.repeat(64);
  const nonceHash = createHash('sha256').update(`nonce-${suffix}`, 'utf8').digest('hex');
  try {
    await initializePgSchemas(a, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    await initializePgSchemas(b, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    const [systemA, systemB] = await Promise.all([
      a.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
      b.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
    ]);
    assert.notEqual(systemA.rows[0].id, systemB.rows[0].id);

    await a.query(
      'INSERT INTO ultra_identity_bindings (pair_id, tsk_client_id, agent_id) VALUES ($1,$2,$3)',
      [pairId, `tsk-${suffix}`, `agent-${suffix}`],
    );
    await a.query(
      `INSERT INTO ultra_idempotency (idempotency_key, operation, agent_id, state, response)
       VALUES ($1,'safe-op',$3,'complete',$2::jsonb),($4,'secret-op',$3,'complete',$5::jsonb)`,
      [safeKey, JSON.stringify({ ok: true, pairId }), `agent-${suffix}`, secretKey,
       JSON.stringify({ ok: true, sharedSecret: 'must-not-cross-sites' })],
    );
    const nonceA = new PgNonceTombstoneStore(a);
    assert.equal(await nonceA.checkAndConsume(`nonce-${suffix}`, 120_000), false);
    assert.equal(await nonceA.checkAndConsume(`nonce-${suffix}`, 120_000), true);

    const sourceBundle = await exportIndependentState(a, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourceKeyId: 'source-key-1',
      sourcePrivateKey: source.privateKey,
      tskActivationDigest,
    });
    const serialized = JSON.stringify(sourceBundle);
    assert.equal(serialized.includes('must-not-cross-sites'), false);
    assert.equal(sourceBundle.manifest.state.idempotency.find(
      (item) => item.idempotencyKey === secretKey,
    ).secretReprovisionRequired, true);
    const bundle = guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: commandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'guard-key-1',
      guardPrivateKey: guard.privateKey,
    });
    assert.equal(verifyIndependentStateBundle(bundle, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
    }), true);

    const tampered = structuredClone(bundle);
    tampered.manifest.state.identityBindings[0].agentId = 'attacker';
    assert.throws(() => verifyIndependentStateBundle(tampered, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
    }), /digest mismatch/);
    await assert.rejects(importIndependentState(a, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      tskActivationDigest,
    }), /not independent/);

    const imported = await importIndependentState(b, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      tskActivationDigest,
    });
    assert.equal(imported.idempotent, false);
    assert.equal((await importIndependentState(b, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      tskActivationDigest,
    })).idempotent, true);
    assert.deepEqual((await b.query(
      'SELECT tsk_client_id, agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0], { tsk_client_id: `tsk-${suffix}`, agent_id: `agent-${suffix}` });
    assert.deepEqual((await b.query(
      'SELECT response FROM ultra_idempotency WHERE idempotency_key=$1', [secretKey],
    )).rows[0].response.error, 'SECRET_REPROVISION_REQUIRED');
    const nonceB = new PgNonceTombstoneStore(b);
    assert.equal(await nonceB.checkAndConsume(`nonce-${suffix}`, 120_000), true);
    assert.equal((await assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    })).targetSystemId, systemB.rows[0].id);
    await b.query('UPDATE ultra_identity_bindings SET agent_id=$2 WHERE pair_id=$1', [pairId, 'attacker']);
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /rolled back or tampered/);
    await assert.rejects(importIndependentState(b, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      tskActivationDigest,
    }), /rolled back or tampered/);
    await b.query('UPDATE ultra_identity_bindings SET agent_id=$2 WHERE pair_id=$1', [pairId, `agent-${suffix}`]);

    const fork = structuredClone(bundle);
    fork.manifestDigest = '0'.repeat(64);
    await assert.rejects(importIndependentState(b, fork, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      tskActivationDigest,
    }), /digest mismatch/);
  } finally {
    for (const pool of [a, b]) {
      await pool.query('DELETE FROM ultra_ha_import_head WHERE cluster_id=$1', [clusterId]).catch(() => {});
      await pool.query('DELETE FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]).catch(() => {});
      await pool.query('DELETE FROM ultra_idempotency WHERE idempotency_key IN ($1,$2)', [safeKey, secretKey]).catch(() => {});
      await pool.query('DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1', [nonceHash]).catch(() => {});
      await pool.end();
    }
  }
});
