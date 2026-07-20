import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';

import {
  HA_OUTBOX_PG_SCHEMA,
  NodePostgresTransactor,
  PgDurableOutbox,
  PgReceiverCheckpoint,
  adoptCurrentSchemaVersion,
} from '@bpc/server';
import { Pool } from 'pg';

import { ULTRA_INDEPENDENT_STATE_SCHEMA } from './independent-state.js';
import { ULTRA_PG_SCHEMA, initializePgSchemas } from './runtime-stores.js';
import {
  PgReplicatedIdempotencyStore,
  PgReplicatedIdentityBindingStore,
  PgReplicatedNonceTombstoneStore,
  UltraStateMutationApplier,
  ultraStateMutationSanitizer,
} from './ultra-state-outbox.js';

const urlA = process.env.ULTRA_TEST_POSTGRES_URL_A;
const urlB = process.env.ULTRA_TEST_POSTGRES_URL_B;
if (!urlA || !urlB) throw new Error(
  'ULTRA_TEST_POSTGRES_URL_A and ULTRA_TEST_POSTGRES_URL_B are required (this drill never skips)',
);

async function provisionStream(db, streamId, epoch, fenceToken) {
  await db.transaction(async (exec) => {
    await exec.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,$2)', [streamId, fenceToken]);
    await exec.query(
      'INSERT INTO ha_outbox_source_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
      [streamId, epoch],
    );
    await exec.query(
      'INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
      [streamId, epoch],
    );
  });
}

test('Ultra authority mutations commit with secret-stripped ordered outbox records', async () => {
  const a = new Pool({ connectionString: urlA });
  const b = new Pool({ connectionString: urlB });
  const streamId = `ultra-${randomUUID()}`;
  const epoch = `epoch-${randomUUID()}`;
  const pairId = `pair-${randomUUID()}`;
  const oldClientId = `client-${randomUUID()}`;
  const newClientId = `client-${randomUUID()}`;
  const agentId = `agent-${randomUUID()}`;
  const idemKey = randomUUID();
  const nonceValue = `nonce-${randomUUID()}`;
  const nonceHash = createHash('sha256').update(nonceValue, 'utf8').digest('hex');
  try {
    await initializePgSchemas(a, HA_OUTBOX_PG_SCHEMA, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    await initializePgSchemas(b, HA_OUTBOX_PG_SCHEMA, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    const dbA = new NodePostgresTransactor(a);
    const dbB = new NodePostgresTransactor(b);
    const readyA = await adoptCurrentSchemaVersion(dbA, 'public');
    const readyB = await adoptCurrentSchemaVersion(dbB, 'public');
    await provisionStream(dbA, streamId, epoch, 1);
    await provisionStream(dbB, streamId, epoch, 1);
    const outbox = new PgDurableOutbox(dbA, readyA, {
      streamId, sanitizer: ultraStateMutationSanitizer, maxPendingRows: 100,
      backpressure: 'fail-authoritative-mutation',
    });
    const bindings = new PgReplicatedIdentityBindingStore(outbox, streamId, 1n);
    const idempotency = new PgReplicatedIdempotencyStore(a, outbox, streamId, 1n);
    const nonces = new PgReplicatedNonceTombstoneStore(outbox, streamId, 1n);

    await bindings.set(pairId, { tskClientId: oldClientId, agentId });
    assert.equal(await bindings.compareAndSwap(
      pairId, oldClientId, { tskClientId: newClientId, agentId },
    ), 'updated');
    assert.deepEqual(await idempotency.claim(idemKey, 'credential-op', agentId), { kind: 'claimed' });
    const sourceResponse = { ok: true, sharedSecret: 'source-only-secret' };
    const completion = idempotency.complete(idemKey, sourceResponse);
    sourceResponse.sharedSecret = 'caller-mutated-after-entry';
    await completion;
    assert.equal((await a.query(
      'SELECT response FROM ultra_idempotency WHERE idempotency_key=$1', [idemKey],
    )).rows[0].response.sharedSecret, 'source-only-secret');
    assert.equal(await nonces.checkAndConsume(nonceValue, 120_000), false);

    const records = (await a.query(
      `SELECT contract_version,stream_id,source_epoch,sequence,fence_token::text,op_digest,mutation
         FROM (SELECT '1'::text AS contract_version,* FROM ha_outbox_rows) rows
        WHERE stream_id=$1 ORDER BY sequence`, [streamId],
    )).rows.map((row) => ({
      contractVersion: row.contract_version, streamId: row.stream_id,
      sourceEpoch: row.source_epoch, sequence: Number(row.sequence),
      fenceToken: row.fence_token, opDigest: row.op_digest, mutation: row.mutation,
    }));
    assert.equal(records.length, 5);
    assert.deepEqual(records.map((record) => record.sequence), [1, 2, 3, 4, 5]);
    assert.equal(JSON.stringify(records).includes('source-only-secret'), false);
    assert.equal(records[3].mutation.secretReprovisionRequired, true);

    await assert.rejects(outbox.withOutboxTx(async (tx) => {
      await outbox.appendInTx(tx, {
        streamId, fenceToken: 1n,
        rawMutation: {
          kind: 'ultra.binding.set.v1', pairId: `pair-${randomUUID()}`,
          tskClientId: `client-${randomUUID()}`, agentId,
        },
      });
      throw new Error('simulated authoritative mutation failure');
    }), /simulated authoritative mutation failure/);
    assert.equal(Number((await a.query(
      'SELECT count(*) FROM ha_outbox_rows WHERE stream_id=$1', [streamId],
    )).rows[0].count), 5);

    const receiver = new PgReceiverCheckpoint(
      dbB, streamId, ultraStateMutationSanitizer, new UltraStateMutationApplier(), readyB,
    );
    for (const record of records) assert.equal(await receiver.verifyAndApplyDelivered(record), 'applied');
    assert.equal(await receiver.verifyAndApplyDelivered(records[4]), 'duplicate-ok');
    const bindingB = (await b.query(
      'SELECT tsk_client_id,agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0];
    assert.deepEqual(bindingB, { tsk_client_id: newClientId, agent_id: agentId });
    const idemB = (await b.query(
      'SELECT state,response FROM ultra_idempotency WHERE idempotency_key=$1', [idemKey],
    )).rows[0];
    assert.equal(idemB.state, 'complete');
    assert.deepEqual(idemB.response, {
      ok: false, error: 'SECRET_REPROVISION_REQUIRED',
      originalResponseDigest: records[3].mutation.responseDigest,
    });

    await a.query('UPDATE ha_outbox_fence SET fence_token=2 WHERE stream_id=$1', [streamId]);
    await assert.rejects(
      bindings.set(`pair-${randomUUID()}`, { tskClientId: `client-${randomUUID()}`, agentId }),
      /fence token .* stale/i,
    );
    assert.equal(Number((await a.query(
      'SELECT count(*) FROM ha_outbox_rows WHERE stream_id=$1', [streamId],
    )).rows[0].count), 5);
  } finally {
    for (const pool of [a, b]) {
      try {
        await pool.query('DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1', [nonceHash]);
        await pool.query('DELETE FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]);
        await pool.query('DELETE FROM ultra_idempotency WHERE idempotency_key=$1', [idemKey]);
        await pool.query('DELETE FROM ha_outbox_applied WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM ha_outbox_quarantine WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM ha_outbox_rows WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM ha_outbox_publisher_lease WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM ha_outbox_fence WHERE stream_id=$1', [streamId]);
      } catch { /* preserve the primary assertion failure */ }
    }
    await a.end();
    await b.end();
  }
});
