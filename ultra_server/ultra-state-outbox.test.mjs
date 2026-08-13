import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  HA_OUTBOX_PG_SCHEMA,
  BPC_TRANSPORT_NONCE_SCHEMA,
  NodePostgresTransactor,
  PgReplayNonceStore,
  provisionSchemaVersion,
} from '@bpc/server';
import {
  TSK_SOURCE_LEASE_SCHEMA,
  installLeaseGrant,
  signLeaseGrant,
} from '@tsk/server';
import { Pool } from 'pg';

import { ULTRA_INDEPENDENT_STATE_SCHEMA } from './independent-state.js';
import {
  ULTRA_PG_SCHEMA,
  identityPrincipalsFromPublicKeyHex,
  initializePgSchemas,
} from './runtime-stores.js';
import { loadGovernedUltraStateAuthority } from './ultra-state-authority-config.js';
import {
  createUltraStateHttpReceiver,
  signUltraStateAck,
  ultraStateMutationSanitizer,
} from './ultra-state-outbox.js';

const COLLIDING_KEY_A = 'b71042b79f8a5b631eab1a0bf9eeb716506cc4021101190b54e9bc9058058b69';
const COLLIDING_KEY_B = '92abf75c9884799c19a780015345a8cce5ae56c2791ad5771d79969125c15b3f';

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
  const epoch = 1;
  const pairId = `pair-${randomUUID()}`;
  const oldClientId = `client-${randomUUID()}`;
  const newClientId = `client-${randomUUID()}`;
  const agentPublicKeyHex = COLLIDING_KEY_A;
  const { agentId, canonicalId } = identityPrincipalsFromPublicKeyHex(agentPublicKeyHex);
  const owner = { agentId, canonicalId, agentPublicKeyHex };
  const collider = {
    ...identityPrincipalsFromPublicKeyHex(COLLIDING_KEY_B),
    agentPublicKeyHex: COLLIDING_KEY_B,
  };
  const idemKey = randomUUID();
  const nonceValue = `nonce-${randomUUID()}`;
  const nonceHash = createHash('sha256').update(nonceValue, 'utf8').digest('hex');
  let receiverProcess;
  let runtimeDirectory;
  let files;
  try {
    await initializePgSchemas(
      a, HA_OUTBOX_PG_SCHEMA, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA,
      TSK_SOURCE_LEASE_SCHEMA,
    );
    await initializePgSchemas(
      b, HA_OUTBOX_PG_SCHEMA, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA,
      BPC_TRANSPORT_NONCE_SCHEMA,
    );
    const dbA = new NodePostgresTransactor(a);
    const dbB = new NodePostgresTransactor(b);
    await provisionSchemaVersion(dbA, 'public');
    const readyB = await provisionSchemaVersion(dbB, 'public');
    await provisionStream(dbA, streamId, String(epoch), 1);
    await provisionStream(dbB, streamId, String(epoch), 1);
    const guardKeys = generateKeyPairSync('ed25519');
    const sourceLeaseResolver = {
      resolve: (keyId) => keyId === 'source-guard-1' ? guardKeys.publicKey : null,
    };
    const lease = signLeaseGrant('source-guard-1', guardKeys.privateKey, {
      streamId, leaseEpoch: epoch, leaseStatus: 'active', holderNodeId: 'site-a',
      leaseId: 'site-a-lease-1', commandId: 'site-a-grant-1',
      leaseExpiresAtMs: Date.now() + 300_000, leaseGrantSeq: 1, prevGrantDigest: null,
    });
    await dbA.transaction((exec) => installLeaseGrant(exec, sourceLeaseResolver, lease));
    runtimeDirectory = await mkdtemp(join(tmpdir(), 'ultra-state-stream-'));
    files = {
      guardPublic: join(runtimeDirectory, 'source-guard-public.pem'),
      authority: join(runtimeDirectory, 'source-authority.json'),
    };
    await writeFile(files.guardPublic, guardKeys.publicKey.export({ type: 'spki', format: 'pem' }));
    await writeFile(files.authority, JSON.stringify({
      streamId, sourceEpoch: epoch, holderNodeId: lease.holderNodeId,
      leaseId: lease.leaseId, grantDigest: lease.grantDigest,
      controlToASkewBoundMs: 5_000,
      sourceLeasePublicKeyFiles: { 'source-guard-1': files.guardPublic },
    }));
    const authority = await loadGovernedUltraStateAuthority(a, files.authority);
    const { outbox, identityBinding: bindings, idempotencyStore: idempotency,
      nonceBackend: nonces } = authority;

    await bindings.set(pairId, { tskClientId: oldClientId, ...owner });
    assert.equal(await bindings.compareAndSwap(
      pairId, oldClientId, { tskClientId: newClientId, ...owner },
    ), 'updated');
    assert.equal(collider.agentId, owner.agentId);
    assert.notEqual(collider.canonicalId, owner.canonicalId);
    assert.equal(await bindings.compareAndSwap(
      pairId, newClientId, { tskClientId: `client-${randomUUID()}`, ...collider },
    ), 'conflict');
    assert.throws(
      () => ultraStateMutationSanitizer.sanitize({
        kind: 'ultra.binding.set.v2', pairId: `pair-${randomUUID()}`,
        tskClientId: `client-${randomUUID()}`, ...owner,
        canonicalId: collider.canonicalId,
      }),
      /does not match/,
    );
    assert.throws(
      () => ultraStateMutationSanitizer.sanitize({
        kind: 'ultra.binding.set.v1', pairId: `pair-${randomUUID()}`,
        tskClientId: `client-${randomUUID()}`, agentId,
      }),
      /unsupported/,
    );
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
          kind: 'ultra.binding.set.v2', pairId: `pair-${randomUUID()}`,
          tskClientId: `client-${randomUUID()}`, ...owner,
        },
      });
      throw new Error('simulated authoritative mutation failure');
    }), /simulated authoritative mutation failure/);
    assert.equal(Number((await a.query(
      'SELECT count(*) FROM ha_outbox_rows WHERE stream_id=$1', [streamId],
    )).rows[0].count), 5);

    const ackKeys = generateKeyPairSync('ed25519');
    const resolveAckPublicKey = (keyId) => keyId === 'receiver-key-1' ? ackKeys.publicKey : null;
    const nonceStore = await PgReplayNonceStore.open(dbB, 'public');
    const requestSecret = randomBytes(32);
    const responseSecret = randomBytes(32);
    const receiverRuntime = createUltraStateHttpReceiver({
      db: dbB, ready: readyB, streamId,
      expectedPath: '/v1/ultra-state',
      resolveRequestKey: (keyId) => keyId === 'transport-key-1' ? requestSecret : null,
      responseKeyId: 'response-key-1', responseSecret, nonceStore,
      receiverId: 'site-b', ackKeyId: 'receiver-key-1',
      ackPrivateKey: ackKeys.privateKey, resolveAckPublicKey,
    });
    const wrongReceiver = signUltraStateAck(records[0], 'applied', {
      receiverId: 'site-evil', keyId: 'receiver-key-1', privateKey: ackKeys.privateKey,
    });
    await assert.rejects(
      receiverRuntime.ackVerifier.verify(wrongReceiver, records[0]),
      /forged or not bound/,
    );
    // Exercise the shipped receiver and publisher process boundary, including
    // file-held key custody and independent database connections.
    const portProbe = createServer();
    await new Promise((resolve) => portProbe.listen(0, '127.0.0.1', resolve));
    const port = portProbe.address().port;
    await new Promise((resolve) => portProbe.close(resolve));
    Object.assign(files, {
      request: join(runtimeDirectory, 'request.secret'),
      response: join(runtimeDirectory, 'response.secret'),
      privateAck: join(runtimeDirectory, 'ack-private.pem'),
      publicAck: join(runtimeDirectory, 'ack-public.pem'),
      receiver: join(runtimeDirectory, 'receiver.json'),
      publisher: join(runtimeDirectory, 'publisher.json'),
    });
    await Promise.all([
      writeFile(files.request, requestSecret),
      writeFile(files.response, responseSecret),
      writeFile(files.privateAck, ackKeys.privateKey.export({ type: 'pkcs8', format: 'pem' })),
      writeFile(files.publicAck, ackKeys.publicKey.export({ type: 'spki', format: 'pem' })),
      writeFile(files.receiver, JSON.stringify({
        streamId, expectedPath: '/v1/ultra-state', host: '127.0.0.1', port,
        requestKeyId: 'transport-key-1', requestSecretFile: files.request,
        responseKeyId: 'response-key-1', responseSecretFile: files.response,
        receiverId: 'site-b', ackKeyId: 'receiver-key-1', ackPrivateKeyFile: files.privateAck,
        ackPublicKeyFiles: { 'receiver-key-1': files.publicAck },
      })),
      writeFile(files.publisher, JSON.stringify({
        streamId, expectedReceiverId: 'site-b', url: `http://127.0.0.1:${port}/v1/ultra-state`,
        requestKeyId: 'transport-key-1', requestSecretFile: files.request,
        responseKeyId: 'response-key-1', responseSecretFile: files.response,
        ackPublicKeyFiles: { 'receiver-key-1': files.publicAck }, leaseMs: 5_000,
      })),
    ]);
    receiverProcess = spawn(process.execPath, ['ultra-state-stream-command.mjs', 'receiver', files.receiver], {
      cwd: new URL('.', import.meta.url), env: { ...process.env, DATABASE_URL: urlB },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const readyLine = await new Promise((resolve, reject) => {
      let stdout = ''; let stderr = '';
      const timer = setTimeout(() => reject(new Error(`receiver startup timed out: ${stderr}`)), 10_000);
      receiverProcess.stdout.on('data', (chunk) => {
        stdout += chunk;
        if (stdout.includes('\n')) { clearTimeout(timer); resolve(stdout.trim()); }
      });
      receiverProcess.stderr.on('data', (chunk) => { stderr += chunk; });
      receiverProcess.once('exit', (code) => {
        clearTimeout(timer); reject(new Error(`receiver exited ${code}: ${stderr}`));
      });
    });
    assert.equal(JSON.parse(readyLine).mode, 'receiver');
    const publisherOutput = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['ultra-state-stream-command.mjs', 'publish-once', files.publisher], {
        cwd: new URL('.', import.meta.url), env: { ...process.env, DATABASE_URL: urlA },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = ''; let stderr = '';
      child.stdout.on('data', (chunk) => { stdout += chunk; });
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.once('exit', (code) => code === 0 ? resolve(stdout.trim()) : reject(new Error(stderr)));
    });
    assert.deepEqual(JSON.parse(publisherOutput), {
      ok: true, mode: 'publish-once', published: 5, acked: 5, quarantined: 0, retriable: false,
    });
    assert.equal(Number((await a.query(
      'SELECT count(*) FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NOT NULL', [streamId],
    )).rows[0].count), 5);
    assert.equal(await receiverRuntime.checkpoint.verifyAndApplyDelivered(records[4]), 'duplicate-ok');
    const bindingB = (await b.query(
      `SELECT tsk_client_id,agent_id,canonical_id,agent_public_key_hex
         FROM ultra_identity_bindings WHERE pair_id=$1`, [pairId],
    )).rows[0];
    assert.deepEqual(bindingB, {
      tsk_client_id: newClientId,
      agent_id: agentId,
      canonical_id: canonicalId,
      agent_public_key_hex: agentPublicKeyHex,
    });
    const idemB = (await b.query(
      'SELECT state,response FROM ultra_idempotency WHERE idempotency_key=$1', [idemKey],
    )).rows[0];
    assert.equal(idemB.state, 'complete');
    assert.deepEqual(idemB.response, {
      ok: false, error: 'SECRET_REPROVISION_REQUIRED',
      originalResponseDigest: records[3].mutation.responseDigest,
    });

    const revoked = signLeaseGrant('source-guard-1', guardKeys.privateKey, {
      streamId, leaseEpoch: epoch, leaseStatus: 'revoked', holderNodeId: lease.holderNodeId,
      leaseId: lease.leaseId, commandId: 'site-a-revoke-1',
      leaseExpiresAtMs: lease.leaseExpiresAtMs, leaseGrantSeq: 2,
      prevGrantDigest: lease.grantDigest,
    });
    const preCommitPairId = `pair-${randomUUID()}`;
    await assert.rejects(outbox.withOutboxTx(async (tx, exec) => {
      const mutation = {
        kind: 'ultra.binding.set.v2', pairId: preCommitPairId,
        tskClientId: `client-${randomUUID()}`, ...owner,
      };
      await outbox.appendInTx(tx, { streamId, fenceToken: 1n, rawMutation: mutation });
      await exec.query(
        `INSERT INTO ultra_identity_bindings
           (pair_id,tsk_client_id,agent_id,canonical_id,agent_public_key_hex)
         VALUES($1,$2,$3,$4,$5)`,
        [mutation.pairId, mutation.tskClientId, mutation.agentId, mutation.canonicalId,
          mutation.agentPublicKeyHex],
      );
      // The lease changes after the authoritative DML but before the outbox
      // pre-commit gate. The entire source transaction must roll back.
      await dbA.transaction((leaseExec) => installLeaseGrant(
        leaseExec, sourceLeaseResolver, revoked,
      ));
    }), /source lease is revoked|grant digest|could not serialize access due to concurrent update/i);
    assert.equal((await a.query(
      'SELECT 1 FROM ultra_identity_bindings WHERE pair_id=$1', [preCommitPairId],
    )).rowCount, 0);
    await assert.rejects(
      bindings.set(`pair-${randomUUID()}`, { tskClientId: `client-${randomUUID()}`, ...owner }),
      /source lease is revoked|grant digest/i,
    );
    assert.equal(Number((await a.query(
      'SELECT count(*) FROM ha_outbox_rows WHERE stream_id=$1', [streamId],
    )).rows[0].count), 5);
  } finally {
    if (receiverProcess && receiverProcess.exitCode === null) {
      receiverProcess.kill('SIGTERM');
      await new Promise((resolve) => receiverProcess.once('exit', resolve));
    }
    if (runtimeDirectory) await rm(runtimeDirectory, { recursive: true, force: true });
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
        await pool.query('DELETE FROM tsk_source_lease_history WHERE stream_id=$1', [streamId]);
        await pool.query('DELETE FROM tsk_source_lease WHERE stream_id=$1', [streamId]);
      } catch { /* preserve the primary assertion failure */ }
    }
    await a.end();
    await b.end();
  }
});
