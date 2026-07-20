import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign as edSign } from 'node:crypto';
import test from 'node:test';

import { Pool } from 'pg';
import { generateTumblerMap } from '@tsk/core';

import {
  PgNonceTombstoneStore,
  ULTRA_INDEPENDENT_STATE_SCHEMA,
  assertIndependentStateReady,
  completeImportedTskReprovision,
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

function frame(...parts) {
  const buffers = [];
  for (const part of parts) {
    if (part === null) { buffers.push(Buffer.from([0])); continue; }
    const value = Buffer.from(String(part), 'utf8');
    const length = Buffer.alloc(4); length.writeUInt32BE(value.length);
    buffers.push(Buffer.from([1]), length, value);
  }
  return Buffer.concat(buffers);
}

function signedProtocolEvidence({ commandId, sourceSystemId, targetSystemId, keys }) {
  const bpcKeyId = 'bpc-snapshot-key-1';
  const bKeyId = 'b-key-1';
  const guardKeyId = 'tsk-guard-key-1';
  const bpcBare = {
    streamId: 'ultra-stream', commandId, targetEpoch: 1, targetSourceEpoch: 'epoch-1',
    targetSystemId, snapshotKeyId: bpcKeyId, manifestDigest: '1'.repeat(64),
    appliedSequence: 0, stateDigest: '2'.repeat(64), fencedDigest: '3'.repeat(64),
  };
  const bpcMessage = (digest) => frame(
    'bpc-promotion-readiness/v1', bpcBare.streamId, bpcBare.commandId,
    bpcBare.targetEpoch, bpcBare.targetSourceEpoch, bpcBare.targetSystemId,
    bpcBare.snapshotKeyId, bpcBare.manifestDigest, bpcBare.appliedSequence,
    bpcBare.stateDigest, bpcBare.fencedDigest, digest,
  );
  const attestationDigest = createHash('sha256').update(bpcMessage('')).digest('hex');
  const bpcPromotionAttestation = {
    ...bpcBare,
    keyId: bpcKeyId,
    attestationDigest,
    signature: edSign(null, Buffer.concat([
      frame('bpc-ha-key/v1', bpcKeyId), bpcMessage(attestationDigest),
    ]), keys.bpc.privateKey).toString('base64url'),
  };

  const bBare = {
    streamId: 'ultra-stream', commandId, epoch: 0, sourceEpoch: 'epoch-0', n: 0,
    generationId: 'generation-1', frozenReceiptDigest: '4'.repeat(64),
    manifestDigest: '5'.repeat(64), manifestRoot: '6'.repeat(64), sourceSystemId,
    sourceKeyId: 'source-key', sourceSignature: 'source-signature',
    guardKeyId, guardSignature: 'guard-signature', signedHeadDigestAtN: '7'.repeat(64),
    sourceStateDigestAtN: '8'.repeat(64), bSystemId: targetSystemId,
  };
  const bMessage = (digest) => frame(
    'tsk_b_finalized/v2', bBare.streamId, bBare.commandId, bBare.epoch, bBare.sourceEpoch,
    bBare.n, bBare.generationId, bBare.frozenReceiptDigest, bBare.manifestDigest,
    bBare.manifestRoot, bBare.sourceSystemId, bBare.sourceKeyId, bBare.sourceSignature,
    bBare.guardKeyId, bBare.guardSignature, bBare.signedHeadDigestAtN,
    bBare.sourceStateDigestAtN, bBare.bSystemId, digest,
  );
  const receiptDigest = createHash('sha256').update(bMessage('')).digest('hex');
  const tskFinalizedReceipt = {
    ...bBare,
    receiptDigest,
    bKeyId,
    bSignature: edSign(null, Buffer.concat([
      frame('tsk_src_key', bKeyId), bMessage(receiptDigest),
    ]), keys.b.privateKey).toString('base64url'),
  };

  const leaseBare = {
    streamId: 'ultra-stream', leaseEpoch: 1, leaseStatus: 'active', holderNodeId: bKeyId,
    leaseId: 'lease-1', commandId, leaseExpiresAtMs: Date.now() + 300_000,
    leaseGrantSeq: 1, prevGrantDigest: null,
  };
  const leaseMessage = (digest) => frame(
    'tsk_source_lease/v1', leaseBare.streamId, leaseBare.leaseEpoch,
    leaseBare.leaseStatus, leaseBare.holderNodeId, leaseBare.leaseId,
    leaseBare.commandId, leaseBare.leaseExpiresAtMs, leaseBare.leaseGrantSeq,
    leaseBare.prevGrantDigest, digest,
  );
  const grantDigest = createHash('sha256').update(leaseMessage('')).digest('hex');
  const tskActivationLease = {
    ...leaseBare,
    grantDigest,
    guardKeyId,
    guardSignature: edSign(null, Buffer.concat([
      frame('tsk_src_key', guardKeyId), leaseMessage(grantDigest),
    ]), keys.guard.privateKey).toString('base64url'),
  };
  return { bpcPromotionAttestation, tskActivationLease, tskFinalizedReceipt };
}

test('signed independent-state handoff is atomic, redacted, replay-safe, and rollback-safe', async () => {
  const a = new Pool({ connectionString: urlA });
  const b = new Pool({ connectionString: urlB });
  const source = generateKeyPairSync('ed25519');
  const guard = generateKeyPairSync('ed25519');
  const protocolKeys = {
    bpc: generateKeyPairSync('ed25519'),
    b: generateKeyPairSync('ed25519'),
    guard: generateKeyPairSync('ed25519'),
  };
  const suffix = randomUUID();
  const clusterId = `ha-${suffix}`;
  const commandId = `promote-${suffix}`;
  const pairId = `pair-${suffix}`;
  const safeKey = randomUUID();
  const secretKey = randomUUID();
  const processingKey = randomUUID();
  const lockKey = `ultra-ha:${clusterId}:transition`;
  const nonceHash = createHash('sha256').update(`nonce-${suffix}`, 'utf8').digest('hex');
  let sourceMap;
  let targetMap;
  try {
    await initializePgSchemas(a, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    await initializePgSchemas(b, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    const [systemA, systemB] = await Promise.all([
      a.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
      b.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
    ]);
    assert.notEqual(systemA.rows[0].id, systemB.rows[0].id);
    const protocolEvidence = signedProtocolEvidence({
      commandId,
      sourceSystemId: systemA.rows[0].id,
      targetSystemId: systemB.rows[0].id,
      keys: protocolKeys,
    });
    const bpcPromotionDigest = protocolEvidence.bpcPromotionAttestation.attestationDigest;
    const tskActivationDigest = protocolEvidence.tskActivationLease.grantDigest;
    const tskFinalizedDigest = protocolEvidence.tskFinalizedReceipt.receiptDigest;
    const resolvers = {
      bpcResolver: { resolve: (keyId) => keyId === 'bpc-snapshot-key-1' ? protocolKeys.bpc.publicKey : null },
      tskBResolver: { resolve: (keyId) => keyId === 'b-key-1' ? protocolKeys.b.publicKey : null },
      tskGuardResolver: { resolve: (keyId) => keyId === 'tsk-guard-key-1' ? protocolKeys.guard.publicKey : null },
    };

    sourceMap = generateTumblerMap();
    sourceMap.label = `agent:agent-${suffix}`;
    sourceMap.status = 'active';
    targetMap = generateTumblerMap();
    targetMap.label = `agent:agent-${suffix}`;
    targetMap.status = 'active';

    await a.query(
      'INSERT INTO ultra_identity_bindings (pair_id, tsk_client_id, agent_id) VALUES ($1,$2,$3)',
      [pairId, sourceMap.clientId, `agent-${suffix}`],
    );
    await a.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [sourceMap.clientId, JSON.stringify(sourceMap)],
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

    const exportInput = {
      advisoryLockKey: lockKey,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourceKeyId: 'source-key-1',
      sourcePrivateKey: source.privateKey,
      protocolEvidence,
    };
    const unboundMap = generateTumblerMap();
    unboundMap.label = `agent:agent-${suffix}`;
    unboundMap.status = 'active';
    await a.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [unboundMap.clientId, JSON.stringify(unboundMap)],
    );
    await assert.rejects(exportIndependentState(a, exportInput), /active unbound TSK credential/);
    await a.query('DELETE FROM ultra_tumbler_maps WHERE client_id=$1', [unboundMap.clientId]);

    const sourceBundle = await exportIndependentState(a, exportInput);
    const serialized = JSON.stringify(sourceBundle);
    assert.equal(serialized.includes('must-not-cross-sites'), false);
    assert.equal(serialized.includes(sourceMap.sharedSecret), false);
    assert.equal(sourceBundle.manifest.state.idempotency.find(
      (item) => item.idempotencyKey === secretKey,
    ).secretReprovisionRequired, true);
    const bundle = guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: commandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'guard-key-1',
      guardPrivateKey: guard.privateKey,
      ...resolvers,
    });
    assert.throws(() => guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: commandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'same-custody-key',
      guardPrivateKey: source.privateKey,
      ...resolvers,
    }), /custody keys must be distinct/);
    assert.equal(verifyIndependentStateBundle(bundle, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
    }), true);
    const protocolTamper = structuredClone(bundle);
    protocolTamper.protocolEvidence.tskFinalizedReceipt.bSystemId = systemA.rows[0].id;
    assert.throws(() => verifyIndependentStateBundle(protocolTamper, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
    }), /digest mismatch/);

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
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
    }), /not independent/);

    const imported = await importIndependentState(b, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
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
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
    })).idempotent, true);
    assert.deepEqual((await b.query(
      'SELECT tsk_client_id, agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0], { tsk_client_id: sourceMap.clientId, agent_id: `agent-${suffix}` });
    assert.deepEqual((await b.query(
      'SELECT response FROM ultra_idempotency WHERE idempotency_key=$1', [secretKey],
    )).rows[0].response.error, 'SECRET_REPROVISION_REQUIRED');
    const nonceB = new PgNonceTombstoneStore(b);
    assert.equal(await nonceB.checkAndConsume(`nonce-${suffix}`, 120_000), true);
    await b.query(
      `INSERT INTO ultra_idempotency (idempotency_key, operation, agent_id, state)
       VALUES ($1,'in-flight-op',$2,'processing')`,
      [processingKey, `agent-${suffix}`],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /in-flight idempotency/);
    await b.query('DELETE FROM ultra_idempotency WHERE idempotency_key=$1', [processingKey]);
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /requires TSK credential reprovisioning/);
    await assert.rejects(completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: `agent-${suffix}`,
      assertWritable: async () => ({ ok: true, fenceEpoch: 2 }),
      clusterId,
      commandId,
      pairId,
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    }), /writer fence was lost/);
    const reprovision = await completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: `agent-${suffix}`,
      clusterId,
      commandId,
      pairId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    });
    assert.equal(reprovision.idempotent, false);
    assert.equal(JSON.stringify(reprovision).includes(targetMap.sharedSecret), false);
    assert.equal((await completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: `agent-${suffix}`,
      clusterId,
      commandId,
      pairId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    })).idempotent, true);
    assert.equal((await b.query(
      'SELECT tsk_client_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0].tsk_client_id, targetMap.clientId);
    assert.equal((await assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    })).targetSystemId, systemB.rows[0].id);
    await b.query(
      "UPDATE ultra_tumbler_maps SET map=jsonb_set(map, '{sharedSecret}', '\"attacker-secret-attacker-secret-00\"'::jsonb) WHERE client_id=$1",
      [targetMap.clientId],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /rolled back or tampered/);
    await assert.rejects(completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: `agent-${suffix}`,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      clusterId,
      commandId,
      pairId,
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    }), /rolled back or tampered/);
    await b.query('UPDATE ultra_tumbler_maps SET map=$2::jsonb WHERE client_id=$1', [
      targetMap.clientId, JSON.stringify(targetMap),
    ]);
    await b.query(
      "UPDATE ultra_tumbler_maps SET map=jsonb_set(map, '{status}', '\"revoked\"'::jsonb) WHERE client_id=$1",
      [targetMap.clientId],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /rolled back or tampered/);
    await b.query('UPDATE ultra_tumbler_maps SET map=$2::jsonb WHERE client_id=$1', [
      targetMap.clientId, JSON.stringify(targetMap),
    ]);
    await b.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [unboundMap.clientId, JSON.stringify(unboundMap)],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /active unbound TSK credential/);
    await b.query('DELETE FROM ultra_tumbler_maps WHERE client_id=$1', [unboundMap.clientId]);
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
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
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
      await pool.query(
        'DELETE FROM ultra_tumbler_maps WHERE client_id IN ($1,$2)',
        [sourceMap?.clientId ?? '', targetMap?.clientId ?? ''],
      ).catch(() => {});
      await pool.query(
        'DELETE FROM ultra_idempotency WHERE idempotency_key IN ($1,$2,$3)',
        [safeKey, secretKey, processingKey],
      ).catch(() => {});
      await pool.query('DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1', [nonceHash]).catch(() => {});
      await pool.end();
    }
  }
});
