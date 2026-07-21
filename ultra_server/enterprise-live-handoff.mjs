import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, randomUUID } from 'node:crypto';

import { generateTumblerMap } from '@tsk/core';
import pg from 'pg';

import {
  ULTRA_INDEPENDENT_STATE_SCHEMA,
  assertIndependentStateReady,
  completeImportedPromotedTskCredential,
  exportIndependentState,
  guardCountersignIndependentState,
  importIndependentState,
} from './independent-state.js';
import { createPromotedTskAuthorityCapability } from './promoted-tsk-authority.js';
import { ULTRA_PG_SCHEMA, initializePgSchemas } from './runtime-stores.js';

const { Pool } = pg;

async function resetUltra(pool) {
  await pool.query(`DROP TABLE IF EXISTS
    ultra_idempotency_redaction,ultra_ha_tsk_reprovision,ultra_ha_import_head,
    ultra_nonce_tombstones,ultra_idempotency,ultra_identity_bindings,
    ultra_tumbler_maps CASCADE`);
  await initializePgSchemas(pool, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
}

/**
 * Compose the Enterprise state authority with the already-completed real BPC
 * and TSK promotions. This uses the exact signed artifacts returned by those
 * reviewed authorities and never persists the promoted TSK shared secret.
 */
export async function runEnterpriseLiveHandoff(composition, env = process.env) {
  const aUrl = env.ULTRA_TEST_POSTGRES_URL_A;
  const bUrl = env.ULTRA_TEST_POSTGRES_URL_B;
  if (!aUrl || !bUrl || aUrl === bUrl) throw new Error('two distinct Ultra PostgreSQL URLs are required');
  const a = new Pool({ connectionString: aUrl, max: 4 });
  const b = new Pool({ connectionString: bUrl, max: 4 });
  const sourceSigning = generateKeyPairSync('ed25519');
  const guardSigning = generateKeyPairSync('ed25519');
  const clusterId = 'enterprise28-live-cluster';
  const pairId = composition.tsk.targetCredentialProof.pairId;
  const agentId = composition.tsk.targetCredentialProof.agentId;
  const sourceClientId = composition.tsk.publicCredentialSource.clientId;
  const sourceEpoch = composition.tsk.credentialActivationLeaseGrant.leaseEpoch;
  const advisoryLockKey = `enterprise28:${clusterId}:independent-state`;
  try {
    await Promise.all([resetUltra(a), resetUltra(b)]);
    const sourceMap = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
    sourceMap.clientId = sourceClientId;
    sourceMap.label = `agent:${agentId}`;
    sourceMap.status = 'active';
    await a.query(
      'INSERT INTO ultra_tumbler_maps(client_id,map) VALUES($1,$2::jsonb)',
      [sourceClientId, JSON.stringify(sourceMap)],
    );
    await a.query(
      'INSERT INTO ultra_identity_bindings(pair_id,tsk_client_id,agent_id) VALUES($1,$2,$3)',
      [pairId, sourceClientId, agentId],
    );
    const safeId = randomUUID();
    const secretId = randomUUID();
    await a.query(
      `INSERT INTO ultra_idempotency(idempotency_key,operation,agent_id,state,response)
       VALUES($1,'status', $3,'complete',$4::jsonb),
             ($2,'provision-tsk',$3,'complete',$5::jsonb)`,
      [safeId, secretId, agentId, JSON.stringify({ ok: true, value: 'preserved' }),
        JSON.stringify({ ok: true, sharedSecret: sourceMap.sharedSecret })],
    );
    const protocolEvidence = {
      bpcPromotionAttestation: composition.bpc.readinessAttestation,
      tskActivationLease: composition.tsk.activationLeaseGrant,
      tskFinalizedReceipt: composition.tsk.bFinalizedReceipt,
    };
    const sourceBundle = await exportIndependentState(a, {
      advisoryLockKey,
      clusterId,
      commandId: composition.commandId,
      protocolEvidence,
      sourceEpoch,
      sourceKeyId: 'enterprise28-source-key-1',
      sourcePrivateKey: sourceSigning.privateKey,
    });
    const bundle = guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: composition.commandId,
      guardKeyId: 'enterprise28-guard-key-1',
      guardPrivateKey: guardSigning.privateKey,
      sourcePublicKey: sourceSigning.publicKey,
      ...composition.resolvers,
    });
    assert.equal(JSON.stringify(bundle).includes(sourceMap.sharedSecret), false);
    const imported = await importIndependentState(b, bundle, {
      advisoryLockKey,
      clusterId,
      commandId: composition.commandId,
      sourceEpoch,
      bpcPromotionDigest: composition.bpc.readinessAttestation.attestationDigest,
      tskActivationDigest: composition.tsk.activationLeaseGrant.grantDigest,
      tskFinalizedDigest: composition.tsk.bFinalizedReceipt.receiptDigest,
      sourcePublicKey: sourceSigning.publicKey,
      guardPublicKey: guardSigning.publicKey,
      ...composition.resolvers,
    });
    const leaseResolver = { resolve: (keyId) =>
      keyId === composition.tsk.credentialActivationLeaseGrant.guardKeyId
        ? composition.resolvers.tskGuardResolver.resolve(keyId) : null };
    const headKeyResolver = { resolve: (keyId, alg) =>
      keyId === composition.tsk.targetCredentialProof.head.keyId && alg === 'ed25519'
        ? createPublicKey(composition.tsk.publicKeys.credentialHead) : null };
    const authority = createPromotedTskAuthorityCapability({
      activationLease: composition.tsk.credentialActivationLeaseGrant,
      leaseResolver,
      headKeyResolver,
    });
    const sourceSecretDigest = (await b.query(
      `SELECT source_secret_digest FROM ultra_ha_tsk_reprovision
        WHERE cluster_id=$1 AND pair_id=$2`, [clusterId, pairId],
    )).rows[0].source_secret_digest;
    const reprovisioned = await completeImportedPromotedTskCredential(b, authority, {
      advisoryLockKey,
      agentId,
      clusterId,
      commandId: composition.commandId,
      pairId,
      sourceClientId,
      sourceEpoch,
      sourceSecretDigest,
      targetProof: composition.tsk.targetCredentialProof,
    });
    const ready = await assertIndependentStateReady(b, {
      clusterId,
      commandId: composition.commandId,
      manifestDigest: bundle.manifestDigest,
      sourceEpoch,
    });
    const binding = (await b.query(
      'SELECT pair_id,agent_id,tsk_client_id FROM ultra_identity_bindings WHERE pair_id=$1',
      [pairId],
    )).rows[0];
    const copiedTarget = Number((await b.query(
      'SELECT COUNT(*)::int AS n FROM ultra_tumbler_maps WHERE client_id=$1',
      [reprovisioned.targetClientId],
    )).rows[0].n);
    const redacted = (await b.query(
      `SELECT response FROM ultra_idempotency WHERE idempotency_key=$1`, [secretId],
    )).rows[0].response;
    assert.deepEqual(binding, { pair_id: pairId, agent_id: agentId,
      tsk_client_id: reprovisioned.targetClientId });
    assert.equal(copiedTarget, 0, 'promoted TSK secret/map must not be copied into Enterprise');
    assert.equal(redacted.error, 'SECRET_REPROVISION_REQUIRED');
    return Object.freeze({
      clusterId,
      manifestDigest: bundle.manifestDigest,
      sourceSystemId: bundle.manifest.sourceSystemId,
      targetSystemId: ready.targetSystemId,
      sourceClientId,
      targetClientId: reprovisioned.targetClientId,
      targetProofDigest: reprovisioned.targetProofDigest,
      receiptDigest: reprovisioned.receiptDigest,
      copiedTargetCredentialRows: copiedTarget,
      redactionPreserved: true,
      rpo: 0,
    });
  } finally {
    await Promise.allSettled([a.end(), b.end()]);
  }
}
