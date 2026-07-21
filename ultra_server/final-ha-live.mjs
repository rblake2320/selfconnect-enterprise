import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { runBpcLiveComposition } from './bpc-live-composition.mjs';
import { runEnterpriseLiveHandoff } from './enterprise-live-handoff.mjs';
import { assertCleanReviewedCheckout } from './final-ha-acceptance.mjs';
import {
  createPromotedTskAuthorityCapability,
  verifyPromotedTskCredentialProof,
  verifySourceTskCredentialProof,
} from './promoted-tsk-authority.js';
import { runTskLiveComposition } from './tsk-live-composition.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;

function required(value, name) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function fingerprint(pem) {
  return createHash('sha256').update(
    createPublicKey(pem).export({ type: 'spki', format: 'der' }),
  ).digest('hex');
}

async function importPinnedServer(root, component) {
  const entry = resolve(root, 'packages', 'server', 'dist', 'index.js');
  try {
    return await import(pathToFileURL(entry).href);
  } catch (error) {
    throw new Error(`${component} reviewed distribution cannot be imported: ${error.message}`);
  }
}

export function validateLiveProtocolComposition(bpc, tsk, commandId) {
  assert.equal(bpc.readinessAttestation.commandId, commandId);
  assert.equal(tsk.bFinalizedReceipt.commandId, commandId);
  assert.equal(tsk.activationLeaseGrant.commandId, commandId);
  assert.equal(bpc.staleWriterDenied, true);
  assert.equal(tsk.staleWriterDenied, true);
  assert.equal(tsk.nextSequence, tsk.n + 1);
  assert.equal(tsk.publicCredential.status, 'active');
  assert.match(tsk.publicCredential.publicMapDigest, DIGEST);
  assert.equal(tsk.staleCredentialWriterDenied, true);
  assert.notEqual(tsk.publicCredentialSource.clientId, tsk.publicCredentialTarget.clientId);
  assert.notEqual(tsk.publicCredentialSource.publicMapDigest,
    tsk.publicCredentialTarget.publicMapDigest);
  assert.equal(tsk.targetCredentialProof.commandId, commandId);
  assert.equal(tsk.targetCredentialProof.record.mutation.clientId,
    tsk.publicCredentialTarget.clientId);
  assert.equal(tsk.credentialSourceRevocation.commandId, commandId);
  assert.equal(tsk.credentialActivationLeaseGrant.commandId, commandId);
  assert.equal(new Set(Object.values(bpc.systemIds)).size, 3);
  assert.equal(new Set(Object.values(tsk.systemIds)).size, 3);
  assert.notEqual(bpc.systemIds.promotedB, tsk.systemIds.receiverB);
  return true;
}

/**
 * Runs both reviewed protocol authorities in-process and returns their exact
 * signed artifacts. This is the composition phase, not by itself the final
 * Enterprise acceptance: the caller must still complete the Enterprise
 * signed handoff/fault/restore phases before emitting acceptance evidence.
 */
export async function runLiveProtocolComposition(env = process.env) {
  const lock = JSON.parse(await readFile(resolve(REPO, 'portfolio-lock.json'), 'utf8'));
  const enterpriseSha = required(env.ULTRA_FINAL_EXPECTED_ENTERPRISE_SHA, 'ULTRA_FINAL_EXPECTED_ENTERPRISE_SHA');
  if (!SHA.test(enterpriseSha)) throw new Error('ULTRA_FINAL_EXPECTED_ENTERPRISE_SHA must be a full commit SHA');
  await assertCleanReviewedCheckout(REPO, enterpriseSha);
  const bpcRoot = resolve(required(env.BPC_PROTOCOL_ROOT, 'BPC_PROTOCOL_ROOT'));
  const tskRoot = resolve(required(env.TSK_PROTOCOL_ROOT, 'TSK_PROTOCOL_ROOT'));
  const bpcCommit = lock.components?.['bpc-protocol']?.commit;
  const tskCommit = lock.components?.['tsk-protocol']?.commit;
  if (!SHA.test(bpcCommit ?? '') || !SHA.test(tskCommit ?? '')) throw new Error('protocol commit pins are invalid');
  const commandId = required(env.ULTRA_FINAL_COMMAND_ID, 'ULTRA_FINAL_COMMAND_ID');

  const bpc = await runBpcLiveComposition({
    bpcRoot, expectedBpcCommit: bpcCommit, commandId,
    postgresUrls: [env.BPC_TEST_POSTGRES_URL, env.BPC_TEST_POSTGRES_B_URL,
      env.BPC_TEST_POSTGRES_CONTROL_URL],
    redisUrls: required(env.BPC_TEST_REDIS_URLS, 'BPC_TEST_REDIS_URLS').split(','),
    streamId: 'bpc:enterprise:live/v1',
  });
  const tsk = await runTskLiveComposition({
    tskRoot, expectedTskCommit: tskCommit, commandId,
    aPostgresUrl: env.TSK_TEST_SOURCE_PG_URL_A,
    bPostgresUrl: env.TSK_TEST_RECEIVER_PG_URL_B,
    controlPostgresUrl: env.TSK_TEST_CONTROL_PG_URL,
    redisUrl: env.TSK_TEST_REDIS_URL,
    streamId: 'enterprise28:tsk-live/v1', destructiveReset: true,
  });

  const [bpcApi, tskApi] = await Promise.all([
    importPinnedServer(bpcRoot, 'BPC'), importPinnedServer(tskRoot, 'TSK'),
  ]);
  const bpcResolver = { resolve: (keyId) => keyId === bpc.readinessAttestation.snapshotKeyId
    ? createPublicKey(bpc.publicKeys.source) : null };
  const tskBResolver = { resolve: (keyId) => keyId === tsk.bFinalizedReceipt.bKeyId
    ? createPublicKey(tsk.publicKeys.bReceipt) : null };
  const tskGuardResolver = { resolve: (keyId) => keyId === tsk.activationLeaseGrant.guardKeyId
    ? createPublicKey(tsk.publicKeys.guard) : null };
  bpcApi.verifyPromotionReadinessAttestation(bpcResolver, bpc.readinessAttestation);
  tskApi.verifyBFinalizedReceipt(tskBResolver, tsk.bFinalizedReceipt);
  tskApi.verifyLeaseGrant(tskGuardResolver, tsk.activationLeaseGrant);
  const credentialGuardResolver = { resolve: (keyId) =>
    keyId === tsk.credentialActivationLeaseGrant.guardKeyId
      ? createPublicKey(tsk.publicKeys.guard) : null };
  const credentialHeadResolver = { resolve: (keyId, alg) =>
    keyId === tsk.targetCredentialProof.head.keyId && alg === 'ed25519'
      ? createPublicKey(tsk.publicKeys.credentialHead) : null };
  const credentialAuthority = createPromotedTskAuthorityCapability({
    activationLease: tsk.credentialActivationLeaseGrant,
    leaseResolver: credentialGuardResolver,
    headKeyResolver: credentialHeadResolver,
  });
  const verifiedTargetCredential = await verifyPromotedTskCredentialProof(
    credentialAuthority,
    tsk.targetCredentialProof,
    {
      agentId: tsk.targetCredentialProof.agentId,
      pairId: tsk.targetCredentialProof.pairId,
      sourceClientId: tsk.publicCredentialSource.clientId,
      sourceSecretDigest: tsk.publicCredentialSource.secretDigest,
    },
  );
  const sourceCredentialHeadResolver = { resolve: (keyId, alg) =>
    keyId === tsk.sourceCredentialProof.head.keyId && alg === 'ed25519'
      ? createPublicKey(tsk.publicKeys.sourceCredentialHead) : null };
  const sourceCredentialAuthority = createPromotedTskAuthorityCapability({
    activationLease: tsk.credentialSourceLeaseGrant,
    leaseResolver: credentialGuardResolver,
    headKeyResolver: sourceCredentialHeadResolver,
  });
  const verifiedSourceCredential = await verifySourceTskCredentialProof(
    sourceCredentialAuthority,
    tsk.sourceCredentialProof,
    {
      agentId: tsk.sourceCredentialProof.agentId,
      pairId: tsk.sourceCredentialProof.pairId,
      sourceClientId: tsk.publicCredentialSource.clientId,
    },
  );
  validateLiveProtocolComposition(bpc, tsk, commandId);

  return Object.freeze({
    commandId,
    commits: Object.freeze({ enterprise: enterpriseSha, bpc: bpcCommit, tsk: tskCommit }),
    bpc,
    tsk,
    verifiedSourceCredential,
    verifiedTargetCredential,
    resolvers: Object.freeze({ bpcResolver, tskBResolver, tskGuardResolver }),
    publicKeyFingerprints: Object.freeze({
      bpcSource: fingerprint(bpc.publicKeys.source),
      tskB: fingerprint(tsk.publicKeys.bReceipt),
    tskGuard: fingerprint(tsk.publicKeys.guard),
      tskSourceCredentialHead: fingerprint(tsk.publicKeys.sourceCredentialHead),
      tskTargetCredentialHead: fingerprint(tsk.publicKeys.credentialHead),
    }),
  });
}

export async function runLiveEnterpriseAcceptance(env = process.env) {
  const protocols = await runLiveProtocolComposition(env);
  const enterprise = await runEnterpriseLiveHandoff(protocols, env);
  return Object.freeze({ ...protocols, enterprise });
}
