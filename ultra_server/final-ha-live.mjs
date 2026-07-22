import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  discardPostHealBpcRestartProbes,
  runBpcLiveComposition,
  runPostHealBpcRestartProbes,
} from './bpc-live-composition.mjs';
import { runEnterpriseLiveHandoff } from './enterprise-live-handoff.mjs';
import { assertCleanReviewedCheckout } from './final-ha-acceptance.mjs';
import {
  createPromotedTskAuthorityCapability,
  verifyPromotedTskCredentialProof,
  verifySourceTskCredentialProof,
} from './promoted-tsk-authority.js';
import {
  discardPostHealTskRestartProbes,
  runPostHealTskRestartProbes,
  runTskLiveComposition,
} from './tsk-live-composition.mjs';
import {
  runSameRedisAuthorityFaults,
  runSameTskRedisAuthorityFaults,
} from './tsk-same-authority-faults.mjs';
import {
  createUltraRedisClient,
  loadUltraRedisAuthorityConfig,
} from './ultra-redis-authority.js';
import { UltraHaController, loadUltraHaConfig } from './ha-controller.js';
import { RedisFencingStore, signGuardCommand } from '@tsk/server';
import { Redis } from 'ioredis';

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

function parseHostPort(value, name) {
  const [host, portText, ...rest] = required(value, name).split(':');
  const port = Number(portText);
  if (rest.length || !host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be host:port`);
  }
  return Object.freeze({ host, port });
}

function tskRedisOptions(env) {
  if (env.TSK_TEST_SENTINELS) {
    const sentinels = env.TSK_TEST_SENTINELS.split(',').map((value, index) =>
      parseHostPort(value.trim(), `TSK_TEST_SENTINELS[${index}]`));
    const natMap = {};
    for (const [index, pair] of required(env.TSK_SENTINEL_NATMAP,
      'TSK_SENTINEL_NATMAP').split(',').entries()) {
      const [internal, external, ...rest] = pair.trim().split('=');
      if (rest.length || !internal) throw new Error(`TSK_SENTINEL_NATMAP[${index}] is invalid`);
      natMap[internal] = parseHostPort(external, `TSK_SENTINEL_NATMAP[${index}]`);
    }
    return Object.freeze({ kind: 'sentinel', sentinels: Object.freeze(sentinels),
      masterName: required(env.TSK_TEST_SENTINEL_MASTER, 'TSK_TEST_SENTINEL_MASTER'),
      natMap: Object.freeze(natMap) });
  }
  return Object.freeze({ kind: 'url',
    url: required(env.TSK_TEST_REDIS_URL, 'TSK_TEST_REDIS_URL') });
}

function sameAuthorityTopology(env) {
  return Object.freeze({ network: required(env.TSK_SENTINEL_NETWORK, 'TSK_SENTINEL_NETWORK'),
    nodes: Object.freeze({
      '172.28.7.10:6379': Object.freeze({ ip: '172.28.7.10',
        container: required(env.TSK_SENTINEL_MASTER_CONTAINER, 'TSK_SENTINEL_MASTER_CONTAINER') }),
      '172.28.7.11:6379': Object.freeze({ ip: '172.28.7.11',
        container: required(env.TSK_SENTINEL_REPLICA1_CONTAINER, 'TSK_SENTINEL_REPLICA1_CONTAINER') }),
      '172.28.7.12:6379': Object.freeze({ ip: '172.28.7.12',
        container: required(env.TSK_SENTINEL_REPLICA2_CONTAINER, 'TSK_SENTINEL_REPLICA2_CONTAINER') }),
    }) });
}

async function claimUltraRedisAuthority(env, commandId) {
  const runtimeEnv = Object.freeze({ ...env, ULTRA_HA_ENABLED: 'true',
    ULTRA_HA_CLUSTER_ID: 'enterprise28-final', ULTRA_HA_NODE_ID: 'ultra-site-b',
    ULTRA_HA_NODE_ROLE: 'primary',
    ULTRA_HA_GUARD_SECRET: 'enterprise28-ultra-guard-secret-32-bytes-minimum',
    ULTRA_HA_MAX_COMMAND_AGE_MS: '60000', ULTRA_HA_MAX_LEASE_MS: '1200000',
    ULTRA_HA_MIN_LEASE_REMAINING_MS: '5000' });
  const ha = loadUltraHaConfig(runtimeEnv, 'production');
  const config = loadUltraRedisAuthorityConfig(runtimeEnv, { haEnabled: ha.enabled });
  const client = createUltraRedisClient(Redis, config);
  client.on('error', () => {});
  try {
    await client.connect();
    const store = new RedisFencingStore(client, ha.fenceKey, config.durability);
    const controller = new UltraHaController({ ...ha, fenceStore: store });
    const issuedAt = Date.now();
    const command = signGuardCommand({ command: 'activate', commandId,
      clusterId: ha.clusterId, nodeId: ha.nodeId, fenceEpoch: 1, issuedAt,
      expiresAt: issuedAt + 15 * 60_000, by: 'enterprise28-final-acceptance',
      reason: 'exercise exact production Ultra Sentinel writer fence' }, ha.guardSecret);
    const applied = await controller.applyCommand(command);
    if (applied.status !== 200 || !applied.result?.ok || !applied.result.snapshot?.writable) {
      throw new Error('Ultra production controller did not acquire its durable Sentinel fence');
    }
    const current = await store.current();
    if (!current || current.commandId !== commandId || current.nodeId !== ha.nodeId ||
        current.fenceEpoch !== 1 || current.expiresAt !== command.expiresAt || !current.active) {
      throw new Error('Ultra production controller fence did not re-read exactly');
    }
    return Object.freeze({ key: ha.fenceKey, record: Object.freeze({ ...current }) });
  } finally {
    client.disconnect();
  }
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
  assert.equal(bpc.failback.targetSystemId, bpc.systemIds.sourceA);
  assert.equal(bpc.failback.targetEpoch > bpc.readinessAttestation.targetEpoch, true);
  assert.equal(bpc.failback.staleBWriterDenied, true);
  assert.equal(bpc.failback.priorAuthoritiesReset, false);
  assert.equal(bpc.failback.sourcePostgresSystemReused, true);
  assert.equal(tsk.staleWriterDenied, true);
  assert.equal(tsk.staleTargetWriterDenied, true);
  for (const value of [tsk.n, tsk.nextSequence, tsk.returnSequence,
    tsk.returnSourceActivation.n]) {
    assert.equal(Number.isSafeInteger(value) && value > 0, true);
  }
  assert.equal(tsk.nextSequence, tsk.n + 1);
  assert.equal(tsk.returnSequence, tsk.n + 2);
  assert.equal(tsk.returnFrozenReceipt.n, tsk.n + 1);
  assert.equal(tsk.returnFinalizedReceipt.n, tsk.n + 1);
  assert.equal(tsk.returnFinalizedReceipt.bSystemId, tsk.systemIds.sourceA);
  assert.equal(tsk.returnFinalizedReceipt.commandId, tsk.returnCommandId);
  assert.equal(Number.isSafeInteger(tsk.returnFinalizedReceipt.epoch) &&
    tsk.returnFinalizedReceipt.epoch >= 0, true);
  assert.equal(Number.isSafeInteger(tsk.returnActivationLeaseGrant.leaseEpoch) &&
    tsk.returnActivationLeaseGrant.leaseEpoch >= 1, true);
  assert.equal(tsk.returnActivationLeaseGrant.leaseEpoch,
    tsk.returnFinalizedReceipt.epoch + 1);
  assert.equal(tsk.returnActivationLeaseGrant.commandId, tsk.returnCommandId);
  assert.equal(tsk.returnActivationLeaseGrant.holderNodeId,
    tsk.returnFinalizedReceipt.bKeyId);
  assert.equal(tsk.returnSourceActivation.n, tsk.n + 1);
  assert.equal(tsk.returnSourceActivation.activationGrantDigest,
    tsk.returnActivationLeaseGrant.grantDigest);
  assert.equal(tsk.redisAuthority.record.commandId,
    tsk.recoveredSite.handoff.commandId);
  assert.equal(tsk.redisAuthority.record.fenceEpoch,
    tsk.recoveredSite.handoff.activationLease.leaseEpoch);
  assert.equal(tsk.redisAuthority.record.nodeId,
    tsk.recoveredSite.handoff.activationLease.holderNodeId);
  assert.equal(tsk.redisAuthority.record.active, true);
  assert.equal(tsk.publicCredential.status, 'active');
  assert.match(tsk.publicCredential.publicMapDigest, DIGEST);
  assert.equal(tsk.staleCredentialWriterDenied, true);
  assert.equal(tsk.staleReturnedCredentialWriterDenied, true);
  assert.notEqual(tsk.publicCredentialSource.clientId, tsk.publicCredentialTarget.clientId);
  assert.notEqual(tsk.publicCredentialSource.publicMapDigest,
    tsk.publicCredentialTarget.publicMapDigest);
  assert.equal(tsk.targetCredentialProof.commandId, commandId);
  assert.equal(tsk.targetCredentialProof.record.mutation.clientId,
    tsk.publicCredentialTarget.clientId);
  assert.equal(tsk.credentialSourceRevocation.commandId, commandId);
  assert.equal(tsk.credentialActivationLeaseGrant.commandId, commandId);
  assert.equal(tsk.targetCredentialRevocation.commandId, tsk.returnCommandId);
  assert.equal(tsk.targetCredentialRevocation.leaseStatus, 'revoked');
  assert.equal(tsk.returnCredentialActivationLeaseGrant.commandId, tsk.returnCommandId);
  assert.equal(tsk.returnCredentialActivationLeaseGrant.leaseEpoch,
    tsk.returnActivationLeaseGrant.leaseEpoch);
  assert.equal(tsk.returnCredentialProof.commandId, tsk.returnCommandId);
  assert.equal(tsk.returnCredentialProof.record.mutation.clientId,
    tsk.publicCredentialReturn.clientId);
  assert.equal(tsk.repeatedCycle.forward.sourceEpoch, 2);
  assert.equal(tsk.repeatedCycle.forward.targetEpoch, 3);
  assert.equal(tsk.repeatedCycle.forward.staleWriterDenied, true);
  assert.equal(tsk.repeatedCycle.failback.sourceEpoch, 3);
  assert.equal(tsk.repeatedCycle.failback.targetEpoch, 4);
  assert.equal(tsk.repeatedCycle.failback.staleWriterDenied, true);
  assert.equal(tsk.repeatForwardCredential.leaseGrant.leaseEpoch, 3);
  assert.equal(tsk.repeatForwardCredential.proof.commandId,
    tsk.repeatedCycle.forward.commandId);
  assert.equal(tsk.repeatReturnCredential.leaseGrant.leaseEpoch, 4);
  assert.equal(tsk.repeatReturnCredential.proof.commandId,
    tsk.repeatedCycle.failback.commandId);
  assert.equal(tsk.staleRepeatForwardCredentialDenied, true);
  assert.equal(tsk.staleRepeatReturnCredentialDenied, true);
  assert.equal(bpc.repeatedCycle.forward.targetEpoch, 4);
  assert.equal(bpc.repeatedCycle.failback.targetEpoch, 5);
  assert.equal(bpc.recoveredSite.targetEpoch, 6);
  assert.equal(bpc.recoveredSite.staleDatabaseReused, true);
  assert.equal(bpc.recoveredSite.firstMutationSequence, 1);
  assert.equal(tsk.recoveredSite.handoff.targetEpoch, 5);
  assert.equal(tsk.recoveredSite.handoff.staleWriterDenied, true);
  assert.equal(tsk.recoveredSite.staleCredentialDenied, true);
  assert.notEqual(tsk.publicCredentialReturn.clientId, tsk.publicCredentialTarget.clientId);
  assert.notEqual(tsk.publicCredentialReturn.secretDigest,
    tsk.publicCredentialTarget.secretDigest);
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
  const sameAuthorityFaults = env.TSK_SAME_AUTHORITY_FAULTS === '1';

  const redis = tskRedisOptions(env);
  let bpc;
  let tsk;
  let tskRedisFaults = null;
  let postHealRestartDenials = null;
  try {
    bpc = await runBpcLiveComposition({
      bpcRoot, expectedBpcCommit: bpcCommit, commandId,
      postgresUrls: [env.BPC_TEST_POSTGRES_URL, env.BPC_TEST_POSTGRES_B_URL,
        env.BPC_TEST_POSTGRES_CONTROL_URL],
      redisUrls: required(env.BPC_TEST_REDIS_URLS, 'BPC_TEST_REDIS_URLS').split(','),
      preservePostHealProbes: sameAuthorityFaults,
      streamId: 'bpc:enterprise:live/v1',
    });
    tsk = await runTskLiveComposition({
      tskRoot, expectedTskCommit: tskCommit, commandId,
      aPostgresUrl: env.TSK_TEST_SOURCE_PG_URL_A,
      bPostgresUrl: env.TSK_TEST_RECEIVER_PG_URL_B,
      controlPostgresUrl: env.TSK_TEST_CONTROL_PG_URL,
      redis,
      preserveRedisAuthority: sameAuthorityFaults,
      preservePostHealProbes: sameAuthorityFaults,
      streamId: 'enterprise28:tsk-live/v1', destructiveReset: true,
    });
    if (sameAuthorityFaults) {
      tskRedisFaults = await runSameTskRedisAuthorityFaults({
        authority: tsk.redisAuthority,
        commandId: tsk.recoveredSite.handoff.commandId, redis,
        streamId: 'enterprise28:tsk-live/v1', systemIds: tsk.systemIds,
        topology: sameAuthorityTopology(env),
      });
      const healed = tskRedisFaults.faults.livePartition;
      assert.equal(healed.oldMasterRefusedWrites, true);
      assert.equal(healed.exactTuplePreserved, true);
      assert.equal(healed.rpo, 0);
      const [postHealBpc, postHealTsk] = await Promise.all([
        runPostHealBpcRestartProbes(bpc),
        runPostHealTskRestartProbes(tsk),
      ]);
      postHealRestartDenials = Object.freeze({
        healedAuthority: Object.freeze({
          commandId: tskRedisFaults.commandId,
          fenceEpoch: tskRedisFaults.fenceEpoch,
          authorityNodeId: tskRedisFaults.authorityNodeId,
          redisAuthorityTupleDigest: tskRedisFaults.redisAuthorityTupleDigest,
          partitionRtoMs: healed.rtoMs,
        }),
        bpc: postHealBpc,
        tsk: postHealTsk,
      });
    }
  } catch (error) {
    const cleanup = await Promise.allSettled([
      bpc ? discardPostHealBpcRestartProbes(bpc) : Promise.resolve(),
      tsk ? discardPostHealTskRestartProbes(tsk) : Promise.resolve(),
    ]);
    const cleanupFailures = cleanup.filter((outcome) => outcome.status === 'rejected')
      .map((outcome) => outcome.reason);
    if (cleanupFailures.length > 0) {
      throw new AggregateError([error, ...cleanupFailures],
        'protocol composition failed and retained-authority cleanup was incomplete');
    }
    throw error;
  }

  const [bpcApi, tskApi] = await Promise.all([
    importPinnedServer(bpcRoot, 'BPC'), importPinnedServer(tskRoot, 'TSK'),
  ]);
  const bpcResolver = { resolve: (keyId) => keyId === bpc.readinessAttestation.snapshotKeyId
    ? createPublicKey(bpc.publicKeys.source) : null };
  const tskBResolver = { resolve: (keyId) => keyId === tsk.bFinalizedReceipt.bKeyId
    ? createPublicKey(tsk.publicKeys.bReceipt) : null };
  const tskGuardResolver = { resolve: (keyId) => keyId === tsk.activationLeaseGrant.guardKeyId
    ? createPublicKey(tsk.publicKeys.guard) : null };
  const tskReturnResolver = { resolve: (keyId) =>
    keyId === tsk.returnFinalizedReceipt.bKeyId
      ? createPublicKey(tsk.publicKeys.aReceipt) : null };
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
  const returnCredentialGuardResolver = { resolve: (keyId) =>
    keyId === tsk.returnCredentialActivationLeaseGrant.guardKeyId
      ? createPublicKey(tsk.publicKeys.guard) : null };
  const returnCredentialHeadResolver = { resolve: (keyId, alg) =>
    keyId === tsk.returnCredentialProof.head.keyId && alg === 'ed25519'
      ? createPublicKey(tsk.publicKeys.returnCredentialHead) : null };
  const returnCredentialAuthority = createPromotedTskAuthorityCapability({
    activationLease: tsk.returnCredentialActivationLeaseGrant,
    leaseResolver: returnCredentialGuardResolver,
    headKeyResolver: returnCredentialHeadResolver,
  });
  const verifiedReturnCredential = await verifyPromotedTskCredentialProof(
    returnCredentialAuthority,
    tsk.returnCredentialProof,
    {
      agentId: tsk.returnCredentialProof.agentId,
      pairId: tsk.returnCredentialProof.pairId,
      sourceClientId: tsk.publicCredentialTarget.clientId,
      sourceSecretDigest: tsk.publicCredentialTarget.secretDigest,
    },
  );
  const repeatForwardCredentialAuthority = createPromotedTskAuthorityCapability({
    activationLease: tsk.repeatForwardCredential.leaseGrant,
    leaseResolver: returnCredentialGuardResolver,
    headKeyResolver: credentialHeadResolver,
  });
  const verifiedRepeatForwardCredential = await verifyPromotedTskCredentialProof(
    repeatForwardCredentialAuthority,
    tsk.repeatForwardCredential.proof,
    {
      agentId: tsk.repeatForwardCredential.proof.agentId,
      pairId: tsk.repeatForwardCredential.proof.pairId,
      sourceClientId: tsk.publicCredentialReturn.clientId,
      sourceSecretDigest: tsk.publicCredentialReturn.secretDigest,
    },
  );
  const repeatReturnCredentialAuthority = createPromotedTskAuthorityCapability({
    activationLease: tsk.repeatReturnCredential.leaseGrant,
    leaseResolver: returnCredentialGuardResolver,
    headKeyResolver: returnCredentialHeadResolver,
  });
  const verifiedRepeatReturnCredential = await verifyPromotedTskCredentialProof(
    repeatReturnCredentialAuthority,
    tsk.repeatReturnCredential.proof,
    {
      agentId: tsk.repeatReturnCredential.proof.agentId,
      pairId: tsk.repeatReturnCredential.proof.pairId,
      sourceClientId: tsk.repeatForwardCredential.publicCredential.clientId,
      sourceSecretDigest: tsk.repeatForwardCredential.publicCredential.secretDigest,
    },
  );
  const recoveredCredentialAuthority = createPromotedTskAuthorityCapability({
    activationLease: tsk.recoveredSite.credential.leaseGrant,
    leaseResolver: returnCredentialGuardResolver,
    headKeyResolver: credentialHeadResolver,
  });
  const verifiedRecoveredCredential = await verifyPromotedTskCredentialProof(
    recoveredCredentialAuthority,
    tsk.recoveredSite.credential.proof,
    {
      agentId: tsk.recoveredSite.credential.proof.agentId,
      pairId: tsk.recoveredSite.credential.proof.pairId,
      sourceClientId: tsk.repeatReturnCredential.publicCredential.clientId,
      sourceSecretDigest: tsk.repeatReturnCredential.publicCredential.secretDigest,
    },
  );
  validateLiveProtocolComposition(bpc, tsk, commandId);

  return Object.freeze({
    commandId,
    commits: Object.freeze({ enterprise: enterpriseSha, bpc: bpcCommit, tsk: tskCommit }),
    bpc,
    tsk,
    tskRedisFaults,
    postHealRestartDenials,
    sourceCredentialAuthority,
    verifiedSourceCredential,
    verifiedTargetCredential,
    returnCredentialAuthority,
    verifiedReturnCredential,
    repeatForwardCredentialAuthority,
    verifiedRepeatForwardCredential,
    repeatReturnCredentialAuthority,
    verifiedRepeatReturnCredential,
    recoveredCredentialAuthority,
    verifiedRecoveredCredential,
    resolvers: Object.freeze({ bpcResolver, tskBResolver, tskGuardResolver,
      tskReturnResolver }),
    publicKeyFingerprints: Object.freeze({
      bpcSource: fingerprint(bpc.publicKeys.source),
      tskB: fingerprint(tsk.publicKeys.bReceipt),
    tskGuard: fingerprint(tsk.publicKeys.guard),
      tskSourceCredentialHead: fingerprint(tsk.publicKeys.sourceCredentialHead),
      tskTargetCredentialHead: fingerprint(tsk.publicKeys.credentialHead),
      tskReturnCredentialHead: fingerprint(tsk.publicKeys.returnCredentialHead),
    }),
  });
}

export async function runLiveEnterpriseAcceptance(env = process.env) {
  const protocols = await runLiveProtocolComposition(env);
  const enterprise = await runEnterpriseLiveHandoff(protocols, env);
  const sameAuthorityFaults = env.TSK_SAME_AUTHORITY_FAULTS === '1';
  const ultraRedisFaults = sameAuthorityFaults
    ? await runSameRedisAuthorityFaults({
      authority: await claimUltraRedisAuthority(env, protocols.commandId),
      commandId: protocols.commandId,
      redis: tskRedisOptions(env),
      streamId: 'enterprise28:ultra-writer-fence/v1',
      systemIds: Object.freeze({ sourceA: enterprise.sourceSystemId,
        promotedB: enterprise.targetSystemId, control: protocols.tsk.systemIds.control }),
      topology: sameAuthorityTopology(env),
      kind: 'ultra-same-redis-authority-faults',
    })
    : null;
  return Object.freeze({ ...protocols, enterprise, ultraRedisFaults });
}
