import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const COMMAND_ID = /^[A-Za-z0-9_.:/-]{1,128}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicEvidence(result) {
  return {
    schemaVersion: 5,
    kind: 'enterprise-live-authority-handoff',
    commandId: result.commandId,
    commits: result.commits,
    systems: {
      bpc: result.bpc.systemIds,
      tsk: result.tsk.systemIds,
      enterprise: {
        source: result.enterprise.sourceSystemId,
        target: result.enterprise.targetSystemId,
        failbackTarget: result.enterprise.failback.targetSystemId,
      },
    },
    artifacts: {
      bpcPromotion: result.bpc.readinessAttestation.attestationDigest,
      bpcFailback: result.bpc.failback.readinessAttestation.attestationDigest,
      tskFinalized: result.tsk.bFinalizedReceipt.receiptDigest,
      tskActivation: result.tsk.activationLeaseGrant.grantDigest,
      tskReturnFinalized: result.tsk.returnFinalizedReceipt.receiptDigest,
      tskReturnActivation: result.tsk.returnActivationLeaseGrant.grantDigest,
      enterpriseManifest: result.enterprise.manifestDigest,
      promotedCredentialProof: result.enterprise.targetProofDigest,
      promotedCredentialReceipt: result.enterprise.receiptDigest,
      returnedCredentialProof: result.tsk.returnCredentialProof.head.headDigest,
      returnedCredentialActivation:
        result.tsk.returnCredentialActivationLeaseGrant.grantDigest,
      enterpriseFailbackManifest: result.enterprise.failback.manifestDigest,
      enterpriseFailbackCredentialReceipt: result.enterprise.failback.receiptDigest,
    },
    outcomes: {
      bpcStaleWriterDenied: result.bpc.staleWriterDenied,
      bpcFailbackStaleWriterDenied: result.bpc.failback.staleBWriterDenied,
      bpcFailbackTargetEpoch: result.bpc.failback.targetEpoch,
      bpcFailbackTargetSystem: result.bpc.failback.targetSystemId,
      tskStaleWriterDenied: result.tsk.staleWriterDenied,
      tskReturnStaleWriterDenied: result.tsk.staleTargetWriterDenied,
      tskStaleCredentialWriterDenied: result.tsk.staleCredentialWriterDenied,
      tskReturnStaleCredentialWriterDenied:
        result.tsk.staleReturnedCredentialWriterDenied,
      promotedSourceNextSequence: result.tsk.nextSequence,
      returnedSourceNextSequence: result.tsk.returnSequence,
      tskReturnCommandId: result.tsk.returnCommandId,
      enterpriseTargetClientId: result.enterprise.targetClientId,
      copiedTargetCredentialRows: result.enterprise.copiedTargetCredentialRows,
      redactionPreserved: result.enterprise.redactionPreserved,
      dataLossRpo: result.enterprise.rpo,
      enterpriseFailbackCommandId: result.enterprise.failback.commandId,
      enterpriseFailbackSourceEpoch: result.enterprise.failback.sourceEpoch,
      enterpriseFailbackTargetClientId: result.enterprise.failback.targetClientId,
      enterpriseFailbackIdempotentRetry: result.enterprise.failback.idempotentRetry,
      enterpriseFailbackStaleBCompletionDenied:
        result.enterprise.failback.staleBCompletionDenied,
      enterpriseFailbackStaleBProtocolWriterDenied:
        result.enterprise.failback.staleBProtocolWriterDenied,
      enterpriseFailbackRpo: result.enterprise.failback.rpo,
      enterpriseFailbackRtoMs: result.enterprise.failback.rtoMs,
    },
    tskReturnAuthority: {
      commandId: result.tsk.returnCommandId,
      finalizedReceiptDigest: result.tsk.returnFinalizedReceipt.receiptDigest,
      activationGrantDigest: result.tsk.returnActivationLeaseGrant.grantDigest,
      targetHolderId: result.tsk.returnActivationLeaseGrant.holderNodeId,
      targetSystemId: result.tsk.returnFinalizedReceipt.bSystemId,
      sourceEpoch: result.tsk.returnFinalizedReceipt.epoch,
      targetEpoch: result.tsk.returnActivationLeaseGrant.leaseEpoch,
      importedSequence: result.tsk.returnSourceActivation.n,
      nextSequence: result.tsk.returnSequence,
      redisFenceEpoch: result.tsk.redisAuthority.record.fenceEpoch,
      redisNodeId: result.tsk.redisAuthority.record.nodeId,
    },
    tskRedisFaults: result.tskRedisFaults,
    ultraRedisFaults: result.ultraRedisFaults,
  };
}

export function validateLiveCompositionEvidence(evidence, expected = {}) {
  assert.equal(evidence?.schemaVersion, 5);
  assert.equal(evidence?.kind, 'enterprise-live-authority-handoff');
  assert.equal(evidence?.commandId, expected.commandId ?? evidence.commandId);
  assert.match(evidence?.commandId, COMMAND_ID);
  for (const [name, value] of Object.entries(evidence?.commits ?? {})) {
    assert.match(value, SHA, `${name} commit must be a full SHA`);
    if (expected.commits?.[name]) assert.equal(value, expected.commits[name]);
  }
  assert.deepEqual(Object.keys(evidence?.commits ?? {}).sort(), ['bpc', 'enterprise', 'tsk']);
  for (const value of Object.values(evidence?.artifacts ?? {})) assert.match(value, DIGEST);
  assert.equal(new Set(Object.values(evidence.systems.bpc)).size, 3);
  assert.equal(new Set(Object.values(evidence.systems.tsk)).size, 3);
  assert.equal(evidence.systems.enterprise.target, evidence.systems.tsk.receiverB);
  assert.equal(evidence.systems.enterprise.failbackTarget,
    evidence.systems.enterprise.source);
  assert.notEqual(evidence.systems.enterprise.source, evidence.systems.enterprise.target);
  assert.equal(evidence.outcomes.bpcStaleWriterDenied, true);
  assert.equal(evidence.outcomes.bpcFailbackStaleWriterDenied, true);
  assert.equal(evidence.outcomes.bpcFailbackTargetSystem, evidence.systems.bpc.sourceA);
  assert.equal(Number.isSafeInteger(evidence.outcomes.bpcFailbackTargetEpoch) &&
    evidence.outcomes.bpcFailbackTargetEpoch > 1, true);
  assert.equal(evidence.outcomes.tskStaleWriterDenied, true);
  assert.equal(evidence.outcomes.tskReturnStaleWriterDenied, true);
  assert.match(evidence.outcomes.tskReturnCommandId, COMMAND_ID);
  assert.notEqual(evidence.outcomes.tskReturnCommandId, evidence.commandId);
  for (const value of [evidence.outcomes.promotedSourceNextSequence,
    evidence.outcomes.returnedSourceNextSequence,
    evidence.tskReturnAuthority?.importedSequence,
    evidence.tskReturnAuthority?.nextSequence]) {
    assert.equal(Number.isSafeInteger(value) && value > 0, true);
  }
  assert.equal(evidence.outcomes.returnedSourceNextSequence,
    evidence.outcomes.promotedSourceNextSequence + 1);
  assert.equal(evidence.systems.tsk.sourceA !== evidence.systems.tsk.receiverB, true);
  assert.equal(evidence.outcomes.tskStaleCredentialWriterDenied, true);
  assert.equal(evidence.outcomes.tskReturnStaleCredentialWriterDenied, true);
  assert.equal(evidence.outcomes.copiedTargetCredentialRows, 0);
  assert.equal(evidence.outcomes.redactionPreserved, true);
  assert.equal(evidence.outcomes.dataLossRpo, 0);
  assert.equal(evidence.outcomes.enterpriseFailbackCommandId,
    evidence.outcomes.tskReturnCommandId);
  assert.equal(evidence.outcomes.enterpriseFailbackSourceEpoch,
    evidence.tskReturnAuthority.targetEpoch);
  assert.equal(evidence.outcomes.enterpriseFailbackIdempotentRetry, true);
  assert.equal(evidence.outcomes.enterpriseFailbackStaleBCompletionDenied, true);
  assert.equal(evidence.outcomes.enterpriseFailbackStaleBProtocolWriterDenied, true);
  assert.equal(evidence.outcomes.enterpriseFailbackRpo, 0);
  assert.equal(Number.isSafeInteger(evidence.outcomes.enterpriseFailbackRtoMs) &&
    evidence.outcomes.enterpriseFailbackRtoMs >= 0, true);
  assert.match(evidence.outcomes.enterpriseFailbackTargetClientId, COMMAND_ID);
  assert.equal(evidence.tskReturnAuthority?.commandId,
    evidence.outcomes.tskReturnCommandId);
  assert.equal(evidence.tskReturnAuthority?.finalizedReceiptDigest,
    evidence.artifacts.tskReturnFinalized);
  assert.equal(evidence.tskReturnAuthority?.activationGrantDigest,
    evidence.artifacts.tskReturnActivation);
  assert.equal(evidence.tskReturnAuthority?.targetSystemId,
    evidence.systems.tsk.sourceA);
  assert.equal(Number.isSafeInteger(evidence.tskReturnAuthority?.sourceEpoch) &&
    evidence.tskReturnAuthority.sourceEpoch >= 0, true);
  assert.equal(Number.isSafeInteger(evidence.tskReturnAuthority?.targetEpoch) &&
    evidence.tskReturnAuthority.targetEpoch >= 1, true);
  assert.equal(evidence.tskReturnAuthority.targetEpoch,
    evidence.tskReturnAuthority.sourceEpoch + 1);
  assert.equal(evidence.tskReturnAuthority.importedSequence,
    evidence.outcomes.promotedSourceNextSequence);
  assert.equal(evidence.tskReturnAuthority.nextSequence,
    evidence.outcomes.returnedSourceNextSequence);
  assert.match(evidence.tskReturnAuthority?.targetHolderId, COMMAND_ID);
  assert.equal(evidence.tskReturnAuthority.redisFenceEpoch,
    evidence.tskReturnAuthority.targetEpoch);
  assert.equal(evidence.tskReturnAuthority.redisNodeId,
    evidence.tskReturnAuthority.targetHolderId);
  assert.equal(evidence.tskRedisFaults?.kind, 'tsk-same-redis-authority-faults');
  assert.equal(evidence.tskRedisFaults?.commandId,
    evidence.outcomes.tskReturnCommandId);
  assert.equal(evidence.tskRedisFaults?.fenceEpoch,
    evidence.tskReturnAuthority.targetEpoch);
  assert.equal(evidence.tskRedisFaults?.authorityNodeId,
    evidence.tskReturnAuthority.targetHolderId);
  assert.deepEqual(evidence.tskRedisFaults?.systemIds, evidence.systems.tsk);
  assert.equal(evidence.tskRedisFaults?.faults?.livePartition?.rpo, 0);
  assert.equal(evidence.tskRedisFaults?.faults?.livePartition?.oldMasterRefusedWrites, true);
  assert.equal(evidence.tskRedisFaults?.faults?.livePartition?.exactTuplePreserved, true);
  assert.equal(evidence.tskRedisFaults?.faults?.masterSigkill?.rpo, 0);
  assert.equal(evidence.tskRedisFaults?.faults?.masterSigkill?.exactTuplePreserved, true);
  assert.equal(evidence.ultraRedisFaults?.kind, 'ultra-same-redis-authority-faults');
  assert.equal(evidence.ultraRedisFaults?.commandId, evidence.commandId);
  assert.equal(evidence.ultraRedisFaults?.systemIds?.sourceA, evidence.systems.enterprise.source);
  assert.equal(evidence.ultraRedisFaults?.systemIds?.promotedB, evidence.systems.enterprise.target);
  assert.equal(evidence.ultraRedisFaults?.faults?.livePartition?.rpo, 0);
  assert.equal(evidence.ultraRedisFaults?.faults?.livePartition?.oldMasterRefusedWrites, true);
  assert.equal(evidence.ultraRedisFaults?.faults?.livePartition?.exactTuplePreserved, true);
  assert.equal(evidence.ultraRedisFaults?.faults?.masterSigkill?.rpo, 0);
  assert.equal(evidence.ultraRedisFaults?.faults?.masterSigkill?.exactTuplePreserved, true);
  return evidence;
}

export async function writeLiveCompositionEvidence(path, result) {
  const evidence = validateLiveCompositionEvidence(publicEvidence(result));
  const canonical = JSON.stringify(evidence);
  const envelope = { evidence, evidenceSha256: sha256(canonical) };
  await writeFile(path, `${JSON.stringify(envelope, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  return Object.freeze(envelope);
}

export async function readLiveCompositionEvidence(path, expected = {}) {
  const envelope = JSON.parse(await readFile(path, 'utf8'));
  const canonical = JSON.stringify(envelope.evidence);
  assert.match(envelope.evidenceSha256, DIGEST);
  assert.equal(envelope.evidenceSha256, sha256(canonical), 'live composition evidence digest mismatch');
  validateLiveCompositionEvidence(envelope.evidence, expected);
  return Object.freeze(envelope);
}
