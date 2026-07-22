import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const COMMAND_ID = /^[A-Za-z0-9_.:/-]{1,128}$/;
const ARTIFACT_KEYS = Object.freeze([
  'bpcFailback', 'bpcPromotion', 'bpcRepeatFailback', 'bpcRepeatForward',
  'bpcRecoveredReadiness',
  'enterpriseFailbackCredentialReceipt', 'enterpriseFailbackManifest',
  'enterpriseManifest', 'enterpriseRepeatFailbackCredentialReceipt',
  'enterpriseRepeatFailbackManifest', 'enterpriseRepeatForwardCredentialReceipt',
  'enterpriseRepeatForwardManifest', 'promotedCredentialProof',
  'enterpriseRecoveredCredentialReceipt', 'enterpriseRecoveredManifest',
  'promotedCredentialReceipt', 'returnedCredentialActivation',
  'returnedCredentialProof', 'tskActivation', 'tskFinalized',
  'tskRepeatFailbackActivation', 'tskRepeatFailbackFinalized',
  'tskRepeatForwardActivation', 'tskRepeatForwardFinalized',
  'tskRecoveredActivation', 'tskRecoveredFinalized',
  'tskReturnActivation', 'tskReturnFinalized',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicEvidence(result) {
  return {
    schemaVersion: 7,
    kind: 'enterprise-live-authority-handoff',
    commandId: result.commandId,
    commits: result.commits,
    systems: {
      bpc: result.bpc.systemIds,
      tsk: result.tsk.systemIds,
      enterprise: {
        source: result.enterprise.sourceSystemId,
        target: result.enterprise.targetSystemId,
        failbackSource: result.enterprise.failback.sourceSystemId,
        failbackTarget: result.enterprise.failback.targetSystemId,
        recoveredSource: result.enterprise.recoveredSite.sourceSystemId,
        recoveredTarget: result.enterprise.recoveredSite.targetSystemId,
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
      bpcRepeatForward:
        result.bpc.repeatedCycle.forward.readinessAttestation.attestationDigest,
      bpcRepeatFailback:
        result.bpc.repeatedCycle.failback.readinessAttestation.attestationDigest,
      tskRepeatForwardFinalized:
        result.tsk.repeatedCycle.forward.finalizedReceipt.receiptDigest,
      tskRepeatForwardActivation:
        result.tsk.repeatedCycle.forward.activationLease.grantDigest,
      tskRepeatFailbackFinalized:
        result.tsk.repeatedCycle.failback.finalizedReceipt.receiptDigest,
      tskRepeatFailbackActivation:
        result.tsk.repeatedCycle.failback.activationLease.grantDigest,
      enterpriseRepeatForwardManifest:
        result.enterprise.repeatedCycle.forward.manifestDigest,
      enterpriseRepeatForwardCredentialReceipt:
        result.enterprise.repeatedCycle.forward.receiptDigest,
      enterpriseRepeatFailbackManifest:
        result.enterprise.repeatedCycle.failback.manifestDigest,
      enterpriseRepeatFailbackCredentialReceipt:
        result.enterprise.repeatedCycle.failback.receiptDigest,
      bpcRecoveredReadiness:
        result.bpc.recoveredSite.readinessAttestation.attestationDigest,
      tskRecoveredFinalized:
        result.tsk.recoveredSite.handoff.finalizedReceipt.receiptDigest,
      tskRecoveredActivation:
        result.tsk.recoveredSite.handoff.activationLease.grantDigest,
      enterpriseRecoveredManifest: result.enterprise.recoveredSite.manifestDigest,
      enterpriseRecoveredCredentialReceipt: result.enterprise.recoveredSite.receiptDigest,
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
      enterpriseFailbackSourceClientId: result.enterprise.failback.sourceClientId,
      enterpriseFailbackTargetClientId: result.enterprise.failback.targetClientId,
      enterpriseFailbackIdempotentRetry: result.enterprise.failback.idempotentRetry,
      enterpriseFailbackStaleBCompletionDenied:
        result.enterprise.failback.staleBCompletionDenied,
      enterpriseFailbackStaleBProtocolWriterDenied:
        result.enterprise.failback.staleBProtocolWriterDenied,
      enterpriseFailbackRpo: result.enterprise.failback.rpo,
      enterpriseFailbackRtoMs: result.enterprise.failback.rtoMs,
      tskRepeatForwardStaleWriterDenied:
        result.tsk.repeatedCycle.forward.staleWriterDenied,
      tskRepeatFailbackStaleWriterDenied:
        result.tsk.repeatedCycle.failback.staleWriterDenied,
      tskRepeatForwardStaleCredentialDenied:
        result.tsk.staleRepeatForwardCredentialDenied,
      tskRepeatFailbackStaleCredentialDenied:
        result.tsk.staleRepeatReturnCredentialDenied,
      bpcRecoveredStaleWriterDenied:
        result.bpc.recoveredSite.staleSourceWriterDenied,
      bpcRecoveredFirstMutationSequence:
        result.bpc.recoveredSite.firstMutationSequence,
      tskRecoveredStaleWriterDenied:
        result.tsk.recoveredSite.handoff.staleWriterDenied,
      tskRecoveredStaleCredentialDenied:
        result.tsk.recoveredSite.staleCredentialDenied,
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
    repeatedCycle: {
      forward: {
        bpcCommandId: result.bpc.repeatedCycle.forward.commandId,
        tskCommandId: result.tsk.repeatedCycle.forward.commandId,
        enterpriseCommandId: result.enterprise.repeatedCycle.forward.commandId,
        bpcSourceEpoch: result.bpc.repeatedCycle.forward.sourceEpoch,
        bpcTargetEpoch: result.bpc.repeatedCycle.forward.targetEpoch,
        tskSourceEpoch: result.tsk.repeatedCycle.forward.sourceEpoch,
        tskTargetEpoch: result.tsk.repeatedCycle.forward.targetEpoch,
        enterpriseSourceEpoch: result.enterprise.repeatedCycle.forward.sourceEpoch,
        sourceSystemId: result.enterprise.repeatedCycle.forward.sourceSystemId,
        targetSystemId: result.enterprise.repeatedCycle.forward.targetSystemId,
        sourceClientId: result.enterprise.repeatedCycle.forward.sourceClientId,
        targetClientId: result.enterprise.repeatedCycle.forward.targetClientId,
        staleSourceCompletionDenied:
          result.enterprise.repeatedCycle.forward.staleSourceCompletionDenied,
        idempotentRetry: result.enterprise.repeatedCycle.forward.idempotentRetry,
        rpo: result.enterprise.repeatedCycle.forward.rpo,
        rtoMs: result.enterprise.repeatedCycle.forward.rtoMs,
        artifacts: {
          bpcReadiness:
            result.bpc.repeatedCycle.forward.readinessAttestation.attestationDigest,
          tskFinalized:
            result.tsk.repeatedCycle.forward.finalizedReceipt.receiptDigest,
          tskActivation:
            result.tsk.repeatedCycle.forward.activationLease.grantDigest,
          enterpriseManifest: result.enterprise.repeatedCycle.forward.manifestDigest,
          enterpriseCredentialReceipt:
            result.enterprise.repeatedCycle.forward.receiptDigest,
        },
      },
      failback: {
        bpcCommandId: result.bpc.repeatedCycle.failback.commandId,
        tskCommandId: result.tsk.repeatedCycle.failback.commandId,
        enterpriseCommandId: result.enterprise.repeatedCycle.failback.commandId,
        bpcSourceEpoch: result.bpc.repeatedCycle.failback.sourceEpoch,
        bpcTargetEpoch: result.bpc.repeatedCycle.failback.targetEpoch,
        tskSourceEpoch: result.tsk.repeatedCycle.failback.sourceEpoch,
        tskTargetEpoch: result.tsk.repeatedCycle.failback.targetEpoch,
        enterpriseSourceEpoch: result.enterprise.repeatedCycle.failback.sourceEpoch,
        sourceSystemId: result.enterprise.repeatedCycle.failback.sourceSystemId,
        targetSystemId: result.enterprise.repeatedCycle.failback.targetSystemId,
        sourceClientId: result.enterprise.repeatedCycle.failback.sourceClientId,
        targetClientId: result.enterprise.repeatedCycle.failback.targetClientId,
        staleSourceCompletionDenied:
          result.enterprise.repeatedCycle.failback.staleSourceCompletionDenied,
        idempotentRetry: result.enterprise.repeatedCycle.failback.idempotentRetry,
        rpo: result.enterprise.repeatedCycle.failback.rpo,
        rtoMs: result.enterprise.repeatedCycle.failback.rtoMs,
        artifacts: {
          bpcReadiness:
            result.bpc.repeatedCycle.failback.readinessAttestation.attestationDigest,
          tskFinalized:
            result.tsk.repeatedCycle.failback.finalizedReceipt.receiptDigest,
          tskActivation:
            result.tsk.repeatedCycle.failback.activationLease.grantDigest,
          enterpriseManifest: result.enterprise.repeatedCycle.failback.manifestDigest,
          enterpriseCredentialReceipt:
            result.enterprise.repeatedCycle.failback.receiptDigest,
        },
      },
    },
    recoveredSite: {
      bpcCommandId: result.bpc.recoveredSite.commandId,
      tskCommandId: result.tsk.recoveredSite.handoff.commandId,
      enterpriseCommandId: result.enterprise.recoveredSite.commandId,
      bpcSourceEpoch: result.bpc.recoveredSite.sourceEpoch,
      bpcTargetEpoch: result.bpc.recoveredSite.targetEpoch,
      tskSourceEpoch: result.tsk.recoveredSite.handoff.sourceEpoch,
      tskTargetEpoch: result.tsk.recoveredSite.handoff.targetEpoch,
      enterpriseSourceEpoch: result.enterprise.recoveredSite.sourceEpoch,
      sourceSystemId: result.enterprise.recoveredSite.sourceSystemId,
      targetSystemId: result.enterprise.recoveredSite.targetSystemId,
      sourceClientId: result.enterprise.recoveredSite.sourceClientId,
      targetClientId: result.enterprise.recoveredSite.targetClientId,
      targetHolderId:
        result.tsk.recoveredSite.handoff.activationLease.holderNodeId,
      staleSourceCompletionDenied:
        result.enterprise.recoveredSite.staleSourceCompletionDenied,
      processRestarted: result.enterprise.recoveredSite.restartDenial.processRestarted,
      restartedStaleCompletionDenied:
        result.enterprise.recoveredSite.restartDenial.denied,
      idempotentRetry: result.enterprise.recoveredSite.idempotentRetry,
      rpo: result.enterprise.recoveredSite.rpo,
      rtoMs: result.enterprise.recoveredSite.rtoMs,
      artifacts: {
        bpcReadiness:
          result.bpc.recoveredSite.readinessAttestation.attestationDigest,
        tskFinalized:
          result.tsk.recoveredSite.handoff.finalizedReceipt.receiptDigest,
        tskActivation:
          result.tsk.recoveredSite.handoff.activationLease.grantDigest,
        enterpriseManifest: result.enterprise.recoveredSite.manifestDigest,
        enterpriseCredentialReceipt: result.enterprise.recoveredSite.receiptDigest,
      },
    },
    protocolRestartDenials: {
      bpc: result.bpc.restartDenials,
      tsk: result.tsk.restartDenials,
    },
    tskLatestAuthority: {
      commandId: result.tsk.recoveredSite.handoff.commandId,
      fenceEpoch: result.tsk.redisAuthority.record.fenceEpoch,
      nodeId: result.tsk.redisAuthority.record.nodeId,
      activationGrantDigest:
        result.tsk.recoveredSite.handoff.activationLease.grantDigest,
    },
    tskRedisFaults: result.tskRedisFaults,
    ultraRedisFaults: result.ultraRedisFaults,
  };
}

export function validateLiveCompositionEvidence(evidence, expected = {}) {
  assert.equal(evidence?.schemaVersion, 7);
  assert.equal(evidence?.kind, 'enterprise-live-authority-handoff');
  assert.equal(evidence?.commandId, expected.commandId ?? evidence.commandId);
  assert.match(evidence?.commandId, COMMAND_ID);
  for (const [name, value] of Object.entries(evidence?.commits ?? {})) {
    assert.match(value, SHA, `${name} commit must be a full SHA`);
    if (expected.commits?.[name]) assert.equal(value, expected.commits[name]);
  }
  assert.deepEqual(Object.keys(evidence?.commits ?? {}).sort(), ['bpc', 'enterprise', 'tsk']);
  assert.deepEqual(Object.keys(evidence?.artifacts ?? {}).sort(),
    [...ARTIFACT_KEYS].sort());
  for (const value of Object.values(evidence?.artifacts ?? {})) assert.match(value, DIGEST);
  assert.equal(new Set(Object.values(evidence.systems.bpc)).size, 3);
  assert.equal(new Set(Object.values(evidence.systems.tsk)).size, 3);
  assert.equal(evidence.systems.enterprise.target, evidence.systems.tsk.receiverB);
  assert.equal(evidence.systems.enterprise.failbackSource,
    evidence.systems.enterprise.target);
  assert.equal(evidence.systems.enterprise.failbackTarget,
    evidence.systems.enterprise.source);
  assert.equal(evidence.systems.enterprise.recoveredSource,
    evidence.systems.enterprise.source);
  assert.equal(evidence.systems.enterprise.recoveredTarget,
    evidence.systems.enterprise.target);
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
  assert.equal(evidence.outcomes.enterpriseFailbackSourceClientId,
    evidence.outcomes.enterpriseTargetClientId);
  assert.notEqual(evidence.outcomes.enterpriseFailbackTargetClientId,
    evidence.outcomes.enterpriseFailbackSourceClientId);
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
  assert.equal(evidence.tskLatestAuthority.commandId,
    evidence.recoveredSite.tskCommandId);
  assert.equal(evidence.tskLatestAuthority.fenceEpoch,
    evidence.recoveredSite.tskTargetEpoch);
  assert.equal(evidence.tskLatestAuthority.nodeId,
    evidence.recoveredSite.targetHolderId);
  assert.equal(evidence.tskLatestAuthority.activationGrantDigest,
    evidence.artifacts.tskRecoveredActivation);
  const cycleArtifactBindings = {
    forward: {
      bpcReadiness: 'bpcRepeatForward',
      tskFinalized: 'tskRepeatForwardFinalized',
      tskActivation: 'tskRepeatForwardActivation',
      enterpriseManifest: 'enterpriseRepeatForwardManifest',
      enterpriseCredentialReceipt: 'enterpriseRepeatForwardCredentialReceipt',
    },
    failback: {
      bpcReadiness: 'bpcRepeatFailback',
      tskFinalized: 'tskRepeatFailbackFinalized',
      tskActivation: 'tskRepeatFailbackActivation',
      enterpriseManifest: 'enterpriseRepeatFailbackManifest',
      enterpriseCredentialReceipt: 'enterpriseRepeatFailbackCredentialReceipt',
    },
  };
  const cycleKeys = [
    'artifacts', 'bpcCommandId', 'bpcSourceEpoch', 'bpcTargetEpoch',
    'enterpriseCommandId', 'enterpriseSourceEpoch', 'idempotentRetry', 'rpo',
    'rtoMs', 'sourceClientId', 'sourceSystemId', 'staleSourceCompletionDenied',
    'targetClientId', 'targetSystemId', 'tskCommandId', 'tskSourceEpoch',
    'tskTargetEpoch',
  ].sort();
  for (const [name, cycle] of Object.entries(evidence.repeatedCycle)) {
    assert.deepEqual(Object.keys(cycle).sort(), cycleKeys);
    assert.deepEqual(Object.keys(cycle.artifacts).sort(), [
      'bpcReadiness', 'enterpriseCredentialReceipt', 'enterpriseManifest',
      'tskActivation', 'tskFinalized',
    ]);
    assert.match(cycle.bpcCommandId, COMMAND_ID);
    assert.equal(cycle.tskCommandId, cycle.bpcCommandId);
    assert.equal(cycle.enterpriseCommandId, cycle.bpcCommandId);
    assert.equal(cycle.enterpriseSourceEpoch, cycle.tskTargetEpoch);
    for (const [field, artifactName] of Object.entries(cycleArtifactBindings[name])) {
      assert.equal(cycle.artifacts[field], evidence.artifacts[artifactName]);
    }
  }
  assert.equal(evidence.repeatedCycle.forward.bpcTargetEpoch,
    evidence.repeatedCycle.forward.bpcSourceEpoch + 1);
  assert.equal(evidence.repeatedCycle.forward.tskTargetEpoch,
    evidence.repeatedCycle.forward.tskSourceEpoch + 1);
  assert.equal(evidence.repeatedCycle.forward.sourceSystemId,
    evidence.systems.enterprise.source);
  assert.equal(evidence.repeatedCycle.forward.targetSystemId,
    evidence.systems.enterprise.target);
  assert.equal(evidence.repeatedCycle.forward.staleSourceCompletionDenied, true);
  assert.equal(evidence.repeatedCycle.forward.idempotentRetry, true);
  assert.equal(evidence.repeatedCycle.forward.rpo, 0);
  assert.equal(evidence.repeatedCycle.failback.bpcTargetEpoch,
    evidence.repeatedCycle.forward.bpcTargetEpoch + 1);
  assert.equal(evidence.repeatedCycle.failback.tskTargetEpoch,
    evidence.repeatedCycle.forward.tskTargetEpoch + 1);
  assert.equal(evidence.repeatedCycle.failback.sourceSystemId,
    evidence.systems.enterprise.target);
  assert.equal(evidence.repeatedCycle.failback.targetSystemId,
    evidence.systems.enterprise.source);
  assert.equal(evidence.repeatedCycle.failback.sourceClientId,
    evidence.repeatedCycle.forward.targetClientId);
  assert.equal(evidence.repeatedCycle.failback.staleSourceCompletionDenied, true);
  assert.equal(evidence.repeatedCycle.failback.idempotentRetry, true);
  assert.equal(evidence.repeatedCycle.failback.rpo, 0);
  for (const cycle of Object.values(evidence.repeatedCycle)) {
    assert.notEqual(cycle.sourceClientId, cycle.targetClientId);
    assert.equal(Number.isSafeInteger(cycle.rtoMs) && cycle.rtoMs >= 0, true);
  }
  assert.equal(evidence.outcomes.tskRepeatForwardStaleWriterDenied, true);
  assert.equal(evidence.outcomes.tskRepeatFailbackStaleWriterDenied, true);
  assert.equal(evidence.outcomes.tskRepeatForwardStaleCredentialDenied, true);
  assert.equal(evidence.outcomes.tskRepeatFailbackStaleCredentialDenied, true);
  assert.equal(evidence.outcomes.bpcRecoveredStaleWriterDenied, true);
  assert.equal(evidence.outcomes.bpcRecoveredFirstMutationSequence, 1);
  assert.equal(evidence.outcomes.tskRecoveredStaleWriterDenied, true);
  assert.equal(evidence.outcomes.tskRecoveredStaleCredentialDenied, true);
  const recoveredKeys = [
    'artifacts', 'bpcCommandId', 'bpcSourceEpoch', 'bpcTargetEpoch',
    'enterpriseCommandId', 'enterpriseSourceEpoch', 'idempotentRetry',
    'processRestarted', 'restartedStaleCompletionDenied', 'rpo', 'rtoMs',
    'sourceClientId', 'sourceSystemId', 'staleSourceCompletionDenied',
    'targetClientId', 'targetHolderId', 'targetSystemId', 'tskCommandId', 'tskSourceEpoch',
    'tskTargetEpoch',
  ].sort();
  assert.deepEqual(Object.keys(evidence.recoveredSite).sort(), recoveredKeys);
  assert.equal(evidence.recoveredSite.bpcCommandId,
    evidence.recoveredSite.tskCommandId);
  assert.equal(evidence.recoveredSite.enterpriseCommandId,
    evidence.recoveredSite.tskCommandId);
  assert.equal(evidence.recoveredSite.bpcTargetEpoch,
    evidence.repeatedCycle.failback.bpcTargetEpoch + 1);
  assert.equal(evidence.recoveredSite.tskTargetEpoch,
    evidence.repeatedCycle.failback.tskTargetEpoch + 1);
  assert.equal(evidence.recoveredSite.enterpriseSourceEpoch,
    evidence.recoveredSite.tskTargetEpoch);
  assert.equal(evidence.recoveredSite.sourceSystemId,
    evidence.systems.enterprise.source);
  assert.equal(evidence.recoveredSite.targetSystemId,
    evidence.systems.enterprise.target);
  assert.equal(evidence.recoveredSite.sourceClientId,
    evidence.repeatedCycle.failback.targetClientId);
  assert.notEqual(evidence.recoveredSite.sourceClientId,
    evidence.recoveredSite.targetClientId);
  assert.equal(evidence.recoveredSite.staleSourceCompletionDenied, true);
  assert.equal(evidence.recoveredSite.processRestarted, true);
  assert.equal(evidence.recoveredSite.restartedStaleCompletionDenied, true);
  assert.equal(evidence.recoveredSite.idempotentRetry, true);
  assert.equal(evidence.recoveredSite.rpo, 0);
  assert.equal(Number.isSafeInteger(evidence.recoveredSite.rtoMs) &&
    evidence.recoveredSite.rtoMs >= 0, true);
  const recoveredArtifactBindings = {
    bpcReadiness: 'bpcRecoveredReadiness',
    tskFinalized: 'tskRecoveredFinalized',
    tskActivation: 'tskRecoveredActivation',
    enterpriseManifest: 'enterpriseRecoveredManifest',
    enterpriseCredentialReceipt: 'enterpriseRecoveredCredentialReceipt',
  };
  for (const [field, artifactName] of Object.entries(recoveredArtifactBindings)) {
    assert.equal(evidence.recoveredSite.artifacts[field],
      evidence.artifacts[artifactName]);
  }
  const restartCuts = [
    'initial', 'failback', 'repeatForward', 'repeatFailback', 'recoveredSite',
  ];
  const allRestartPids = new Set();
  assert.deepEqual(Object.keys(evidence.protocolRestartDenials).sort(), ['bpc', 'tsk']);
  for (const protocol of ['bpc', 'tsk']) {
    const probes = evidence.protocolRestartDenials[protocol];
    assert.deepEqual(Object.keys(probes).sort(), [...restartCuts].sort());
    const protocolPids = new Set();
    for (const cut of restartCuts) {
      const probe = probes[cut];
      assert.equal(probe.processRestarted, true);
      assert.equal(probe.denied, true);
      assert.equal(Number.isSafeInteger(probe.childPid) && probe.childPid > 0, true);
      assert.equal(Number.isSafeInteger(probe.rtoMs) && probe.rtoMs >= 0, true);
      protocolPids.add(probe.childPid);
      allRestartPids.add(probe.childPid);
    }
    assert.equal(protocolPids.size, restartCuts.length);
  }
  assert.equal(allRestartPids.size, restartCuts.length * 2,
    'each BPC and TSK cut must use a distinct restarted child process');
  assert.equal(evidence.tskRedisFaults?.kind, 'tsk-same-redis-authority-faults');
  assert.equal(evidence.tskRedisFaults?.commandId,
    evidence.tskLatestAuthority.commandId);
  assert.equal(evidence.tskRedisFaults?.fenceEpoch,
    evidence.tskLatestAuthority.fenceEpoch);
  assert.equal(evidence.tskRedisFaults?.authorityNodeId,
    evidence.tskLatestAuthority.nodeId);
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
