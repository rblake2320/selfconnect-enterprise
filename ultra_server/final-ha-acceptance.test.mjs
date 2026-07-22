import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ACCEPTANCE_STEPS, assertCleanReviewedCheckout, assertStepEvidence, evidenceLines, validatePins,
} from './final-ha-acceptance.mjs';
import { validateLiveCompositionEvidence } from './live-composition-evidence.mjs';

function liveEvidence() {
  return {
    schemaVersion: 6, kind: 'enterprise-live-authority-handoff', commandId: 'promote-1',
    commits: { enterprise: 'a'.repeat(40), bpc: 'b'.repeat(40), tsk: 'c'.repeat(40) },
    systems: {
      bpc: { sourceA: '1', promotedB: '2', control: '3' },
      tsk: { sourceA: '4', receiverB: '5', control: '6' },
      enterprise: { source: '4', target: '5', failbackSource: '5', failbackTarget: '4' },
    },
    artifacts: {
      bpcPromotion: '1'.repeat(64), bpcFailback: '0'.repeat(64),
      tskFinalized: '2'.repeat(64),
      tskActivation: '3'.repeat(64),
      tskReturnFinalized: '7'.repeat(64), tskReturnActivation: '8'.repeat(64),
      enterpriseManifest: '4'.repeat(64),
      promotedCredentialProof: '5'.repeat(64), promotedCredentialReceipt: '6'.repeat(64),
      returnedCredentialProof: '9'.repeat(64),
      returnedCredentialActivation: 'a'.repeat(64),
      enterpriseFailbackManifest: 'b'.repeat(64),
      enterpriseFailbackCredentialReceipt: 'c'.repeat(64),
      bpcRepeatForward: 'd'.repeat(64), bpcRepeatFailback: 'e'.repeat(64),
      tskRepeatForwardFinalized: 'f'.repeat(64),
      tskRepeatForwardActivation: '0'.repeat(64),
      tskRepeatFailbackFinalized: '1'.repeat(64),
      tskRepeatFailbackActivation: '2'.repeat(64),
      enterpriseRepeatForwardManifest: '3'.repeat(64),
      enterpriseRepeatForwardCredentialReceipt: '4'.repeat(64),
      enterpriseRepeatFailbackManifest: '5'.repeat(64),
      enterpriseRepeatFailbackCredentialReceipt: '6'.repeat(64),
    },
    outcomes: {
      bpcStaleWriterDenied: true, bpcFailbackStaleWriterDenied: true,
      bpcFailbackTargetEpoch: 3, bpcFailbackTargetSystem: '1',
      tskStaleWriterDenied: true,
      tskReturnStaleWriterDenied: true,
      tskStaleCredentialWriterDenied: true, promotedSourceNextSequence: 2,
      tskReturnStaleCredentialWriterDenied: true,
      returnedSourceNextSequence: 3,
      tskReturnCommandId: 'return-1',
      enterpriseTargetClientId: 'target', copiedTargetCredentialRows: 0,
      redactionPreserved: true, dataLossRpo: 0,
      enterpriseFailbackCommandId: 'return-1', enterpriseFailbackSourceEpoch: 2,
      enterpriseFailbackSourceClientId: 'target',
      enterpriseFailbackTargetClientId: 'return-target',
      enterpriseFailbackIdempotentRetry: true,
      enterpriseFailbackStaleBCompletionDenied: true,
      enterpriseFailbackStaleBProtocolWriterDenied: true,
      enterpriseFailbackRpo: 0, enterpriseFailbackRtoMs: 12,
      tskRepeatForwardStaleWriterDenied: true,
      tskRepeatFailbackStaleWriterDenied: true,
      tskRepeatForwardStaleCredentialDenied: true,
      tskRepeatFailbackStaleCredentialDenied: true,
    },
    tskReturnAuthority: {
      commandId: 'return-1',
      finalizedReceiptDigest: '7'.repeat(64),
      activationGrantDigest: '8'.repeat(64),
      targetHolderId: 'return-a', targetSystemId: '4', sourceEpoch: 1, targetEpoch: 2,
      importedSequence: 2, nextSequence: 3,
      redisFenceEpoch: 2, redisNodeId: 'return-a',
    },
    repeatedCycle: {
      forward: {
        bpcCommandId: 'promote-1-cycle-2-promote',
        tskCommandId: 'promote-1-cycle-2-promote',
        enterpriseCommandId: 'promote-1-cycle-2-promote',
        bpcSourceEpoch: 3, bpcTargetEpoch: 4,
        tskSourceEpoch: 2, tskTargetEpoch: 3,
        enterpriseSourceEpoch: 3,
        sourceSystemId: '4', targetSystemId: '5',
        sourceClientId: 'return-target', targetClientId: 'repeat-b',
        staleSourceCompletionDenied: true, idempotentRetry: true,
        rpo: 0, rtoMs: 14,
        artifacts: {
          bpcReadiness: 'd'.repeat(64), tskFinalized: 'f'.repeat(64),
          tskActivation: '0'.repeat(64), enterpriseManifest: '3'.repeat(64),
          enterpriseCredentialReceipt: '4'.repeat(64),
        },
      },
      failback: {
        bpcCommandId: 'promote-1-cycle-2-failback',
        tskCommandId: 'promote-1-cycle-2-failback',
        enterpriseCommandId: 'promote-1-cycle-2-failback',
        bpcSourceEpoch: 4, bpcTargetEpoch: 5,
        tskSourceEpoch: 3, tskTargetEpoch: 4,
        enterpriseSourceEpoch: 4,
        sourceSystemId: '5', targetSystemId: '4',
        sourceClientId: 'repeat-b', targetClientId: 'repeat-a',
        staleSourceCompletionDenied: true, idempotentRetry: true,
        rpo: 0, rtoMs: 15,
        artifacts: {
          bpcReadiness: 'e'.repeat(64), tskFinalized: '1'.repeat(64),
          tskActivation: '2'.repeat(64), enterpriseManifest: '5'.repeat(64),
          enterpriseCredentialReceipt: '6'.repeat(64),
        },
      },
    },
    tskLatestAuthority: {
      commandId: 'promote-1-cycle-2-failback', fenceEpoch: 4,
      nodeId: 'return-a', activationGrantDigest: '2'.repeat(64),
    },
    tskRedisFaults: {
      schemaVersion: 1, kind: 'tsk-same-redis-authority-faults',
      commandId: 'promote-1-cycle-2-failback',
      streamId: 'enterprise28:tsk-live/v1', systemIds: { sourceA: '4', receiverB: '5', control: '6' },
      redisAuthorityKeyDigest: '7'.repeat(64), redisAuthorityTupleDigest: '8'.repeat(64),
      fenceEpoch: 4, authorityNodeId: 'return-a',
      faults: {
        livePartition: { rpo: 0, rtoMs: 10, oldMasterRefusedWrites: true,
          exactTuplePreserved: true, promotedMasterAddressDigest: '9'.repeat(64) },
        masterSigkill: { rpo: 0, rtoMs: 10, exactTuplePreserved: true },
      },
    },
    ultraRedisFaults: {
      schemaVersion: 1, kind: 'ultra-same-redis-authority-faults', commandId: 'promote-1',
      streamId: 'enterprise28:ultra-writer-fence/v1',
      systemIds: { sourceA: '4', promotedB: '5', control: '6' },
      redisAuthorityKeyDigest: 'a'.repeat(64), redisAuthorityTupleDigest: 'b'.repeat(64),
      fenceEpoch: 1,
      faults: {
        livePartition: { rpo: 0, rtoMs: 10, oldMasterRefusedWrites: true,
          exactTuplePreserved: true, promotedMasterAddressDigest: 'c'.repeat(64) },
        masterSigkill: { rpo: 0, rtoMs: 10, exactTuplePreserved: true },
      },
    },
  };
}

test('final plan covers direct authorities, process/network faults, and Enterprise handoff', () => {
  assert.deepEqual(ACCEPTANCE_STEPS.map((step) => step.id), [
    'bpc-authority-ha', 'tsk-credential-authority', 'tsk-process-sigkill',
    'tsk-source-activation', 'enterprise-authenticated-outbox',
  ]);
  assert.equal(new Set(ACCEPTANCE_STEPS.map((step) => step.id)).size, ACCEPTANCE_STEPS.length);
});

test('step evidence fails closed when any required marker is absent', () => {
  const step = { id: 'bounded', markers: ['RPO=0', 'old writer denied'] };
  assert.doesNotThrow(() => assertStepEvidence(step, 'RPO=0\nold writer denied'));
  assert.throws(() => assertStepEvidence(step, 'RPO=0'), /old writer denied/);
  assert.deepEqual(evidenceLines(step, 'noise\nRPO=0\nRTO=12ms\nold writer denied'),
    ['RPO=0', 'RTO=12ms', 'old writer denied']);
  assert.throws(() => evidenceLines(step, 'RPO=0 postgresql://user:secret@db/authority'),
    /secret-like material/);
});

test('portfolio pins must be exact full commit IDs and roots must exist in the plan', () => {
  const lock = { components: {
    'bpc-protocol': { commit: 'a'.repeat(40) },
    'tsk-protocol': { commit: 'b'.repeat(40) },
  } };
  assert.doesNotThrow(() => validatePins(lock, {
    'bpc-protocol': 'C:/bpc', 'tsk-protocol': 'C:/tsk',
  }));
  assert.throws(() => validatePins({ components: {
    ...lock.components, 'tsk-protocol': { commit: 'short' },
  } }, { 'bpc-protocol': 'C:/bpc', 'tsk-protocol': 'C:/tsk' }), /pin is invalid/);
});

test('reviewed Enterprise checkout requires an exact full SHA', async () => {
  await assert.rejects(assertCleanReviewedCheckout('.', 'short'), /full commit SHA/);
});

test('direct handoff evidence is exact, secret-free authority output', () => {
  const evidence = liveEvidence();
  assert.equal(validateLiveCompositionEvidence(evidence), evidence);
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence, outcomes: { ...evidence.outcomes, copiedTargetCredentialRows: 1 },
  }));
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence, systems: { ...evidence.systems,
      enterprise: { source: '4', target: 'wrong' } },
  }));
  for (const tskReturnCommandId of ['', evidence.commandId, 'contains space']) {
    assert.throws(() => validateLiveCompositionEvidence({
      ...evidence,
      outcomes: { ...evidence.outcomes, tskReturnCommandId },
      tskReturnAuthority: { ...evidence.tskReturnAuthority,
        commandId: tskReturnCommandId },
    }));
  }
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence,
    tskReturnAuthority: { ...evidence.tskReturnAuthority,
      finalizedReceiptDigest: 'f'.repeat(64) },
  }));
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence,
    tskReturnAuthority: { ...evidence.tskReturnAuthority,
      targetSystemId: evidence.systems.tsk.receiverB },
  }));
  for (const promotedSourceNextSequence of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateLiveCompositionEvidence({
      ...evidence,
      outcomes: { ...evidence.outcomes, promotedSourceNextSequence },
    }));
  }
  for (const returnedSourceNextSequence of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateLiveCompositionEvidence({
      ...evidence,
      outcomes: { ...evidence.outcomes, returnedSourceNextSequence },
    }));
  }
  for (const key of ['importedSequence', 'nextSequence']) {
    for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => validateLiveCompositionEvidence({
        ...evidence,
        tskReturnAuthority: { ...evidence.tskReturnAuthority, [key]: value },
      }));
    }
  }
  for (const sourceEpoch of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateLiveCompositionEvidence({
      ...evidence,
      tskReturnAuthority: { ...evidence.tskReturnAuthority, sourceEpoch },
    }));
  }
  for (const targetEpoch of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateLiveCompositionEvidence({
      ...evidence,
      tskReturnAuthority: { ...evidence.tskReturnAuthority, targetEpoch },
    }));
  }
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence,
    tskRedisFaults: { ...evidence.tskRedisFaults, fenceEpoch: 3 },
  }));
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence,
    tskRedisFaults: { ...evidence.tskRedisFaults, authorityNodeId: 'wrong-node' },
  }));
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence,
    tskLatestAuthority: { ...evidence.tskLatestAuthority, nodeId: 'wrong-node' },
  }));
  assert.throws(() => validateLiveCompositionEvidence({
    ...evidence,
    artifacts: { ...evidence.artifacts, unboundDigest: 'f'.repeat(64) },
  }));
  for (const cycleName of ['forward', 'failback']) {
    const cycle = evidence.repeatedCycle[cycleName];
    for (const commandField of ['bpcCommandId', 'tskCommandId', 'enterpriseCommandId']) {
      assert.throws(() => validateLiveCompositionEvidence({
        ...evidence,
        repeatedCycle: { ...evidence.repeatedCycle,
          [cycleName]: { ...cycle, [commandField]: `${cycle[commandField]}-wrong` } },
      }));
    }
    for (const artifactField of Object.keys(cycle.artifacts)) {
      assert.throws(() => validateLiveCompositionEvidence({
        ...evidence,
        repeatedCycle: { ...evidence.repeatedCycle,
          [cycleName]: { ...cycle, artifacts: { ...cycle.artifacts,
            [artifactField]: '9'.repeat(64) } } },
      }));
    }
  }
});
