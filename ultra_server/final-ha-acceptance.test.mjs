import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ACCEPTANCE_STEPS, assertCleanReviewedCheckout, assertStepEvidence, evidenceLines, validatePins,
} from './final-ha-acceptance.mjs';
import { validateLiveCompositionEvidence } from './live-composition-evidence.mjs';

function liveEvidence() {
  return {
    schemaVersion: 1, kind: 'enterprise-live-authority-handoff', commandId: 'promote-1',
    commits: { enterprise: 'a'.repeat(40), bpc: 'b'.repeat(40), tsk: 'c'.repeat(40) },
    systems: {
      bpc: { sourceA: '1', promotedB: '2', control: '3' },
      tsk: { sourceA: '4', receiverB: '5', control: '6' },
      enterprise: { source: '4', target: '5' },
    },
    artifacts: {
      bpcPromotion: '1'.repeat(64), tskFinalized: '2'.repeat(64),
      tskActivation: '3'.repeat(64), enterpriseManifest: '4'.repeat(64),
      promotedCredentialProof: '5'.repeat(64), promotedCredentialReceipt: '6'.repeat(64),
    },
    outcomes: {
      bpcStaleWriterDenied: true, tskStaleWriterDenied: true,
      tskStaleCredentialWriterDenied: true, promotedSourceNextSequence: 2,
      enterpriseTargetClientId: 'target', copiedTargetCredentialRows: 0,
      redactionPreserved: true, dataLossRpo: 0,
    },
  };
}

test('final plan covers direct authorities, process/network faults, and Enterprise handoff', () => {
  assert.deepEqual(ACCEPTANCE_STEPS.map((step) => step.id), [
    'bpc-authority-ha', 'tsk-credential-authority', 'tsk-process-sigkill',
    'tsk-source-activation', 'enterprise-authenticated-outbox', 'tsk-redis-sentinel-crash',
    'tsk-live-redis-partition',
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
});
