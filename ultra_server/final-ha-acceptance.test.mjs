import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ACCEPTANCE_STEPS, assertCleanReviewedCheckout, assertStepEvidence, evidenceLines, validatePins,
} from './final-ha-acceptance.mjs';

test('final plan covers direct authorities, process/network faults, and Enterprise handoff', () => {
  assert.deepEqual(ACCEPTANCE_STEPS.map((step) => step.id), [
    'bpc-authority-ha', 'tsk-credential-authority', 'tsk-process-sigkill',
    'tsk-source-activation', 'enterprise-independent-failover-failback',
    'enterprise-authenticated-outbox', 'tsk-redis-sentinel-crash',
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
