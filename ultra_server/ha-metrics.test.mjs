import assert from 'node:assert/strict';
import test from 'node:test';

import {
  HA_PROMOTION_DENIAL_LABEL_LIMIT,
  HA_RECOVERY_FAILURE_STAGE_LABEL_LIMIT,
  haPromotionDenialLabel,
  haRecoveryFailureStageLabel,
  isHaCommandDenied,
} from './ha-metrics.js';

test('known promotion-denial reasons keep their exact label', () => {
  for (const reason of [
    'fence_epoch_not_monotonic',
    'fencing_authority_unavailable',
    'lease_mismatch',
    'command_stale',
    'wrong_command_for_role',
    'signature_invalid',
  ]) {
    assert.equal(haPromotionDenialLabel(reason), reason);
  }
});

test('unknown or hostile promotion-denial reasons collapse to __other__', () => {
  for (const reason of [
    'made_up_reason',
    '',
    null,
    undefined,
    'a'.repeat(10_000),
    { toString: () => 'fence_epoch_not_monotonic' },
  ]) {
    assert.equal(haPromotionDenialLabel(reason), '__other__');
  }
});

test('known recovery-failure stages keep their exact label', () => {
  for (const stage of ['tsk_reprovision', 'tsk_authority_reload', 'sighup_reload']) {
    assert.equal(haRecoveryFailureStageLabel(stage), stage);
  }
});

test('unknown recovery-failure stages collapse to __other__', () => {
  assert.equal(haRecoveryFailureStageLabel('unexpected_stage'), '__other__');
  assert.equal(haRecoveryFailureStageLabel(''), '__other__');
  assert.equal(haRecoveryFailureStageLabel(undefined), '__other__');
});

test('label limits are small, bounded constants', () => {
  assert.ok(HA_PROMOTION_DENIAL_LABEL_LIMIT > 0 && HA_PROMOTION_DENIAL_LABEL_LIMIT < 32);
  assert.ok(HA_RECOVERY_FAILURE_STAGE_LABEL_LIMIT > 0 && HA_RECOVERY_FAILURE_STAGE_LABEL_LIMIT < 8);
});

test('isHaCommandDenied is true for any non-200 status and false for 200', () => {
  assert.equal(isHaCommandDenied(200), false);
  assert.equal(isHaCommandDenied(400), true);
  assert.equal(isHaCommandDenied(401), true);
  assert.equal(isHaCommandDenied(409), true);
  assert.equal(isHaCommandDenied(503), true);
  assert.equal(isHaCommandDenied(undefined), false);
  assert.equal(isHaCommandDenied('200'), false);
});
