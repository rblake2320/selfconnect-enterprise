import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createRecoveryKeyring,
  issueRecoveryToken,
  verifyRecoveryToken,
} from './recovery-token.js';

const CURRENT = 'current-recovery-secret-that-is-long-enough-for-production';
const PREVIOUS = 'previous-recovery-secret-that-is-also-long-enough';
const claims = {
  agentName: 'recovery-agent',
  agentId: 'SC-1234ABCD',
  newPubHex: 'ab'.repeat(32),
  challengeHash: 'cd'.repeat(32),
};

test('recovery token binds identity, key, challenge, time, and key id', () => {
  const keyring = createRecoveryKeyring(CURRENT);
  const token = issueRecoveryToken(claims, keyring, 1_700_000_000);
  assert.equal(verifyRecoveryToken(token, keyring, {
    nowSec: 1_700_000_030,
    ttlSec: 60,
  }).valid, true);

  for (const [field, value] of [
    ['agentName', 'other-agent'],
    ['agentId', 'SC-00000000'],
    ['newPubHex', 'ef'.repeat(32)],
    ['challengeHash', '01'.repeat(32)],
    ['issuedAt', 1_700_000_001],
    ['kid', '0'.repeat(16)],
  ]) {
    const changed = { ...token, [field]: value };
    assert.equal(verifyRecoveryToken(changed, keyring, {
      nowSec: 1_700_000_030,
      ttlSec: 60,
    }).valid, false, `${field} tampering was accepted`);
  }
});

test('rolling keyring verifies the previous key only during overlap', () => {
  const oldOnly = createRecoveryKeyring(PREVIOUS);
  const oldToken = issueRecoveryToken(claims, oldOnly, 1_700_000_000);
  const overlap = createRecoveryKeyring(CURRENT, PREVIOUS);
  assert.equal(verifyRecoveryToken(oldToken, overlap, {
    nowSec: 1_700_000_010,
    ttlSec: 60,
  }).valid, true);

  const retired = createRecoveryKeyring(CURRENT);
  const result = verifyRecoveryToken(oldToken, retired, {
    nowSec: 1_700_000_010,
    ttlSec: 60,
  });
  assert.equal(result.valid, false);
  assert.equal(result.error, 'unknown key id');
});

test('recovery token rejects expiration, future issuance, and malformed claims', () => {
  const keyring = createRecoveryKeyring(CURRENT);
  const token = issueRecoveryToken(claims, keyring, 1_700_000_000);
  assert.equal(verifyRecoveryToken(token, keyring, {
    nowSec: 1_700_000_061,
    ttlSec: 60,
  }).valid, false);
  assert.equal(verifyRecoveryToken(token, keyring, {
    nowSec: 1_699_999_999,
    ttlSec: 60,
  }).valid, false);
  assert.throws(
    () => issueRecoveryToken({ ...claims, challengeHash: 'deadbeef' }, keyring),
    /challengeHash/,
  );
  assert.throws(() => createRecoveryKeyring(CURRENT, CURRENT), /must be different/);
});
