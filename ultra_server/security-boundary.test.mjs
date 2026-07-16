import assert from 'node:assert/strict';
import test from 'node:test';

import { enforceBpcAuthorization } from './security-boundary.js';

test('shadow and ghost decisions cannot authorize an Ultra action', () => {
  for (const result of [
    { ok: true, pairId: 'pair-shadow', shadow: true },
    { ok: true, pairId: 'pair-ghost', shadow: true, ghostAlert: true },
  ]) {
    const enforced = enforceBpcAuthorization(result);
    assert.equal(enforced.ok, false);
    assert.equal(enforced.error, 'shadow_denied');
    assert.equal(enforced.pairId, result.pairId);
  }
});

test('ordinary BPC pass and failure retain their exact decision', () => {
  const pass = { ok: true, pairId: 'pair-valid', pair: { scope: 'read-write' } };
  const failure = { ok: false, error: 'invalid_signature' };
  assert.equal(enforceBpcAuthorization(pass), pass);
  assert.equal(enforceBpcAuthorization(failure), failure);
  assert.deepEqual(enforceBpcAuthorization(null), { ok: false, error: 'invalid_result' });
});
