import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createCleanupTransfer,
  runExhaustiveCleanup,
} from './post-heal-probe-lifecycle.mjs';

test('cleanup ownership stays local when lifecycle registration fails', () => {
  const ownership = createCleanupTransfer();
  assert.throws(() => ownership.transfer(() => {
    throw new Error('fault before lifecycle registration');
  }), /fault before lifecycle registration/);
  assert.equal(ownership.transferred, false);
  ownership.transfer(() => {});
  assert.equal(ownership.transferred, true);
  assert.throws(() => ownership.transfer(() => {}), /already transferred/);
});

test('cleanup attempts every database and aggregates drop failures', async () => {
  const attempted = [];
  await assert.rejects(() => runExhaustiveCleanup([
    () => { attempted.push('first'); throw new Error('first drop failed synchronously'); },
    async () => { attempted.push('second'); },
    async () => { attempted.push('third'); throw new Error('third drop failed'); },
  ], 'retained authority cleanup failed'), (error) => {
    assert.equal(error instanceof AggregateError, true);
    assert.equal(error.errors.length, 2);
    assert.match(error.message, /retained authority cleanup failed/);
    return true;
  });
  assert.deepEqual(attempted, ['first', 'second', 'third']);
});
