import assert from 'node:assert/strict';
import test from 'node:test';

import { parseUltraStateAuthorityDescriptor } from './ultra-state-authority-config.js';

const valid = {
  streamId: 'ultra:site-b', sourceEpoch: 2, holderNodeId: 'site-b',
  leaseId: 'lease-b-2', grantDigest: 'a'.repeat(64), controlToASkewBoundMs: 5_000,
  sourceLeasePublicKeyFiles: { 'guard-1': 'C:/secure/guard-1.pub' },
};

test('independent authority descriptor is exact, bounded, and immutable', () => {
  const parsed = parseUltraStateAuthorityDescriptor(valid);
  assert.equal(parsed.streamId, valid.streamId);
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.sourceLeasePublicKeyFiles), true);
  assert.throws(() => parseUltraStateAuthorityDescriptor({ ...valid, extra: true }), /invalid shape/);
  assert.throws(() => parseUltraStateAuthorityDescriptor({ ...valid, sourceEpoch: -1 }), /sourceEpoch/);
  assert.throws(() => parseUltraStateAuthorityDescriptor({ ...valid,
    sourceLeasePublicKeyFiles: {} }), /non-empty key map/);
});
