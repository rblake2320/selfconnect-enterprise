import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildSpark2Evidence, validateSpark2Result, validateSpark2Topology,
} from './spark2-host-evidence.js';

function fixture() {
  return {
    systemIds: { sourceA: '10000000001', receiverB: '20000000002', control: '30000000003' },
    staleWriterDenied: true,
    staleTargetWriterDenied: true,
    n: 4,
    nextSequence: 5,
    returnSequence: 6,
    returnFinalizedReceipt: { bSystemId: '10000000001', value: 'receipt' },
    returnActivationLeaseGrant: { holderNodeId: 'source-a', grantDigest: 'a'.repeat(64) },
    redisAuthority: { record: { active: true, nodeId: 'source-a' } },
  };
}

test('accepts an exact three-cluster Spark-2 return handoff', () => {
  const result = fixture();
  assert.equal(validateSpark2Result(result, result.systemIds.receiverB), true);
  const evidence = buildSpark2Evidence(result, {
    commandId: 'spark2-test', durationMs: 123,
    enterpriseCommit: 'a'.repeat(40), tskCommit: 'b'.repeat(40),
  });
  assert.equal(evidence.scope, 'separate-physical-host-same-lan');
  assert.equal(evidence.outcome.dataLossRpo, 0);
  assert.equal(evidence.commits.enterprise, 'a'.repeat(40));
  assert.deepEqual(evidence.exclusions,
    ['separate-site', 'independent-power-domain', 'independent-network-domain']);
});

test('rejects an unexpected target cluster or reused authority', () => {
  const result = fixture();
  assert.throws(() => validateSpark2Result(result, '40000000004'), /Spark-2/);
  result.systemIds.control = result.systemIds.sourceA;
  assert.throws(() => validateSpark2Result(result, result.systemIds.receiverB), /independent/);
});

test('binds the claim to the admitted private inter-host endpoints', () => {
  const topology = {
    source: 'postgresql://user:secret@192.168.12.132:5541/db',
    control: 'postgresql://user:secret@192.168.12.132:5542/db',
    target: 'postgresql://user:secret@10.0.0.2:5543/db',
    redis: 'redis://:secret@192.168.12.132:6391/0',
  };
  assert.equal(validateSpark2Topology(topology), true);
  assert.throws(() => validateSpark2Topology({ ...topology,
    target: 'postgresql://user:secret@127.0.0.1:5543/db' }), /admitted/);
  assert.throws(() => validateSpark2Topology({ ...topology,
    redis: 'redis://:secret@10.0.0.2:6395/0' }), /admitted/);
});
