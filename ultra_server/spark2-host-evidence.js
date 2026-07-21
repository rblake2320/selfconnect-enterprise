import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const SYSTEM_ID = /^[0-9]{10,24}$/;

function digest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export function validateSpark2Result(result, expectedTargetSystemId) {
  if (!SYSTEM_ID.test(expectedTargetSystemId)) {
    throw new Error('SPARK2_EXPECTED_SYSTEM_ID is invalid');
  }
  assert.equal(new Set(Object.values(result.systemIds)).size, 3,
    'source, target, and control PostgreSQL clusters must be independent');
  assert.equal(result.systemIds.receiverB, expectedTargetSystemId,
    'the receiver did not run on the admitted Spark-2 PostgreSQL cluster');
  assert.equal(result.staleWriterDenied, true);
  assert.equal(result.staleTargetWriterDenied, true);
  assert.equal(result.nextSequence, result.n + 1);
  assert.equal(result.returnSequence, result.n + 2);
  assert.equal(result.returnFinalizedReceipt.bSystemId, result.systemIds.sourceA);
  assert.equal(result.redisAuthority.record.active, true);
  assert.equal(result.redisAuthority.record.nodeId,
    result.returnActivationLeaseGrant.holderNodeId);
  return true;
}

export function buildSpark2Evidence(result, {
  commandId, durationMs, enterpriseCommit, tskCommit,
}) {
  validateSpark2Result(result, result.systemIds.receiverB);
  return Object.freeze({
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    scope: 'separate-physical-host-same-lan',
    exclusions: Object.freeze([
      'separate-site',
      'independent-power-domain',
      'independent-network-domain',
    ]),
    commits: Object.freeze({ enterprise: enterpriseCommit, tsk: tskCommit }),
    commandId,
    topology: Object.freeze({
      sourceHost: 'spark-3cdf',
      controlHost: 'spark-3cdf',
      targetHost: 'spark-3173',
      postgresSystemIds: result.systemIds,
    }),
    outcome: Object.freeze({
      dataLossRpo: 0,
      durationMs,
      initialSequence: result.n,
      promotedSequence: result.nextSequence,
      returnedSequence: result.returnSequence,
      staleSourceWriterDenied: result.staleWriterDenied,
      staleTargetWriterDenied: result.staleTargetWriterDenied,
      returnReceiptDigest: digest(result.returnFinalizedReceipt),
      returnLeaseDigest: result.returnActivationLeaseGrant.grantDigest,
      redisAuthorityDigest: digest(result.redisAuthority.record),
    }),
  });
}
