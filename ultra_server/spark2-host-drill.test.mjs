import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildSpark2Evidence, validateSpark2Result, validateSpark2Topology,
} from './spark2-host-evidence.js';
import { validateAdmissionDocument } from './spark2-host-admission.js';

function admission() {
  return {
    schemaVersion: 1,
    scope: 'separate-physical-host-same-lan',
    identityBasis: 'distinct-ssh-ed25519-host-keys-with-strict-live-observation',
    source: {
      hostname: 'spark-3cdf', address: '192.168.12.132',
      sshHostKey: `ssh-ed25519 ${Buffer.alloc(32, 1).toString('base64')}`,
      machineIdSha256: '1'.repeat(64),
      postgresSystemIds: { source: '10000000001', control: '30000000003' },
    },
    target: {
      hostname: 'spark-3173', address: '10.0.0.2', sshPort: 22,
      sshUser: 'rblake2320',
      sshHostKey: `ssh-ed25519 ${Buffer.alloc(32, 2).toString('base64')}`,
      machineIdSha256: '1'.repeat(64), postgresSystemId: '20000000002',
      postgresContainer: 'selfconnect-spark2-ha-postgres-target-1',
      postgresImageRef: 'postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777',
      postgresImageId: `sha256:${'2'.repeat(64)}/arm64`,
    },
  };
}

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
  const admitted = admission();
  assert.equal(validateAdmissionDocument(admitted), true);
  assert.equal(validateSpark2Result(result, admitted), true);
  const evidence = buildSpark2Evidence(result, {
    admission: admitted, admissionDigest: 'c'.repeat(64),
    commandId: 'spark2-test', durationMs: 123,
    enterpriseCommit: 'a'.repeat(40), tskCommit: 'b'.repeat(40),
  });
  assert.equal(evidence.scope, 'separate-physical-host-same-lan');
  assert.equal(evidence.outcome.dataLossRpo, 0);
  assert.equal(evidence.commits.enterprise, 'a'.repeat(40));
  assert.equal(evidence.hostAdmissionDigest, 'c'.repeat(64));
  assert.equal(evidence.topology.sourceHost, 'spark-3cdf');
  assert.equal(evidence.topology.targetHost, 'spark-3173');
  assert.equal(evidence.topology.machineIdDistinct, false);
  assert.deepEqual(evidence.exclusions,
    ['separate-site', 'independent-power-domain', 'independent-network-domain']);
});

test('rejects an unexpected target cluster or reused authority', () => {
  const result = fixture();
  const admitted = admission();
  admitted.target.postgresSystemId = '40000000004';
  assert.throws(() => validateSpark2Result(result, admitted), /admitted/);
  admitted.target.postgresSystemId = result.systemIds.receiverB;
  result.systemIds.control = result.systemIds.sourceA;
  assert.throws(() => validateSpark2Result(result, admitted), /independent/);
});

test('rejects an admission with reused host identity or cluster identity', () => {
  const reusedHost = admission();
  reusedHost.target.sshHostKey = reusedHost.source.sshHostKey;
  assert.throws(() => validateAdmissionDocument(reusedHost), /distinct/);
  const reusedCluster = admission();
  reusedCluster.target.postgresSystemId = reusedCluster.source.postgresSystemIds.source;
  assert.throws(() => validateAdmissionDocument(reusedCluster));
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
