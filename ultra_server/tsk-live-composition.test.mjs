import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadPinnedTskModule, runTskLiveComposition } from './tsk-live-composition.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TSK_ROOT = resolve(HERE, '..', '..', 'tsk-protocol');
const TSK_COMMIT = '20bf099e0b4f7479b93cf1d5e245b3f7c87e1675';

test('loads the reviewed TSK distribution by explicit root', async () => {
  const tsk = await loadPinnedTskModule(TSK_ROOT);
  assert.equal(typeof tsk.HaControlFencing, 'function');
  assert.equal(typeof tsk.PgTskDurableOutbox, 'function');
  assert.equal(typeof tsk.stageAndFinalizeReceiverGeneration, 'function');
  assert.equal(typeof tsk.activateFinalizedReceiverAsSource, 'function');
});

test('refuses to reset databases without the explicit destructive acceptance guard', async () => {
  await assert.rejects(() => runTskLiveComposition({
    tskRoot: TSK_ROOT,
    aPostgresUrl: 'postgres://unused/a',
    bPostgresUrl: 'postgres://unused/b',
    controlPostgresUrl: 'postgres://unused/control',
    redis: { kind: 'url', url: 'redis://unused' },
    preserveRedisAuthority: false,
    streamId: 'enterprise28:test',
    commandId: 'enterprise28-promote-1',
    expectedTskCommit: TSK_COMMIT,
    destructiveReset: false,
  }), /destructiveReset=true/);
});

test('refuses a TSK checkout that does not match the reviewed full commit', async () => {
  await assert.rejects(() => runTskLiveComposition({
    tskRoot: TSK_ROOT,
    aPostgresUrl: 'postgres://unused/a',
    bPostgresUrl: 'postgres://unused/b',
    controlPostgresUrl: 'postgres://unused/control',
    redis: { kind: 'url', url: 'redis://unused' },
    preserveRedisAuthority: false,
    streamId: 'enterprise28:test',
    commandId: 'enterprise28-promote-1',
    expectedTskCommit: '0'.repeat(40),
    destructiveReset: true,
  }), /TSK checkout mismatch/);
});

test('executes the full live lifecycle when dedicated acceptance authorities are provided', {
  skip: !process.env.TSK_LIVE_COMPOSITION_A_URL || process.env.LIVE_COMPOSITION_COMBINED === '1',
}, async () => {
  const result = await runTskLiveComposition({
    tskRoot: TSK_ROOT,
    aPostgresUrl: process.env.TSK_LIVE_COMPOSITION_A_URL,
    bPostgresUrl: process.env.TSK_LIVE_COMPOSITION_B_URL,
    controlPostgresUrl: process.env.TSK_LIVE_COMPOSITION_CONTROL_URL,
    redis: { kind: 'url', url: process.env.TSK_LIVE_COMPOSITION_REDIS_URL },
    preserveRedisAuthority: false,
    streamId: 'enterprise28:tsk-live/v1',
    commandId: 'enterprise28-promote-1',
    expectedTskCommit: TSK_COMMIT,
    destructiveReset: true,
  });
  assert.equal(result.staleWriterDenied, true);
  assert.equal(result.staleTargetWriterDenied, true);
  assert.equal(result.nextSequence, result.n + 1);
  assert.equal(result.returnSequence, result.n + 2);
  assert.equal(new Set(Object.values(result.systemIds)).size, 3);
  assert.equal(result.sourceFrozenReceipt.n, result.n);
  assert.equal(result.bFinalizedReceipt.n, result.n);
  assert.equal(result.activationLeaseGrant.leaseEpoch, 1);
  assert.equal(result.bSourceActivation.n, result.n);
  assert.equal(result.bSourceActivation.headDigest,
    result.bFinalizedReceipt.signedHeadDigestAtN);
  assert.equal(result.bSourceActivation.activationGrantDigest,
    result.activationLeaseGrant.grantDigest);
  assert.equal(result.returnFrozenReceipt.n, result.n + 1);
  assert.equal(result.returnFinalizedReceipt.n, result.n + 1);
  assert.equal(result.returnActivationLeaseGrant.leaseEpoch, 2);
  assert.equal(result.returnActivationLeaseGrant.commandId, result.returnCommandId);
  assert.equal(result.returnActivationLeaseGrant.leaseGrantSeq, 3);
  assert.equal(result.returnSourceActivation.n, result.n + 1);
  assert.equal(result.returnSourceActivation.headDigest,
    result.returnFinalizedReceipt.signedHeadDigestAtN);
  assert.equal(result.returnSourceActivation.activationGrantDigest,
    result.returnActivationLeaseGrant.grantDigest);
  assert.equal(result.repeatedCycle.forward.sourceEpoch, 2);
  assert.equal(result.repeatedCycle.forward.targetEpoch, 3);
  assert.equal(result.repeatedCycle.forward.append.head.sequence, result.n + 3);
  assert.equal(result.repeatedCycle.forward.staleWriterDenied, true);
  assert.equal(result.repeatedCycle.failback.sourceEpoch, 3);
  assert.equal(result.repeatedCycle.failback.targetEpoch, 4);
  assert.equal(result.repeatedCycle.failback.append.head.sequence, result.n + 4);
  assert.equal(result.repeatedCycle.failback.staleWriterDenied, true);
  assert.equal(result.recoveredSite.handoff.sourceEpoch, 4);
  assert.equal(result.recoveredSite.handoff.targetEpoch, 5);
  assert.equal(result.recoveredSite.handoff.targetNodeId, 'node-b');
  assert.equal(result.recoveredSite.handoff.append.head.sequence, result.n + 5);
  assert.equal(result.recoveredSite.handoff.staleWriterDenied, true);
  assert.equal(result.recoveredSite.staleCredentialDenied, true);
  assert.equal(result.recoveredSite.credential.leaseGrant.leaseEpoch, 5);
  assert.equal(result.recoveredSite.credential.publicCredential.status, 'active');
  assert.equal(result.tskCommit, TSK_COMMIT);
  assert.equal(result.publicCredentialSource.status, 'active');
  assert.equal(result.publicCredentialTarget.status, 'active');
  assert.equal(result.publicCredentialSource.sequence, 1);
  assert.equal(result.publicCredentialTarget.sequence, 1);
  assert.equal(result.publicCredentialSource.fenceEpoch, 0);
  assert.equal(result.publicCredentialTarget.fenceEpoch, 1);
  assert.notEqual(
    result.publicCredentialSource.clientId,
    result.publicCredentialTarget.clientId,
  );
  assert.notEqual(
    result.publicCredentialSource.publicMapDigest,
    result.publicCredentialTarget.publicMapDigest,
  );
  assert.equal(result.staleCredentialWriterDenied, true);
  assert.equal(result.staleReturnedCredentialWriterDenied, true);
  assert.equal(result.credentialActivationLeaseGrant.leaseEpoch, 1);
  assert.equal(result.credentialSourceLeaseGrant.leaseEpoch, 0);
  assert.equal(result.credentialSourceRevocation.leaseStatus, 'revoked');
  assert.equal(result.targetCredentialRevocation.leaseStatus, 'revoked');
  assert.equal(result.targetCredentialRevocation.commandId, result.returnCommandId);
  assert.equal(result.returnCredentialActivationLeaseGrant.leaseEpoch, 2);
  assert.equal(result.returnCredentialActivationLeaseGrant.commandId,
    result.returnCommandId);
  assert.equal(result.returnCredentialRevocation.leaseStatus, 'revoked');
  assert.equal(result.returnCredentialRevocation.commandId,
    result.repeatedCycle.forward.commandId);
  assert.equal(result.repeatForwardCredential.leaseGrant.leaseEpoch, 3);
  assert.equal(result.repeatForwardCredential.publicCredential.status, 'active');
  assert.equal(result.repeatForwardCredentialRevocation.leaseStatus, 'revoked');
  assert.equal(result.repeatReturnCredential.leaseGrant.leaseEpoch, 4);
  assert.equal(result.repeatReturnCredential.publicCredential.status, 'active');
  assert.equal(result.staleRepeatForwardCredentialDenied, true);
  assert.equal(result.staleRepeatReturnCredentialDenied, true);
  assert.equal(result.publicCredentialReturn.status, 'active');
  assert.notEqual(result.publicCredentialReturn.clientId,
    result.publicCredentialTarget.clientId);
  assert.notEqual(result.publicCredentialReturn.secretDigest,
    result.publicCredentialTarget.secretDigest);
  assert.match(result.publicCredentialTarget.publicMapDigest, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(result).includes('PRIVATE KEY'), false);
  assert.match(result.publicKeys.credentialHead, /BEGIN PUBLIC KEY/);
  assert.match(result.publicKeys.sourceCredentialHead, /BEGIN PUBLIC KEY/);
  assert.match(result.publicKeys.returnCredentialHead, /BEGIN PUBLIC KEY/);
  assert.match(
    result.publicVerificationKeys['credential-head-b-live-1'],
    /BEGIN PUBLIC KEY/,
  );
});
