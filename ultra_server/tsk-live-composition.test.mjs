import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadPinnedTskModule, runTskLiveComposition } from './tsk-live-composition.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TSK_ROOT = resolve(HERE, '..', '..', 'tsk-protocol');
const TSK_COMMIT = 'abcd7cb5aaf71dc8400891dc7a3efafcb028758b';

test('loads the reviewed TSK distribution by explicit root', async () => {
  const tsk = await loadPinnedTskModule(TSK_ROOT);
  assert.equal(typeof tsk.HaControlFencing, 'function');
  assert.equal(typeof tsk.PgTskDurableOutbox, 'function');
  assert.equal(typeof tsk.stageAndFinalizeReceiverGeneration, 'function');
});

test('refuses to reset databases without the explicit destructive acceptance guard', async () => {
  await assert.rejects(() => runTskLiveComposition({
    tskRoot: TSK_ROOT,
    aPostgresUrl: 'postgres://unused/a',
    bPostgresUrl: 'postgres://unused/b',
    controlPostgresUrl: 'postgres://unused/control',
    redisUrl: 'redis://unused',
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
    redisUrl: 'redis://unused',
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
    redisUrl: process.env.TSK_LIVE_COMPOSITION_REDIS_URL,
    streamId: 'enterprise28:tsk-live/v1',
    commandId: 'enterprise28-promote-1',
    expectedTskCommit: TSK_COMMIT,
    destructiveReset: true,
  });
  assert.equal(result.staleWriterDenied, true);
  assert.equal(result.nextSequence, result.n + 1);
  assert.equal(new Set(Object.values(result.systemIds)).size, 3);
  assert.equal(result.sourceFrozenReceipt.n, result.n);
  assert.equal(result.bFinalizedReceipt.n, result.n);
  assert.equal(result.activationLeaseGrant.leaseEpoch, 1);
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
  assert.equal(result.credentialActivationLeaseGrant.leaseEpoch, 1);
  assert.equal(result.credentialSourceLeaseGrant.leaseEpoch, 0);
  assert.equal(result.credentialSourceRevocation.leaseStatus, 'revoked');
  assert.match(result.publicCredentialTarget.publicMapDigest, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(result).includes('PRIVATE KEY'), false);
  assert.match(result.publicKeys.credentialHead, /BEGIN PUBLIC KEY/);
  assert.match(result.publicKeys.sourceCredentialHead, /BEGIN PUBLIC KEY/);
  assert.match(
    result.publicVerificationKeys['credential-head-b-live-1'],
    /BEGIN PUBLIC KEY/,
  );
});
