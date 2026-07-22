import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { loadPinnedBpcModule, runBpcLiveComposition } from './bpc-live-composition.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const BPC_ROOT = resolve(HERE, '..', '..', 'bpc-protocol');
const REVIEWED_BPC = 'aedf67b89574066e1df0575e68fdb58ea0dc9297';

test('BPC live composition loads only the exact reviewed checkout', () => {
  const loaded = loadPinnedBpcModule(BPC_ROOT, REVIEWED_BPC);
  assert.equal(loaded.actualCommit, REVIEWED_BPC);
  assert.match(loaded.moduleUrl, /packages\/server\/dist\/index\.js$/);
  assert.throws(() => loadPinnedBpcModule(BPC_ROOT, '0'.repeat(40)), /checkout mismatch/);
});

test('executes governed BPC A to B promotion and B to A failback', {
  skip: !process.env.BPC_LIVE_COMPOSITION_A_URL || process.env.LIVE_COMPOSITION_COMBINED === '1',
}, async () => {
  const result = await runBpcLiveComposition({
    bpcRoot: BPC_ROOT,
    expectedBpcCommit: REVIEWED_BPC,
    commandId: 'enterprise28-promote-1',
    postgresUrls: [
      process.env.BPC_LIVE_COMPOSITION_A_URL,
      process.env.BPC_LIVE_COMPOSITION_B_URL,
      process.env.BPC_LIVE_COMPOSITION_CONTROL_URL,
    ],
    redisUrls: process.env.BPC_LIVE_COMPOSITION_REDIS_URLS.split(','),
    streamId: 'bpc:enterprise:live/v1',
  });
  assert.equal(result.staleWriterDenied, true);
  assert.equal(result.finalSequence, 1);
  assert.equal(result.promotedEpochSequence, 2);
  assert.equal(new Set(Object.values(result.systemIds)).size, 3);
  assert.equal(result.readinessAttestation.commandId, 'enterprise28-promote-1');
  assert.equal(result.failback.commandId, 'enterprise28-promote-1-failback');
  assert.equal(result.failback.targetEpoch, 3);
  assert.equal(result.failback.targetSystemId, result.systemIds.sourceA);
  assert.equal(result.failback.sourcePostgresSystemReused, true);
  assert.equal(result.failback.priorAuthoritiesReset, false);
  assert.equal(result.failback.staleBWriterDenied, true);
  assert.equal(result.failback.importedSequence, 2);
  assert.equal(result.failback.originatedSequence, 3);
  assert.equal(result.repeatedCycle.principalId, 'enterprise-pair-1');
  assert.equal(result.repeatedCycle.forward.sourceEpoch, 3);
  assert.equal(result.repeatedCycle.forward.targetEpoch, 4);
  assert.equal(result.repeatedCycle.forward.sourceSystemId, result.systemIds.sourceA);
  assert.equal(result.repeatedCycle.forward.targetSystemId, result.systemIds.promotedB);
  assert.equal(result.repeatedCycle.forward.originatedSequence, 5);
  assert.equal(result.repeatedCycle.forward.staleSourceWriterDenied, true);
  assert.equal(result.repeatedCycle.failback.sourceEpoch, 4);
  assert.equal(result.repeatedCycle.failback.targetEpoch, 5);
  assert.equal(result.repeatedCycle.failback.sourceSystemId, result.systemIds.promotedB);
  assert.equal(result.repeatedCycle.failback.targetSystemId, result.systemIds.sourceA);
  assert.equal(result.repeatedCycle.failback.originatedSequence, 7);
  assert.equal(result.repeatedCycle.failback.staleSourceWriterDenied, true);
  assert.equal(result.repeatedCycle.priorAuthoritiesReset, false);
  assert.equal(result.repeatedCycle.rpo, 0);
  assert.equal(Number.isSafeInteger(result.repeatedCycle.rtoMs) &&
    result.repeatedCycle.rtoMs >= 0, true);
  assert.equal(result.recoveredSite.sourceEpoch, 5);
  assert.equal(result.recoveredSite.targetEpoch, 6);
  assert.equal(result.recoveredSite.targetSystemId, result.systemIds.promotedB);
  assert.equal(result.recoveredSite.staleDatabaseReused, true);
  assert.equal(result.recoveredSite.importedSequence, 7);
  assert.equal(result.recoveredSite.firstMutationSequence, 1);
  assert.equal(result.recoveredSite.staleSourceWriterDenied, true);
  assert.equal(result.recoveredSite.rpo, 0);
  assert.equal(Number.isSafeInteger(result.recoveredSite.rtoMs) &&
    result.recoveredSite.rtoMs >= 0, true);
  assert.deepEqual(Object.keys(result.restartDenials).sort(),
    ['failback', 'initial', 'recoveredSite', 'repeatFailback', 'repeatForward']);
  assert.equal(new Set(Object.values(result.restartDenials)
    .map((probe) => probe.childPid)).size, 5);
  for (const probe of Object.values(result.restartDenials)) {
    assert.equal(probe.processRestarted, true);
    assert.equal(probe.denied, true);
  }
});
