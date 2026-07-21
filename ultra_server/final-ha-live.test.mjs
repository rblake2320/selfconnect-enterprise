import assert from 'node:assert/strict';
import test from 'node:test';

import { runLiveProtocolComposition, validateLiveProtocolComposition } from './final-ha-live.mjs';

test('live composition requires exact command binding, independent systems, and stale denial', () => {
  const commandId = 'promote-live-1';
  const bpc = {
    readinessAttestation: { commandId }, staleWriterDenied: true,
    systemIds: { sourceA: '1', promotedB: '2', control: '3' },
  };
  const tsk = {
    bFinalizedReceipt: { commandId }, activationLeaseGrant: { commandId },
    staleWriterDenied: true, n: 4, nextSequence: 5,
    staleCredentialWriterDenied: true,
    publicCredential: { status: 'active', publicMapDigest: 'a'.repeat(64) },
    publicCredentialSource: { clientId: 'source-client', publicMapDigest: 'b'.repeat(64) },
    publicCredentialTarget: { clientId: 'target-client', publicMapDigest: 'a'.repeat(64) },
    credentialSourceRevocation: { commandId },
    credentialActivationLeaseGrant: { commandId },
    systemIds: { sourceA: '4', receiverB: '5', control: '6' },
  };
  assert.equal(validateLiveProtocolComposition(bpc, tsk, commandId), true);
  assert.throws(() => validateLiveProtocolComposition(
    bpc, { ...tsk, staleWriterDenied: false }, commandId,
  ));
  assert.throws(() => validateLiveProtocolComposition(
    bpc, { ...tsk, systemIds: { sourceA: '4', receiverB: '2', control: '6' } }, commandId,
  ));
});

test('directly composes exact reviewed live BPC and TSK artifacts', {
  skip: process.env.LIVE_COMPOSITION_COMBINED !== '1',
  timeout: 180_000,
}, async () => {
  const result = await runLiveProtocolComposition();
  assert.equal(result.bpc.readinessAttestation.commandId, result.commandId);
  assert.equal(result.tsk.bFinalizedReceipt.commandId, result.commandId);
  assert.equal(result.tsk.activationLeaseGrant.commandId, result.commandId);
  assert.equal(result.bpc.staleWriterDenied, true);
  assert.equal(result.tsk.staleWriterDenied, true);
});
