import assert from 'node:assert/strict';
import test from 'node:test';

import {
  runLiveEnterpriseAcceptance,
  validateLiveProtocolComposition,
} from './final-ha-live.mjs';
import { writeEnterpriseFaultEvidence } from './enterprise-fault-evidence.mjs';
import { writeLiveCompositionEvidence } from './live-composition-evidence.mjs';

test('live composition requires exact command binding, independent systems, and stale denial', () => {
  const commandId = 'promote-live-1';
  const bpc = {
    readinessAttestation: { commandId, targetEpoch: 2 }, staleWriterDenied: true,
    failback: { targetSystemId: '1', targetEpoch: 3, staleBWriterDenied: true,
      priorAuthoritiesReset: false, sourcePostgresSystemReused: true },
    repeatedCycle: {
      forward: { targetEpoch: 4 },
      failback: { targetEpoch: 5 },
    },
    systemIds: { sourceA: '1', promotedB: '2', control: '3' },
  };
  const tsk = {
    bFinalizedReceipt: { commandId }, activationLeaseGrant: { commandId },
    staleWriterDenied: true, n: 4, nextSequence: 5,
    staleTargetWriterDenied: true, returnSequence: 6,
    returnFrozenReceipt: { n: 5 },
    returnCommandId: 'return-promote-live-1',
    returnFinalizedReceipt: { n: 5, epoch: 1, bKeyId: 'return-a', bSystemId: '4',
      commandId: 'return-promote-live-1' },
    returnActivationLeaseGrant: { leaseEpoch: 2, commandId: 'return-promote-live-1',
      holderNodeId: 'return-a', grantDigest: 'c'.repeat(64) },
    returnSourceActivation: { n: 5, activationGrantDigest: 'c'.repeat(64) },
    redisAuthority: { record: { commandId: 'promote-live-1-cycle-2-failback', fenceEpoch: 4,
      nodeId: 'return-a', active: true } },
    staleCredentialWriterDenied: true,
    staleReturnedCredentialWriterDenied: true,
    publicCredential: { status: 'active', publicMapDigest: 'a'.repeat(64) },
    publicCredentialSource: { clientId: 'source-client', publicMapDigest: 'b'.repeat(64) },
    publicCredentialTarget: { clientId: 'target-client', publicMapDigest: 'a'.repeat(64) },
    publicCredentialReturn: { clientId: 'return-client', publicMapDigest: 'd'.repeat(64),
      secretDigest: 'e'.repeat(64) },
    targetCredentialProof: {
      commandId,
      record: { mutation: { clientId: 'target-client' } },
    },
    credentialSourceRevocation: { commandId },
    credentialActivationLeaseGrant: { commandId },
    targetCredentialRevocation: { commandId: 'return-promote-live-1',
      leaseStatus: 'revoked' },
    returnCredentialActivationLeaseGrant: { commandId: 'return-promote-live-1',
      leaseEpoch: 2 },
    returnCredentialProof: { commandId: 'return-promote-live-1',
      record: { mutation: { clientId: 'return-client' } } },
    repeatedCycle: {
      forward: { sourceEpoch: 2, targetEpoch: 3, staleWriterDenied: true,
        commandId: 'promote-live-1-cycle-2-promote' },
      failback: { sourceEpoch: 3, targetEpoch: 4, staleWriterDenied: true,
        commandId: 'promote-live-1-cycle-2-failback',
        activationLease: { leaseEpoch: 4, holderNodeId: 'return-a' } },
    },
    repeatForwardCredential: {
      leaseGrant: { leaseEpoch: 3 },
      proof: { commandId: 'promote-live-1-cycle-2-promote' },
    },
    repeatReturnCredential: {
      leaseGrant: { leaseEpoch: 4 },
      proof: { commandId: 'promote-live-1-cycle-2-failback' },
    },
    staleRepeatForwardCredentialDenied: true,
    staleRepeatReturnCredentialDenied: true,
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
  timeout: 600_000,
}, async () => {
  const result = await runLiveEnterpriseAcceptance();
  assert.equal(result.bpc.readinessAttestation.commandId, result.commandId);
  assert.equal(result.tsk.bFinalizedReceipt.commandId, result.commandId);
  assert.equal(result.tsk.activationLeaseGrant.commandId, result.commandId);
  assert.equal(result.bpc.staleWriterDenied, true);
  assert.equal(result.tsk.staleWriterDenied, true);
  assert.equal(result.tsk.staleTargetWriterDenied, true);
  assert.equal(result.tsk.returnSequence, result.tsk.n + 2);
  assert.equal(result.enterprise.rpo, 0);
  assert.equal(result.enterprise.copiedTargetCredentialRows, 0);
  assert.equal(result.enterprise.targetClientId, result.tsk.publicCredentialTarget.clientId);
  assert.equal(result.enterprise.failback.targetClientId,
    result.tsk.publicCredentialReturn.clientId);
  assert.equal(result.enterprise.failback.staleBProtocolWriterDenied, true);
  if (process.env.ULTRA_LIVE_COMPOSITION_EVIDENCE_FILE) {
    await writeLiveCompositionEvidence(process.env.ULTRA_LIVE_COMPOSITION_EVIDENCE_FILE, result);
  }
  if (process.env.ULTRA_LIVE_FAULT_EVIDENCE_FILE) {
    await writeEnterpriseFaultEvidence(process.env.ULTRA_LIVE_FAULT_EVIDENCE_FILE, result);
  }
});
