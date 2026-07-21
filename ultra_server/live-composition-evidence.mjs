import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicEvidence(result) {
  return {
    schemaVersion: 2,
    kind: 'enterprise-live-authority-handoff',
    commandId: result.commandId,
    commits: result.commits,
    systems: {
      bpc: result.bpc.systemIds,
      tsk: result.tsk.systemIds,
      enterprise: {
        source: result.enterprise.sourceSystemId,
        target: result.enterprise.targetSystemId,
      },
    },
    artifacts: {
      bpcPromotion: result.bpc.readinessAttestation.attestationDigest,
      tskFinalized: result.tsk.bFinalizedReceipt.receiptDigest,
      tskActivation: result.tsk.activationLeaseGrant.grantDigest,
      enterpriseManifest: result.enterprise.manifestDigest,
      promotedCredentialProof: result.enterprise.targetProofDigest,
      promotedCredentialReceipt: result.enterprise.receiptDigest,
    },
    outcomes: {
      bpcStaleWriterDenied: result.bpc.staleWriterDenied,
      tskStaleWriterDenied: result.tsk.staleWriterDenied,
      tskStaleCredentialWriterDenied: result.tsk.staleCredentialWriterDenied,
      promotedSourceNextSequence: result.tsk.nextSequence,
      enterpriseTargetClientId: result.enterprise.targetClientId,
      copiedTargetCredentialRows: result.enterprise.copiedTargetCredentialRows,
      redactionPreserved: result.enterprise.redactionPreserved,
      dataLossRpo: result.enterprise.rpo,
    },
    tskRedisFaults: result.tskRedisFaults,
  };
}

export function validateLiveCompositionEvidence(evidence, expected = {}) {
  assert.equal(evidence?.schemaVersion, 2);
  assert.equal(evidence?.kind, 'enterprise-live-authority-handoff');
  assert.equal(evidence?.commandId, expected.commandId ?? evidence.commandId);
  for (const [name, value] of Object.entries(evidence?.commits ?? {})) {
    assert.match(value, SHA, `${name} commit must be a full SHA`);
    if (expected.commits?.[name]) assert.equal(value, expected.commits[name]);
  }
  assert.deepEqual(Object.keys(evidence?.commits ?? {}).sort(), ['bpc', 'enterprise', 'tsk']);
  for (const value of Object.values(evidence?.artifacts ?? {})) assert.match(value, DIGEST);
  assert.equal(new Set(Object.values(evidence.systems.bpc)).size, 3);
  assert.equal(new Set(Object.values(evidence.systems.tsk)).size, 3);
  assert.equal(evidence.systems.enterprise.target, evidence.systems.tsk.receiverB);
  assert.notEqual(evidence.systems.enterprise.source, evidence.systems.enterprise.target);
  assert.equal(evidence.outcomes.bpcStaleWriterDenied, true);
  assert.equal(evidence.outcomes.tskStaleWriterDenied, true);
  assert.equal(evidence.outcomes.tskStaleCredentialWriterDenied, true);
  assert.equal(evidence.outcomes.copiedTargetCredentialRows, 0);
  assert.equal(evidence.outcomes.redactionPreserved, true);
  assert.equal(evidence.outcomes.dataLossRpo, 0);
  assert.equal(evidence.tskRedisFaults?.kind, 'tsk-same-redis-authority-faults');
  assert.equal(evidence.tskRedisFaults?.commandId, evidence.commandId);
  assert.deepEqual(evidence.tskRedisFaults?.systemIds, evidence.systems.tsk);
  assert.equal(evidence.tskRedisFaults?.faults?.livePartition?.rpo, 0);
  assert.equal(evidence.tskRedisFaults?.faults?.livePartition?.oldMasterRefusedWrites, true);
  assert.equal(evidence.tskRedisFaults?.faults?.livePartition?.exactTuplePreserved, true);
  assert.equal(evidence.tskRedisFaults?.faults?.masterSigkill?.rpo, 0);
  assert.equal(evidence.tskRedisFaults?.faults?.masterSigkill?.exactTuplePreserved, true);
  return evidence;
}

export async function writeLiveCompositionEvidence(path, result) {
  const evidence = validateLiveCompositionEvidence(publicEvidence(result));
  const canonical = JSON.stringify(evidence);
  const envelope = { evidence, evidenceSha256: sha256(canonical) };
  await writeFile(path, `${JSON.stringify(envelope, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  return Object.freeze(envelope);
}

export async function readLiveCompositionEvidence(path, expected = {}) {
  const envelope = JSON.parse(await readFile(path, 'utf8'));
  const canonical = JSON.stringify(envelope.evidence);
  assert.match(envelope.evidenceSha256, DIGEST);
  assert.equal(envelope.evidenceSha256, sha256(canonical), 'live composition evidence digest mismatch');
  validateLiveCompositionEvidence(envelope.evidence, expected);
  return Object.freeze(envelope);
}
