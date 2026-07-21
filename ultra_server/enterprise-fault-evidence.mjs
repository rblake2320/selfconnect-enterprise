import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const DIGEST = /^[0-9a-f]{64}$/;
const ALLOWED_FAULTS = Object.freeze({
  childProcessSigkill: 'sigkill-enterprise-importer-before-commit',
  destructiveRestore: 'drop-and-rebuild-enterprise-authority-on-promoted-b',
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicEvidence(result) {
  return {
    schemaVersion: 1,
    kind: 'enterprise-same-authority-fault-acceptance',
    commandId: result.commandId,
    enterpriseManifestDigest: result.enterprise.manifestDigest,
    sourceSystemId: result.enterprise.sourceSystemId,
    targetSystemId: result.enterprise.targetSystemId,
    faults: result.enterprise.faults,
  };
}

export function validateEnterpriseFaultEvidence(evidence, expected = {}) {
  assert.equal(evidence?.schemaVersion, 1);
  assert.equal(evidence?.kind, 'enterprise-same-authority-fault-acceptance');
  assert.equal(evidence?.commandId, expected.commandId ?? evidence.commandId);
  assert.match(evidence?.enterpriseManifestDigest, DIGEST);
  assert.equal(typeof evidence?.sourceSystemId, 'string');
  assert.equal(typeof evidence?.targetSystemId, 'string');
  assert.notEqual(evidence.sourceSystemId, evidence.targetSystemId);
  assert.deepEqual(Object.keys(evidence?.faults ?? {}).sort(), Object.keys(ALLOWED_FAULTS).sort());
  for (const [name, expectedFault] of Object.entries(ALLOWED_FAULTS)) {
    const fault = evidence.faults[name];
    assert.equal(fault?.fault, expectedFault);
    assert.equal(fault?.resumed, true);
    assert.equal(fault?.rpo, 0);
    assert.equal(Number.isSafeInteger(fault?.rtoMs) && fault.rtoMs >= 0, true);
  }
  assert.equal(evidence.faults.childProcessSigkill.tornAuthorityRows, 0);
  assert.equal(evidence.faults.destructiveRestore.sameTargetSystemId, true);
  assert.equal(evidence.faults.destructiveRestore.sameCredentialReceipt, true);
  return evidence;
}

export async function writeEnterpriseFaultEvidence(path, result) {
  const evidence = validateEnterpriseFaultEvidence(publicEvidence(result));
  const canonical = JSON.stringify(evidence);
  const envelope = { evidence, evidenceSha256: sha256(canonical) };
  await writeFile(path, `${JSON.stringify(envelope, null, 2)}\n`, {
    encoding: 'utf8', flag: 'wx',
  });
  return Object.freeze(envelope);
}

export async function readEnterpriseFaultEvidence(path, expected = {}) {
  const envelope = JSON.parse(await readFile(path, 'utf8'));
  assert.match(envelope.evidenceSha256, DIGEST);
  assert.equal(envelope.evidenceSha256, sha256(JSON.stringify(envelope.evidence)),
    'Enterprise fault evidence digest mismatch');
  validateEnterpriseFaultEvidence(envelope.evidence, expected);
  return Object.freeze(envelope);
}
