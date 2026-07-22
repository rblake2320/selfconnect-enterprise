import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const DIGEST = /^[0-9a-f]{64}$/;
const ALLOWED_FAULTS = Object.freeze({
  childProcessSigkill: 'sigkill-enterprise-importer-before-commit',
  destructiveRestore: 'drop-and-rebuild-enterprise-authority-on-promoted-b',
  databaseSigkill: 'sigkill-exact-promoted-enterprise-postgres',
});
const RESTART_CUTS = Object.freeze([
  'initial', 'failback', 'repeatForward', 'repeatFailback', 'recoveredSite',
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicEvidence(result) {
  const restarts = Object.fromEntries(RESTART_CUTS.map((cut) => {
    const probe = result.enterprise.faults.staleCompletionRestarts[cut];
    return [cut, {
      processRestarted: probe.processRestarted,
      childPid: probe.childPid,
      denied: probe.denied,
      denialCode: probe.denialCode,
      noCommittedEffect: probe.noCommittedEffect,
      authorityStateDigest: probe.authorityStateDigest,
      rtoMs: probe.rtoMs,
    }];
  }));
  const child = result.enterprise.faults.childProcessSigkill;
  const restore = result.enterprise.faults.destructiveRestore;
  const database = result.enterprise.faults.databaseSigkill;
  return {
    schemaVersion: 2,
    kind: 'enterprise-same-authority-fault-acceptance',
    commandId: result.commandId,
    enterpriseManifestDigest: result.enterprise.manifestDigest,
    sourceSystemId: result.enterprise.sourceSystemId,
    targetSystemId: result.enterprise.targetSystemId,
    faults: {
      staleCompletionRestarts: restarts,
      childProcessSigkill: {
        fault: child.fault, resumed: child.resumed,
        tornAuthorityRows: child.tornAuthorityRows, rpo: child.rpo, rtoMs: child.rtoMs,
      },
      destructiveRestore: {
        fault: restore.fault, resumed: restore.resumed,
        sameTargetSystemId: restore.sameTargetSystemId,
        sameCredentialReceipt: restore.sameCredentialReceipt,
        rpo: restore.rpo, rtoMs: restore.rtoMs,
      },
      databaseSigkill: {
        fault: database.fault, resumed: database.resumed,
        sameTargetSystemId: database.sameTargetSystemId,
        sameCredentialReceipt: database.sameCredentialReceipt,
        rpo: database.rpo, rtoMs: database.rtoMs,
      },
    },
  };
}

export function validateEnterpriseFaultEvidence(evidence, expected = {}) {
  assert.equal(evidence?.schemaVersion, 2);
  assert.equal(evidence?.kind, 'enterprise-same-authority-fault-acceptance');
  assert.equal(evidence?.commandId, expected.commandId ?? evidence.commandId);
  assert.match(evidence?.enterpriseManifestDigest, DIGEST);
  assert.equal(typeof evidence?.sourceSystemId, 'string');
  assert.equal(typeof evidence?.targetSystemId, 'string');
  assert.notEqual(evidence.sourceSystemId, evidence.targetSystemId);
  assert.deepEqual(Object.keys(evidence?.faults ?? {}).sort(),
    [...Object.keys(ALLOWED_FAULTS), 'staleCompletionRestarts'].sort());
  for (const [name, expectedFault] of Object.entries(ALLOWED_FAULTS)) {
    const fault = evidence.faults[name];
    const exactKeys = name === 'childProcessSigkill'
      ? ['fault', 'resumed', 'rpo', 'rtoMs', 'tornAuthorityRows']
      : ['fault', 'resumed', 'rpo', 'rtoMs', 'sameCredentialReceipt', 'sameTargetSystemId'];
    assert.deepEqual(Object.keys(fault).sort(), exactKeys.sort());
    assert.equal(fault?.fault, expectedFault);
    assert.equal(fault?.resumed, true);
    assert.equal(fault?.rpo, 0);
    assert.equal(Number.isSafeInteger(fault?.rtoMs) && fault.rtoMs >= 0, true);
  }
  assert.equal(evidence.faults.childProcessSigkill.tornAuthorityRows, 0);
  assert.equal(evidence.faults.destructiveRestore.sameTargetSystemId, true);
  assert.equal(evidence.faults.destructiveRestore.sameCredentialReceipt, true);
  assert.equal(evidence.faults.databaseSigkill.sameTargetSystemId, true);
  assert.equal(evidence.faults.databaseSigkill.sameCredentialReceipt, true);
  assert.deepEqual(Object.keys(evidence.faults.staleCompletionRestarts).sort(),
    [...RESTART_CUTS].sort());
  const pids = new Set();
  for (const cut of RESTART_CUTS) {
    const probe = evidence.faults.staleCompletionRestarts[cut];
    assert.deepEqual(Object.keys(probe).sort(), [
      'authorityStateDigest', 'childPid', 'denialCode', 'denied',
      'noCommittedEffect', 'processRestarted', 'rtoMs',
    ]);
    assert.equal(probe.processRestarted, true);
    assert.equal(probe.denied, true);
    assert.equal(probe.denialCode, 'import-binding-rejected');
    assert.equal(probe.noCommittedEffect, true);
    assert.match(probe.authorityStateDigest, DIGEST);
    assert.equal(Number.isSafeInteger(probe.childPid) && probe.childPid > 0, true);
    assert.equal(Number.isSafeInteger(probe.rtoMs) && probe.rtoMs >= 0, true);
    pids.add(probe.childPid);
  }
  assert.equal(pids.size, RESTART_CUTS.length,
    'every stale cut must be probed by a distinct restarted child process');
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
