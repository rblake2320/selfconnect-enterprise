import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  readEnterpriseFaultEvidence,
  validateEnterpriseFaultEvidence,
  writeEnterpriseFaultEvidence,
} from './enterprise-fault-evidence.mjs';

function result() {
  return {
    commandId: 'promote-1',
    enterprise: {
      manifestDigest: 'a'.repeat(64), sourceSystemId: '1', targetSystemId: '2',
      faults: {
        childProcessSigkill: {
          fault: 'sigkill-enterprise-importer-before-commit', resumed: true,
          tornAuthorityRows: 0, rpo: 0, rtoMs: 9,
        },
        destructiveRestore: {
          fault: 'drop-and-rebuild-enterprise-authority-on-promoted-b', resumed: true,
          sameTargetSystemId: true, sameCredentialReceipt: true, rpo: 0, rtoMs: 23,
        },
        databaseSigkill: {
          fault: 'sigkill-exact-promoted-enterprise-postgres', resumed: true,
          sameTargetSystemId: true, sameCredentialReceipt: true, rpo: 0, rtoMs: 31,
        },
        staleCompletionRestarts: Object.fromEntries(
          ['initial', 'failback', 'repeatForward', 'repeatFailback', 'recoveredSite']
            .map((name, index) => [name, {
              processRestarted: true, denied: true, childPid: 100 + index, rtoMs: 4,
            }]),
        ),
      },
    },
  };
}

test('same-authority fault evidence is strict, hashed, and write-once', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'enterprise-fault-'));
  const path = join(dir, 'evidence.json');
  await writeEnterpriseFaultEvidence(path, result());
  const envelope = await readEnterpriseFaultEvidence(path, { commandId: 'promote-1' });
  assert.equal(envelope.evidence.faults.childProcessSigkill.rpo, 0);
  await assert.rejects(writeEnterpriseFaultEvidence(path, result()), /exist/i);
  const tampered = JSON.parse(await readFile(path, 'utf8'));
  tampered.evidence.faults.childProcessSigkill.rpo = 1;
  await import('node:fs/promises').then(({ writeFile }) =>
    writeFile(path, JSON.stringify(tampered)));
  await assert.rejects(readEnterpriseFaultEvidence(path), /digest mismatch/);
});

test('fault acceptance rejects marker-like or incomplete claims', () => {
  const valid = {
    schemaVersion: 2, kind: 'enterprise-same-authority-fault-acceptance',
    commandId: 'promote-1', enterpriseManifestDigest: 'a'.repeat(64),
    sourceSystemId: '1', targetSystemId: '2', faults: result().enterprise.faults,
  };
  assert.equal(validateEnterpriseFaultEvidence(valid), valid);
  assert.throws(() => validateEnterpriseFaultEvidence({
    ...valid, faults: { ...valid.faults,
      childProcessSigkill: { ...valid.faults.childProcessSigkill, tornAuthorityRows: 1 } },
  }));
  assert.throws(() => validateEnterpriseFaultEvidence({
    ...valid, faults: { childProcessSigkill: valid.faults.childProcessSigkill },
  }));
});
