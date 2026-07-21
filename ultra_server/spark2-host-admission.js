import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';

const DIGEST = /^[0-9a-f]{64}$/;
const ID = /^[0-9]{10,24}$/;
const HOST = /^[a-z0-9][a-z0-9.-]{0,62}$/;
const IMAGE = /^sha256:[0-9a-f]{64}\/arm64$/;
const KEY = /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/;

function exactKeys(value, keys, name) {
  assert.equal(value && typeof value === 'object' && !Array.isArray(value), true,
    `${name} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${name} has an invalid shape`);
}

export function validateAdmissionDocument(value) {
  exactKeys(value, ['identityBasis', 'schemaVersion', 'scope', 'source', 'target'], 'admission');
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, 'separate-physical-host-same-lan');
  assert.equal(value.identityBasis,
    'distinct-ssh-ed25519-host-keys-with-strict-live-observation');
  exactKeys(value.source, ['address', 'hostname', 'machineIdSha256',
    'postgresSystemIds', 'sshHostKey'], 'admission.source');
  exactKeys(value.source.postgresSystemIds, ['control', 'source'],
    'admission.source.postgresSystemIds');
  exactKeys(value.target, ['address', 'hostname', 'machineIdSha256',
    'postgresContainer', 'postgresImageId', 'postgresImageRef',
    'postgresSystemId', 'sshHostKey', 'sshPort', 'sshUser'], 'admission.target');
  for (const [name, host] of [['source.hostname', value.source.hostname],
    ['source.address', value.source.address], ['target.hostname', value.target.hostname],
    ['target.address', value.target.address]]) {
    assert.match(host, HOST, name);
  }
  assert.equal(value.source.address, '192.168.12.132');
  assert.equal(value.target.address, '10.0.0.2');
  assert.match(value.source.sshHostKey, KEY);
  assert.match(value.target.sshHostKey, KEY);
  assert.notEqual(value.source.sshHostKey, value.target.sshHostKey,
    'source and target SSH host keys must be distinct');
  assert.match(value.source.machineIdSha256, DIGEST);
  assert.match(value.target.machineIdSha256, DIGEST);
  for (const id of [value.source.postgresSystemIds.source,
    value.source.postgresSystemIds.control, value.target.postgresSystemId]) assert.match(id, ID);
  assert.equal(new Set([value.source.postgresSystemIds.source,
    value.source.postgresSystemIds.control, value.target.postgresSystemId]).size, 3);
  assert.equal(value.target.sshPort, 22);
  assert.match(value.target.sshUser, /^[a-z_][a-z0-9_-]{0,31}$/);
  assert.match(value.target.postgresContainer, /^[a-z0-9][a-z0-9_.-]{0,127}$/);
  assert.equal(value.target.postgresImageRef,
    'postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777');
  assert.match(value.target.postgresImageId, IMAGE);
  return true;
}

function keyParts(value) {
  const [type, material] = value.split(' ');
  return `${type} ${material}`;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function remote(sshArgs, ...command) {
  return execFileSync('ssh', [...sshArgs, ...command], {
    encoding: 'utf8', timeout: 30_000, windowsHide: true,
  }).trim();
}

export async function verifySparkHostAdmission(path) {
  const raw = await readFile(path, 'utf8');
  const admission = JSON.parse(raw);
  validateAdmissionDocument(admission);
  assert.equal(hostname(), admission.source.hostname, 'controller hostname is not admitted');
  const [localMachineId, localHostKey] = await Promise.all([
    readFile('/etc/machine-id', 'utf8'),
    readFile('/etc/ssh/ssh_host_ed25519_key.pub', 'utf8'),
  ]);
  assert.equal(sha256(localMachineId.trim()), admission.source.machineIdSha256,
    'controller machine-id does not match admission');
  assert.equal(keyParts(localHostKey.trim()), admission.source.sshHostKey,
    'controller SSH host key does not match admission');

  const directory = await mkdtemp(join(tmpdir(), 'spark2-admission-'));
  const knownHosts = join(directory, 'known_hosts');
  try {
    await writeFile(knownHosts,
      `${admission.target.address} ${admission.target.sshHostKey}\n`,
      { encoding: 'utf8', mode: 0o600 });
    const sshArgs = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
      '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHosts}`,
      '-o', 'GlobalKnownHostsFile=/dev/null', '-p', String(admission.target.sshPort),
      `${admission.target.sshUser}@${admission.target.address}`];
    assert.equal(remote(sshArgs, 'hostname'), admission.target.hostname,
      'target hostname does not match admission');
    const targetMachineId = remote(sshArgs, 'cat', '/etc/machine-id');
    assert.equal(sha256(targetMachineId.trim()), admission.target.machineIdSha256,
      'target machine-id does not match admission');
    const targetHostKey = remote(sshArgs, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub');
    assert.equal(keyParts(targetHostKey), admission.target.sshHostKey,
      'target SSH host key does not match admission');
    assert.equal(remote(sshArgs, 'docker', 'image', 'inspect',
      admission.target.postgresImageRef, '--format={{.Id}}/{{.Architecture}}'),
    admission.target.postgresImageId, 'target PostgreSQL image does not match admission');
    assert.equal(remote(sshArgs, 'docker', 'inspect', admission.target.postgresContainer,
      '--format={{.Config.Image}}'), admission.target.postgresImageRef,
    'target PostgreSQL container does not use the admitted image');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
  return Object.freeze({ admission: Object.freeze(admission), digest: sha256(raw) });
}
