import { createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { NodePostgresTransactor, assertSchemaReady } from '@bpc/server';
import { assertSourceFenceReady } from '@tsk/server';

import { createGovernedUltraStateAuthority } from './ultra-state-outbox.js';

const ID = /^[A-Za-z0-9_.:/-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const EXACT_KEYS = [
  'controlToASkewBoundMs', 'grantDigest', 'holderNodeId', 'leaseId',
  'sourceEpoch', 'sourceLeasePublicKeyFiles', 'streamId',
];

function exactPlain(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error('Ultra state authority descriptor must be plain JSON');
  }
  const actual = Object.keys(value).sort();
  if (actual.length !== EXACT_KEYS.length || actual.some((key, index) => key !== EXACT_KEYS[index])) {
    throw new Error('Ultra state authority descriptor has an invalid shape');
  }
}

function id(value, name) {
  if (typeof value !== 'string' || !ID.test(value)) throw new Error(`${name} invalid`);
  return value;
}

export function parseUltraStateAuthorityDescriptor(value) {
  exactPlain(value);
  const sourceEpoch = value.sourceEpoch;
  const controlToASkewBoundMs = value.controlToASkewBoundMs;
  if (!Number.isSafeInteger(sourceEpoch) || sourceEpoch < 0 || sourceEpoch > 2 ** 40) {
    throw new Error('sourceEpoch invalid');
  }
  if (!Number.isSafeInteger(controlToASkewBoundMs) ||
      controlToASkewBoundMs < 0 || controlToASkewBoundMs > 3_600_000) {
    throw new Error('controlToASkewBoundMs invalid');
  }
  if (typeof value.grantDigest !== 'string' || !HEX64.test(value.grantDigest)) {
    throw new Error('grantDigest invalid');
  }
  if (!value.sourceLeasePublicKeyFiles || typeof value.sourceLeasePublicKeyFiles !== 'object' ||
      Array.isArray(value.sourceLeasePublicKeyFiles) ||
      Object.keys(value.sourceLeasePublicKeyFiles).length === 0) {
    throw new Error('sourceLeasePublicKeyFiles must be a non-empty key map');
  }
  const files = {};
  for (const [keyId, path] of Object.entries(value.sourceLeasePublicKeyFiles)) {
    if (typeof path !== 'string' || path.length < 1 || path.length > 4096 || path.includes('\0')) {
      throw new Error('source lease public-key path invalid');
    }
    files[id(keyId, 'source lease keyId')] = path;
  }
  return Object.freeze({
    streamId: id(value.streamId, 'streamId'), sourceEpoch,
    holderNodeId: id(value.holderNodeId, 'holderNodeId'),
    leaseId: id(value.leaseId, 'leaseId'), grantDigest: value.grantDigest,
    controlToASkewBoundMs, sourceLeasePublicKeyFiles: Object.freeze(files),
  });
}

async function publicResolver(files) {
  const keys = new Map();
  for (const [keyId, path] of Object.entries(files)) {
    const encoded = await readFile(path);
    if (encoded.toString('ascii').includes('PRIVATE KEY')) {
      throw new Error(`source lease verifier file '${keyId}' contains private key material`);
    }
    const key = createPublicKey(encoded);
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
      throw new Error(`source lease verifier file '${keyId}' is not a public Ed25519 key`);
    }
    keys.set(keyId, key);
  }
  return Object.freeze({ resolve: (keyId) => keys.get(keyId) ?? null });
}

export async function loadGovernedUltraStateAuthority(pool, descriptorPath) {
  if (typeof descriptorPath !== 'string' || descriptorPath.length === 0) {
    throw new Error('ULTRA_STATE_AUTHORITY_CONFIG_FILE is required in independent mode');
  }
  const descriptor = parseUltraStateAuthorityDescriptor(
    JSON.parse(await readFile(descriptorPath, 'utf8')),
  );
  const db = new NodePostgresTransactor(pool);
  const outboxReady = await assertSchemaReady(db, 'public');
  const sourceLeaseResolver = await publicResolver(descriptor.sourceLeasePublicKeyFiles);
  const sourceFenceReady = await assertSourceFenceReady(db, 'public', sourceLeaseResolver, {
    streamId: descriptor.streamId,
    holderNodeId: descriptor.holderNodeId,
    leaseId: descriptor.leaseId,
    grantDigest: descriptor.grantDigest,
  });
  return createGovernedUltraStateAuthority({
    pool, db, outboxReady, sourceFenceReady, sourceLeaseResolver,
    schema: 'public', streamId: descriptor.streamId,
    sourceEpoch: descriptor.sourceEpoch,
    controlToASkewBoundMs: descriptor.controlToASkewBoundMs,
  });
}
