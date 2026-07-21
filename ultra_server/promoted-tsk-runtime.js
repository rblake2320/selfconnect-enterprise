import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { generateTumblerMap, toProvisionPayload } from '@tsk/core';
import {
  HmacCredentialMutationTicketSigner,
  NodePostgresTransactor,
  PgHaTumblerMapStore,
  assertCredentialAuthorityReady,
  assertCredentialRuntimeMutationBoundary,
  assertSchemaReady,
  assertSourceFenceReady,
  verifyLeaseGrant,
} from '@tsk/server';
import pg from 'pg';

import {
  createPromotedTskAuthorityCapability,
  promotedTskCredentialLabel,
  verifyPromotedTskCredentialProof,
} from './promoted-tsk-authority.js';

const ID = /^[A-Za-z0-9_.:/-]{1,128}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SCHEMA = /^[a-z_][a-z0-9_]{0,62}$/;
const CONFIG_KEYS = [
  'activationLease', 'controlToASkewBoundMs', 'grantDigest', 'holderNodeId',
  'leaseId', 'maxPendingRows', 'mutationKeyId', 'mutationSecretFile',
  'runtimeDatabaseUrl', 'schema', 'sourceEpoch', 'sourceLeasePublicKeyFiles',
  'streamHeadKeyId', 'streamHeadPrivateKeyFile', 'streamHeadPublicKeyFiles',
  'streamId',
];

function exact(value, keys, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${name} must be exact plain data`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length ||
      actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${name} has an invalid shape`);
  }
}

function id(value, name, pattern = ID) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${name} invalid`);
  return value;
}

function boundedPath(value, name) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 || value.includes('\0')) {
    throw new Error(`${name} invalid`);
  }
  return value;
}

function keyFiles(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0 || Object.keys(value).length === 0) {
    throw new Error(`${name} must be a non-empty exact key map`);
  }
  const files = {};
  for (const [keyId, path] of Object.entries(value)) {
    files[id(keyId, `${name} keyId`, KEY_ID)] = boundedPath(path, `${name} path`);
  }
  return Object.freeze(files);
}

export function parsePromotedTskRuntimeDescriptor(value) {
  exact(value, CONFIG_KEYS, 'promoted TSK runtime descriptor');
  const sourceEpoch = value.sourceEpoch;
  const skew = value.controlToASkewBoundMs;
  const maxPendingRows = value.maxPendingRows;
  if (!Number.isSafeInteger(sourceEpoch) || sourceEpoch < 1 || sourceEpoch > 2 ** 40) {
    throw new Error('sourceEpoch invalid');
  }
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 3_600_000) {
    throw new Error('controlToASkewBoundMs invalid');
  }
  if (!Number.isSafeInteger(maxPendingRows) || maxPendingRows < 1 || maxPendingRows > 1_000_000) {
    throw new Error('maxPendingRows invalid');
  }
  if (typeof value.grantDigest !== 'string' || !HEX64.test(value.grantDigest)) {
    throw new Error('grantDigest invalid');
  }
  if (typeof value.runtimeDatabaseUrl !== 'string' || value.runtimeDatabaseUrl.length < 1 ||
      value.runtimeDatabaseUrl.length > 8192 || value.runtimeDatabaseUrl.includes('\0')) {
    throw new Error('runtimeDatabaseUrl invalid');
  }
  const schema = id(value.schema, 'schema', SCHEMA);
  if (schema !== 'public') throw new Error('promoted TSK credential authority requires public schema');
  const descriptor = {
    activationLease: structuredClone(value.activationLease),
    controlToASkewBoundMs: skew,
    grantDigest: value.grantDigest,
    holderNodeId: id(value.holderNodeId, 'holderNodeId'),
    leaseId: id(value.leaseId, 'leaseId'),
    maxPendingRows,
    mutationKeyId: id(value.mutationKeyId, 'mutationKeyId', KEY_ID),
    mutationSecretFile: boundedPath(value.mutationSecretFile, 'mutationSecretFile'),
    runtimeDatabaseUrl: value.runtimeDatabaseUrl,
    schema,
    sourceEpoch,
    sourceLeasePublicKeyFiles: keyFiles(
      value.sourceLeasePublicKeyFiles, 'sourceLeasePublicKeyFiles',
    ),
    streamHeadKeyId: id(value.streamHeadKeyId, 'streamHeadKeyId', KEY_ID),
    streamHeadPrivateKeyFile: boundedPath(
      value.streamHeadPrivateKeyFile, 'streamHeadPrivateKeyFile',
    ),
    streamHeadPublicKeyFiles: keyFiles(
      value.streamHeadPublicKeyFiles, 'streamHeadPublicKeyFiles',
    ),
    streamId: id(value.streamId, 'streamId'),
  };
  exact(descriptor.activationLease, [
    'commandId', 'grantDigest', 'guardKeyId', 'guardSignature', 'holderNodeId', 'leaseEpoch',
    'leaseExpiresAtMs', 'leaseGrantSeq', 'leaseId', 'leaseStatus',
    'prevGrantDigest', 'streamId',
  ], 'activationLease');
  if (descriptor.activationLease.streamId !== descriptor.streamId ||
      descriptor.activationLease.leaseEpoch !== descriptor.sourceEpoch ||
      descriptor.activationLease.holderNodeId !== descriptor.holderNodeId ||
      descriptor.activationLease.leaseId !== descriptor.leaseId ||
      descriptor.activationLease.grantDigest !== descriptor.grantDigest ||
      descriptor.activationLease.leaseStatus !== 'active') {
    throw new Error('activationLease does not match the configured promoted authority');
  }
  return Object.freeze(descriptor);
}

async function publicResolver(files) {
  const keys = new Map();
  for (const [keyId, path] of Object.entries(files)) {
    const encoded = await readFile(path);
    if (encoded.toString('ascii').includes('PRIVATE KEY')) {
      throw new Error(`public verifier file '${keyId}' contains private key material`);
    }
    const key = createPublicKey(encoded);
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
      throw new Error(`public verifier file '${keyId}' is not an Ed25519 public key`);
    }
    keys.set(keyId, key);
  }
  return Object.freeze({ resolve: (keyId) => keys.get(keyId) ?? null });
}

function requiredBinding(input) {
  exact(input, [
    'agentId', 'commandId', 'pairId', 'sourceClientId', 'sourceSecretDigest',
  ], 'promoted credential binding');
  if (typeof input.sourceSecretDigest !== 'string' || !HEX64.test(input.sourceSecretDigest)) {
    throw new Error('sourceSecretDigest invalid');
  }
  return Object.freeze({
    agentId: id(input.agentId, 'agentId'),
    commandId: id(input.commandId, 'commandId'),
    pairId: id(input.pairId, 'pairId'),
    sourceClientId: id(input.sourceClientId, 'sourceClientId'),
    sourceSecretDigest: input.sourceSecretDigest,
  });
}

export async function readPromotedTskCredentialProof(
  pool, streamId, clientId, activationLease, binding,
) {
  const result = await pool.query(
    `SELECT sequence::text,source_epoch,fence_token::text,op_digest,mutation,
            head_prev,head_digest,head_key_id,head_alg,head_sig
       FROM tsk_outbox_rows
      WHERE stream_id=$1 AND mutation->>'kind'='tsk.credential.snapshot.v1'
        AND mutation->>'clientId'=$2
      ORDER BY sequence DESC LIMIT 1`,
    [streamId, clientId],
  );
  const row = result.rows[0];
  if (!row || String(row.mutation?.clientId) !== clientId) {
    throw new Error('promoted credential ledger proof is missing');
  }
  const sequence = Number(row.sequence);
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error('promoted credential ledger sequence invalid');
  }
  return Object.freeze({
    format: 'selfconnect-promoted-tsk-credential-proof-v1',
    agentId: binding.agentId,
    pairId: binding.pairId,
    commandId: binding.commandId,
    activationLease: structuredClone(activationLease),
    record: Object.freeze({
      contractVersion: '1', streamId, sourceEpoch: String(row.source_epoch),
      sequence, fenceToken: String(row.fence_token), opDigest: String(row.op_digest),
      mutation: structuredClone(row.mutation),
    }),
    head: Object.freeze({
      streamId, sequence, prevHeadDigest: String(row.head_prev),
      opDigest: String(row.op_digest), keyId: String(row.head_key_id),
      alg: String(row.head_alg), headDigest: String(row.head_digest),
      signature: String(row.head_sig),
    }),
  });
}

export function createPromotedTskCredentialRuntime({
  authorityCapability, proofPool, credentialStore, activationLease, streamId,
}) {
  if (!authorityCapability || !proofPool || typeof proofPool.query !== 'function' ||
      typeof proofPool.connect !== 'function' ||
      !credentialStore || typeof credentialStore.list !== 'function' ||
      typeof credentialStore.get !== 'function' || typeof credentialStore.set !== 'function') {
    throw new Error('promoted TSK runtime authority handles are invalid');
  }
  id(streamId, 'streamId');
  const capturedLease = structuredClone(activationLease);
  return Object.freeze({
    authorityCapability,
    async provision(rawBinding) {
      const binding = requiredBinding(rawBinding);
      if (binding.commandId !== capturedLease.commandId) {
        throw new Error('promoted credential command does not match the activation lease');
      }
      const label = promotedTskCredentialLabel(binding);
      // Serialize the command across server processes. The dedicated session
      // holds the lock while PgHaTumblerMapStore performs its own serializable
      // transactions on the same PostgreSQL authority.
      const lockClient = await proofPool.connect();
      try {
        await lockClient.query(
          'SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1,0))',
          [`promoted-tsk:${label}`],
        );
        const ids = await credentialStore.list();
        if (ids.length > 10_000) throw new Error('promoted credential scan bound exceeded');
        const matches = [];
        for (const clientId of ids) {
          const map = await credentialStore.get(clientId);
          if (map?.label === label) matches.push(map);
        }
        if (matches.length > 1) throw new Error('multiple promoted credentials exist for one command');
        let map = matches[0] ?? null;
        let created = false;
        if (!map) {
          map = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
          map.label = label;
          map.status = 'active';
          await credentialStore.set(map.clientId, map);
          created = true;
        }
        if (map.status !== 'active' || map.clientId === binding.sourceClientId ||
            typeof map.sharedSecret !== 'string' || map.sharedSecret.length < 32) {
          throw new Error('promoted credential is not fresh, active, and secret-bearing');
        }
        const targetProof = await readPromotedTskCredentialProof(
          proofPool, streamId, map.clientId, capturedLease, binding,
        );
        const verified = await verifyPromotedTskCredentialProof(
          authorityCapability, targetProof, {
            agentId: binding.agentId,
            pairId: binding.pairId,
            sourceClientId: binding.sourceClientId,
            sourceSecretDigest: binding.sourceSecretDigest,
          },
        );
        const secretDigest = createHash('sha256').update(map.sharedSecret, 'utf8').digest('hex');
        if (verified.targetClientId !== map.clientId || verified.secretDigest !== secretDigest) {
          throw new Error('promoted credential secret does not match its signed public proof');
        }
        return Object.freeze({
          created,
          targetProof,
          targetClientId: verified.targetClientId,
          // This is an authorized reprovisioning payload, not a durable one-time
          // delivery guarantee. The HTTP boundary decides whether a completed
          // idempotent retry may disclose it again.
          provisionPayload: toProvisionPayload(map),
        });
      } finally {
        await lockClient.query(
          'SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1,0))',
          [`promoted-tsk:${label}`],
        ).catch(() => {});
        lockClient.release();
      }
    },
  });
}

export async function loadPromotedTskCredentialRuntime(descriptorPath) {
  if (typeof descriptorPath !== 'string' || descriptorPath.length < 1) {
    throw new Error('ULTRA_TSK_AUTHORITY_CONFIG_FILE is required in independent production mode');
  }
  const descriptor = parsePromotedTskRuntimeDescriptor(
    JSON.parse(await readFile(descriptorPath, 'utf8')),
  );
  const leaseResolver = await publicResolver(descriptor.sourceLeasePublicKeyFiles);
  const headKeyResolver = await publicResolver(descriptor.streamHeadPublicKeyFiles);
  verifyLeaseGrant(leaseResolver, descriptor.activationLease);

  const privateEncoded = await readFile(descriptor.streamHeadPrivateKeyFile);
  const privateKey = createPrivateKey(privateEncoded);
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('stream-head signer file is not an Ed25519 private key');
  }
  const signer = Object.freeze({
    keyId: descriptor.streamHeadKeyId,
    alg: 'ed25519',
    sign: (digest) => cryptoSign(
      null, Buffer.from(digest, 'hex'), privateKey,
    ).toString('base64url'),
  });
  const signerPublic = headKeyResolver.resolve(descriptor.streamHeadKeyId);
  if (!signerPublic || !createPublicKey(privateKey).equals(signerPublic)) {
    throw new Error('stream-head private key does not match the configured public verifier');
  }

  const mutationSecret = await readFile(descriptor.mutationSecretFile);
  if (mutationSecret.length < 32 || mutationSecret.length > 4096) {
    mutationSecret.fill(0);
    throw new Error('credential mutation secret must contain 32..4096 raw bytes');
  }
  const ticketSigner = new HmacCredentialMutationTicketSigner(
    descriptor.mutationKeyId, mutationSecret,
  );
  mutationSecret.fill(0);

  const runtimePool = new pg.Pool({
    connectionString: descriptor.runtimeDatabaseUrl,
    max: 4,
    connectionTimeoutMillis: 10_000,
  });
  runtimePool.on('error', () => {});
  try {
    const db = new NodePostgresTransactor(runtimePool, { maxSerializationRetries: 2 });
    const outboxReady = await assertSchemaReady(db, descriptor.schema);
    const credentialReady = await assertCredentialAuthorityReady(
      db, descriptor.schema, outboxReady,
    );
    const mutationBoundary = await assertCredentialRuntimeMutationBoundary(
      db, descriptor.schema, ticketSigner,
    );
    const fenceReady = await assertSourceFenceReady(
      db, descriptor.schema, leaseResolver, {
        streamId: descriptor.streamId,
        holderNodeId: descriptor.holderNodeId,
        leaseId: descriptor.leaseId,
        grantDigest: descriptor.grantDigest,
      },
    );
    const credentialStore = new PgHaTumblerMapStore(
      db, outboxReady, credentialReady, mutationBoundary, ticketSigner,
      {
        streamId: descriptor.streamId,
        sourceEpoch: descriptor.sourceEpoch,
        signer,
        maxPendingRows: descriptor.maxPendingRows,
        backpressure: 'fail-authoritative-mutation',
        schema: descriptor.schema,
      },
      {
        resolver: leaseResolver,
        controlToASkewBoundMs: descriptor.controlToASkewBoundMs,
        ready: fenceReady,
      },
    );
    const authorityCapability = createPromotedTskAuthorityCapability({
      activationLease: descriptor.activationLease,
      leaseResolver,
      headKeyResolver,
    });
    return Object.freeze({
      ...createPromotedTskCredentialRuntime({
        authorityCapability, proofPool: runtimePool, credentialStore,
        activationLease: descriptor.activationLease, streamId: descriptor.streamId,
      }),
      close: () => runtimePool.end(),
    });
  } catch (error) {
    await runtimePool.end().catch(() => {});
    throw error;
  }
}
