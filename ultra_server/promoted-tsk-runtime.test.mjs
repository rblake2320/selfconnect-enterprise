import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import test from 'node:test';

import {
  canonicalOpDigest,
  canonicalize,
  signLeaseGrant,
  streamHeadDigest,
} from '@tsk/server';

import {
  createPromotedTskAuthorityCapability,
  promotedTskCredentialLabel,
} from './promoted-tsk-authority.js';
import {
  createPromotedTskCredentialRuntime,
  parsePromotedTskRuntimeDescriptor,
} from './promoted-tsk-runtime.js';

function descriptor() {
  return {
    activationLease: {
      commandId: 'promote-2', grantDigest: 'a'.repeat(64), holderNodeId: 'site-b',
      guardKeyId: 'guard-1', leaseEpoch: 2, leaseExpiresAtMs: 9_000_000_000_000,
      leaseGrantSeq: 1, leaseId: 'lease-b-2', leaseStatus: 'active',
      prevGrantDigest: null, guardSignature: 'signature', streamId: 'tsk:credential:b',
    },
    controlToASkewBoundMs: 5_000,
    grantDigest: 'a'.repeat(64),
    holderNodeId: 'site-b',
    leaseId: 'lease-b-2',
    maxPendingRows: 10_000,
    mutationKeyId: 'mutation-1',
    mutationSecretFile: 'C:/secure/mutation.bin',
    runtimeDatabaseUrl: 'postgres://runtime:redacted@127.0.0.1/tsk',
    schema: 'public',
    sourceEpoch: 2,
    sourceLeasePublicKeyFiles: { 'guard-1': 'C:/secure/guard.pub' },
    streamHeadKeyId: 'head-1',
    streamHeadPrivateKeyFile: 'C:/secure/head.key',
    streamHeadPublicKeyFiles: { 'head-1': 'C:/secure/head.pub' },
    streamId: 'tsk:credential:b',
  };
}

test('runtime descriptor is exact and binds its active lease', () => {
  const parsed = parsePromotedTskRuntimeDescriptor(descriptor());
  assert.equal(parsed.streamId, 'tsk:credential:b');
  assert.equal(Object.isFrozen(parsed), true);
  assert.throws(() => parsePromotedTskRuntimeDescriptor({ ...descriptor(), extra: true }),
    /invalid shape/);
  assert.throws(() => parsePromotedTskRuntimeDescriptor({
    ...descriptor(), sourceEpoch: 3,
  }), /activationLease/);
  assert.throws(() => parsePromotedTskRuntimeDescriptor({
    ...descriptor(), runtimeDatabaseUrl: '',
  }), /runtimeDatabaseUrl/);
});

test('runtime rejects invalid authority handles and never accepts a callback authority', () => {
  assert.throws(() => createPromotedTskCredentialRuntime({
    authorityCapability: {}, proofPool: { query() {}, connect() {} }, credentialStore: {},
    activationLease: {}, streamId: 'tsk:credential:b',
  }), /handles are invalid/);
  assert.equal(
    String(createPromotedTskCredentialRuntime).includes('assertWritable'), false,
  );
  assert.equal(
    String(createPromotedTskCredentialRuntime).includes('completeImportedTskReprovision'), false,
  );
});

test('promoted label is stable per command and principal', () => {
  const a = promotedTskCredentialLabel({
    agentId: 'agent-1', pairId: 'pair-1', commandId: 'promote-2',
  });
  const b = promotedTskCredentialLabel({
    agentId: 'agent-1', pairId: 'pair-1', commandId: 'promote-2',
  });
  assert.equal(a, b);
  assert.notEqual(a, promotedTskCredentialLabel({
    agentId: 'agent-1', pairId: 'pair-1', commandId: 'promote-3',
  }));
});

test('runtime creates one real credential and binds its payload to a signed public proof', async () => {
  const guard = generateKeyPairSync('ed25519');
  const head = generateKeyPairSync('ed25519');
  const activationLease = signLeaseGrant('guard-1', guard.privateKey, {
    streamId: 'tsk:credential:b', leaseEpoch: 2, leaseStatus: 'active',
    holderNodeId: 'site-b', leaseId: 'lease-b-2', commandId: 'promote-2',
    leaseExpiresAtMs: Date.now() + 3_600_000, leaseGrantSeq: 1,
    prevGrantDigest: null,
  });
  const maps = new Map();
  const credentialStore = {
    async list() { return [...maps.keys()]; },
    async get(clientId) { return maps.get(clientId) ?? null; },
    async set(clientId, map) { maps.set(clientId, structuredClone(map)); },
  };
  const ownerPool = {
    async query(_sql, [streamId, clientId]) {
      const map = maps.get(clientId);
      assert.ok(map);
      const publicMap = JSON.parse(JSON.stringify(map));
      delete publicMap.sharedSecret;
      const mutation = {
        kind: 'tsk.credential.snapshot.v1', tumblerId: clientId, counter: 1,
        clientId, publicMap,
        publicMapDigest: createHash('sha256').update(canonicalize(publicMap)).digest('hex'),
        secretDigest: createHash('sha256').update(map.sharedSecret, 'utf8').digest('hex'),
      };
      const record = {
        streamId, sourceEpoch: 'credential-e2', sequence: 1, fenceToken: '2', mutation,
      };
      const opDigest = canonicalOpDigest(record);
      const headDigest = streamHeadDigest({
        streamId, sequence: 1, prevHeadDigest: '0'.repeat(64), opDigest,
        keyId: 'head-1', alg: 'ed25519',
      });
      return { rows: [{
        sequence: '1', source_epoch: record.sourceEpoch, fence_token: '2', op_digest: opDigest,
        mutation, head_prev: '0'.repeat(64), head_digest: headDigest,
        head_key_id: 'head-1', head_alg: 'ed25519',
        head_sig: cryptoSign(null, Buffer.from(headDigest, 'hex'), head.privateKey)
          .toString('base64url'),
      }] };
    },
    async connect() {
      return { query: async () => ({ rows: [] }), release() {} };
    },
  };
  const authorityCapability = createPromotedTskAuthorityCapability({
    activationLease,
    leaseResolver: { resolve: (keyId) => keyId === 'guard-1' ? guard.publicKey : null },
    headKeyResolver: { resolve: (keyId) => keyId === 'head-1' ? head.publicKey : null },
  });
  const runtime = createPromotedTskCredentialRuntime({
    authorityCapability, proofPool: ownerPool, credentialStore, activationLease,
    streamId: 'tsk:credential:b',
  });
  const binding = {
    agentId: 'agent-1', pairId: 'pair-1', commandId: 'promote-2',
    sourceClientId: 'source-client', sourceSecretDigest: 'f'.repeat(64),
  };
  const first = await runtime.provision(binding);
  const second = await runtime.provision(binding);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.targetClientId, second.targetClientId);
  assert.equal(maps.size, 1);
  assert.equal(runtime.credentialStore, credentialStore,
    'independent server routes must share the same fenced authority store');
  assert.equal(JSON.stringify(first.targetProof).includes('sharedSecret'), false);
  assert.equal(first.targetProof.record.mutation.publicMap.label,
    promotedTskCredentialLabel(binding));
  assert.ok(first.provisionPayload);
  await assert.rejects(() => runtime.provision({ ...binding, commandId: 'promote-3' }),
    /activation lease/);
});
