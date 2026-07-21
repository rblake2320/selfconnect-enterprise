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
  loadReloadablePromotedTskRuntime,
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
  assert.equal(first.sharedSecret, maps.get(first.targetClientId).sharedSecret);
  assert.equal(JSON.stringify(first.targetProof).includes(first.sharedSecret), false);
  assert.equal(JSON.stringify(first.provisionPayload).includes(first.sharedSecret), false);
  assert.equal(first.targetProof.record.mutation.publicMap.label,
    promotedTskCredentialLabel(binding));
  assert.ok(first.provisionPayload);
  await assert.rejects(() => runtime.provision({ ...binding, commandId: 'promote-3' }),
    /activation lease/);
});

function fakeAuthority(seq, overrides = {}) {
  return {
    streamId: 'tsk:credential:b', sourceEpoch: 2, holderNodeId: 'site-b',
    leaseId: 'lease-b-2', commandId: 'promote-2', grantSeq: seq,
    grantDigest: String(seq).padStart(64, 'a').slice(-64),
    prevGrantDigest: seq === 1 ? null : String(seq - 1).padStart(64, 'a').slice(-64),
    leaseExpiresAtMs: 10_000 + seq, controlToASkewBoundMs: 10,
    ...overrides,
  };
}

function fakeRuntime(seq, overrides = {}) {
  const events = overrides.events ?? [];
  const authority = fakeAuthority(seq, overrides.authority);
  const credentialStore = {
    async list() { events.push(`list:${seq}`); return [`client-${seq}`]; },
    async get() { events.push(`get:${seq}`); return { runtime: seq }; },
    async set() { events.push(`set:${seq}`); },
  };
  return {
    authority,
    authorityCapability: { runtime: seq },
    credentialStore,
    async provision(binding) {
      events.push(`provision:${seq}:${binding.commandId}`);
      return { runtime: seq };
    },
    async close() { events.push(`close:${seq}`); },
  };
}

test('reloadable runtime fails closed on initial load and lease expiry', async () => {
  const events = [];
  await assert.rejects(() => loadReloadablePromotedTskRuntime('descriptor.json', {
    now: () => 20_000,
    loader: async () => fakeRuntime(1, { events }),
  }), /expired/);
  assert.deepEqual(events, ['close:1']);

  let clock = 1_000;
  const manager = await loadReloadablePromotedTskRuntime('descriptor.json', {
    now: () => clock,
    loader: async () => fakeRuntime(1, { events }),
  });
  assert.deepEqual(await manager.credentialStore.list(), ['client-1']);
  clock = 20_000;
  await assert.rejects(() => manager.credentialStore.get('client-1'), /expired/);
  await manager.close();
});

test('reload drains old operations, blocks new work, and swaps one captured runtime', async () => {
  const events = [];
  let releaseOld;
  let oldEntered;
  const oldEnteredPromise = new Promise((resolve) => { oldEntered = resolve; });
  const old = fakeRuntime(1, { events });
  old.provision = async () => {
    events.push('old-enter');
    oldEntered();
    await new Promise((resolve) => { releaseOld = resolve; });
    events.push('old-exit');
    return { runtime: 1 };
  };
  const next = fakeRuntime(2, { events });
  const queue = [old, next];
  const manager = await loadReloadablePromotedTskRuntime('descriptor.json', {
    now: () => 1_000,
    loader: async () => queue.shift(),
  });
  const first = manager.provision({ commandId: 'promote-2' });
  await oldEnteredPromise;
  const reload = manager.reload();
  await new Promise((resolve) => setImmediate(resolve));
  let newSettled = false;
  const second = manager.credentialStore.get('client').then((value) => {
    newSettled = true;
    return value;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(newSettled, false, 'new operations must wait behind the swap');
  releaseOld();
  assert.deepEqual(await first, { runtime: 1 });
  assert.equal((await reload).grantSeq, 2);
  assert.deepEqual(await second, { runtime: 2 });
  assert.deepEqual(events, ['old-enter', 'old-exit', 'close:1', 'get:2']);
  await manager.close();
});

test('reload rejects replay, discontinuity, and authority identity changes without losing old runtime', async () => {
  const mutations = [
    { grantSeq: 1 },
    { grantSeq: 2, prevGrantDigest: 'f'.repeat(64) },
    { grantSeq: 2, streamId: 'tsk:other' },
    { grantSeq: 2, sourceEpoch: 3 },
    { grantSeq: 2, holderNodeId: 'site-c' },
    { grantSeq: 2, leaseId: 'lease-other' },
    { grantSeq: 2, commandId: 'promote-other' },
  ];
  for (const authority of mutations) {
    const events = [];
    const queue = [
      fakeRuntime(1, { events }),
      fakeRuntime(authority.grantSeq, { events, authority }),
    ];
    const manager = await loadReloadablePromotedTskRuntime('descriptor.json', {
      now: () => 1_000,
      loader: async () => queue.shift(),
    });
    await assert.rejects(() => manager.reload(), /authority|stale|monotonic/);
    assert.deepEqual(await manager.credentialStore.get('client'), { runtime: 1 });
    assert.ok(events.includes(`close:${authority.grantSeq}`), 'rejected candidate must close');
    await manager.close();
  }
});

test('restart accepts the current signed grant without replaying an in-process predecessor', async () => {
  const manager = await loadReloadablePromotedTskRuntime('descriptor.json', {
    now: () => 1_000,
    loader: async () => fakeRuntime(7),
  });
  assert.deepEqual(await manager.provision({ commandId: 'promote-2' }), { runtime: 7 });
  await manager.close();
});

test('close cannot overtake an operation admitted before its first await', async () => {
  const events = [];
  let releaseOperation;
  let operationEntered;
  const entered = new Promise((resolve) => { operationEntered = resolve; });
  const runtime = fakeRuntime(1, { events });
  runtime.provision = async () => {
    events.push('op-enter');
    operationEntered();
    await new Promise((resolve) => { releaseOperation = resolve; });
    events.push('op-exit');
    return { ok: true };
  };
  const manager = await loadReloadablePromotedTskRuntime('descriptor.json', {
    now: () => 1_000,
    loader: async () => runtime,
  });
  const operation = manager.provision({ commandId: 'promote-2' });
  const close = manager.close();
  await entered;
  assert.equal(events.includes('close:1'), false, 'runtime must remain open while admitted work runs');
  releaseOperation();
  assert.deepEqual(await operation, { ok: true });
  await close;
  assert.deepEqual(events, ['op-enter', 'op-exit', 'close:1']);
});
