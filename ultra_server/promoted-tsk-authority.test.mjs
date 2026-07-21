import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import test from 'node:test';
import { generateTumblerMap } from '@tsk/core';
import {
  canonicalOpDigest,
  canonicalize,
  signLeaseGrant,
  streamHeadDigest,
} from '@tsk/server';
import {
  PROMOTED_TSK_CREDENTIAL_PROOF_FORMAT,
  createPromotedTskAuthorityCapability,
  promotedTskCredentialLabel,
  verifyPromotedTskCredentialProof,
} from './promoted-tsk-authority.js';

function clone(value) { return JSON.parse(JSON.stringify(value)); }

function fixture() {
  const guard = generateKeyPairSync('ed25519');
  const head = generateKeyPairSync('ed25519');
  const commandId = 'cmd-promote-1';
  const agentId = 'agent-1';
  const pairId = 'pair-1';
  const streamId = 'credential-stream-1';
  const sourceSecretDigest = '1'.repeat(64);
  const activationLease = signLeaseGrant('guard-1', guard.privateKey, {
    streamId,
    leaseEpoch: 4,
    leaseStatus: 'active',
    holderNodeId: 'node-b',
    leaseId: 'lease-b-4',
    commandId,
    leaseExpiresAtMs: 2_000_000_000_000,
    leaseGrantSeq: 1,
    prevGrantDigest: null,
  });
  const fullMap = generateTumblerMap({ keyLength: 64, minTumblers: 2, maxTumblers: 2 });
  fullMap.label = promotedTskCredentialLabel({ commandId, pairId, agentId });
  fullMap.status = 'active';
  const publicMap = clone(fullMap);
  delete publicMap.sharedSecret;
  const mutation = {
    kind: 'tsk.credential.snapshot.v1',
    tumblerId: fullMap.clientId,
    clientId: fullMap.clientId,
    counter: 1,
    publicMap,
    publicMapDigest: createHash('sha256').update(canonicalize(publicMap), 'utf8').digest('hex'),
    secretDigest: createHash('sha256').update(fullMap.sharedSecret, 'utf8').digest('hex'),
  };
  const record = {
    contractVersion: '1',
    streamId,
    sourceEpoch: '4',
    sequence: 1,
    fenceToken: '4',
    opDigest: canonicalOpDigest({ streamId, sourceEpoch: '4', sequence: 1, fenceToken: '4', mutation }),
    mutation,
  };
  const unsignedHead = {
    streamId,
    sequence: 1,
    prevHeadDigest: '0'.repeat(64),
    opDigest: record.opDigest,
    keyId: 'head-1',
    alg: 'ed25519',
  };
  const headDigest = streamHeadDigest(unsignedHead);
  const signedHead = {
    ...unsignedHead,
    headDigest,
    signature: sign(null, Buffer.from(headDigest, 'hex'), head.privateKey).toString('base64url'),
  };
  const leaseResolver = { resolve: (keyId) => keyId === 'guard-1' ? guard.publicKey : null };
  const headKeyResolver = { resolve: (keyId, alg) =>
    keyId === 'head-1' && alg === 'ed25519' ? head.publicKey : null };
  return {
    activationLease,
    capability: createPromotedTskAuthorityCapability({ activationLease, leaseResolver, headKeyResolver }),
    expected: { agentId, pairId, sourceClientId: 'source-client-1', sourceSecretDigest },
    guard,
    head,
    proof: {
      format: PROMOTED_TSK_CREDENTIAL_PROOF_FORMAT,
      agentId,
      pairId,
      commandId,
      activationLease,
      record,
      head: signedHead,
    },
  };
}

test('verifies an exact promoted credential proof and returns only public bindings', async () => {
  const value = fixture();
  const verified = await verifyPromotedTskCredentialProof(value.capability, value.proof, value.expected);
  assert.equal(verified.targetClientId, value.proof.record.mutation.clientId);
  assert.equal(verified.activationGrantDigest, value.activationLease.grantDigest);
  assert.equal(JSON.stringify(verified).includes('sharedSecret'), false);
});

test('capability is opaque and cannot be replaced with request callbacks or plain data', async () => {
  const value = fixture();
  await assert.rejects(
    verifyPromotedTskCredentialProof({ assertWritable: async () => true }, value.proof, value.expected),
    /invalid promoted TSK authority capability/,
  );
  assert.throws(() => createPromotedTskAuthorityCapability({
    activationLease: value.activationLease,
    leaseResolver: { resolve: () => value.guard.privateKey },
    headKeyResolver: { resolve: () => value.head.publicKey },
  }), /PUBLIC key|public KeyObject/);
});

test('rejects mutation, lease, principal, freshness, and head-signature substitutions', async () => {
  const vectors = [
    (v) => { v.proof.agentId = 'agent-2'; },
    (v) => { v.proof.record.mutation.publicMap.label = 'agent-1'; },
    (v) => { v.proof.record.mutation.clientId = v.expected.sourceClientId; v.proof.record.mutation.tumblerId = v.expected.sourceClientId; v.proof.record.mutation.publicMap.clientId = v.expected.sourceClientId; },
    (v) => { v.proof.record.mutation.secretDigest = v.expected.sourceSecretDigest; },
    (v) => { v.proof.record.sourceEpoch = '3'; },
    (v) => { v.proof.activationLease.commandId = 'cmd-other'; },
    (v) => { v.proof.head.signature = sign(null, Buffer.from(v.proof.head.headDigest, 'hex'), generateKeyPairSync('ed25519').privateKey).toString('base64url'); },
  ];
  for (const mutate of vectors) {
    const original = fixture();
    const candidate = { ...original, proof: clone(original.proof), expected: clone(original.expected) };
    mutate(candidate);
    await assert.rejects(
      verifyPromotedTskCredentialProof(original.capability, candidate.proof, candidate.expected),
    );
  }
});

test('snapshots untrusted proof before awaiting head verification', async () => {
  const value = fixture();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const delayedCapability = createPromotedTskAuthorityCapability({
    activationLease: value.activationLease,
    leaseResolver: { resolve: (keyId) => keyId === 'guard-1' ? value.guard.publicKey : null },
    headKeyResolver: {
      resolve(keyId, alg) {
        assert.equal(keyId, 'head-1');
        assert.equal(alg, 'ed25519');
        return value.head.publicKey;
      },
    },
  });
  const pending = verifyPromotedTskCredentialProof(delayedCapability, value.proof, value.expected);
  value.proof.record.mutation.publicMap.label = 'evil';
  release();
  const verified = await pending;
  assert.equal(verified.agentId, 'agent-1');
  assert.equal(verify(null, Buffer.from(value.proof.head.headDigest, 'hex'), value.head.publicKey,
    Buffer.from(value.proof.head.signature, 'base64url')), true);
  void gate;
});
