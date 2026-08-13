import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import {
  assertHeaderConformant,
  assertStreamHeadBinds,
  canonicalOpDigest,
  canonicalize,
  credentialMutationSanitizer,
  verifyLeaseGrant,
} from '@tsk/server';

const ID = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const DISPLAY_AGENT_ID = /^SC-[0-9A-F]{8}$/;
const CANONICAL_AGENT_ID = /^SCID-[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const FORMAT = 'selfconnect-promoted-tsk-credential-proof-v2';
const CAPABILITIES = new WeakMap();

function exact(value, keys, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${name} must be exact plain data`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${name} has an invalid shape`);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
      throw new Error(`${name}.${key} must be an enumerable data property`);
    }
  }
  return value;
}

function snapshot(value, name, depth = 0) {
  if (depth > 32) throw new Error(`${name} exceeds the snapshot depth bound`);
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error(`${name} contains a non-safe integer`);
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new Error(`${name} must be a dense data array`);
    }
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || !names.includes('length')) {
      throw new Error(`${name} must be a dense data array`);
    }
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
        throw new Error(`${name}[${index}] must be an enumerable data property`);
      }
      copy.push(snapshot(descriptor.value, `${name}[${index}]`, depth + 1));
    }
    return Object.freeze(copy);
  }
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${name} must contain only plain data`);
  }
  const copy = {};
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
      throw new Error(`${name}.${key} must be an enumerable data property`);
    }
    copy[key] = snapshot(descriptor.value, `${name}.${key}`, depth + 1);
  }
  return Object.freeze(copy);
}

function identifier(value, name) {
  if (typeof value !== 'string' || !ID.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function digest(value, name) {
  if (typeof value !== 'string' || !HEX64.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function publicEd25519(value, name) {
  if (!value || value.type !== 'public' || value.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${name} must resolve to an Ed25519 public KeyObject`);
  }
  return value;
}

export function promotedTskAgentIdentity(value, name = 'promoted TSK agent identity') {
  const { agentId, agentPublicKeyHex, canonicalId } = value ?? {};
  if (typeof agentPublicKeyHex !== 'string' || !HEX64.test(agentPublicKeyHex)) {
    throw new Error(`${name}.agentPublicKeyHex must be a lowercase raw Ed25519 public key`);
  }
  if (typeof agentId !== 'string' || !DISPLAY_AGENT_ID.test(agentId)) {
    throw new Error(`${name}.agentId must be a display agent ID`);
  }
  if (typeof canonicalId !== 'string' || !CANONICAL_AGENT_ID.test(canonicalId)) {
    throw new Error(`${name}.canonicalId must be a canonical agent ID`);
  }
  const rawPublicKey = Buffer.from(agentPublicKeyHex, 'hex');
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
  publicEd25519(publicKey, `${name}.agentPublicKeyHex`);
  const fingerprint = createHash('sha256').update(rawPublicKey).digest('hex');
  if (agentId !== `SC-${fingerprint.slice(0, 8).toUpperCase()}` ||
      canonicalId !== `SCID-${fingerprint}`) {
    throw new Error(`${name} does not match its raw Ed25519 public key`);
  }
  return Object.freeze({ agentId, agentPublicKeyHex, canonicalId });
}

function assertExpected(expected) {
  exact(expected, [
    'agentId', 'agentPublicKeyHex', 'canonicalId', 'pairId', 'sourceClientId',
    'sourceSecretDigest',
  ], 'expected binding');
  promotedTskAgentIdentity(expected, 'expected binding');
  identifier(expected.pairId, 'expected.pairId');
  identifier(expected.sourceClientId, 'expected.sourceClientId');
  digest(expected.sourceSecretDigest, 'expected.sourceSecretDigest');
}

export function promotedTskCredentialLabel(value) {
  const identity = promotedTskAgentIdentity(value, 'credential label');
  const commandId = identifier(value.commandId, 'credential label commandId');
  const pairId = identifier(value.pairId, 'credential label pairId');
  return `ha-reprovision:${createHash('sha256').update(
    canonicalize({ ...identity, commandId, pairId }), 'utf8',
  ).digest('hex')}`;
}

function assertProofShape(proof) {
  exact(proof, [
    'activationLease', 'agentId', 'agentPublicKeyHex', 'canonicalId', 'commandId',
    'format', 'head', 'pairId', 'record',
  ], 'credential proof');
  assertLeaseShape(proof.activationLease, 'credential proof activationLease');
  exact(proof.record, [
    'contractVersion', 'fenceToken', 'mutation', 'opDigest', 'sequence', 'sourceEpoch', 'streamId',
  ], 'credential proof record');
  exact(proof.head, [
    'alg', 'headDigest', 'keyId', 'opDigest', 'prevHeadDigest', 'sequence', 'signature', 'streamId',
  ], 'credential proof head');
}

function assertLeaseShape(lease, name) {
  exact(lease, [
    'commandId', 'grantDigest', 'guardKeyId', 'guardSignature', 'holderNodeId',
    'leaseEpoch', 'leaseExpiresAtMs', 'leaseGrantSeq', 'leaseId', 'leaseStatus',
    'prevGrantDigest', 'streamId',
  ], name);
}

function normalizeConfiguration(configuration) {
  exact(configuration, ['activationLease', 'headKeyResolver', 'leaseResolver'], 'authority configuration');
  if (!configuration.leaseResolver || typeof configuration.leaseResolver.resolve !== 'function') {
    throw new Error('leaseResolver must implement resolve(keyId)');
  }
  if (!configuration.headKeyResolver || typeof configuration.headKeyResolver.resolve !== 'function') {
    throw new Error('headKeyResolver must implement resolve(keyId, alg)');
  }
  const activationLease = snapshot(configuration.activationLease, 'activationLease');
  assertLeaseShape(activationLease, 'activationLease');
  verifyLeaseGrant(configuration.leaseResolver, activationLease);
  if (activationLease.leaseStatus !== 'active') throw new Error('activation lease is not active');
  return Object.freeze({
    activationLease,
    headKeyResolver: configuration.headKeyResolver,
    leaseResolver: configuration.leaseResolver,
  });
}

/**
 * Mint a process-local authority capability from operator-configured public-key
 * resolvers and the exact signed activation lease. Request data can never mint
 * or substitute this capability, and no writable callback is accepted.
 */
export function createPromotedTskAuthorityCapability(configuration) {
  const state = normalizeConfiguration(configuration);
  const capability = Object.freeze({});
  CAPABILITIES.set(capability, state);
  return capability;
}

/**
 * Verify the exact terminal lease transition that freezes a promoted
 * credential authority for read-only export. The revocation must be the next
 * signed state after the configured active grant and must preserve the
 * stream/epoch/holder/lease identity while binding the failback command.
 */
export function verifyPromotedTskCredentialRevocation(
  capability, candidate, expectedCommandId,
) {
  const authority = requireCapability(capability);
  const revocation = snapshot(candidate, 'credential terminal revocation');
  assertLeaseShape(revocation, 'credential terminal revocation');
  identifier(expectedCommandId, 'expected revocation commandId');
  verifyLeaseGrant(authority.leaseResolver, revocation);
  const active = authority.activationLease;
  if (revocation.leaseStatus !== 'revoked' ||
      revocation.commandId !== expectedCommandId ||
      revocation.streamId !== active.streamId ||
      revocation.leaseEpoch !== active.leaseEpoch ||
      revocation.holderNodeId !== active.holderNodeId ||
      revocation.leaseId !== active.leaseId ||
      revocation.leaseExpiresAtMs !== active.leaseExpiresAtMs ||
      revocation.leaseGrantSeq !== active.leaseGrantSeq + 1 ||
      revocation.prevGrantDigest !== active.grantDigest) {
    throw new Error('credential terminal revocation does not continue the active authority');
  }
  return Object.freeze({
    activeGrantDigest: active.grantDigest,
    commandId: revocation.commandId,
    grantDigest: revocation.grantDigest,
    holderNodeId: revocation.holderNodeId,
    leaseEpoch: revocation.leaseEpoch,
    leaseGrantSeq: revocation.leaseGrantSeq,
    leaseId: revocation.leaseId,
    revocation,
    streamId: revocation.streamId,
  });
}

function requireCapability(capability) {
  const state = CAPABILITIES.get(capability);
  if (!state) throw new Error('invalid promoted TSK authority capability');
  return state;
}

/**
 * Strictly verify a public, secret-free credential proof produced by the
 * promoted PgHaTumblerMapStore ledger. The proof binds the exact active lease,
 * command, target epoch, agent/pair label, credential mutation, and signed
 * stream head. It grants no database writability by itself.
 */
export async function verifyPromotedTskCredentialProof(capability, candidate, expectedCandidate) {
  const authority = requireCapability(capability);
  const proof = snapshot(candidate, 'credential proof');
  const expected = snapshot(expectedCandidate, 'expected binding');
  assertExpected(expected);
  assertProofShape(proof);

  if (proof.format !== FORMAT) throw new Error('credential proof format is unsupported');
  promotedTskAgentIdentity(proof, 'credential proof');
  identifier(proof.pairId, 'credential proof pairId');
  identifier(proof.commandId, 'credential proof commandId');
  if (proof.agentId !== expected.agentId ||
      proof.canonicalId !== expected.canonicalId ||
      proof.agentPublicKeyHex !== expected.agentPublicKeyHex ||
      proof.pairId !== expected.pairId) {
    throw new Error('credential proof principal binding mismatch');
  }

  verifyLeaseGrant(authority.leaseResolver, proof.activationLease);
  if (canonicalize(proof.activationLease) !== canonicalize(authority.activationLease)) {
    throw new Error('credential proof does not carry the configured activation lease');
  }
  const lease = proof.activationLease;
  if (lease.leaseStatus !== 'active' || proof.commandId !== lease.commandId ||
      proof.record.streamId !== lease.streamId ||
      proof.record.fenceToken !== String(lease.leaseEpoch)) {
    throw new Error('credential proof is not bound to the promoted lease');
  }

  assertHeaderConformant(proof.record);
  credentialMutationSanitizer.assertSanitized(proof.record.mutation);
  const mutation = proof.record.mutation;
  if (mutation.kind !== 'tsk.credential.snapshot.v1' || mutation.counter < 1 ||
      mutation.clientId !== mutation.tumblerId || mutation.clientId === expected.sourceClientId ||
      mutation.publicMap.clientId !== mutation.clientId || mutation.publicMap.status !== 'active' ||
      mutation.publicMap.label !== promotedTskCredentialLabel(proof) ||
      mutation.secretDigest === expected.sourceSecretDigest) {
    throw new Error('credential proof does not bind a fresh active target credential');
  }
  if (canonicalOpDigest({
    streamId: proof.record.streamId,
    sourceEpoch: proof.record.sourceEpoch,
    sequence: proof.record.sequence,
    fenceToken: proof.record.fenceToken,
    mutation,
  }) !== proof.record.opDigest) {
    throw new Error('credential proof operation digest mismatch');
  }
  assertStreamHeadBinds(proof.record, proof.head);
  if (proof.head.alg !== 'ed25519' || !B64URL.test(proof.head.signature)) {
    throw new Error('credential proof head signature encoding or algorithm is unsupported');
  }
  const key = publicEd25519(
    authority.headKeyResolver.resolve(proof.head.keyId, proof.head.alg),
    'headKeyResolver',
  );
  if (!cryptoVerify(
    null,
    Buffer.from(proof.head.headDigest, 'hex'),
    key,
    Buffer.from(proof.head.signature, 'base64url'),
  )) {
    throw new Error('credential proof head signature is invalid');
  }

  return Object.freeze({
    activationGrantDigest: lease.grantDigest,
    agentId: proof.agentId,
    agentPublicKeyHex: proof.agentPublicKeyHex,
    canonicalId: proof.canonicalId,
    commandId: proof.commandId,
    headDigest: proof.head.headDigest,
    operationDigest: proof.record.opDigest,
    pairId: proof.pairId,
    publicMapDigest: mutation.publicMapDigest,
    secretDigest: mutation.secretDigest,
    sequence: proof.record.sequence,
    sourceEpoch: lease.leaseEpoch,
    streamId: lease.streamId,
    targetClientId: mutation.clientId,
  });
}

/** Verify the signed active source credential that an Enterprise export names. */
export async function verifySourceTskCredentialProof(capability, candidate, expectedCandidate) {
  const authority = requireCapability(capability);
  const proof = snapshot(candidate, 'source credential proof');
  const expected = snapshot(expectedCandidate, 'source expected binding');
  exact(expected, [
    'agentId', 'agentPublicKeyHex', 'canonicalId', 'pairId', 'sourceClientId',
  ], 'source expected binding');
  promotedTskAgentIdentity(expected, 'source expected binding');
  identifier(expected.pairId, 'source expected.pairId');
  identifier(expected.sourceClientId, 'source expected.sourceClientId');
  assertProofShape(proof);
  promotedTskAgentIdentity(proof, 'source credential proof');
  if (proof.format !== FORMAT || proof.agentId !== expected.agentId ||
      proof.canonicalId !== expected.canonicalId ||
      proof.agentPublicKeyHex !== expected.agentPublicKeyHex ||
      proof.pairId !== expected.pairId) {
    throw new Error('source credential proof principal/format mismatch');
  }
  verifyLeaseGrant(authority.leaseResolver, proof.activationLease);
  if (canonicalize(proof.activationLease) !== canonicalize(authority.activationLease)) {
    throw new Error('source credential proof does not carry the configured activation lease');
  }
  const lease = proof.activationLease;
  if (lease.leaseStatus !== 'active' || proof.commandId !== lease.commandId ||
      proof.record.streamId !== lease.streamId ||
      proof.record.fenceToken !== String(lease.leaseEpoch)) {
    throw new Error('source credential proof is not bound to its active lease');
  }
  assertHeaderConformant(proof.record);
  credentialMutationSanitizer.assertSanitized(proof.record.mutation);
  const mutation = proof.record.mutation;
  if (mutation.kind !== 'tsk.credential.snapshot.v1' || mutation.counter < 1 ||
      mutation.clientId !== mutation.tumblerId || mutation.clientId !== expected.sourceClientId ||
      mutation.publicMap.clientId !== mutation.clientId || mutation.publicMap.status !== 'active' ||
      mutation.publicMap.label !== `agent:${proof.canonicalId}`) {
    throw new Error('source credential proof does not bind the active source credential');
  }
  if (canonicalOpDigest({
    streamId: proof.record.streamId,
    sourceEpoch: proof.record.sourceEpoch,
    sequence: proof.record.sequence,
    fenceToken: proof.record.fenceToken,
    mutation,
  }) !== proof.record.opDigest) throw new Error('source credential proof operation digest mismatch');
  assertStreamHeadBinds(proof.record, proof.head);
  if (proof.head.alg !== 'ed25519' || !B64URL.test(proof.head.signature)) {
    throw new Error('source credential proof head signature encoding or algorithm is unsupported');
  }
  const key = publicEd25519(
    authority.headKeyResolver.resolve(proof.head.keyId, proof.head.alg),
    'source headKeyResolver',
  );
  if (!cryptoVerify(null, Buffer.from(proof.head.headDigest, 'hex'), key,
    Buffer.from(proof.head.signature, 'base64url'))) {
    throw new Error('source credential proof head signature is invalid');
  }
  return Object.freeze({
    activationGrantDigest: lease.grantDigest,
    agentId: proof.agentId,
    agentPublicKeyHex: proof.agentPublicKeyHex,
    canonicalId: proof.canonicalId,
    commandId: proof.commandId,
    headDigest: proof.head.headDigest,
    operationDigest: proof.record.opDigest,
    pairId: proof.pairId,
    publicMapDigest: mutation.publicMapDigest,
    secretDigest: mutation.secretDigest,
    sequence: proof.record.sequence,
    sourceEpoch: lease.leaseEpoch,
    streamId: lease.streamId,
    sourceClientId: mutation.clientId,
  });
}

export const PROMOTED_TSK_CREDENTIAL_PROOF_FORMAT = FORMAT;
