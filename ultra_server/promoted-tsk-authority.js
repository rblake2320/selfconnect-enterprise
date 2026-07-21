import { createHash, verify as cryptoVerify } from 'node:crypto';
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
const FORMAT = 'selfconnect-promoted-tsk-credential-proof-v1';
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

function assertExpected(expected) {
  exact(expected, ['agentId', 'pairId', 'sourceClientId', 'sourceSecretDigest'], 'expected binding');
  identifier(expected.agentId, 'expected.agentId');
  identifier(expected.pairId, 'expected.pairId');
  identifier(expected.sourceClientId, 'expected.sourceClientId');
  digest(expected.sourceSecretDigest, 'expected.sourceSecretDigest');
}

export function promotedTskCredentialLabel({ agentId, commandId, pairId }) {
  identifier(agentId, 'credential label agentId');
  identifier(commandId, 'credential label commandId');
  identifier(pairId, 'credential label pairId');
  return `ha-reprovision:${createHash('sha256').update(
    canonicalize({ agentId, commandId, pairId }), 'utf8',
  ).digest('hex')}`;
}

function assertProofShape(proof) {
  exact(proof, ['activationLease', 'agentId', 'commandId', 'format', 'head', 'pairId', 'record'], 'credential proof');
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
  identifier(proof.agentId, 'credential proof agentId');
  identifier(proof.pairId, 'credential proof pairId');
  identifier(proof.commandId, 'credential proof commandId');
  if (proof.agentId !== expected.agentId || proof.pairId !== expected.pairId) {
    throw new Error('credential proof principal binding mismatch');
  }

  verifyLeaseGrant(authority.leaseResolver, proof.activationLease);
  if (canonicalize(proof.activationLease) !== canonicalize(authority.activationLease)) {
    throw new Error('credential proof does not carry the configured activation lease');
  }
  const lease = proof.activationLease;
  if (lease.leaseStatus !== 'active' || proof.commandId !== lease.commandId ||
      proof.record.streamId !== lease.streamId || proof.record.sourceEpoch !== String(lease.leaseEpoch) ||
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

export const PROMOTED_TSK_CREDENTIAL_PROOF_FORMAT = FORMAT;
