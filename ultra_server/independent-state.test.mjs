import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID, sign as edSign } from 'node:crypto';
import test from 'node:test';

import { Pool } from 'pg';
import { generateTumblerMap } from '@tsk/core';
import { canonicalOpDigest, canonicalize, streamHeadDigest } from '@tsk/server';

import {
  PgNonceTombstoneStore,
  ULTRA_INDEPENDENT_STATE_MANIFEST_DIGEST,
  ULTRA_INDEPENDENT_STATE_SCHEMA,
  attestIndependentStateSchema,
  assertIndependentStateReady,
  completeImportedTskReprovision,
  exportIndependentState,
  guardCountersignIndependentState,
  importIndependentState,
  readImportedTskReprovision,
  verifyIndependentStateBundle,
} from './independent-state.js';
import {
  PROMOTED_TSK_CREDENTIAL_PROOF_FORMAT,
  createPromotedTskAuthorityCapability,
} from './promoted-tsk-authority.js';
import { ULTRA_PG_SCHEMA, initializePgSchemas } from './runtime-stores.js';

const urlA = process.env.ULTRA_TEST_POSTGRES_URL_A;
const urlB = process.env.ULTRA_TEST_POSTGRES_URL_B;
if (!urlA || !urlB) throw new Error(
  'ULTRA_TEST_POSTGRES_URL_A and ULTRA_TEST_POSTGRES_URL_B are required (this drill never skips)',
);

async function resetUltraAuthority(pool) {
  await pool.query(`DROP TABLE IF EXISTS
    ultra_idempotency_redaction,ultra_ha_tsk_reprovision,ultra_ha_import_head,
    ultra_nonce_tombstones,ultra_idempotency,ultra_identity_bindings,
    ultra_tumbler_maps CASCADE`);
}

test('compiled catalog attestation rejects independent-state schema drift', async () => {
  const a = new Pool({ connectionString: urlA });
  const b = new Pool({ connectionString: urlB });
  try {
    await initializePgSchemas(a, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    await initializePgSchemas(b, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    assert.equal(await attestIndependentStateSchema(a), ULTRA_INDEPENDENT_STATE_MANIFEST_DIGEST);
    assert.equal(await attestIndependentStateSchema(b), ULTRA_INDEPENDENT_STATE_MANIFEST_DIGEST);
    await a.query('ALTER TABLE ultra_ha_import_head ADD COLUMN unauthorized_state TEXT');
    await assert.rejects(attestIndependentStateSchema(a), /schema attestation failed/);
    await assert.rejects(
      new PgNonceTombstoneStore(a).checkAndConsume(`drift-${randomUUID()}`, 60_000),
      /schema attestation failed/,
    );
  } finally {
    await a.query('ALTER TABLE ultra_ha_import_head DROP COLUMN IF EXISTS unauthorized_state');
    await a.end();
    await b.end();
  }
});

function frame(...parts) {
  const buffers = [];
  for (const part of parts) {
    if (part === null) { buffers.push(Buffer.from([0])); continue; }
    const value = Buffer.from(String(part), 'utf8');
    const length = Buffer.alloc(4); length.writeUInt32BE(value.length);
    buffers.push(Buffer.from([1]), length, value);
  }
  return Buffer.concat(buffers);
}

function signedProtocolEvidence({ commandId, sourceSystemId, targetSystemId, keys, targetEpoch = 1 }) {
  const bpcKeyId = 'bpc-snapshot-key-1';
  const bKeyId = 'b-key-1';
  const guardKeyId = 'tsk-guard-key-1';
  const bpcBare = {
    streamId: 'ultra-stream', commandId, targetEpoch, targetSourceEpoch: `epoch-${targetEpoch}`,
    targetSystemId: (BigInt(targetSystemId) + 1n).toString(),
    snapshotKeyId: bpcKeyId, manifestDigest: '1'.repeat(64),
    appliedSequence: 0, stateDigest: '2'.repeat(64), fencedDigest: '3'.repeat(64),
  };
  const bpcMessage = (digest) => frame(
    'bpc-promotion-readiness/v1', bpcBare.streamId, bpcBare.commandId,
    bpcBare.targetEpoch, bpcBare.targetSourceEpoch, bpcBare.targetSystemId,
    bpcBare.snapshotKeyId, bpcBare.manifestDigest, bpcBare.appliedSequence,
    bpcBare.stateDigest, bpcBare.fencedDigest, digest,
  );
  const attestationDigest = createHash('sha256').update(bpcMessage('')).digest('hex');
  const bpcPromotionAttestation = {
    ...bpcBare,
    keyId: bpcKeyId,
    attestationDigest,
    signature: edSign(null, Buffer.concat([
      frame('bpc-ha-key/v1', bpcKeyId), bpcMessage(attestationDigest),
    ]), keys.bpc.privateKey).toString('base64url'),
  };

  const bBare = {
    streamId: 'ultra-stream', commandId, epoch: targetEpoch - 1,
    sourceEpoch: `epoch-${targetEpoch - 1}`, n: 0,
    generationId: 'generation-1', frozenReceiptDigest: '4'.repeat(64),
    manifestDigest: '5'.repeat(64), manifestRoot: '6'.repeat(64), sourceSystemId,
    sourceKeyId: 'source-key', sourceSignature: 'source-signature',
    guardKeyId, guardSignature: 'guard-signature', signedHeadDigestAtN: '7'.repeat(64),
    sourceStateDigestAtN: '8'.repeat(64), bSystemId: targetSystemId,
  };
  const bMessage = (digest) => frame(
    'tsk_b_finalized/v2', bBare.streamId, bBare.commandId, bBare.epoch, bBare.sourceEpoch,
    bBare.n, bBare.generationId, bBare.frozenReceiptDigest, bBare.manifestDigest,
    bBare.manifestRoot, bBare.sourceSystemId, bBare.sourceKeyId, bBare.sourceSignature,
    bBare.guardKeyId, bBare.guardSignature, bBare.signedHeadDigestAtN,
    bBare.sourceStateDigestAtN, bBare.bSystemId, digest,
  );
  const receiptDigest = createHash('sha256').update(bMessage('')).digest('hex');
  const tskFinalizedReceipt = {
    ...bBare,
    receiptDigest,
    bKeyId,
    bSignature: edSign(null, Buffer.concat([
      frame('tsk_src_key', bKeyId), bMessage(receiptDigest),
    ]), keys.b.privateKey).toString('base64url'),
  };

  const leaseBare = {
    streamId: 'ultra-stream', leaseEpoch: targetEpoch, leaseStatus: 'active', holderNodeId: bKeyId,
    leaseId: 'lease-1', commandId, leaseExpiresAtMs: Date.now() + 300_000,
    leaseGrantSeq: 1, prevGrantDigest: null,
  };
  const leaseMessage = (digest) => frame(
    'tsk_source_lease/v1', leaseBare.streamId, leaseBare.leaseEpoch,
    leaseBare.leaseStatus, leaseBare.holderNodeId, leaseBare.leaseId,
    leaseBare.commandId, leaseBare.leaseExpiresAtMs, leaseBare.leaseGrantSeq,
    leaseBare.prevGrantDigest, digest,
  );
  const grantDigest = createHash('sha256').update(leaseMessage('')).digest('hex');
  const tskActivationLease = {
    ...leaseBare,
    grantDigest,
    guardKeyId,
    guardSignature: edSign(null, Buffer.concat([
      frame('tsk_src_key', guardKeyId), leaseMessage(grantDigest),
    ]), keys.guard.privateKey).toString('base64url'),
  };
  return { bpcPromotionAttestation, tskActivationLease, tskFinalizedReceipt };
}

function signedSourceCredentialBinding({
  agentId, agentPublicKeyHex, canonicalId, map, pairId, protocolEvidence, guardPublicKey,
}) {
  const headKeys = generateKeyPairSync('ed25519');
  const publicMap = JSON.parse(JSON.stringify(map));
  delete publicMap.sharedSecret;
  const lease = protocolEvidence.tskActivationLease;
  const mutation = {
    kind: 'tsk.credential.snapshot.v1',
    tumblerId: map.clientId,
    clientId: map.clientId,
    counter: 1,
    publicMap,
    publicMapDigest: createHash('sha256').update(canonicalize(publicMap), 'utf8').digest('hex'),
    secretDigest: createHash('sha256').update(map.sharedSecret, 'utf8').digest('hex'),
  };
  const record = {
    contractVersion: '1',
    streamId: lease.streamId,
    sourceEpoch: String(lease.leaseEpoch),
    sequence: 1,
    fenceToken: String(lease.leaseEpoch),
    opDigest: canonicalOpDigest({
      streamId: lease.streamId,
      sourceEpoch: String(lease.leaseEpoch),
      sequence: 1,
      fenceToken: String(lease.leaseEpoch),
      mutation,
    }),
    mutation,
  };
  const unsignedHead = {
    streamId: lease.streamId,
    sequence: 1,
    prevHeadDigest: '0'.repeat(64),
    opDigest: record.opDigest,
    keyId: 'source-credential-head-1',
    alg: 'ed25519',
  };
  const headDigest = streamHeadDigest(unsignedHead);
  const proof = {
    format: PROMOTED_TSK_CREDENTIAL_PROOF_FORMAT,
    agentId,
    agentPublicKeyHex,
    canonicalId,
    pairId,
    commandId: lease.commandId,
    activationLease: lease,
    record,
    head: {
      ...unsignedHead,
      headDigest,
      signature: edSign(null, Buffer.from(headDigest, 'hex'), headKeys.privateKey).toString('base64url'),
    },
  };
  return {
    authorityCapability: createPromotedTskAuthorityCapability({
      activationLease: lease,
      leaseResolver: { resolve: (keyId) => keyId === lease.guardKeyId ? guardPublicKey : null },
      headKeyResolver: { resolve: (keyId, alg) =>
        keyId === unsignedHead.keyId && alg === 'ed25519' ? headKeys.publicKey : null },
    }),
    expected: { agentId, agentPublicKeyHex, canonicalId, pairId, sourceClientId: map.clientId },
    proof,
  };
}

test('signed independent-state handoff is atomic, redacted, replay-safe, and rollback-safe', async () => {
  const a = new Pool({ connectionString: urlA });
  const b = new Pool({ connectionString: urlB });
  const source = generateKeyPairSync('ed25519');
  const guard = generateKeyPairSync('ed25519');
  const protocolKeys = {
    bpc: generateKeyPairSync('ed25519'),
    b: generateKeyPairSync('ed25519'),
    guard: generateKeyPairSync('ed25519'),
  };
  const suffix = randomUUID();
  // These two valid Ed25519 raw public keys share the same legacy 32-bit
  // display ID while retaining distinct canonical principals.
  const agentPublicKeyHex = '67bc101981dfd63eaf5af3c05448a9f8e40902ffe4d6c1d3813fad97f99c8b1f';
  const agentKeyDigest = createHash('sha256').update(
    Buffer.from(agentPublicKeyHex, 'hex'),
  ).digest('hex');
  const displayAgentId = `SC-${agentKeyDigest.slice(0, 8).toUpperCase()}`;
  const canonicalId = `SCID-${agentKeyDigest}`;
  const colliderPublicKeyHex = '3a1a9a9ab515f2baa029ee9df63f93cb65b97a446fb86b13da8824433bbb874b';
  const colliderKeyDigest = createHash('sha256').update(
    Buffer.from(colliderPublicKeyHex, 'hex'),
  ).digest('hex');
  const colliderDisplayAgentId = `SC-${colliderKeyDigest.slice(0, 8).toUpperCase()}`;
  const colliderCanonicalId = `SCID-${colliderKeyDigest}`;
  assert.equal(colliderDisplayAgentId, displayAgentId);
  assert.notEqual(colliderCanonicalId, canonicalId);
  const clusterId = `ha-${suffix}`;
  const commandId = `promote-${suffix}`;
  const pairId = `pair-${suffix}`;
  const safeKey = randomUUID();
  const secretKey = randomUUID();
  const forgedRedactionKey = randomUUID();
  const processingKey = randomUUID();
  const lockKey = `ultra-ha:${clusterId}:transition`;
  const nonceHash = createHash('sha256').update(`nonce-${suffix}`, 'utf8').digest('hex');
  let sourceMap;
  let targetMap;
  let failbackMap;
  try {
    await Promise.all([resetUltraAuthority(a), resetUltraAuthority(b)]);
    await initializePgSchemas(a, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    await initializePgSchemas(b, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
    const [systemA, systemB] = await Promise.all([
      a.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
      b.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
    ]);
    assert.notEqual(systemA.rows[0].id, systemB.rows[0].id);
    const protocolEvidence = signedProtocolEvidence({
      commandId,
      sourceSystemId: systemA.rows[0].id,
      targetSystemId: systemB.rows[0].id,
      keys: protocolKeys,
    });
    const bpcPromotionDigest = protocolEvidence.bpcPromotionAttestation.attestationDigest;
    const tskActivationDigest = protocolEvidence.tskActivationLease.grantDigest;
    const tskFinalizedDigest = protocolEvidence.tskFinalizedReceipt.receiptDigest;
    const resolvers = {
      bpcResolver: { resolve: (keyId) => keyId === 'bpc-snapshot-key-1' ? protocolKeys.bpc.publicKey : null },
      tskBResolver: { resolve: (keyId) => keyId === 'b-key-1' ? protocolKeys.b.publicKey : null },
      tskGuardResolver: { resolve: (keyId) => keyId === 'tsk-guard-key-1' ? protocolKeys.guard.publicKey : null },
    };

    sourceMap = generateTumblerMap();
    sourceMap.label = `agent:${canonicalId}`;
    sourceMap.status = 'active';
    targetMap = generateTumblerMap();
    targetMap.label = `agent:${canonicalId}`;
    targetMap.status = 'active';

    await a.query(
      `INSERT INTO ultra_identity_bindings
         (pair_id, tsk_client_id, agent_id, canonical_id, agent_public_key_hex)
       VALUES ($1,$2,$3,$4,$5)`,
      [pairId, sourceMap.clientId, displayAgentId, canonicalId, agentPublicKeyHex],
    );
    await a.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [sourceMap.clientId, JSON.stringify(sourceMap)],
    );
    await a.query(
      `INSERT INTO ultra_idempotency (idempotency_key, operation, agent_id, state, response)
       VALUES ($1,'safe-op',$3,'complete',$2::jsonb),
              ($4,'secret-op',$3,'complete',$5::jsonb),
              ($6,'forged-redaction-op',$3,'complete',$7::jsonb)`,
      [safeKey, JSON.stringify({ ok: true, pairId }), displayAgentId, secretKey,
       JSON.stringify({ ok: true, sharedSecret: 'must-not-cross-sites' }), forgedRedactionKey,
       JSON.stringify({ ok: false, error: 'SECRET_REPROVISION_REQUIRED',
         originalResponseDigest: 'a'.repeat(64) })],
    );
    const nonceA = new PgNonceTombstoneStore(a);
    assert.equal(await nonceA.checkAndConsume(`nonce-${suffix}`, 120_000), false);
    assert.equal(await nonceA.checkAndConsume(`nonce-${suffix}`, 120_000), true);

    const exportInput = {
      advisoryLockKey: lockKey,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourceKeyId: 'source-key-1',
      sourcePrivateKey: source.privateKey,
      protocolEvidence,
      sourceCredentialProofs: [signedSourceCredentialBinding({
        agentId: displayAgentId,
        agentPublicKeyHex,
        canonicalId,
        map: sourceMap,
        pairId,
        protocolEvidence,
        guardPublicKey: protocolKeys.guard.publicKey,
      })],
    };
    const unboundMap = generateTumblerMap();
    unboundMap.label = `agent:${canonicalId}`;
    unboundMap.status = 'active';
    await a.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [unboundMap.clientId, JSON.stringify(unboundMap)],
    );
    await assert.rejects(exportIndependentState(a, {
      ...exportInput, sourceCredentialProofs: [],
    }), /credential inventory/);
    await a.query('DELETE FROM ultra_tumbler_maps WHERE client_id=$1', [unboundMap.clientId]);

    const sourceBundle = await exportIndependentState(a, exportInput);
    const serialized = JSON.stringify(sourceBundle);
    assert.equal(serialized.includes('must-not-cross-sites'), false);
    assert.equal(serialized.includes(sourceMap.sharedSecret), false);
    assert.equal(sourceBundle.manifest.state.idempotency.find(
      (item) => item.idempotencyKey === secretKey,
    ).secretReprovisionRequired, true);
    assert.deepEqual(sourceBundle.manifest.state.identityBindings[0], {
      agentId: displayAgentId,
      agentPublicKeyHex,
      canonicalId,
      pairId,
      tskClientId: sourceMap.clientId,
    });
    const forgedRedaction = sourceBundle.manifest.state.idempotency.find(
      (item) => item.idempotencyKey === forgedRedactionKey,
    );
    assert.equal(forgedRedaction.secretReprovisionRequired, false);
    assert.equal(forgedRedaction.redactionProvenance, null);

    // Authority references are captured before proof verification yields. A
    // caller cannot swap the signing key or advisory-lock identity mid-export.
    const mutableExportInput = { ...exportInput };
    let lockReads = 0;
    Object.defineProperty(mutableExportInput, 'advisoryLockKey', {
      enumerable: true,
      get() {
        lockReads += 1;
        return lockReads === 1 ? lockKey : `${lockKey}:attacker`;
      },
    });
    const stableExportPending = exportIndependentState(a, mutableExportInput);
    mutableExportInput.sourcePrivateKey = generateKeyPairSync('ed25519').privateKey;
    const stableSourceBundle = await stableExportPending;
    assert.equal(lockReads, 1);
    assert.doesNotThrow(() => guardCountersignIndependentState(stableSourceBundle, {
      expectedCommandId: commandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'guard-key-stable',
      guardPrivateKey: guard.privateKey,
      ...resolvers,
    }));
    const bundle = guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: commandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'guard-key-1',
      guardPrivateKey: guard.privateKey,
      ...resolvers,
    });
    assert.throws(() => guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: commandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'same-custody-key',
      guardPrivateKey: source.privateKey,
      ...resolvers,
    }), /custody keys must be distinct/);
    assert.equal(verifyIndependentStateBundle(bundle, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
    }), true);
    const protocolTamper = structuredClone(bundle);
    protocolTamper.protocolEvidence.tskFinalizedReceipt.bSystemId = systemA.rows[0].id;
    assert.throws(() => verifyIndependentStateBundle(protocolTamper, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
    }), /digest mismatch/);

    const tampered = structuredClone(bundle);
    tampered.manifest.state.identityBindings[0].agentId = 'attacker';
    assert.throws(() => verifyIndependentStateBundle(tampered, {
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
    }), /digest mismatch/);
    await assert.rejects(importIndependentState(a, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
    }), /not independent/);

    const callerOwnedBundle = structuredClone(bundle);
    let releaseConnect;
    let connectEntered;
    const connectGate = new Promise((resolvePromise) => { releaseConnect = resolvePromise; });
    const entered = new Promise((resolvePromise) => { connectEntered = resolvePromise; });
    const delayedPool = {
      async connect() {
        connectEntered();
        await connectGate;
        return b.connect();
      },
    };
    const importPromise = importIndependentState(delayedPool, callerOwnedBundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
    });
    await entered;
    callerOwnedBundle.manifest.state.identityBindings[0].agentId = 'post-verify-attacker';
    callerOwnedBundle.manifest.state.credentialBindings[0].agentId = 'post-verify-attacker';
    releaseConnect();
    const imported = await importPromise;
    assert.equal(imported.idempotent, false);
    assert.equal((await b.query(
      'SELECT agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0].agent_id, displayAgentId);
    assert.equal((await importIndependentState(b, bundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
      tskActivationDigest,
      tskFinalizedDigest,
    })).idempotent, true);
    const provenance = (await b.query(
      'SELECT * FROM ultra_idempotency_redaction WHERE idempotency_key=$1', [secretKey],
    )).rows[0];
    assert.equal(provenance.original_response_digest,
      sourceBundle.manifest.state.idempotency.find((item) => item.idempotencyKey === secretKey).responseDigest);
    await b.query(
      "UPDATE ultra_idempotency_redaction SET original_response_digest=$2 WHERE idempotency_key=$1",
      [secretKey, 'b'.repeat(64)],
    );
    await assert.rejects(importIndependentState(b, bundle, {
      advisoryLockKey: lockKey, bpcPromotionDigest, clusterId, commandId, sourceEpoch: 1,
      sourcePublicKey: source.publicKey, guardPublicKey: guard.publicKey, ...resolvers,
      tskActivationDigest, tskFinalizedDigest,
    }), /redaction placeholder|rolled back or tampered/);
    await b.query('DELETE FROM ultra_idempotency_redaction WHERE idempotency_key=$1', [secretKey]);
    await assert.rejects(importIndependentState(b, bundle, {
      advisoryLockKey: lockKey, bpcPromotionDigest, clusterId, commandId, sourceEpoch: 1,
      sourcePublicKey: source.publicKey, guardPublicKey: guard.publicKey, ...resolvers,
      tskActivationDigest, tskFinalizedDigest,
    }), /rolled back or tampered/);
    await b.query(
      `INSERT INTO ultra_idempotency_redaction
         (idempotency_key, original_response_digest, source_manifest_digest, source_system_id,
          command_id, source_epoch, source_signature_digest, guard_signature_digest)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [provenance.idempotency_key, provenance.original_response_digest,
       provenance.source_manifest_digest, provenance.source_system_id, provenance.command_id,
       provenance.source_epoch, provenance.source_signature_digest, provenance.guard_signature_digest],
    );
    assert.deepEqual((await b.query(
      'SELECT tsk_client_id, agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0], { tsk_client_id: sourceMap.clientId, agent_id: displayAgentId });
    assert.deepEqual((await b.query(
      'SELECT response FROM ultra_idempotency WHERE idempotency_key=$1', [secretKey],
    )).rows[0].response.error, 'SECRET_REPROVISION_REQUIRED');
    const nonceB = new PgNonceTombstoneStore(b);
    assert.equal(await nonceB.checkAndConsume(`nonce-${suffix}`, 120_000), true);
    await b.query(
      `INSERT INTO ultra_idempotency (idempotency_key, operation, agent_id, state)
       VALUES ($1,'in-flight-op',$2,'processing')`,
      [processingKey, displayAgentId],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /in-flight idempotency/);
    await b.query('DELETE FROM ultra_idempotency WHERE idempotency_key=$1', [processingKey]);
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /requires TSK credential reprovisioning/);
    const importedIdentity = await readImportedTskReprovision(b, { clusterId, pairId });
    assert.equal(importedIdentity.agentPublicKeyHex, agentPublicKeyHex);
    assert.equal(importedIdentity.canonicalId, canonicalId);
    await assert.rejects(completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: colliderDisplayAgentId,
      agentPublicKeyHex: colliderPublicKeyHex,
      canonicalId: colliderCanonicalId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      clusterId,
      commandId,
      pairId,
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    }), /fresh active owned credential|binding mismatch/);
    await assert.rejects(completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: displayAgentId,
      agentPublicKeyHex,
      canonicalId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 2 }),
      clusterId,
      commandId,
      pairId,
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    }), /writer fence was lost/);
    const reprovision = await completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: displayAgentId,
      agentPublicKeyHex,
      canonicalId,
      clusterId,
      commandId,
      pairId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    });
    assert.equal(reprovision.idempotent, false);
    assert.equal(JSON.stringify(reprovision).includes(targetMap.sharedSecret), false);
    assert.equal((await completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: displayAgentId,
      agentPublicKeyHex,
      canonicalId,
      clusterId,
      commandId,
      pairId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    })).idempotent, true);
    assert.equal((await b.query(
      'SELECT tsk_client_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0].tsk_client_id, targetMap.clientId);
    assert.equal((await assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    })).targetSystemId, systemB.rows[0].id);
    await b.query(
      "UPDATE ultra_tumbler_maps SET map=jsonb_set(map, '{sharedSecret}', '\"attacker-secret-attacker-secret-00\"'::jsonb) WHERE client_id=$1",
      [targetMap.clientId],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /rolled back or tampered/);
    await assert.rejects(completeImportedTskReprovision(b, {
      advisoryLockKey: lockKey,
      agentId: displayAgentId,
      agentPublicKeyHex,
      canonicalId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 1 }),
      clusterId,
      commandId,
      pairId,
      sourceClientId: sourceMap.clientId,
      sourceEpoch: 1,
      targetMap,
    }), /rolled back or tampered/);
    await b.query('UPDATE ultra_tumbler_maps SET map=$2::jsonb WHERE client_id=$1', [
      targetMap.clientId, JSON.stringify(targetMap),
    ]);
    await b.query(
      "UPDATE ultra_tumbler_maps SET map=jsonb_set(map, '{status}', '\"revoked\"'::jsonb) WHERE client_id=$1",
      [targetMap.clientId],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /rolled back or tampered/);
    await b.query('UPDATE ultra_tumbler_maps SET map=$2::jsonb WHERE client_id=$1', [
      targetMap.clientId, JSON.stringify(targetMap),
    ]);
    await b.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [unboundMap.clientId, JSON.stringify(unboundMap)],
    );
    await assert.rejects(assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    }), /active unbound TSK credential/);
    await b.query('DELETE FROM ultra_tumbler_maps WHERE client_id=$1', [unboundMap.clientId]);
    await assert.rejects(
      b.query('UPDATE ultra_identity_bindings SET agent_id=$2 WHERE pair_id=$1', [pairId, 'attacker']),
      /ultra_identity_bindings_full_key_identity/,
    );
    assert.equal((await assertIndependentStateReady(b, {
      clusterId, commandId, sourceEpoch: 1, manifestDigest: bundle.manifestDigest,
    })).targetSystemId, systemB.rows[0].id);

    const fork = structuredClone(bundle);
    fork.manifestDigest = '0'.repeat(64);
    await assert.rejects(importIndependentState(b, fork, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest,
      clusterId,
      commandId,
      sourceEpoch: 1,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      tskActivationDigest,
    }), /digest mismatch/);

    // A complete failback is a new, higher-epoch handoff. It preserves the bound
    // principal while secrets are reprovisioned again on the recovered authority.
    const failbackCommandId = `failback-${suffix}`;
    const failbackEvidence = signedProtocolEvidence({
      commandId: failbackCommandId,
      sourceSystemId: systemB.rows[0].id,
      targetSystemId: systemA.rows[0].id,
      keys: protocolKeys,
      targetEpoch: 2,
    });
    const pendingCredential = await readImportedTskReprovision(b, {
      clusterId, pairId,
    });
    assert.equal(pendingCredential.sourceSecretDigest,
      createHash('sha256').update(sourceMap.sharedSecret, 'utf8').digest('hex'));
    const failbackSource = await exportIndependentState(b, {
      advisoryLockKey: lockKey,
      clusterId,
      commandId: failbackCommandId,
      sourceEpoch: 2,
      sourceKeyId: 'source-key-1',
      sourcePrivateKey: source.privateKey,
      protocolEvidence: failbackEvidence,
      sourceCredentialProofs: [signedSourceCredentialBinding({
        agentId: displayAgentId,
        agentPublicKeyHex,
        canonicalId,
        map: targetMap,
        pairId,
        protocolEvidence: failbackEvidence,
        guardPublicKey: protocolKeys.guard.publicKey,
      })],
    });
    const failbackBundle = guardCountersignIndependentState(failbackSource, {
      expectedCommandId: failbackCommandId,
      sourcePublicKey: source.publicKey,
      guardKeyId: 'guard-key-1',
      guardPrivateKey: guard.privateKey,
      ...resolvers,
    });

    // Model an isolated recovered A authority: schema remains attested, while
    // authoritative application state is restored only from the signed bundle.
    await a.query('DELETE FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]);
    await a.query('DELETE FROM ultra_tumbler_maps WHERE client_id IN ($1,$2)', [
      sourceMap.clientId, targetMap.clientId,
    ]);
    await a.query('DELETE FROM ultra_idempotency WHERE idempotency_key IN ($1,$2)', [safeKey, secretKey]);
    await a.query('DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1', [nonceHash]);
    await a.query('DELETE FROM ultra_ha_import_head WHERE cluster_id=$1', [clusterId]);

    const failbackImported = await importIndependentState(a, failbackBundle, {
      advisoryLockKey: lockKey,
      bpcPromotionDigest: failbackEvidence.bpcPromotionAttestation.attestationDigest,
      clusterId,
      commandId: failbackCommandId,
      sourceEpoch: 2,
      sourcePublicKey: source.publicKey,
      guardPublicKey: guard.publicKey,
      ...resolvers,
      tskActivationDigest: failbackEvidence.tskActivationLease.grantDigest,
      tskFinalizedDigest: failbackEvidence.tskFinalizedReceipt.receiptDigest,
    });
    assert.equal(failbackImported.targetSystemId, systemA.rows[0].id);
    await assert.rejects(assertIndependentStateReady(a, {
      clusterId,
      commandId: failbackCommandId,
      sourceEpoch: 2,
      manifestDigest: failbackBundle.manifestDigest,
    }), /requires TSK credential reprovisioning/);
    failbackMap = generateTumblerMap();
    failbackMap.label = `agent:${canonicalId}`;
    failbackMap.status = 'active';
    await completeImportedTskReprovision(a, {
      advisoryLockKey: lockKey,
      agentId: displayAgentId,
      agentPublicKeyHex,
      canonicalId,
      assertWritable: async () => ({ ok: true, fenceEpoch: 2 }),
      clusterId,
      commandId: failbackCommandId,
      pairId,
      sourceClientId: targetMap.clientId,
      sourceEpoch: 2,
      targetMap: failbackMap,
    });
    const failbackReady = await assertIndependentStateReady(a, {
      clusterId,
      commandId: failbackCommandId,
      sourceEpoch: 2,
      manifestDigest: failbackBundle.manifestDigest,
    });
    assert.equal(failbackReady.targetSystemId, systemA.rows[0].id);
    assert.deepEqual((await a.query(
      'SELECT tsk_client_id, agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    )).rows[0], { tsk_client_id: failbackMap.clientId, agent_id: displayAgentId });
    console.log('same-principal failback A -> B -> A completed; data-loss-RPO=0');
  } finally {
    for (const pool of [a, b]) {
      await pool.query('DELETE FROM ultra_ha_import_head WHERE cluster_id=$1', [clusterId]).catch(() => {});
      await pool.query('DELETE FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]).catch(() => {});
      await pool.query(
        'DELETE FROM ultra_tumbler_maps WHERE client_id IN ($1,$2,$3)',
        [sourceMap?.clientId ?? '', targetMap?.clientId ?? '', failbackMap?.clientId ?? ''],
      ).catch(() => {});
      await pool.query(
        'DELETE FROM ultra_idempotency WHERE idempotency_key IN ($1,$2,$3,$4)',
        [safeKey, secretKey, processingKey, forgedRedactionKey],
      ).catch(() => {});
      await pool.query('DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1', [nonceHash]).catch(() => {});
      await pool.end();
    }
  }
});
