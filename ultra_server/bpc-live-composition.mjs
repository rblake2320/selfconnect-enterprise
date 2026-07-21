import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import Redis from 'ioredis';
import pg from 'pg';

const { Pool } = pg;

const DEFAULT_STREAM_ID = 'bpc:enterprise:live/v1';
const SOURCE_EPOCH_A = 'bpc-enterprise-epoch-1';
const SOURCE_EPOCH_B = 'bpc-enterprise-epoch-2';
const RUNTIME_ROLE = 'bpc_runtime_enterprise28';
const KEY_IDS = Object.freeze({
  guard: 'guard-enterprise-v1',
  source: 'source-enterprise-v1',
  nodeA: 'node-a-enterprise-v1',
  nodeB: 'node-b-enterprise-v1',
  mutation: 'mutation-enterprise-v1',
  seal: 'seal-enterprise-v1',
});

function requiredString(value, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${name} is required`);
  }
  return value;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function exactUrls(value, name, count) {
  if (!Array.isArray(value) || value.length !== count) {
    throw new TypeError(`${name} must contain exactly ${count} URLs`);
  }
  const normalized = value.map((entry, index) => requiredString(entry, `${name}[${index}]`));
  if (new Set(normalized).size !== count) {
    throw new TypeError(`${name} entries must be distinct`);
  }
  return normalized;
}

export function loadPinnedBpcModule(bpcRoot, expectedCommit) {
  const root = path.resolve(requiredString(bpcRoot, 'bpcRoot'));
  const expected = requiredString(expectedCommit, 'expectedBpcCommit').toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(expected)) {
    throw new TypeError('expectedBpcCommit must be a full 40-character commit');
  }
  const actual = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    encoding: 'utf8',
    windowsHide: true,
  }).trim().toLowerCase();
  if (actual !== expected) {
    throw new Error(`BPC checkout mismatch: expected ${expected}, got ${actual}`);
  }
  try {
    execFileSync('git', ['-C', root, 'diff', '--quiet', '--exit-code', 'HEAD', '--'], {
      stdio: 'ignore',
      windowsHide: true,
    });
  } catch {
    throw new Error('BPC checkout has tracked content changes; refusing unreviewed protocol code');
  }
  const distFile = path.join(root, 'packages', 'server', 'dist', 'index.js');
  if (!existsSync(distFile)) throw new Error(`pinned BPC dist is missing: ${distFile}`);
  return { actualCommit: actual, moduleUrl: pathToFileURL(distFile).href };
}

async function resetAuthority(pool, bpc) {
  await pool.query('DROP SCHEMA IF EXISTS bpc_ha CASCADE');
  await pool.query(`
    DROP TABLE IF EXISTS
      bpc_transport_nonce,bpc_pending,bpc_pairs,ha_outbox_rows,
      ha_outbox_applied,ha_outbox_fence,ha_outbox_source_checkpoint,
      ha_outbox_receiver_checkpoint,ha_outbox_publisher_lease,
      ha_outbox_quarantine,ha_outbox_meta
    CASCADE
  `);
  await pool.query(bpc.HA_OUTBOX_PG_SCHEMA);
  await pool.query(bpc.BPC_HA_SCHEMA);
}

async function systemId(pool) {
  const result = await pool.query(
    'SELECT system_identifier::text AS value FROM pg_catalog.pg_control_system()',
  );
  return String(result.rows[0]?.value ?? '');
}

function runtimeUrl(base, password) {
  const value = new URL(base);
  value.username = RUNTIME_ROLE;
  value.password = password;
  return value.toString();
}

async function recreateRuntimeRole(pool, password) {
  const owner = String((await pool.query('SELECT current_user AS value')).rows[0]?.value);
  if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(owner)) {
    throw new Error('PostgreSQL current_user is not a safe identifier');
  }
  const quotedOwner = `"${owner.replaceAll('"', '""')}"`;
  await pool.query(`
    DO $do$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='${RUNTIME_ROLE}') THEN
        EXECUTE 'REASSIGN OWNED BY ${RUNTIME_ROLE} TO ${quotedOwner}';
        EXECUTE 'DROP OWNED BY ${RUNTIME_ROLE}';
        EXECUTE 'DROP ROLE ${RUNTIME_ROLE}';
      END IF;
      EXECUTE 'CREATE ROLE ${RUNTIME_ROLE} LOGIN PASSWORD ''${password}''';
    END
    $do$
  `);
}

function pair(number) {
  return {
    id: `enterprise-pair-${number}`,
    name: `Enterprise Pair ${number}`,
    scope: 'read',
    mode: 'production',
    secretHash: Buffer.alloc(32, number).toString('base64url'),
    pubJwk: {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.alloc(32, number + 1).toString('base64url'),
      y: Buffer.alloc(32, number + 2).toString('base64url'),
    },
    status: 'active',
    created: 1_800_000_000_000 + number,
    lastActive: null,
    requests: 0,
    failedSigs: 0,
  };
}

function mutationTicketSigner(bpc, secret, keyring) {
  const codec = new bpc.Aes256GcmPairPayloadCodec(KEY_IDS.seal, keyring.resolveKey);
  return {
    keyId: KEY_IDS.mutation,
    async signTicket(request, context) {
      bpc.validateDbMutationPolicyContext(request, context, codec);
      return createHmac('sha256', secret).update([
        request.domain, request.keyId, request.nonce, request.streamId,
        request.epoch, request.leaseId, request.grantDigest, request.txid,
        request.expiresAtMs, request.sourceEpoch, request.sequence,
        request.opDigest, request.action, request.maxPendingRows,
        request.payloadDigest, request.policyDigest,
      ].join('|')).digest('hex');
    },
  };
}

function makePool(connectionString, max = 5) {
  const pool = new Pool({ connectionString, max });
  pool.on('error', () => {});
  return pool;
}

/**
 * Executes the reviewed BPC public HA lifecycle directly. This helper never
 * parses subprocess output and never constructs a promotion/readiness receipt;
 * all returned evidence is emitted by the pinned BPC protocol implementation.
 */
export async function runBpcLiveComposition(options) {
  if (!options || typeof options !== 'object') throw new TypeError('options are required');
  const postgresUrls = exactUrls(options.postgresUrls, 'postgresUrls', 3);
  const redisUrls = exactUrls(options.redisUrls, 'redisUrls', 3);
  const streamId = options.streamId ?? DEFAULT_STREAM_ID;
  const commandId = requiredString(options.commandId, 'commandId');
  const { actualCommit, moduleUrl } = loadPinnedBpcModule(
    options.bpcRoot,
    options.expectedBpcCommit,
  );
  const bpc = await import(moduleUrl);

  const pools = postgresUrls.map((url) => makePool(url));
  const [poolA, poolB, poolControl] = pools;
  const redisMembers = redisUrls.map((url) => {
    const client = new Redis(url, { maxRetriesPerRequest: 1 });
    client.on('error', () => {});
    return client;
  });
  const runtimePools = [];
  const sealKey = randomBytes(32);
  const mutationSecret = randomBytes(32);
  const runtimePassword = randomBytes(24).toString('hex');
  const { publicKey: guardPublic, privateKey: guardPrivate } = generateKeyPairSync('ed25519');
  const { publicKey: sourcePublic, privateKey: sourcePrivate } = generateKeyPairSync('ed25519');
  const { publicKey: nodeAPublic, privateKey: nodeAPrivate } = generateKeyPairSync('ed25519');
  const { publicKey: nodeBPublic, privateKey: nodeBPrivate } = generateKeyPairSync('ed25519');

  try {
    await Promise.all(redisMembers.map((client) => client.flushdb()));
    await Promise.all(pools.map((pool) => resetAuthority(pool, bpc)));

    const [idA, idB, idControl] = await Promise.all(pools.map(systemId));
    assert.equal(new Set([idA, idB, idControl]).size, 3, 'BPC requires three independent PostgreSQL authorities');

    const dbA = new bpc.NodePostgresTransactor(poolA);
    const dbB = new bpc.NodePostgresTransactor(poolB);
    const dbControl = new bpc.NodePostgresTransactor(poolControl);
    const [readyA, readyB] = await Promise.all([
      bpc.provisionSchemaVersion(dbA, 'public'),
      bpc.provisionSchemaVersion(dbB, 'public'),
    ]);
    const [haReadyA, haReadyB, haReadyControl] = await Promise.all([
      bpc.provisionBpcHaSchema(dbA),
      bpc.provisionBpcHaSchema(dbB),
      bpc.provisionBpcHaSchema(dbControl),
    ]);

    await Promise.all([
      recreateRuntimeRole(poolA, runtimePassword),
      recreateRuntimeRole(poolB, runtimePassword),
    ]);
    await Promise.all([
      poolA.query(
        'INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',
        [KEY_IDS.mutation, mutationSecret],
      ),
      poolB.query(
        'INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',
        [KEY_IDS.mutation, mutationSecret],
      ),
    ]);
    await Promise.all([
      bpc.provisionBpcRuntimeMutationBoundary(
        dbA, RUNTIME_ROLE, KEY_IDS.mutation, mutationSecret,
      ),
      bpc.provisionBpcRuntimeMutationBoundary(
        dbB, RUNTIME_ROLE, KEY_IDS.mutation, mutationSecret,
      ),
    ]);

    const poolRuntimeA = makePool(runtimeUrl(postgresUrls[0], runtimePassword));
    const poolRuntimeB = makePool(runtimeUrl(postgresUrls[1], runtimePassword));
    runtimePools.push(poolRuntimeA, poolRuntimeB);
    const dbRuntimeA = new bpc.NodePostgresTransactor(poolRuntimeA, {
      statementTimeoutMs: 350,
      transactionTimeoutMs: 500,
    });
    const dbRuntimeB = new bpc.NodePostgresTransactor(poolRuntimeB, {
      statementTimeoutMs: 350,
      transactionTimeoutMs: 500,
    });
    const [readyRuntimeA, readyRuntimeB, haReadyRuntimeA, haReadyRuntimeB] = await Promise.all([
      bpc.assertSchemaReady(dbRuntimeA, 'public'),
      bpc.assertSchemaReady(dbRuntimeB, 'public'),
      bpc.assertBpcHaSchemaReady(dbRuntimeA),
      bpc.assertBpcHaSchemaReady(dbRuntimeB),
    ]);

    await Promise.all([
      poolA.query(
        'INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',
        [streamId],
      ),
      poolA.query(
        'INSERT INTO ha_outbox_source_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
        [streamId, SOURCE_EPOCH_A],
      ),
      poolB.query(
        'INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',
        [streamId],
      ),
      poolB.query(
        'INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
        [streamId, SOURCE_EPOCH_A],
      ),
    ]);

    const resolver = {
      resolve(keyId) {
        if (keyId === KEY_IDS.guard) return guardPublic;
        if (keyId === KEY_IDS.source) return sourcePublic;
        if (keyId === KEY_IDS.nodeA) return nodeAPublic;
        if (keyId === KEY_IDS.nodeB) return nodeBPublic;
        return null;
      },
    };
    const nodeAIdentity = {
      keyId: KEY_IDS.nodeA,
      prove: async (challenge) => bpc.signNodeIdentityChallenge(
        KEY_IDS.nodeA, nodeAPrivate, challenge,
      ),
    };
    const nodeBIdentity = {
      keyId: KEY_IDS.nodeB,
      prove: async (challenge) => bpc.signNodeIdentityChallenge(
        KEY_IDS.nodeB, nodeBPrivate, challenge,
      ),
    };
    const keyring = {
      activeKeyId: KEY_IDS.seal,
      resolveKey(keyId) {
        if (keyId !== KEY_IDS.seal) throw new Error('unknown pair seal key');
        return sealKey;
      },
    };
    const ticketSigner = mutationTicketSigner(bpc, mutationSecret, keyring);

    const redisWitness = await bpc.PgRedisFenceWitness.open(
      dbControl, haReadyControl, resolver,
    );
    const fenceStore = await bpc.BpcRedisQuorumFenceStore.open(
      redisMembers, resolver, redisWitness, `bpc:enterprise28:${streamId}`,
    );
    const redisA = bpc.signRedisFenceRecord(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 1,
      nodeId: 'node-a',
      authoritySystemId: idA,
      nodeCredentialKeyId: KEY_IDS.nodeA,
      commandId: 'activate-a',
      claimedAtMs: Date.now(),
    });
    await redisWitness.bootstrapGenesis(redisA);
    assert.equal(await fenceStore.claim(redisA), true, 'BPC epoch-1 quorum claim failed');

    // Leave enough room for a slow CI database to commit the source mutation
    // and signed snapshot before the governed cutover intentionally waits out
    // the old authority window.
    const leaseExpiry = Date.now() + 6_000;
    const grantA = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 1,
      status: 'active',
      holderNodeId: 'node-a',
      leaseId: 'lease-a',
      commandId: 'grant-a',
      expiresAtMs: leaseExpiry,
      maxTransactionDurationMs: dbRuntimeA.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    await Promise.all([
      dbA.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantA)),
      dbControl.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantA)),
    ]);
    const bindingA = {
      streamId,
      epoch: 1,
      holderNodeId: 'node-a',
      authoritySystemId: idA,
      nodeCredentialKeyId: KEY_IDS.nodeA,
      leaseId: 'lease-a',
      grantDigest: grantA.grantDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisA),
      maxClockSkewMs: 25,
      maxTransactionDurationMs: dbRuntimeA.maxTransactionDurationMs,
    };
    const sourceFenceA = await bpc.PgSourceLeaseFence.open(
      dbRuntimeA, haReadyRuntimeA, resolver, bindingA, fenceStore,
      nodeAIdentity, ticketSigner,
    );
    const storeA = bpc.createHaPairAuthority(
      dbRuntimeA,
      readyRuntimeA,
      { streamId, fenceToken: 1n, keyring, maxPendingRows: 100 },
      sourceFenceA,
    );
    await storeA.set(pair(1));
    const finalSequence = Number((await poolA.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1',
      [streamId],
    )).rows[0]?.sequence);
    assert.equal(finalSequence, 1, 'BPC source did not commit the expected frozen sequence');

    const revokedA = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 1,
      status: 'revoked',
      holderNodeId: 'node-a',
      leaseId: 'lease-a',
      commandId: 'revoke-a',
      expiresAtMs: grantA.expiresAtMs,
      maxTransactionDurationMs: grantA.maxTransactionDurationMs,
      grantSeq: 2,
      prevDigest: grantA.grantDigest,
    });
    await Promise.all([
      dbA.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, revokedA)),
      dbControl.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, revokedA)),
    ]);
    const snapshot = await bpc.buildPairSnapshotBundle(
      dbA, streamId, finalSequence, KEY_IDS.source, sourcePrivate,
    );
    const applier = new bpc.PgPairMutationApplier(streamId, keyring);
    await bpc.importPairSnapshotBundle(
      dbB, resolver, snapshot, bpc.bpcPairMutationSanitizer, applier,
    );

    const redisB = bpc.signRedisFenceRecord(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 2,
      nodeId: 'node-b',
      authoritySystemId: idB,
      nodeCredentialKeyId: KEY_IDS.nodeB,
      commandId,
      claimedAtMs: Date.now(),
    });
    const controller = await bpc.BpcCutoverController.open(
      dbControl, haReadyControl, resolver, KEY_IDS.guard, guardPrivate, 25,
    );
    await controller.begin({
      streamId,
      commandId,
      previousEpoch: 1,
      targetEpoch: 2,
      targetNodeId: 'node-b',
      targetSourceEpoch: SOURCE_EPOCH_B,
      manifestDigest: bpc.pairSnapshotManifestDigest(snapshot.manifest),
      finalSourceSequence: snapshot.manifest.finalSequence,
      stateDigest: snapshot.manifest.stateDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisB),
      oldLeaseDigest: revokedA.grantDigest,
      oldLeaseExpiresAtMs: revokedA.expiresAtMs,
      sourceTransactionWindowMs: revokedA.maxTransactionDurationMs,
    });
    assert.equal(await fenceStore.claim(redisB), true, 'BPC epoch-2 quorum claim failed');
    const fenceReadyAt = revokedA.expiresAtMs + 25 + revokedA.maxTransactionDurationMs;
    if (Date.now() <= fenceReadyAt) {
      await new Promise((resolve) => setTimeout(resolve, fenceReadyAt - Date.now() + 20));
    }
    const fenced = await controller.markFenced(commandId, fenceStore);

    const grantB = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 2,
      status: 'active',
      holderNodeId: 'node-b',
      leaseId: 'lease-b',
      commandId: 'grant-b',
      expiresAtMs: Date.now() + 60_000,
      maxTransactionDurationMs: dbRuntimeB.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    await dbB.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantB));
    await bpc.promoteReceiverToSource(
      dbB, resolver, snapshot, bpc.bpcPairMutationSanitizer,
      2, SOURCE_EPOCH_B, resolver, fenced,
    );
    const readinessAttestation = await bpc.buildPromotionReadinessAttestation(
      dbB, fenced, snapshot.manifest.keyId, KEY_IDS.source, sourcePrivate,
    );
    bpc.verifyPromotionReadinessAttestation(resolver, readinessAttestation);
    const activeCutoverReceipt = await controller.markActive(
      commandId, readinessAttestation, resolver,
    );
    await bpc.installActiveCutoverReceipt(
      dbB, resolver, activeCutoverReceipt, readinessAttestation,
    );

    const bindingB = {
      streamId,
      epoch: 2,
      holderNodeId: 'node-b',
      authoritySystemId: idB,
      nodeCredentialKeyId: KEY_IDS.nodeB,
      leaseId: 'lease-b',
      grantDigest: grantB.grantDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisB),
      maxClockSkewMs: 25,
      maxTransactionDurationMs: dbRuntimeB.maxTransactionDurationMs,
      activationDigest: activeCutoverReceipt.stateDigestSigned,
    };
    const sourceFenceB = await bpc.PgSourceLeaseFence.open(
      dbRuntimeB, haReadyRuntimeB, resolver, bindingB, fenceStore,
      nodeBIdentity, ticketSigner,
    );
    const storeB = bpc.createHaPairAuthority(
      dbRuntimeB,
      readyRuntimeB,
      { streamId, fenceToken: 2n, keyring, maxPendingRows: 100 },
      sourceFenceB,
    );
    await storeB.set(pair(2));
    const promotedEpochSequence = Number((await poolB.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1',
      [streamId],
    )).rows[0]?.sequence);
    assert.equal(promotedEpochSequence, 1, 'promoted B did not originate its first mutation');

    let staleWriterDenied = false;
    try {
      await storeA.set(pair(3));
    } catch {
      staleWriterDenied = true;
    }
    assert.equal(staleWriterDenied, true, 'revoked old source A remained writable');
    assert.equal(Number((await poolA.query(
      "SELECT count(*)::int AS value FROM bpc_pairs WHERE id='enterprise-pair-3'",
    )).rows[0]?.value), 0, 'stale source mutation reached A');

    return deepFreeze({
      protocolCommit: actualCommit,
      streamId,
      systemIds: { sourceA: idA, promotedB: idB, control: idControl },
      finalSequence,
      nextLogicalSequence: finalSequence + 1,
      promotedSourceEpoch: SOURCE_EPOCH_B,
      promotedEpochSequence,
      staleWriterDenied,
      readinessAttestation: structuredClone(readinessAttestation),
      activeCutoverReceipt: structuredClone(activeCutoverReceipt),
      snapshotManifest: structuredClone(snapshot.manifest),
      publicKeys: {
        guard: guardPublic.export({ type: 'spki', format: 'pem' }).toString(),
        source: sourcePublic.export({ type: 'spki', format: 'pem' }).toString(),
      },
    });
  } finally {
    await Promise.allSettled(runtimePools.map((pool) => pool.end()));
    await Promise.allSettled(pools.map((pool) => pool.end()));
    for (const client of redisMembers) client.disconnect();
    sealKey.fill(0);
    mutationSecret.fill(0);
  }
}
