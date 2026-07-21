import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign as edSign } from 'node:crypto';
import { access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import pg from 'pg';
import { Redis } from 'ioredis';

const HOUR_MS = 3_600_000;
const ID = /^[A-Za-z0-9_.:/-]{1,128}$/;

function requiredString(value, name) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function requiredId(value, name) {
  requiredString(value, name);
  if (!ID.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

function exactKeys(value, expected, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${name} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${name} has an invalid shape`);
  }
}

export async function loadPinnedTskModule(tskRoot) {
  const root = resolve(requiredString(tskRoot, 'tskRoot'));
  const entry = resolve(root, 'packages', 'server', 'dist', 'index.js');
  await access(entry);
  return import(pathToFileURL(entry).href);
}

async function loadReviewedTsk(tskRoot, expectedCommit) {
  const root = resolve(requiredString(tskRoot, 'tskRoot'));
  const expected = requiredString(expectedCommit, 'expectedTskCommit').toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(expected)) {
    throw new Error('expectedTskCommit must be a full 40-character commit');
  }
  const actual = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    encoding: 'utf8', windowsHide: true,
  }).trim().toLowerCase();
  if (actual !== expected) {
    throw new Error(`TSK checkout mismatch: expected ${expected}, got ${actual}`);
  }
  try {
    execFileSync('git', ['-C', root, 'diff', '--quiet', '--exit-code', 'HEAD', '--'], {
      stdio: 'ignore', windowsHide: true,
    });
  } catch {
    throw new Error('TSK checkout has tracked content changes; refusing unreviewed protocol code');
  }
  const server = await loadPinnedTskModule(root);
  const coreEntry = resolve(root, 'packages', 'core', 'dist', 'index.js');
  await access(coreEntry);
  const core = await import(pathToFileURL(coreEntry).href);
  return Object.freeze({ actualCommit: actual, server, core });
}

function signer(keyId, privateKey) {
  return Object.freeze({
    keyId,
    alg: 'ed25519',
    async sign(digest) {
      return edSign(null, Buffer.from(digest, 'utf8'), privateKey).toString('base64url');
    },
  });
}

function hexDigestSigner(keyId, privateKey) {
  return Object.freeze({
    keyId,
    alg: 'ed25519',
    async sign(digest) {
      if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
        throw new Error('credential head digest is invalid');
      }
      return edSign(null, Buffer.from(digest, 'hex'), privateKey).toString('base64url');
    },
  });
}

function hotpSanitizer(ContractValidationError) {
  return Object.freeze({
    sanitize(raw) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
          Object.getPrototypeOf(raw) !== Object.prototype ||
          Object.keys(raw).sort().join(',') !== 'counter,tumblerId' ||
          typeof raw.tumblerId !== 'string' || !ID.test(raw.tumblerId) ||
          !Number.isSafeInteger(raw.counter) || raw.counter < 0) {
        throw new ContractValidationError('invalid HOTP mutation');
      }
      return Object.freeze({ tumblerId: raw.tumblerId, counter: raw.counter });
    },
    assertSanitized(candidate) {
      if (!candidate || typeof candidate !== 'object' ||
          typeof candidate.tumblerId !== 'string' || !Number.isSafeInteger(candidate.counter)) {
        throw new ContractValidationError('unsanitized HOTP mutation');
      }
    },
  });
}

async function executeSchema(pool, ddl) {
  for (const statement of ddl.split(';').map((item) => item.trim()).filter(Boolean)) {
    await pool.query(statement);
  }
}

async function systemId(pool) {
  const result = await pool.query('SELECT system_identifier::text AS value FROM pg_control_system()');
  return String(result.rows[0].value);
}

async function dbClockMs(pool) {
  const result = await pool.query(
    'SELECT (extract(epoch from pg_catalog.clock_timestamp()) * 1000)::bigint AS value',
  );
  return Number(result.rows[0].value);
}

function runtimePostgresUrl(base, username, password) {
  const value = new URL(base);
  value.username = username;
  value.password = password;
  return value.toString();
}

async function ensureRuntimeRole(pool, role, password) {
  await pool.query(`
    DO $do$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='${role}') THEN
        CREATE ROLE ${role} LOGIN PASSWORD '${password}';
      ELSE
        ALTER ROLE ${role} LOGIN PASSWORD '${password}';
      END IF;
    END
    $do$
  `);
}

function derivedId(prefix, value) {
  return `${prefix}:${createHash('sha256').update(value).digest('hex').slice(0, 24)}`;
}

async function readPublicCredential(pool, streamId, clientId, expectedSequence) {
  const row = (await pool.query(
    `SELECT sequence::text,source_epoch,fence_token::text,op_digest,head_digest,
            mutation->>'clientId' AS client_id,
            mutation->>'publicMapDigest' AS public_map_digest,
            mutation->>'secretDigest' AS secret_digest
       FROM tsk_outbox_rows
      WHERE stream_id=$1 AND mutation->>'kind'='tsk.credential.snapshot.v1'
      ORDER BY sequence DESC LIMIT 1`,
    [streamId],
  )).rows[0];
  assert.equal(String(row?.client_id), clientId);
  for (const field of ['op_digest', 'head_digest', 'public_map_digest', 'secret_digest']) {
    assert.match(String(row?.[field]), /^[0-9a-f]{64}$/);
  }
  assert.equal(Number(row.sequence), expectedSequence);
  return Object.freeze({
    clientId: String(row.client_id),
    publicMapDigest: String(row.public_map_digest),
    operationDigest: String(row.op_digest),
    headDigest: String(row.head_digest),
    sequence: Number(row.sequence),
    sourceEpoch: String(row.source_epoch),
    fenceEpoch: Number(row.fence_token),
    status: 'active',
  });
}

function createMaterial() {
  return Object.freeze({
    guard: generateKeyPairSync('ed25519'),
    source: generateKeyPairSync('ed25519'),
    aHead: generateKeyPairSync('ed25519'),
    sourceCredentialHead: generateKeyPairSync('ed25519'),
    bHead: generateKeyPairSync('ed25519'),
    credentialHead: generateKeyPairSync('ed25519'),
    bReceipt: generateKeyPairSync('ed25519'),
    controlSecret: Buffer.alloc(32, 0x5d),
  });
}

function validateOptions(options) {
  exactKeys(options, [
    'aPostgresUrl', 'bPostgresUrl', 'controlPostgresUrl', 'destructiveReset',
    'commandId', 'expectedTskCommit', 'redisUrl', 'streamId', 'tskRoot',
  ], 'TSK live-composition options');
  if (options.destructiveReset !== true) {
    throw new Error('destructiveReset=true is required for dedicated acceptance databases');
  }
  return Object.freeze({
    tskRoot: resolve(requiredString(options.tskRoot, 'tskRoot')),
    aPostgresUrl: requiredString(options.aPostgresUrl, 'aPostgresUrl'),
    bPostgresUrl: requiredString(options.bPostgresUrl, 'bPostgresUrl'),
    controlPostgresUrl: requiredString(options.controlPostgresUrl, 'controlPostgresUrl'),
    redisUrl: requiredString(options.redisUrl, 'redisUrl'),
    streamId: requiredId(options.streamId, 'streamId'),
    commandId: requiredId(options.commandId, 'commandId'),
    expectedTskCommit: requiredString(options.expectedTskCommit, 'expectedTskCommit').toLowerCase(),
  });
}

/**
 * Execute the pinned TSK public API's complete A -> B activation lifecycle.
 *
 * The three PostgreSQL URLs must name dedicated, independent databases. This
 * function resets the governed TSK tables in them and deliberately refuses to
 * run unless destructiveReset=true is supplied. No protocol artifact is
 * synthesized: the returned receipts and lease are values emitted and verified
 * by the pinned TSK implementation.
 */
export async function runTskLiveComposition(rawOptions) {
  const options = validateOptions(rawOptions);
  const reviewed = await loadReviewedTsk(options.tskRoot, options.expectedTskCommit);
  const tsk = reviewed.server;
  const { generateTumblerMap } = reviewed.core;
  const {
    TSK_OUTBOX_PG_SCHEMA, TSK_SOURCE_LEASE_SCHEMA, TSK_SOURCE_WITNESS_SCHEMA,
    TSK_RECEIVER_SCHEMA, TSK_RECEIVER_TABLES, HA_CONTROL_PG_SCHEMA,
    HA_CONTROL_TABLES, PgTskDurableOutbox, NodePostgresTransactor,
    ContractValidationError, provisionSchemaVersion, signLeaseGrant,
    installLeaseGrant, assertSourceFenceReady, emitSourceFrozenReceipt,
    buildSourceExportManifest, guardCountersignSourceExport, assertReceiverReady,
    stageAndFinalizeReceiverGeneration, verifyBFinalizedReceipt,
    provisionControlSchema, HaControlFencing, GuardSigner, RedisFencingStore,
    verifyLeaseGrant, TSK_CREDENTIAL_AUTHORITY_SCHEMA, PgHaTumblerMapStore,
    HmacCredentialMutationTicketSigner, assertCredentialAuthorityReady,
    provisionCredentialRuntimeMutationBoundary,
    assertCredentialRuntimeMutationBoundary, assertSchemaReady,
  } = tsk;

  for (const [name, value] of Object.entries({
    PgTskDurableOutbox, NodePostgresTransactor, provisionSchemaVersion,
    emitSourceFrozenReceipt, buildSourceExportManifest,
    stageAndFinalizeReceiverGeneration, HaControlFencing,
    PgHaTumblerMapStore, HmacCredentialMutationTicketSigner,
    provisionCredentialRuntimeMutationBoundary, assertCredentialRuntimeMutationBoundary,
    generateTumblerMap,
  })) {
    if (typeof value !== 'function') throw new Error(`pinned TSK export '${name}' is unavailable`);
  }

  const material = createMaterial();
  const keyIds = Object.freeze({
    guard: 'guard-live-1', source: 'source-live-1', aHead: 'head-a-live-1',
    sourceCredentialHead: 'credential-head-a-live-1',
    bHead: 'head-b-live-1', credentialHead: 'credential-head-b-live-1',
    bReceipt: 'receipt-b-live-1', control: 'control-live-1',
  });
  const publicKeys = new Map([
    [keyIds.guard, material.guard.publicKey],
    [keyIds.source, material.source.publicKey],
    [keyIds.aHead, material.aHead.publicKey],
    [keyIds.sourceCredentialHead, material.sourceCredentialHead.publicKey],
    [keyIds.bHead, material.bHead.publicKey],
    [keyIds.credentialHead, material.credentialHead.publicKey],
    [keyIds.bReceipt, material.bReceipt.publicKey],
  ]);
  const resolver = Object.freeze({ resolve: (keyId) => publicKeys.get(keyId) ?? null });
  const controlResolver = Object.freeze({
    resolve: (keyId) => keyId === keyIds.control ? Buffer.from(material.controlSecret) : null,
  });
  const sanitizer = hotpSanitizer(ContractValidationError);
  const aSigner = signer(keyIds.aHead, material.aHead.privateKey);
  const bSigner = signer(keyIds.bHead, material.bHead.privateKey);
  const credentialSigner = hexDigestSigner(
    keyIds.credentialHead, material.credentialHead.privateKey,
  );
  const sourceCredentialSigner = hexDigestSigner(
    keyIds.sourceCredentialHead, material.sourceCredentialHead.privateKey,
  );

  const aPool = new pg.Pool({
    connectionString: options.aPostgresUrl, max: 4, connectionTimeoutMillis: 10_000,
  });
  const bPool = new pg.Pool({
    connectionString: options.bPostgresUrl, max: 4, connectionTimeoutMillis: 10_000,
  });
  const controlPool = new pg.Pool({
    connectionString: options.controlPostgresUrl, max: 6, connectionTimeoutMillis: 10_000,
  });
  for (const pool of [aPool, bPool, controlPool]) pool.on('error', () => {});
  const redis = new Redis(options.redisUrl, {
    maxRetriesPerRequest: 2,
    connectTimeout: 10_000,
    lazyConnect: false,
  });
  redis.on('error', () => {});

  const redisKey = `enterprise28:tsk-live:${options.streamId}`;
  const aDb = new NodePostgresTransactor(aPool);
  const bDb = new NodePostgresTransactor(bPool);
  const controlDb = new NodePostgresTransactor(controlPool);
  const sourceEpoch = 'e1';
  const commandId = options.commandId;
  const targetEpoch = 1;
  const aNodeId = 'A';
  const leaseId = 'enterprise28-source-lease-1';
  const bNodeId = keyIds.bReceipt;
  const credentialStreamId = derivedId('tsk:credential', options.streamId);
  const sourceCredentialLeaseId = derivedId('lease-a', options.commandId);
  const targetCredentialLeaseId = derivedId('lease-b', options.commandId);
  const runtimeRole = 'tsk_enterprise28_runtime';
  const aRuntimePassword = randomBytes(24).toString('hex');
  const bRuntimePassword = randomBytes(24).toString('hex');
  let aRuntimePool;
  let bRuntimePool;

  try {
    const sourceDrop = 'DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, ' +
      'tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, ' +
      'tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, ' +
      'tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, ' +
      'tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history, ' +
      'tsk_credential_mutation_nonce, tsk_credential_mutation_key, ' +
      'tsk_credential_replica_maps, tsk_credential_maps CASCADE';
    const installSource = async (pool) => {
      await pool.query(sourceDrop);
      await executeSchema(pool, TSK_OUTBOX_PG_SCHEMA);
      await executeSchema(pool, TSK_SOURCE_LEASE_SCHEMA);
      await executeSchema(pool, TSK_SOURCE_WITNESS_SCHEMA);
    };
    await installSource(aPool);
    await aPool.query(TSK_CREDENTIAL_AUTHORITY_SCHEMA);
    await bPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
    await executeSchema(bPool, TSK_RECEIVER_SCHEMA);
    await installSource(bPool);
    await bPool.query(TSK_CREDENTIAL_AUTHORITY_SCHEMA);
    await controlPool.query(`DROP TABLE IF EXISTS ${HA_CONTROL_TABLES.join(', ')} CASCADE`);
    await executeSchema(controlPool, HA_CONTROL_PG_SCHEMA);
    await redis.del(redisKey);

    const systemIds = Object.freeze({
      sourceA: await systemId(aPool),
      receiverB: await systemId(bPool),
      control: await systemId(controlPool),
    });
    assert.equal(new Set(Object.values(systemIds)).size, 3, 'A, B, and control PostgreSQL must be independent');

    const aSchemaReady = await provisionSchemaVersion(aDb, 'public');
    await aPool.query(
      'INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1, 0)',
      [options.streamId],
    );
    await aPool.query(
      'INSERT INTO tsk_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
      [options.streamId, sourceEpoch],
    );
    const aGrant = signLeaseGrant(keyIds.guard, material.guard.privateKey, {
      streamId: options.streamId, leaseEpoch: 0, leaseStatus: 'active',
      holderNodeId: aNodeId, leaseId, commandId: 'enterprise28-grant-1',
      leaseExpiresAtMs: await dbClockMs(aPool) + HOUR_MS,
      leaseGrantSeq: 1, prevGrantDigest: null,
    });
    await aDb.transaction((exec) => installLeaseGrant(exec, resolver, aGrant));
    const aFenceReady = await assertSourceFenceReady(aDb, 'public', resolver, {
      streamId: options.streamId, holderNodeId: aNodeId,
      leaseId, grantDigest: aGrant.grantDigest,
    });
    const aOutbox = new PgTskDurableOutbox(aDb, aSchemaReady, {
      streamId: options.streamId, sanitizer, signer: aSigner,
      maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation',
    }, { resolver, controlToASkewBoundMs: 0, ready: aFenceReady });

    const mutations = [['T1', 1], ['T2', 5], ['T1', 2], ['T3', 9]];
    for (const [tumblerId, counter] of mutations) {
      await aOutbox.withOutboxTx((tx) => aOutbox.appendInTx(tx, {
        streamId: options.streamId,
        rawMutation: { tumblerId, counter },
        fenceToken: 0n,
      }));
    }
    const n = mutations.length;

    // Establish the real pre-cutover credential authority on an isolated stream.
    // This keeps credential mutation records out of the generic snapshot stream.
    const aCredentialReady = await assertCredentialAuthorityReady(
      aDb, 'public', aSchemaReady,
    );
    await aPool.query(
      'INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1, 0)',
      [credentialStreamId],
    );
    await aPool.query(
      'INSERT INTO tsk_outbox_source_checkpoint ' +
      '(stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
      [credentialStreamId, 'credential-e1'],
    );
    const sourceCredentialGrant = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: credentialStreamId, leaseEpoch: 0, leaseStatus: 'active',
        holderNodeId: aNodeId, leaseId: sourceCredentialLeaseId,
        commandId: derivedId('credential-grant-a', options.commandId),
        leaseExpiresAtMs: await dbClockMs(aPool) + HOUR_MS,
        leaseGrantSeq: 1, prevGrantDigest: null,
      },
    );
    await aDb.transaction((exec) => installLeaseGrant(exec, resolver, sourceCredentialGrant));
    await ensureRuntimeRole(aPool, runtimeRole, aRuntimePassword);
    const aMutationSecret = randomBytes(32);
    const aTicketSigner = new HmacCredentialMutationTicketSigner(
      'enterprise28-credential-source-1', aMutationSecret,
    );
    await provisionCredentialRuntimeMutationBoundary(
      aDb, 'public', runtimeRole, aTicketSigner.keyId, aMutationSecret,
    );
    aMutationSecret.fill(0);
    aRuntimePool = new pg.Pool({
      connectionString: runtimePostgresUrl(
        options.aPostgresUrl, runtimeRole, aRuntimePassword,
      ),
      max: 2,
      connectionTimeoutMillis: 10_000,
    });
    aRuntimePool.on('error', () => {});
    const aRuntimeDb = new NodePostgresTransactor(aRuntimePool, {
      maxSerializationRetries: 2,
    });
    const aRuntimeOutboxReady = await assertSchemaReady(aRuntimeDb, 'public');
    const aRuntimeCredentialReady = await assertCredentialAuthorityReady(
      aRuntimeDb, 'public', aRuntimeOutboxReady,
    );
    const aMutationBoundary = await assertCredentialRuntimeMutationBoundary(
      aRuntimeDb, 'public', aTicketSigner,
    );
    const aCredentialFenceReady = await assertSourceFenceReady(
      aRuntimeDb, 'public', resolver, {
        streamId: credentialStreamId,
        holderNodeId: sourceCredentialGrant.holderNodeId,
        leaseId: sourceCredentialGrant.leaseId,
        grantDigest: sourceCredentialGrant.grantDigest,
      },
    );
    const sourceCredentialStore = new PgHaTumblerMapStore(
      aRuntimeDb,
      aRuntimeOutboxReady,
      aRuntimeCredentialReady,
      aMutationBoundary,
      aTicketSigner,
      {
        streamId: credentialStreamId,
        sourceEpoch: 0,
        signer: sourceCredentialSigner,
      },
      { resolver, controlToASkewBoundMs: 0, ready: aCredentialFenceReady },
    );
    const sourceCredentialMap = generateTumblerMap({
      keyLength: 64, minTumblers: 2, maxTumblers: 2,
    });
    sourceCredentialMap.label = 'enterprise28:source-principal';
    sourceCredentialMap.status = 'active';
    await sourceCredentialStore.set(sourceCredentialMap.clientId, sourceCredentialMap);
    const publicCredentialSource = await readPublicCredential(
      aPool, credentialStreamId, sourceCredentialMap.clientId, 1,
    );
    assert.equal(
      JSON.stringify(publicCredentialSource).includes(sourceCredentialMap.sharedSecret),
      false,
    );
    const sourceCredentialRevocation = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: credentialStreamId, leaseEpoch: 0, leaseStatus: 'revoked',
        holderNodeId: aNodeId, leaseId: sourceCredentialLeaseId,
        commandId,
        leaseExpiresAtMs: sourceCredentialGrant.leaseExpiresAtMs,
        leaseGrantSeq: 2, prevGrantDigest: sourceCredentialGrant.grantDigest,
      },
    );
    await aDb.transaction((exec) => installLeaseGrant(
      exec, resolver, sourceCredentialRevocation,
    ));

    const revokedGrant = signLeaseGrant(keyIds.guard, material.guard.privateKey, {
      streamId: options.streamId, leaseEpoch: 0, leaseStatus: 'revoked',
      holderNodeId: aNodeId, leaseId, commandId,
      leaseExpiresAtMs: await dbClockMs(aPool) + HOUR_MS,
      leaseGrantSeq: 2, prevGrantDigest: aGrant.grantDigest,
    });
    await aDb.transaction((exec) => installLeaseGrant(exec, resolver, revokedGrant));

    const sourceFrozenReceipt = await emitSourceFrozenReceipt(aDb, 'public', {
      sourceKeyId: keyIds.source, sourcePrivateKey: material.source.privateKey,
      leaseResolver: resolver, headResolver: resolver,
    }, {
      streamId: options.streamId, commandId, epoch: 0, sourceNodeId: aNodeId,
    });
    assert.equal(sourceFrozenReceipt.n, n);

    const exported = await buildSourceExportManifest(aDb, 'public', {
      streamId: options.streamId, epoch: 0, commandId, sourceNodeId: aNodeId,
    }, {
      sourceKeyId: keyIds.source, sourcePrivateKey: material.source.privateKey,
      sanitizer, leaseResolver: resolver, headResolver: resolver,
      frozenReceipt: sourceFrozenReceipt, maxChunkItems: 4,
    });
    const countersigned = guardCountersignSourceExport(exported.bundle, exported.manifest, {
      guardKeyId: keyIds.guard, guardPrivateKey: material.guard.privateKey,
      sanitizer, sourceManifestResolver: resolver, headResolver: resolver,
      frozenResolver: resolver, frozenReceipt: sourceFrozenReceipt,
      expectedCommandId: commandId,
    });
    const bFinalizedReceipt = await stageAndFinalizeReceiverGeneration(
      bDb, 'public', await assertReceiverReady(bDb, 'public'),
      'enterprise28-generation-1', exported.bundle, countersigned,
      {
        sanitizer, sourceResolver: resolver, guardResolver: resolver,
        headResolver: resolver, frozenResolver: resolver, bVerifyResolver: resolver,
        frozenReceipt: sourceFrozenReceipt, expectedCommandId: commandId,
        bKeyId: keyIds.bReceipt, bPrivateKey: material.bReceipt.privateKey,
      },
    );
    verifyBFinalizedReceipt(resolver, bFinalizedReceipt);

    const controlReady = await provisionControlSchema(controlDb, 'public');
    const control = new HaControlFencing(
      controlDb,
      new GuardSigner(keyIds.control, Buffer.from(material.controlSecret)),
      controlResolver,
      controlReady,
      {
        minClaimRemainingMs: 5_000,
        sourceGuard: {
          keyId: keyIds.guard,
          privateKey: material.guard.privateKey,
          activationTtlMs: HOUR_MS,
        },
      },
    );
    const controlNow = () => dbClockMs(controlPool);
    await control.provision(options.streamId, 'enterprise28-genesis');
    await control.writeLease({
      streamId: options.streamId, leaseId, holderNodeId: aNodeId, epoch: 0,
      status: 'active', grantedMaxExpiryMs: await controlNow() - 5_000,
      grantCommandId: 'enterprise28-control-grant-1',
    });
    await control.beginPromotionIntent(options.streamId, commandId, targetEpoch);
    await control.bindSourceFenced(
      options.streamId, commandId, targetEpoch, sourceFrozenReceipt, resolver,
    );
    await control.writeLease({
      streamId: options.streamId, leaseId, holderNodeId: aNodeId, epoch: 0,
      status: 'revoked', grantedMaxExpiryMs: await controlNow() - 5_000,
      grantCommandId: 'enterprise28-control-revoke-1',
    });
    const fenceStore = new RedisFencingStore(redis, redisKey);
    await control.advanceEpoch(options.streamId, commandId, targetEpoch, 'Bnode', fenceStore, {
      safetyMarginMs: 0,
      claimExpiresAtMs: await controlNow() + HOUR_MS,
    });
    await control.markImporting(options.streamId, commandId, targetEpoch);
    await control.markReady(
      options.streamId, commandId, targetEpoch, bFinalizedReceipt, resolver,
    );
    await control.activate(options.streamId, commandId, targetEpoch);
    const activationLeaseGrant = await control.activateSource(
      options.streamId, commandId, targetEpoch, bFinalizedReceipt, resolver,
    );
    verifyLeaseGrant(resolver, activationLeaseGrant);
    assert.equal(activationLeaseGrant.holderNodeId, bNodeId);

    await bPool.query(
      'INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1, $2)',
      [options.streamId, targetEpoch],
    );
    await bPool.query(
      'INSERT INTO tsk_outbox_source_checkpoint ' +
      '(stream_id, source_epoch, sequence, head_digest) VALUES ($1, $2, $3, $4)',
      [options.streamId, sourceEpoch, n, bFinalizedReceipt.signedHeadDigestAtN],
    );
    await bDb.transaction((exec) => installLeaseGrant(exec, resolver, activationLeaseGrant));
    const bFenceReady = await assertSourceFenceReady(bDb, 'public', resolver, {
      streamId: options.streamId,
      holderNodeId: activationLeaseGrant.holderNodeId,
      leaseId: activationLeaseGrant.leaseId,
      grantDigest: activationLeaseGrant.grantDigest,
    });
    const bSchemaReady = await provisionSchemaVersion(bDb, 'public');
    const bOutbox = new PgTskDurableOutbox(bDb, bSchemaReady, {
      streamId: options.streamId, sanitizer, signer: bSigner,
      maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation',
    }, { resolver, controlToASkewBoundMs: 0, ready: bFenceReady });
    const bAppend = await bOutbox.withOutboxTx((tx) => bOutbox.appendInTx(tx, {
      streamId: options.streamId,
      rawMutation: { tumblerId: 'T9', counter: 1 },
      fenceToken: BigInt(targetEpoch),
    }));
    assert.equal(bAppend.head.sequence, n + 1);
    assert.equal(bAppend.head.prevHeadDigest, bFinalizedReceipt.signedHeadDigestAtN);

    // Exercise the promoted source through TSK's actual credential authority,
    // including its restricted runtime role and DB mutation-ticket boundary.
    const bCredentialReady = await assertCredentialAuthorityReady(
      bDb, 'public', bSchemaReady,
    );
    await bPool.query(
      'INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1, $2)',
      [credentialStreamId, targetEpoch],
    );
    await bPool.query(
      'INSERT INTO tsk_outbox_source_checkpoint ' +
      '(stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
      [credentialStreamId, 'credential-e2'],
    );
    const credentialActivationLeaseGrant = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: credentialStreamId, leaseEpoch: targetEpoch,
        leaseStatus: 'active', holderNodeId: bNodeId,
        leaseId: targetCredentialLeaseId, commandId,
        leaseExpiresAtMs: await dbClockMs(bPool) + HOUR_MS,
        leaseGrantSeq: 1, prevGrantDigest: null,
      },
    );
    verifyLeaseGrant(resolver, credentialActivationLeaseGrant);
    await bDb.transaction((exec) => installLeaseGrant(
      exec, resolver, credentialActivationLeaseGrant,
    ));
    await ensureRuntimeRole(bPool, runtimeRole, bRuntimePassword);
    const mutationSecret = randomBytes(32);
    const mutationTicketSigner = new HmacCredentialMutationTicketSigner(
      'enterprise28-credential-runtime-1', mutationSecret,
    );
    await provisionCredentialRuntimeMutationBoundary(
      bDb, 'public', runtimeRole, mutationTicketSigner.keyId, mutationSecret,
    );
    mutationSecret.fill(0);
    bRuntimePool = new pg.Pool({
      connectionString: runtimePostgresUrl(
        options.bPostgresUrl, runtimeRole, bRuntimePassword,
      ),
      max: 2,
      connectionTimeoutMillis: 10_000,
    });
    bRuntimePool.on('error', () => {});
    const runtimeDb = new NodePostgresTransactor(bRuntimePool, {
      maxSerializationRetries: 2,
    });
    const runtimeOutboxReady = await assertSchemaReady(runtimeDb, 'public');
    const runtimeCredentialReady = await assertCredentialAuthorityReady(
      runtimeDb, 'public', runtimeOutboxReady,
    );
    const mutationBoundary = await assertCredentialRuntimeMutationBoundary(
      runtimeDb, 'public', mutationTicketSigner,
    );
    const runtimeFenceReady = await assertSourceFenceReady(
      runtimeDb, 'public', resolver, {
        streamId: credentialStreamId,
        holderNodeId: credentialActivationLeaseGrant.holderNodeId,
        leaseId: credentialActivationLeaseGrant.leaseId,
        grantDigest: credentialActivationLeaseGrant.grantDigest,
      },
    );
    const credentialStore = new PgHaTumblerMapStore(
      runtimeDb,
      runtimeOutboxReady,
      runtimeCredentialReady,
      mutationBoundary,
      mutationTicketSigner,
      {
        streamId: credentialStreamId,
        sourceEpoch: targetEpoch,
        signer: credentialSigner,
      },
      { resolver, controlToASkewBoundMs: 0, ready: runtimeFenceReady },
    );
    const credentialMap = generateTumblerMap({
      keyLength: 64, minTumblers: 2, maxTumblers: 2,
    });
    credentialMap.label = 'enterprise28:reprovisioned-principal';
    credentialMap.status = 'active';
    await credentialStore.set(credentialMap.clientId, credentialMap);
    const persistedCredential = await credentialStore.get(credentialMap.clientId);
    assert.equal(persistedCredential?.clientId, credentialMap.clientId);
    assert.equal(persistedCredential?.status, 'active');
    const publicCredentialTarget = await readPublicCredential(
      bPool, credentialStreamId, credentialMap.clientId, 1,
    );
    assert.notEqual(
      publicCredentialTarget.clientId,
      publicCredentialSource.clientId,
      'site reprovisioning must mint a fresh target credential identity',
    );
    assert.notEqual(
      publicCredentialTarget.publicMapDigest,
      publicCredentialSource.publicMapDigest,
      'reprovisioned target must carry new public credential material',
    );
    assert.equal(
      JSON.stringify(publicCredentialTarget).includes(credentialMap.sharedSecret), false,
    );

    let staleCredentialWriterDenied = false;
    try {
      await sourceCredentialStore.set(sourceCredentialMap.clientId, sourceCredentialMap);
    } catch (error) {
      if (!/revoked|not writable|lease|fence|grant digest/i.test(
        String(error?.message ?? error),
      )) throw error;
      staleCredentialWriterDenied = true;
    }
    assert.equal(staleCredentialWriterDenied, true);

    let staleWriterDenied = false;
    try {
      await aOutbox.withOutboxTx((tx) => aOutbox.appendInTx(tx, {
        streamId: options.streamId,
        rawMutation: { tumblerId: 'T1', counter: 3 },
        fenceToken: 0n,
      }));
    } catch (error) {
      if (!/revoked|not writable|lease|fence/i.test(String(error?.message ?? error))) throw error;
      staleWriterDenied = true;
    }
    assert.equal(staleWriterDenied, true, 'old A writer must be denied');
    const aMaximum = Number((await aPool.query(
      'SELECT COALESCE(MAX(sequence), 0) AS value FROM tsk_outbox_rows WHERE stream_id=$1',
      [options.streamId],
    )).rows[0].value);
    assert.equal(aMaximum, n, 'old A wrote nothing after the frozen sequence');

    return Object.freeze({
      sourceFrozenReceipt,
      bFinalizedReceipt,
      activationLeaseGrant,
      systemIds,
      n,
      nextSequence: bAppend.head.sequence,
      nextHeadDigest: bAppend.head.streamHeadDigest,
      staleWriterDenied,
      staleCredentialWriterDenied,
      credentialStreamId,
      credentialSourceLeaseGrant: sourceCredentialGrant,
      credentialSourceRevocation: sourceCredentialRevocation,
      credentialActivationLeaseGrant,
      publicCredentialSource,
      publicCredentialTarget,
      // Backward-compatible alias for the promoted target credential.
      publicCredential: publicCredentialTarget,
      tskCommit: reviewed.actualCommit,
      publicKeys: Object.freeze({
        guard: material.guard.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        source: material.source.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        aHead: material.aHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        sourceCredentialHead: material.sourceCredentialHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        bHead: material.bHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        credentialHead: material.credentialHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        bReceipt: material.bReceipt.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      }),
      publicVerificationKeys: Object.freeze(Object.fromEntries(
        [...publicKeys.entries()].map(([keyId, key]) => [
          keyId,
          key.export({ type: 'spki', format: 'pem' }).toString(),
        ]),
      )),
    });
  } finally {
    await Promise.allSettled([
      redis.del(redisKey),
      redis.quit(),
      aPool.end(),
      bPool.end(),
      controlPool.end(),
      aRuntimePool?.end(),
      bRuntimePool?.end(),
    ]);
  }
}
