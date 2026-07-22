import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { execFileSync, fork } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import Redis from 'ioredis';
import pg from 'pg';

const { Pool } = pg;

const DEFAULT_STREAM_ID = 'bpc:enterprise:live/v1';
const SOURCE_EPOCH_A = 'bpc-enterprise-epoch-1';
const SOURCE_EPOCH_B = 'bpc-enterprise-epoch-2';
const SOURCE_EPOCH_A_FAILBACK = 'bpc-enterprise-epoch-3';
const SOURCE_EPOCH_B_REPEAT = 'bpc-enterprise-epoch-4';
const SOURCE_EPOCH_A_REPEAT = 'bpc-enterprise-epoch-5';
const SOURCE_EPOCH_B_RECOVERED = 'bpc-enterprise-epoch-6';
const RUNTIME_ROLE = 'bpc_runtime_enterprise28';
const AUTHORITY_ROLES = Object.freeze(['source-a', 'promoted-b', 'control']);
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

async function readAuthorityIdentity(client, role) {
  const result = await client.query(`
    SELECT system_identifier::text AS system_identifier
    FROM pg_catalog.pg_control_system()
  `);
  const systemIdentifier = String(result.rows[0]?.system_identifier ?? '');
  if (!/^[0-9]{1,20}$/.test(systemIdentifier)) {
    throw new Error(`PostgreSQL authority ${role} returned an invalid system identifier`);
  }
  return Object.freeze({ role, systemIdentifier });
}

const identitySet = (identities) => new Set(
  identities.map(({ systemIdentifier }) => systemIdentifier),
);

/**
 * Admit three independently initialized PostgreSQL authorities. One dedicated
 * connection per role is retained for the complete sampling window so routing
 * cannot splice identities between samples. Two identical snapshots are
 * required; a duplicate identity never becomes acceptable through retry.
 */
export async function admitPostgresAuthorities(pools, options = {}) {
  if (!Array.isArray(pools) || pools.length !== AUTHORITY_ROLES.length) {
    throw new TypeError('exactly three PostgreSQL authority pools are required');
  }
  const attempts = options.attempts ?? 4;
  const delayMs = options.delayMs ?? 100;
  if (!Number.isSafeInteger(attempts) || attempts < 2 || attempts > 20 ||
      !Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 5_000) {
    throw new TypeError('authority identity admission retry configuration is invalid');
  }
  const connected = await Promise.allSettled(pools.map((pool) => pool.connect()));
  const clients = connected.filter((result) => result.status === 'fulfilled')
    .map((result) => result.value);
  const connectFailure = connected.find((result) => result.status === 'rejected');
  if (connectFailure) {
    for (const client of clients) {
      try { client.release(); } catch { /* Preserve the primary connection failure. */ }
    }
    throw connectFailure.reason;
  }
  let operationError = null;
  try {
    let previous = null;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const sampled = await Promise.allSettled(clients.map(
        (client, index) => readAuthorityIdentity(client, AUTHORITY_ROLES[index]),
      ));
      const queryFailure = sampled.find((result) => result.status === 'rejected');
      if (queryFailure) throw queryFailure.reason;
      const current = sampled.map((result) => result.value);
      const stable = previous !== null && current.every((entry, index) =>
        entry.systemIdentifier === previous[index].systemIdentifier);
      if (stable) {
        if (identitySet(current).size !== AUTHORITY_ROLES.length) {
          const diagnostic = current.map(
            ({ role, systemIdentifier }) => `${role}=${systemIdentifier}`,
          ).join(',');
          throw new Error(
            `BPC requires three independent PostgreSQL authorities (${diagnostic})`,
          );
        }
        return Object.freeze({
          attempts: attempt,
          identities: Object.freeze(current),
        });
      }
      previous = current;
      if (attempt < attempts && delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    const diagnostic = previous.map(
      ({ role, systemIdentifier }) => `${role}=${systemIdentifier}`,
    ).join(',');
    throw new Error(`PostgreSQL authority identities did not stabilize (${diagnostic})`);
  } catch (error) {
    operationError = error;
    throw error;
  } finally {
    let releaseError = null;
    for (const client of clients) {
      try { client.release(); } catch (error) { releaseError ??= error; }
    }
    if (!operationError && releaseError) throw releaseError;
  }
}

function runtimeUrl(base, password) {
  const value = new URL(base);
  value.username = RUNTIME_ROLE;
  value.password = password;
  return value.toString();
}

function databaseUrl(base, database) {
  const value = new URL(base);
  value.pathname = `/${database}`;
  return value.toString();
}

async function createIsolatedDatabase(pool, database) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database)) {
    throw new TypeError('isolated database name is invalid');
  }
  await pool.query(`CREATE DATABASE "${database}" TEMPLATE template0`);
}

async function dropIsolatedDatabase(pool, database) {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(database)) return;
  await pool.query(
    'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname=$1 AND pid<>pg_catalog.pg_backend_pid()',
    [database],
  );
  await pool.query(`DROP DATABASE IF EXISTS "${database}"`);
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

async function proveStaleBpcWriterDeniedAfterRestart(config) {
  const directory = await mkdtemp(path.join(tmpdir(), 'bpc-stale-restart-'));
  const configPath = path.join(directory, 'input.json');
  await writeFile(configPath, JSON.stringify(config), { encoding: 'utf8', mode: 0o600 });
  const startedAt = Date.now();
  try {
    return await new Promise((resolvePromise, rejectPromise) => {
      const child = fork(new URL('./bpc-stale-writer-worker.mjs', import.meta.url),
        [configPath], {
          cwd: new URL('.', import.meta.url),
          stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
          windowsHide: true,
          execArgv: process.execArgv.filter((arg) => !arg.startsWith('--input-type')),
        });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        rejectPromise(new Error('stale BPC restart probe timed out'));
      }, 30_000);
      let evidence = null;
      let stderr = '';
      child.stderr?.setEncoding('utf8');
      child.stderr?.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-2_000); });
      child.once('message', (message) => {
        if (message?.kind === 'stale-bpc-writer-denied') evidence = message;
      });
      child.once('error', (error) => {
        clearTimeout(timer);
        rejectPromise(error);
      });
      child.once('close', (code, signal) => {
        clearTimeout(timer);
        if (code !== 0 || signal || !evidence || evidence.pid === process.pid ||
            evidence.denialCode !== 'source-fence-rejected' ||
            evidence.noCommittedEffect !== true ||
            !/^[0-9a-f]{64}$/.test(evidence.authorityDigest)) {
          rejectPromise(new Error(
            `stale BPC restart probe failed (code=${code}, signal=${signal ?? 'none'}): ${stderr.trim()}`,
          ));
          return;
        }
        resolvePromise(Object.freeze({ processRestarted: true,
          childPid: evidence.pid, denied: true,
          denialCode: evidence.denialCode, noCommittedEffect: true,
          authorityStateDigest: evidence.authorityDigest,
          rtoMs: Date.now() - startedAt }));
      });
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function makePool(connectionString, max = 5) {
  const pool = new Pool({ connectionString, max });
  pool.on('error', () => {});
  return pool;
}

async function awaitDatabaseClockAfter(pool, thresholdMs, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await pool.query(
      'SELECT (extract(epoch from pg_catalog.clock_timestamp()) * 1000)::bigint AS now_ms',
    );
    if (Number(result.rows[0].now_ms) > thresholdMs) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('control PostgreSQL clock did not pass the signed fencing threshold');
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
  const isolatedPools = [];
  const failbackDatabase = `bpc_failback_${randomBytes(8).toString('hex')}`;
  const repeatBDatabase = `bpc_repeat_b_${randomBytes(8).toString('hex')}`;
  const repeatADatabase = `bpc_repeat_a_${randomBytes(8).toString('hex')}`;
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

    const admittedAuthorities = await admitPostgresAuthorities(pools);
    const [idA, idB, idControl] = admittedAuthorities.identities.map(
      ({ systemIdentifier }) => systemIdentifier,
    );

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
    await awaitDatabaseClockAfter(poolControl, fenceReadyAt);
    const fenced = await controller.markFenced(commandId, fenceStore);

    const grantB = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 2,
      status: 'active',
      holderNodeId: 'node-b',
      leaseId: 'lease-b',
      commandId: 'grant-b',
      expiresAtMs: Date.now() + 6_000,
      maxTransactionDurationMs: dbRuntimeB.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    const grantBControl = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId: grantB.streamId,
      epoch: grantB.epoch,
      status: grantB.status,
      holderNodeId: grantB.holderNodeId,
      leaseId: grantB.leaseId,
      commandId: grantB.commandId,
      expiresAtMs: grantB.expiresAtMs,
      maxTransactionDurationMs: grantB.maxTransactionDurationMs,
      grantSeq: 3,
      prevDigest: revokedA.grantDigest,
    });
    await Promise.all([
      dbB.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantB)),
      dbControl.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantBControl)),
    ]);
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
    // The promoted epoch must carry a complete replayable state transition for
    // a later failback. Delete the inherited epoch-1 state, then originate the
    // epoch-2 state; replaying this epoch from an empty receiver reconstructs
    // the exact authoritative state rather than relying on an implicit base.
    await storeB.delete('enterprise-pair-1');
    await storeB.set(pair(2));
    const promotedEpochSequence = Number((await poolB.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1',
      [streamId],
    )).rows[0]?.sequence);
    assert.equal(promotedEpochSequence, 2, 'promoted B did not originate its complete epoch state');

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

    // Governed B -> A failback. B is frozen and its signed epoch-2 history is
    // replayed into a fresh isolated database on the same A PostgreSQL system.
    // Neither the old A database nor the live B authority is reset.
    const revokedB = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 2,
      status: 'revoked',
      holderNodeId: 'node-b',
      leaseId: 'lease-b',
      commandId: 'revoke-b-for-failback',
      expiresAtMs: grantB.expiresAtMs,
      maxTransactionDurationMs: grantB.maxTransactionDurationMs,
      grantSeq: 2,
      prevDigest: grantB.grantDigest,
    });
    const revokedBControl = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 2,
      status: 'revoked',
      holderNodeId: 'node-b',
      leaseId: 'lease-b',
      commandId: 'revoke-b-for-failback',
      expiresAtMs: grantBControl.expiresAtMs,
      maxTransactionDurationMs: grantBControl.maxTransactionDurationMs,
      grantSeq: 4,
      prevDigest: grantBControl.grantDigest,
    });
    await Promise.all([
      dbB.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, revokedB)),
      dbControl.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, revokedBControl)),
    ]);
    const snapshotB = await bpc.buildPairSnapshotBundle(
      dbB, streamId, promotedEpochSequence, KEY_IDS.source, sourcePrivate,
    );

    await createIsolatedDatabase(poolA, failbackDatabase);
    const failbackOwnerPool = makePool(databaseUrl(postgresUrls[0], failbackDatabase));
    isolatedPools.push(failbackOwnerPool);
    await resetAuthority(failbackOwnerPool, bpc);
    const dbFailbackOwner = new bpc.NodePostgresTransactor(failbackOwnerPool);
    await bpc.provisionSchemaVersion(dbFailbackOwner, 'public');
    await bpc.provisionBpcHaSchema(dbFailbackOwner);
    await failbackOwnerPool.query(
      'INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',
      [KEY_IDS.mutation, mutationSecret],
    );
    await bpc.provisionBpcRuntimeMutationBoundary(
      dbFailbackOwner, RUNTIME_ROLE, KEY_IDS.mutation, mutationSecret,
    );
    const failbackRuntimePool = makePool(runtimeUrl(
      databaseUrl(postgresUrls[0], failbackDatabase), runtimePassword,
    ));
    runtimePools.push(failbackRuntimePool);
    const dbFailbackRuntime = new bpc.NodePostgresTransactor(failbackRuntimePool, {
      statementTimeoutMs: 350,
      transactionTimeoutMs: 500,
    });
    const [readyFailbackRuntime, haReadyFailbackRuntime] = await Promise.all([
      bpc.assertSchemaReady(dbFailbackRuntime, 'public'),
      bpc.assertBpcHaSchemaReady(dbFailbackRuntime),
    ]);
    assert.equal(await systemId(failbackOwnerPool), idA, 'failback authority left the A PostgreSQL system');
    await Promise.all([
      failbackOwnerPool.query(
        'INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)', [streamId],
      ),
      failbackOwnerPool.query(
        'INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
        [streamId, SOURCE_EPOCH_B],
      ),
    ]);
    const failbackApplier = new bpc.PgPairMutationApplier(streamId, keyring);
    await bpc.importPairSnapshotBundle(
      dbFailbackOwner, resolver, snapshotB, bpc.bpcPairMutationSanitizer, failbackApplier,
    );

    const failbackCommandId = `${commandId}-failback`;
    const redisA3 = bpc.signRedisFenceRecord(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 3,
      nodeId: 'node-a',
      authoritySystemId: idA,
      nodeCredentialKeyId: KEY_IDS.nodeA,
      commandId: failbackCommandId,
      claimedAtMs: Date.now(),
    });
    await controller.begin({
      streamId,
      commandId: failbackCommandId,
      previousEpoch: 2,
      targetEpoch: 3,
      targetNodeId: 'node-a',
      targetSourceEpoch: SOURCE_EPOCH_A_FAILBACK,
      manifestDigest: bpc.pairSnapshotManifestDigest(snapshotB.manifest),
      finalSourceSequence: snapshotB.manifest.finalSequence,
      stateDigest: snapshotB.manifest.stateDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisA3),
      oldLeaseDigest: revokedBControl.grantDigest,
      oldLeaseExpiresAtMs: revokedBControl.expiresAtMs,
      sourceTransactionWindowMs: revokedBControl.maxTransactionDurationMs,
    });
    assert.equal(await fenceStore.claim(redisA3), true, 'BPC epoch-3 failback quorum claim failed');
    const failbackFenceReadyAt = revokedBControl.expiresAtMs + 25
      + revokedBControl.maxTransactionDurationMs;
    await awaitDatabaseClockAfter(poolControl, failbackFenceReadyAt);
    const failbackFenced = await controller.markFenced(failbackCommandId, fenceStore);
    const grantA3 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 3,
      status: 'active',
      holderNodeId: 'node-a',
      leaseId: 'lease-a-epoch-3',
      commandId: failbackCommandId,
      expiresAtMs: Date.now() + 60_000,
      maxTransactionDurationMs: dbFailbackRuntime.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    const grantA3Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId: grantA3.streamId,
      epoch: grantA3.epoch,
      status: grantA3.status,
      holderNodeId: grantA3.holderNodeId,
      leaseId: grantA3.leaseId,
      commandId: grantA3.commandId,
      expiresAtMs: grantA3.expiresAtMs,
      maxTransactionDurationMs: grantA3.maxTransactionDurationMs,
      grantSeq: 5,
      prevDigest: revokedBControl.grantDigest,
    });
    await Promise.all([
      dbFailbackOwner.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantA3)),
      dbControl.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantA3Control)),
    ]);
    await bpc.promoteReceiverToSource(
      dbFailbackOwner, resolver, snapshotB, bpc.bpcPairMutationSanitizer,
      3, SOURCE_EPOCH_A_FAILBACK, resolver, failbackFenced,
    );
    const failbackReadinessAttestation = await bpc.buildPromotionReadinessAttestation(
      dbFailbackOwner, failbackFenced, snapshotB.manifest.keyId, KEY_IDS.source, sourcePrivate,
    );
    bpc.verifyPromotionReadinessAttestation(resolver, failbackReadinessAttestation);
    const failbackActiveCutoverReceipt = await controller.markActive(
      failbackCommandId, failbackReadinessAttestation, resolver,
    );
    await bpc.installActiveCutoverReceipt(
      dbFailbackOwner, resolver, failbackActiveCutoverReceipt, failbackReadinessAttestation,
    );
    const sourceFenceA3 = await bpc.PgSourceLeaseFence.open(
      dbFailbackRuntime,
      haReadyFailbackRuntime,
      resolver,
      {
        streamId,
        epoch: 3,
        holderNodeId: 'node-a',
        authoritySystemId: idA,
        nodeCredentialKeyId: KEY_IDS.nodeA,
        leaseId: grantA3.leaseId,
        grantDigest: grantA3.grantDigest,
        redisClaimDigest: bpc.redisFenceRecordDigest(redisA3),
        maxClockSkewMs: 25,
        maxTransactionDurationMs: dbFailbackRuntime.maxTransactionDurationMs,
        activationDigest: failbackActiveCutoverReceipt.stateDigestSigned,
      },
      fenceStore,
      nodeAIdentity,
      ticketSigner,
    );
    const failbackStoreA = bpc.createHaPairAuthority(
      dbFailbackRuntime,
      readyFailbackRuntime,
      { streamId, fenceToken: 3n, keyring, maxPendingRows: 100 },
      sourceFenceA3,
    );
    // A promoted authority that may later hand off must originate a complete
    // replayable epoch state, not only its newly added pair.
    await failbackStoreA.delete('enterprise-pair-2');
    await failbackStoreA.set(pair(2));
    await failbackStoreA.set(pair(3));
    const failbackEpochSequence = Number((await failbackOwnerPool.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId],
    )).rows[0]?.sequence);
    assert.equal(failbackEpochSequence, 3,
      'failback A did not originate its complete epoch-3 state');
    assert.equal(Number((await failbackOwnerPool.query(
      "SELECT count(*)::int AS value FROM bpc_pairs WHERE id IN ('enterprise-pair-2','enterprise-pair-3')",
    )).rows[0]?.value), 2, 'failback A did not preserve and extend B state');
    let staleBWriterDenied = false;
    try {
      await storeB.set(pair(4));
    } catch {
      staleBWriterDenied = true;
    }
    assert.equal(staleBWriterDenied, true, 'revoked source B remained writable after failback');
    assert.equal(Number((await poolB.query(
      "SELECT count(*)::int AS value FROM bpc_pairs WHERE id='enterprise-pair-4'",
    )).rows[0]?.value), 0, 'stale B mutation committed after failback');

    // Repeat the exact lifecycle without resetting any prior authority. Revoke
    // epoch-3 A, replay its signed state into a fresh database on physical B,
    // and advance the same control/Redis chains to epoch 4.
    const repeatStartedAt = Date.now();
    const repeatForwardCommandId = `${commandId}-cycle-2-promote`;
    const repeatForwardRevokeCommandId = `${repeatForwardCommandId}-revoke-source`;
    const revokedA3 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 3,
      status: 'revoked',
      holderNodeId: 'node-a',
      leaseId: grantA3.leaseId,
      commandId: repeatForwardRevokeCommandId,
      expiresAtMs: grantA3.expiresAtMs,
      maxTransactionDurationMs: grantA3.maxTransactionDurationMs,
      grantSeq: 2,
      prevDigest: grantA3.grantDigest,
    });
    const revokedA3Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 3,
      status: 'revoked',
      holderNodeId: 'node-a',
      leaseId: grantA3Control.leaseId,
      commandId: repeatForwardRevokeCommandId,
      expiresAtMs: grantA3Control.expiresAtMs,
      maxTransactionDurationMs: grantA3Control.maxTransactionDurationMs,
      grantSeq: 6,
      prevDigest: grantA3Control.grantDigest,
    });
    await Promise.all([
      dbFailbackOwner.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, revokedA3)),
      dbControl.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, revokedA3Control)),
    ]);
    const snapshotA3 = await bpc.buildPairSnapshotBundle(
      dbFailbackOwner, streamId, failbackEpochSequence, KEY_IDS.source, sourcePrivate,
    );

    await createIsolatedDatabase(poolB, repeatBDatabase);
    const repeatBOwnerPool = makePool(databaseUrl(postgresUrls[1], repeatBDatabase));
    isolatedPools.push(repeatBOwnerPool);
    await resetAuthority(repeatBOwnerPool, bpc);
    const dbRepeatBOwner = new bpc.NodePostgresTransactor(repeatBOwnerPool);
    await bpc.provisionSchemaVersion(dbRepeatBOwner, 'public');
    await bpc.provisionBpcHaSchema(dbRepeatBOwner);
    await repeatBOwnerPool.query(
      'INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',
      [KEY_IDS.mutation, mutationSecret],
    );
    await bpc.provisionBpcRuntimeMutationBoundary(
      dbRepeatBOwner, RUNTIME_ROLE, KEY_IDS.mutation, mutationSecret,
    );
    const repeatBRuntimePool = makePool(runtimeUrl(
      databaseUrl(postgresUrls[1], repeatBDatabase), runtimePassword,
    ));
    runtimePools.push(repeatBRuntimePool);
    const dbRepeatBRuntime = new bpc.NodePostgresTransactor(repeatBRuntimePool, {
      statementTimeoutMs: 350,
      transactionTimeoutMs: 500,
    });
    const [readyRepeatBRuntime, haReadyRepeatBRuntime] = await Promise.all([
      bpc.assertSchemaReady(dbRepeatBRuntime, 'public'),
      bpc.assertBpcHaSchemaReady(dbRepeatBRuntime),
    ]);
    assert.equal(await systemId(repeatBOwnerPool), idB,
      'repeat promotion left the B PostgreSQL system');
    await Promise.all([
      repeatBOwnerPool.query(
        'INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,3)', [streamId],
      ),
      repeatBOwnerPool.query(
        'INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
        [streamId, SOURCE_EPOCH_A_FAILBACK],
      ),
    ]);
    const repeatBApplier = new bpc.PgPairMutationApplier(streamId, keyring);
    await bpc.importPairSnapshotBundle(
      dbRepeatBOwner, resolver, snapshotA3, bpc.bpcPairMutationSanitizer, repeatBApplier,
    );
    const redisB4 = bpc.signRedisFenceRecord(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 4,
      nodeId: 'node-b',
      authoritySystemId: idB,
      nodeCredentialKeyId: KEY_IDS.nodeB,
      commandId: repeatForwardCommandId,
      claimedAtMs: Date.now(),
    });
    await controller.begin({
      streamId,
      commandId: repeatForwardCommandId,
      previousEpoch: 3,
      targetEpoch: 4,
      targetNodeId: 'node-b',
      targetSourceEpoch: SOURCE_EPOCH_B_REPEAT,
      manifestDigest: bpc.pairSnapshotManifestDigest(snapshotA3.manifest),
      finalSourceSequence: snapshotA3.manifest.finalSequence,
      stateDigest: snapshotA3.manifest.stateDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisB4),
      oldLeaseDigest: revokedA3Control.grantDigest,
      oldLeaseExpiresAtMs: revokedA3Control.expiresAtMs,
      sourceTransactionWindowMs: revokedA3Control.maxTransactionDurationMs,
    });
    assert.equal(await fenceStore.claim(redisB4), true,
      'BPC epoch-4 repeat promotion quorum claim failed');
    const repeatForwardFenceReadyAt = revokedA3Control.expiresAtMs + 25
      + revokedA3Control.maxTransactionDurationMs;
    await awaitDatabaseClockAfter(poolControl, repeatForwardFenceReadyAt);
    const repeatForwardFenced = await controller.markFenced(
      repeatForwardCommandId, fenceStore,
    );
    const grantB4 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 4,
      status: 'active',
      holderNodeId: 'node-b',
      leaseId: 'lease-b-epoch-4',
      commandId: repeatForwardCommandId,
      expiresAtMs: Date.now() + 60_000,
      maxTransactionDurationMs: dbRepeatBRuntime.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    const grantB4Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId: grantB4.streamId,
      epoch: grantB4.epoch,
      status: grantB4.status,
      holderNodeId: grantB4.holderNodeId,
      leaseId: grantB4.leaseId,
      commandId: grantB4.commandId,
      expiresAtMs: grantB4.expiresAtMs,
      maxTransactionDurationMs: grantB4.maxTransactionDurationMs,
      grantSeq: 7,
      prevDigest: revokedA3Control.grantDigest,
    });
    await Promise.all([
      dbRepeatBOwner.transaction((exec) => bpc.installSourceLeaseGrant(exec, resolver, grantB4)),
      dbControl.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, grantB4Control)),
    ]);
    await bpc.promoteReceiverToSource(
      dbRepeatBOwner, resolver, snapshotA3, bpc.bpcPairMutationSanitizer,
      4, SOURCE_EPOCH_B_REPEAT, resolver, repeatForwardFenced,
    );
    const repeatForwardReadiness = await bpc.buildPromotionReadinessAttestation(
      dbRepeatBOwner, repeatForwardFenced, snapshotA3.manifest.keyId,
      KEY_IDS.source, sourcePrivate,
    );
    bpc.verifyPromotionReadinessAttestation(resolver, repeatForwardReadiness);
    const repeatForwardActive = await controller.markActive(
      repeatForwardCommandId, repeatForwardReadiness, resolver,
    );
    await bpc.installActiveCutoverReceipt(
      dbRepeatBOwner, resolver, repeatForwardActive, repeatForwardReadiness,
    );
    const sourceFenceB4 = await bpc.PgSourceLeaseFence.open(
      dbRepeatBRuntime,
      haReadyRepeatBRuntime,
      resolver,
      {
        streamId,
        epoch: 4,
        holderNodeId: 'node-b',
        authoritySystemId: idB,
        nodeCredentialKeyId: KEY_IDS.nodeB,
        leaseId: grantB4.leaseId,
        grantDigest: grantB4.grantDigest,
        redisClaimDigest: bpc.redisFenceRecordDigest(redisB4),
        maxClockSkewMs: 25,
        maxTransactionDurationMs: dbRepeatBRuntime.maxTransactionDurationMs,
        activationDigest: repeatForwardActive.stateDigestSigned,
      },
      fenceStore,
      nodeBIdentity,
      ticketSigner,
    );
    const repeatStoreB = bpc.createHaPairAuthority(
      dbRepeatBRuntime,
      readyRepeatBRuntime,
      { streamId, fenceToken: 4n, keyring, maxPendingRows: 100 },
      sourceFenceB4,
    );
    await repeatStoreB.delete('enterprise-pair-2');
    await repeatStoreB.delete('enterprise-pair-3');
    await repeatStoreB.set(pair(2));
    await repeatStoreB.set(pair(3));
    await repeatStoreB.set(pair(4));
    const repeatForwardSequence = Number((await repeatBOwnerPool.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId],
    )).rows[0]?.sequence);
    assert.equal(repeatForwardSequence, 5,
      'repeat B did not originate its complete epoch-4 state');
    let staleA3WriterDenied = false;
    try { await failbackStoreA.set(pair(40)); } catch { staleA3WriterDenied = true; }
    assert.equal(staleA3WriterDenied, true,
      'revoked epoch-3 A remained writable after repeat promotion');

    // Complete the second cycle by revoking B4 and returning the same bound
    // principal to a fresh authority database on physical A at epoch 5.
    const repeatReturnCommandId = `${commandId}-cycle-2-failback`;
    const repeatReturnRevokeCommandId = `${repeatReturnCommandId}-revoke-source`;
    const revokedB4 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 4,
      status: 'revoked',
      holderNodeId: 'node-b',
      leaseId: grantB4.leaseId,
      commandId: repeatReturnRevokeCommandId,
      expiresAtMs: grantB4.expiresAtMs,
      maxTransactionDurationMs: grantB4.maxTransactionDurationMs,
      grantSeq: 2,
      prevDigest: grantB4.grantDigest,
    });
    const revokedB4Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 4,
      status: 'revoked',
      holderNodeId: 'node-b',
      leaseId: grantB4Control.leaseId,
      commandId: repeatReturnRevokeCommandId,
      expiresAtMs: grantB4Control.expiresAtMs,
      maxTransactionDurationMs: grantB4Control.maxTransactionDurationMs,
      grantSeq: 8,
      prevDigest: grantB4Control.grantDigest,
    });
    await Promise.all([
      dbRepeatBOwner.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, revokedB4)),
      dbControl.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, revokedB4Control)),
    ]);
    const snapshotB4 = await bpc.buildPairSnapshotBundle(
      dbRepeatBOwner, streamId, repeatForwardSequence, KEY_IDS.source, sourcePrivate,
    );

    await createIsolatedDatabase(poolA, repeatADatabase);
    const repeatAOwnerPool = makePool(databaseUrl(postgresUrls[0], repeatADatabase));
    isolatedPools.push(repeatAOwnerPool);
    await resetAuthority(repeatAOwnerPool, bpc);
    const dbRepeatAOwner = new bpc.NodePostgresTransactor(repeatAOwnerPool);
    await bpc.provisionSchemaVersion(dbRepeatAOwner, 'public');
    await bpc.provisionBpcHaSchema(dbRepeatAOwner);
    await repeatAOwnerPool.query(
      'INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',
      [KEY_IDS.mutation, mutationSecret],
    );
    await bpc.provisionBpcRuntimeMutationBoundary(
      dbRepeatAOwner, RUNTIME_ROLE, KEY_IDS.mutation, mutationSecret,
    );
    const repeatARuntimePool = makePool(runtimeUrl(
      databaseUrl(postgresUrls[0], repeatADatabase), runtimePassword,
    ));
    runtimePools.push(repeatARuntimePool);
    const dbRepeatARuntime = new bpc.NodePostgresTransactor(repeatARuntimePool, {
      statementTimeoutMs: 350,
      transactionTimeoutMs: 500,
    });
    const [readyRepeatARuntime, haReadyRepeatARuntime] = await Promise.all([
      bpc.assertSchemaReady(dbRepeatARuntime, 'public'),
      bpc.assertBpcHaSchemaReady(dbRepeatARuntime),
    ]);
    assert.equal(await systemId(repeatAOwnerPool), idA,
      'repeat failback left the A PostgreSQL system');
    await Promise.all([
      repeatAOwnerPool.query(
        'INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,4)', [streamId],
      ),
      repeatAOwnerPool.query(
        'INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
        [streamId, SOURCE_EPOCH_B_REPEAT],
      ),
    ]);
    const repeatAApplier = new bpc.PgPairMutationApplier(streamId, keyring);
    await bpc.importPairSnapshotBundle(
      dbRepeatAOwner, resolver, snapshotB4, bpc.bpcPairMutationSanitizer, repeatAApplier,
    );
    const redisA5 = bpc.signRedisFenceRecord(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 5,
      nodeId: 'node-a',
      authoritySystemId: idA,
      nodeCredentialKeyId: KEY_IDS.nodeA,
      commandId: repeatReturnCommandId,
      claimedAtMs: Date.now(),
    });
    await controller.begin({
      streamId,
      commandId: repeatReturnCommandId,
      previousEpoch: 4,
      targetEpoch: 5,
      targetNodeId: 'node-a',
      targetSourceEpoch: SOURCE_EPOCH_A_REPEAT,
      manifestDigest: bpc.pairSnapshotManifestDigest(snapshotB4.manifest),
      finalSourceSequence: snapshotB4.manifest.finalSequence,
      stateDigest: snapshotB4.manifest.stateDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisA5),
      oldLeaseDigest: revokedB4Control.grantDigest,
      oldLeaseExpiresAtMs: revokedB4Control.expiresAtMs,
      sourceTransactionWindowMs: revokedB4Control.maxTransactionDurationMs,
    });
    assert.equal(await fenceStore.claim(redisA5), true,
      'BPC epoch-5 repeat failback quorum claim failed');
    const repeatReturnFenceReadyAt = revokedB4Control.expiresAtMs + 25
      + revokedB4Control.maxTransactionDurationMs;
    await awaitDatabaseClockAfter(poolControl, repeatReturnFenceReadyAt);
    const repeatReturnFenced = await controller.markFenced(
      repeatReturnCommandId, fenceStore,
    );
    const grantA5 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 5,
      status: 'active',
      holderNodeId: 'node-a',
      leaseId: 'lease-a-epoch-5',
      commandId: repeatReturnCommandId,
      expiresAtMs: Date.now() + 60_000,
      maxTransactionDurationMs: dbRepeatARuntime.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    const grantA5Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId: grantA5.streamId,
      epoch: grantA5.epoch,
      status: grantA5.status,
      holderNodeId: grantA5.holderNodeId,
      leaseId: grantA5.leaseId,
      commandId: grantA5.commandId,
      expiresAtMs: grantA5.expiresAtMs,
      maxTransactionDurationMs: grantA5.maxTransactionDurationMs,
      grantSeq: 9,
      prevDigest: revokedB4Control.grantDigest,
    });
    await Promise.all([
      dbRepeatAOwner.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, grantA5)),
      dbControl.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, grantA5Control)),
    ]);
    await bpc.promoteReceiverToSource(
      dbRepeatAOwner, resolver, snapshotB4, bpc.bpcPairMutationSanitizer,
      5, SOURCE_EPOCH_A_REPEAT, resolver, repeatReturnFenced,
    );
    const repeatReturnReadiness = await bpc.buildPromotionReadinessAttestation(
      dbRepeatAOwner, repeatReturnFenced, snapshotB4.manifest.keyId,
      KEY_IDS.source, sourcePrivate,
    );
    bpc.verifyPromotionReadinessAttestation(resolver, repeatReturnReadiness);
    const repeatReturnActive = await controller.markActive(
      repeatReturnCommandId, repeatReturnReadiness, resolver,
    );
    await bpc.installActiveCutoverReceipt(
      dbRepeatAOwner, resolver, repeatReturnActive, repeatReturnReadiness,
    );
    const sourceFenceA5 = await bpc.PgSourceLeaseFence.open(
      dbRepeatARuntime,
      haReadyRepeatARuntime,
      resolver,
      {
        streamId,
        epoch: 5,
        holderNodeId: 'node-a',
        authoritySystemId: idA,
        nodeCredentialKeyId: KEY_IDS.nodeA,
        leaseId: grantA5.leaseId,
        grantDigest: grantA5.grantDigest,
        redisClaimDigest: bpc.redisFenceRecordDigest(redisA5),
        maxClockSkewMs: 25,
        maxTransactionDurationMs: dbRepeatARuntime.maxTransactionDurationMs,
        activationDigest: repeatReturnActive.stateDigestSigned,
      },
      fenceStore,
      nodeAIdentity,
      ticketSigner,
    );
    const repeatStoreA = bpc.createHaPairAuthority(
      dbRepeatARuntime,
      readyRepeatARuntime,
      { streamId, fenceToken: 5n, keyring, maxPendingRows: 100 },
      sourceFenceA5,
    );
    await repeatStoreA.delete('enterprise-pair-2');
    await repeatStoreA.delete('enterprise-pair-3');
    await repeatStoreA.delete('enterprise-pair-4');
    await repeatStoreA.set(pair(2));
    await repeatStoreA.set(pair(3));
    await repeatStoreA.set(pair(4));
    await repeatStoreA.set(pair(5));
    const repeatReturnSequence = Number((await repeatAOwnerPool.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId],
    )).rows[0]?.sequence);
    assert.equal(repeatReturnSequence, 7,
      'repeat A did not originate its complete epoch-5 state');
    let staleB4WriterDenied = false;
    try { await repeatStoreB.set(pair(50)); } catch { staleB4WriterDenied = true; }
    assert.equal(staleB4WriterDenied, true,
      'revoked epoch-4 B remained writable after repeat failback');

    // Recover the exact stale B authority rather than replacing it with a new
    // logical database. A5 is terminally revoked, its complete committed state
    // is exported, B is reset to a non-authoritative recovered image, and only
    // the governed epoch-6 import/activation permits B's first new mutation.
    const recoveredStartedAt = Date.now();
    const recoveredCommandId = `${commandId}-recovered-site-promote`;
    const recoveredRevokeCommandId = `${recoveredCommandId}-revoke-source`;
    const revokedA5 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 5,
      status: 'revoked',
      holderNodeId: 'node-a',
      leaseId: grantA5.leaseId,
      commandId: recoveredRevokeCommandId,
      expiresAtMs: grantA5.expiresAtMs,
      maxTransactionDurationMs: grantA5.maxTransactionDurationMs,
      grantSeq: 2,
      prevDigest: grantA5.grantDigest,
    });
    const revokedA5Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 5,
      status: 'revoked',
      holderNodeId: 'node-a',
      leaseId: grantA5Control.leaseId,
      commandId: recoveredRevokeCommandId,
      expiresAtMs: grantA5Control.expiresAtMs,
      maxTransactionDurationMs: grantA5Control.maxTransactionDurationMs,
      grantSeq: 10,
      prevDigest: grantA5Control.grantDigest,
    });
    await Promise.all([
      dbRepeatAOwner.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, revokedA5)),
      dbControl.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, revokedA5Control)),
    ]);
    const snapshotA5 = await bpc.buildPairSnapshotBundle(
      dbRepeatAOwner, streamId, repeatReturnSequence, KEY_IDS.source, sourcePrivate,
    );

    // This is the same repeat-B database that was stale at epoch 4. Rebuild its
    // governed schema in place, import the complete A5 state, and retain its
    // PostgreSQL system identity as evidence that recovery did not substitute
    // a fresh authority.
    await resetAuthority(repeatBOwnerPool, bpc);
    const dbRecoveredBOwner = new bpc.NodePostgresTransactor(repeatBOwnerPool);
    await bpc.provisionSchemaVersion(dbRecoveredBOwner, 'public');
    await bpc.provisionBpcHaSchema(dbRecoveredBOwner);
    await repeatBOwnerPool.query(
      'INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',
      [KEY_IDS.mutation, mutationSecret],
    );
    await bpc.provisionBpcRuntimeMutationBoundary(
      dbRecoveredBOwner, RUNTIME_ROLE, KEY_IDS.mutation, mutationSecret,
    );
    const [readyRecoveredBRuntime, haReadyRecoveredBRuntime] = await Promise.all([
      bpc.assertSchemaReady(dbRepeatBRuntime, 'public'),
      bpc.assertBpcHaSchemaReady(dbRepeatBRuntime),
    ]);
    assert.equal(await systemId(repeatBOwnerPool), idB,
      'recovered B did not retain the stale authority PostgreSQL system');
    await Promise.all([
      repeatBOwnerPool.query(
        'INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,5)', [streamId],
      ),
      repeatBOwnerPool.query(
        'INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',
        [streamId, SOURCE_EPOCH_A_REPEAT],
      ),
    ]);
    const recoveredBApplier = new bpc.PgPairMutationApplier(streamId, keyring);
    await bpc.importPairSnapshotBundle(
      dbRecoveredBOwner, resolver, snapshotA5,
      bpc.bpcPairMutationSanitizer, recoveredBApplier,
    );
    const redisB6 = bpc.signRedisFenceRecord(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 6,
      nodeId: 'node-b',
      authoritySystemId: idB,
      nodeCredentialKeyId: KEY_IDS.nodeB,
      commandId: recoveredCommandId,
      claimedAtMs: Date.now(),
    });
    await controller.begin({
      streamId,
      commandId: recoveredCommandId,
      previousEpoch: 5,
      targetEpoch: 6,
      targetNodeId: 'node-b',
      targetSourceEpoch: SOURCE_EPOCH_B_RECOVERED,
      manifestDigest: bpc.pairSnapshotManifestDigest(snapshotA5.manifest),
      finalSourceSequence: snapshotA5.manifest.finalSequence,
      stateDigest: snapshotA5.manifest.stateDigest,
      redisClaimDigest: bpc.redisFenceRecordDigest(redisB6),
      oldLeaseDigest: revokedA5Control.grantDigest,
      oldLeaseExpiresAtMs: revokedA5Control.expiresAtMs,
      sourceTransactionWindowMs: revokedA5Control.maxTransactionDurationMs,
    });
    assert.equal(await fenceStore.claim(redisB6), true,
      'BPC recovered-site epoch-6 quorum claim failed');
    await awaitDatabaseClockAfter(
      poolControl,
      revokedA5Control.expiresAtMs + 25 + revokedA5Control.maxTransactionDurationMs,
    );
    const recoveredFenced = await controller.markFenced(
      recoveredCommandId, fenceStore,
    );
    const grantB6 = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId,
      epoch: 6,
      status: 'active',
      holderNodeId: 'node-b',
      leaseId: 'lease-b-epoch-6',
      commandId: recoveredCommandId,
      expiresAtMs: Date.now() + 60_000,
      maxTransactionDurationMs: dbRepeatBRuntime.maxTransactionDurationMs,
      grantSeq: 1,
      prevDigest: null,
    });
    const grantB6Control = bpc.signSourceLeaseGrant(KEY_IDS.guard, guardPrivate, {
      streamId: grantB6.streamId,
      epoch: grantB6.epoch,
      status: grantB6.status,
      holderNodeId: grantB6.holderNodeId,
      leaseId: grantB6.leaseId,
      commandId: grantB6.commandId,
      expiresAtMs: grantB6.expiresAtMs,
      maxTransactionDurationMs: grantB6.maxTransactionDurationMs,
      grantSeq: 11,
      prevDigest: revokedA5Control.grantDigest,
    });
    await Promise.all([
      dbRecoveredBOwner.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, grantB6)),
      dbControl.transaction((exec) =>
        bpc.installSourceLeaseGrant(exec, resolver, grantB6Control)),
    ]);
    await bpc.promoteReceiverToSource(
      dbRecoveredBOwner, resolver, snapshotA5, bpc.bpcPairMutationSanitizer,
      6, SOURCE_EPOCH_B_RECOVERED, resolver, recoveredFenced,
    );
    const recoveredReadiness = await bpc.buildPromotionReadinessAttestation(
      dbRecoveredBOwner, recoveredFenced, snapshotA5.manifest.keyId,
      KEY_IDS.source, sourcePrivate,
    );
    bpc.verifyPromotionReadinessAttestation(resolver, recoveredReadiness);
    const recoveredActive = await controller.markActive(
      recoveredCommandId, recoveredReadiness, resolver,
    );
    await bpc.installActiveCutoverReceipt(
      dbRecoveredBOwner, resolver, recoveredActive, recoveredReadiness,
    );
    const sourceFenceB6 = await bpc.PgSourceLeaseFence.open(
      dbRepeatBRuntime,
      haReadyRecoveredBRuntime,
      resolver,
      {
        streamId,
        epoch: 6,
        holderNodeId: 'node-b',
        authoritySystemId: idB,
        nodeCredentialKeyId: KEY_IDS.nodeB,
        leaseId: grantB6.leaseId,
        grantDigest: grantB6.grantDigest,
        redisClaimDigest: bpc.redisFenceRecordDigest(redisB6),
        maxClockSkewMs: 25,
        maxTransactionDurationMs: dbRepeatBRuntime.maxTransactionDurationMs,
        activationDigest: recoveredActive.stateDigestSigned,
      },
      fenceStore,
      nodeBIdentity,
      ticketSigner,
    );
    const recoveredStoreB = bpc.createHaPairAuthority(
      dbRepeatBRuntime,
      readyRecoveredBRuntime,
      { streamId, fenceToken: 6n, keyring, maxPendingRows: 100 },
      sourceFenceB6,
    );
    await recoveredStoreB.set(pair(6));
    const recoveredFirstMutationSequence = Number((await repeatBOwnerPool.query(
      'SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId],
    )).rows[0]?.sequence);
    assert.equal(recoveredFirstMutationSequence, 1,
      'recovered B did not originate exactly the first epoch-6 mutation');
    let staleA5WriterDenied = false;
    try { await repeatStoreA.set(pair(60)); } catch { staleA5WriterDenied = true; }
    assert.equal(staleA5WriterDenied, true,
      'revoked epoch-5 A remained writable after recovered-site activation');
    const restartProbe = ({ cut, database, grant, redisRecord, activationDigest,
      nodeKeyId, nodePrivateKey, authoritySystemId, number }) =>
      proveStaleBpcWriterDeniedAfterRestart({
        cut,
        bpcDistFile: path.join(path.resolve(options.bpcRoot),
          'packages', 'server', 'dist', 'index.js'),
        runtimeUrl: runtimeUrl(database, runtimePassword),
        controlUrl: postgresUrls[2],
        redisUrls,
        redisKey: `bpc:enterprise28:${streamId}`,
        publicKeys: {
          [KEY_IDS.guard]: guardPublic.export({ type: 'spki', format: 'pem' }).toString(),
          [KEY_IDS.source]: sourcePublic.export({ type: 'spki', format: 'pem' }).toString(),
          [KEY_IDS.nodeA]: nodeAPublic.export({ type: 'spki', format: 'pem' }).toString(),
          [KEY_IDS.nodeB]: nodeBPublic.export({ type: 'spki', format: 'pem' }).toString(),
        },
        nodeKeyId,
        nodePrivateKey: nodePrivateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        sealKeyId: KEY_IDS.seal,
        sealKey: sealKey.toString('base64'),
        mutationKeyId: KEY_IDS.mutation,
        mutationSecret: mutationSecret.toString('base64'),
        streamId,
        fenceToken: String(grant.epoch),
        fence: {
          streamId,
          epoch: grant.epoch,
          holderNodeId: grant.holderNodeId,
          authoritySystemId,
          nodeCredentialKeyId: nodeKeyId,
          leaseId: grant.leaseId,
          grantDigest: grant.grantDigest,
          redisClaimDigest: bpc.redisFenceRecordDigest(redisRecord),
          maxClockSkewMs: 25,
          maxTransactionDurationMs: grant.maxTransactionDurationMs,
          ...(activationDigest ? { activationDigest } : {}),
        },
        pair: pair(number),
      });
    const initialRestartDenial = await restartProbe({ cut: 'initial',
      database: postgresUrls[0], grant: grantA, redisRecord: redisA,
        nodeKeyId: KEY_IDS.nodeA, nodePrivateKey: nodeAPrivate,
        authoritySystemId: idA, number: 61 });
    const failbackRestartDenial = await restartProbe({ cut: 'failback',
      database: postgresUrls[1], grant: grantB, redisRecord: redisB,
        activationDigest: activeCutoverReceipt.stateDigestSigned,
        nodeKeyId: KEY_IDS.nodeB, nodePrivateKey: nodeBPrivate,
        authoritySystemId: idB, number: 62 });
    const repeatForwardRestartDenial = await restartProbe({ cut: 'repeatForward',
      database: databaseUrl(postgresUrls[0], failbackDatabase),
        grant: grantA3, redisRecord: redisA3,
        activationDigest: failbackActiveCutoverReceipt.stateDigestSigned,
        nodeKeyId: KEY_IDS.nodeA, nodePrivateKey: nodeAPrivate,
        authoritySystemId: idA, number: 63 });
    const repeatFailbackRestartDenial = await restartProbe({ cut: 'repeatFailback',
      database: databaseUrl(postgresUrls[1], repeatBDatabase),
        grant: grantB4, redisRecord: redisB4,
        activationDigest: repeatForwardActive.stateDigestSigned,
        nodeKeyId: KEY_IDS.nodeB, nodePrivateKey: nodeBPrivate,
        authoritySystemId: idB, number: 64 });
    const recoveredRestartDenial = await restartProbe({ cut: 'recoveredSite',
      database: databaseUrl(postgresUrls[0], repeatADatabase),
        grant: grantA5, redisRecord: redisA5,
        activationDigest: repeatReturnActive.stateDigestSigned,
        nodeKeyId: KEY_IDS.nodeA, nodePrivateKey: nodeAPrivate,
        authoritySystemId: idA, number: 65 });

    return deepFreeze({
      protocolCommit: actualCommit,
      streamId,
      systemIds: { sourceA: idA, promotedB: idB, control: idControl },
      finalSequence,
      nextLogicalSequence: finalSequence + 1,
      promotedSourceEpoch: SOURCE_EPOCH_B,
      promotedEpochSequence,
      staleWriterDenied,
      failback: {
        commandId: failbackCommandId,
        targetEpoch: 3,
        targetSourceEpoch: SOURCE_EPOCH_A_FAILBACK,
        targetSystemId: idA,
        sourceDatabaseReused: false,
        sourcePostgresSystemReused: true,
        priorAuthoritiesReset: false,
        importedSequence: snapshotB.manifest.finalSequence,
        originatedSequence: failbackEpochSequence,
        staleBWriterDenied,
        readinessAttestation: structuredClone(failbackReadinessAttestation),
        activeCutoverReceipt: structuredClone(failbackActiveCutoverReceipt),
        snapshotManifest: structuredClone(snapshotB.manifest),
      },
      repeatedCycle: {
        principalId: 'enterprise-pair-1',
        forward: {
          commandId: repeatForwardCommandId,
          sourceEpoch: 3,
          targetEpoch: 4,
          sourceSystemId: idA,
          targetSystemId: idB,
          importedSequence: snapshotA3.manifest.finalSequence,
          originatedSequence: repeatForwardSequence,
          staleSourceWriterDenied: staleA3WriterDenied,
          readinessAttestation: structuredClone(repeatForwardReadiness),
          activeCutoverReceipt: structuredClone(repeatForwardActive),
          snapshotManifest: structuredClone(snapshotA3.manifest),
        },
        failback: {
          commandId: repeatReturnCommandId,
          sourceEpoch: 4,
          targetEpoch: 5,
          sourceSystemId: idB,
          targetSystemId: idA,
          importedSequence: snapshotB4.manifest.finalSequence,
          originatedSequence: repeatReturnSequence,
          staleSourceWriterDenied: staleB4WriterDenied,
          readinessAttestation: structuredClone(repeatReturnReadiness),
          activeCutoverReceipt: structuredClone(repeatReturnActive),
          snapshotManifest: structuredClone(snapshotB4.manifest),
        },
        priorAuthoritiesReset: false,
        rpo: 0,
        rtoMs: Date.now() - repeatStartedAt,
      },
      recoveredSite: {
        commandId: recoveredCommandId,
        sourceEpoch: 5,
        targetEpoch: 6,
        targetSourceEpoch: SOURCE_EPOCH_B_RECOVERED,
        sourceSystemId: idA,
        targetSystemId: idB,
        staleDatabaseReused: true,
        importedSequence: snapshotA5.manifest.finalSequence,
        firstMutationSequence: recoveredFirstMutationSequence,
        staleSourceWriterDenied: staleA5WriterDenied,
        restartDenial: recoveredRestartDenial,
        readinessAttestation: structuredClone(recoveredReadiness),
        activeCutoverReceipt: structuredClone(recoveredActive),
        snapshotManifest: structuredClone(snapshotA5.manifest),
        rpo: 0,
        rtoMs: Date.now() - recoveredStartedAt,
      },
      restartDenials: {
        initial: initialRestartDenial,
        failback: failbackRestartDenial,
        repeatForward: repeatForwardRestartDenial,
        repeatFailback: repeatFailbackRestartDenial,
        recoveredSite: recoveredRestartDenial,
      },
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
    await Promise.allSettled(isolatedPools.map((pool) => pool.end()));
    await Promise.allSettled([
      dropIsolatedDatabase(poolA, failbackDatabase),
      dropIsolatedDatabase(poolB, repeatBDatabase),
      dropIsolatedDatabase(poolA, repeatADatabase),
    ]);
    await Promise.allSettled(pools.map((pool) => pool.end()));
    for (const client of redisMembers) client.disconnect();
    sealKey.fill(0);
    mutationSecret.fill(0);
  }
}
