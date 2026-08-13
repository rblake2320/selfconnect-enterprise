import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign as edSign } from 'node:crypto';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import pg from 'pg';
import { Redis } from 'ioredis';

import {
  createCleanupTransfer,
  runExhaustiveCleanup,
} from './post-heal-probe-lifecycle.mjs';
import { promotedTskCredentialLabel } from './promoted-tsk-authority.js';
import { loadPromotedTskCredentialRuntime } from './promoted-tsk-runtime.js';

const HOUR_MS = 3_600_000;
const ACCEPTANCE_SOURCE_LEASE_MS = 15_000;
const ID = /^[A-Za-z0-9_.:/-]{1,128}$/;
const POST_HEAL_RESTART_PROBES = new WeakMap();

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

async function proveStaleTskWriterDeniedAfterRestart(config) {
  const directory = await mkdtemp(join(tmpdir(), 'tsk-stale-restart-'));
  const configPath = join(directory, 'input.json');
  await writeFile(configPath, JSON.stringify(config), { encoding: 'utf8', mode: 0o600 });
  const startedAt = Date.now();
  try {
    return await new Promise((resolvePromise, rejectPromise) => {
      const child = fork(new URL('./tsk-stale-writer-worker.mjs', import.meta.url),
        [configPath], {
          cwd: new URL('.', import.meta.url),
          stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
          windowsHide: true,
          execArgv: process.execArgv.filter((arg) => !arg.startsWith('--input-type')),
        });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        rejectPromise(new Error('stale TSK restart probe timed out'));
      }, 30_000);
      let evidence = null;
      let stderr = '';
      child.stderr?.setEncoding('utf8');
      child.stderr?.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-2_000); });
      child.once('message', (message) => {
        if (message?.kind === 'stale-tsk-writer-denied') evidence = message;
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
            `stale TSK restart probe failed (code=${code}, signal=${signal ?? 'none'}): ${stderr.trim()}`,
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

export async function runPostHealTskRestartProbes(composition) {
  const lifecycle = POST_HEAL_RESTART_PROBES.get(composition);
  if (!lifecycle) throw new Error('TSK post-heal restart probes are unavailable or already consumed');
  POST_HEAL_RESTART_PROBES.delete(composition);
  try {
    return await lifecycle.run();
  } finally {
    await lifecycle.cleanup();
  }
}

export async function discardPostHealTskRestartProbes(composition) {
  const lifecycle = POST_HEAL_RESTART_PROBES.get(composition);
  if (!lifecycle) return;
  POST_HEAL_RESTART_PROBES.delete(composition);
  await lifecycle.cleanup();
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

async function awaitControlLeaseExpiry(pool, leaseExpiresAtMs) {
  const deadline = Date.now() + ACCEPTANCE_SOURCE_LEASE_MS + 10_000;
  for (;;) {
    const now = await dbClockMs(pool);
    if (now >= leaseExpiresAtMs) return now;
    if (Date.now() >= deadline) {
      throw new Error('control clock did not reach the signed source-lease expiry');
    }
    await new Promise((resolve) => setTimeout(
      resolve, Math.max(1, Math.min(100, leaseExpiresAtMs - now)),
    ));
  }
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

async function readPublicCredentialProof(pool, streamId, clientId, expectedSequence,
  activationLease, { agentId, agentPublicKeyHex, canonicalId, pairId, commandId }) {
  const row = (await pool.query(
    `SELECT sequence::text,source_epoch,fence_token::text,op_digest,mutation,
            head_prev,head_digest,head_key_id,head_alg,head_sig
       FROM tsk_outbox_rows
      WHERE stream_id=$1 AND mutation->>'kind'='tsk.credential.snapshot.v1'
      ORDER BY sequence DESC LIMIT 1`,
    [streamId],
  )).rows[0];
  const mutation = structuredClone(row?.mutation);
  assert.equal(String(mutation?.clientId), clientId);
  for (const value of [row?.op_digest, row?.head_digest, mutation?.publicMapDigest,
    mutation?.secretDigest]) assert.match(String(value), /^[0-9a-f]{64}$/);
  assert.equal(Number(row.sequence), expectedSequence);
  return Object.freeze({
    format: 'selfconnect-promoted-tsk-credential-proof-v2',
    agentId,
    agentPublicKeyHex,
    canonicalId,
    pairId,
    commandId,
    activationLease: structuredClone(activationLease),
    record: Object.freeze({
      contractVersion: '1', streamId, sourceEpoch: String(row.source_epoch),
      sequence: Number(row.sequence), fenceToken: String(row.fence_token),
      opDigest: String(row.op_digest), mutation,
    }),
    head: Object.freeze({
      streamId, sequence: Number(row.sequence), prevHeadDigest: String(row.head_prev),
      opDigest: String(row.op_digest), keyId: String(row.head_key_id),
      alg: String(row.head_alg), headDigest: String(row.head_digest),
      signature: String(row.head_sig),
    }),
  });
}

function publicCredentialSummary(proof) {
  return Object.freeze({
    clientId: proof.record.mutation.clientId,
    publicMapDigest: proof.record.mutation.publicMapDigest,
    secretDigest: proof.record.mutation.secretDigest,
    operationDigest: proof.record.opDigest,
    headDigest: proof.head.headDigest,
    sequence: proof.record.sequence,
    sourceEpoch: proof.record.sourceEpoch,
    fenceEpoch: Number(proof.record.fenceToken),
    status: proof.record.mutation.publicMap.status,
  });
}

function createMaterial() {
  return Object.freeze({
    agent: generateKeyPairSync('ed25519'),
    guard: generateKeyPairSync('ed25519'),
    source: generateKeyPairSync('ed25519'),
    aHead: generateKeyPairSync('ed25519'),
    aReceipt: generateKeyPairSync('ed25519'),
    sourceCredentialHead: generateKeyPairSync('ed25519'),
    bHead: generateKeyPairSync('ed25519'),
    bSource: generateKeyPairSync('ed25519'),
    credentialHead: generateKeyPairSync('ed25519'),
    returnCredentialHead: generateKeyPairSync('ed25519'),
    bReceipt: generateKeyPairSync('ed25519'),
    controlSecret: Buffer.alloc(32, 0x5d),
  });
}

function validateOptions(options) {
  const optionKeys = [
    'aPostgresUrl', 'bPostgresUrl', 'controlPostgresUrl', 'destructiveReset',
    'commandId', 'expectedTskCommit', 'preserveRedisAuthority', 'redis',
    'streamId', 'tskRoot',
  ];
  if (Object.hasOwn(options, 'preservePostHealProbes')) {
    optionKeys.push('preservePostHealProbes');
  }
  exactKeys(options, optionKeys, 'TSK live-composition options');
  if (options.destructiveReset !== true) {
    throw new Error('destructiveReset=true is required for dedicated acceptance databases');
  }
  exactKeys(options.redis, options.redis.kind === 'sentinel'
    ? ['kind', 'masterName', 'natMap', 'sentinels']
    : ['kind', 'url'], 'TSK Redis options');
  let redis;
  if (options.redis.kind === 'url') {
    redis = Object.freeze({ kind: 'url', url: requiredString(options.redis.url, 'redis.url') });
  } else if (options.redis.kind === 'sentinel') {
    if (!Array.isArray(options.redis.sentinels) || options.redis.sentinels.length < 3) {
      throw new Error('redis.sentinels requires at least three endpoints');
    }
    const sentinels = options.redis.sentinels.map((entry, index) => {
      exactKeys(entry, ['host', 'port'], `redis.sentinels[${index}]`);
      const port = Number(entry.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`redis.sentinels[${index}].port is invalid`);
      }
      return Object.freeze({ host: requiredString(entry.host, `redis.sentinels[${index}].host`), port });
    });
    if (!options.redis.natMap || typeof options.redis.natMap !== 'object' ||
        Array.isArray(options.redis.natMap)) throw new Error('redis.natMap must be an object');
    redis = Object.freeze({ kind: 'sentinel', sentinels: Object.freeze(sentinels),
      masterName: requiredString(options.redis.masterName, 'redis.masterName'),
      natMap: Object.freeze({ ...options.redis.natMap }) });
  } else {
    throw new Error('redis.kind must be url or sentinel');
  }
  if (typeof options.preserveRedisAuthority !== 'boolean') {
    throw new Error('preserveRedisAuthority must be boolean');
  }
  if (Object.hasOwn(options, 'preservePostHealProbes') &&
      typeof options.preservePostHealProbes !== 'boolean') {
    throw new Error('preservePostHealProbes must be boolean');
  }
  return Object.freeze({
    tskRoot: resolve(requiredString(options.tskRoot, 'tskRoot')),
    aPostgresUrl: requiredString(options.aPostgresUrl, 'aPostgresUrl'),
    bPostgresUrl: requiredString(options.bPostgresUrl, 'bPostgresUrl'),
    controlPostgresUrl: requiredString(options.controlPostgresUrl, 'controlPostgresUrl'),
    redis,
    preserveRedisAuthority: options.preserveRedisAuthority,
    preservePostHealProbes: options.preservePostHealProbes === true,
    streamId: requiredId(options.streamId, 'streamId'),
    commandId: requiredId(options.commandId, 'commandId'),
    expectedTskCommit: requiredString(options.expectedTskCommit, 'expectedTskCommit').toLowerCase(),
  });
}

function createRedisClient(config) {
  const common = { maxRetriesPerRequest: 2, connectTimeout: 10_000, lazyConnect: false };
  return config.kind === 'url'
    ? new Redis(config.url, common)
    : new Redis({ ...common, sentinels: config.sentinels, name: config.masterName,
      role: 'master', natMap: config.natMap });
}

/**
 * Execute the pinned TSK public API's complete A -> B -> A activation lifecycle.
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
    activateFinalizedReceiverAsSource,
    provisionControlSchema, HaControlFencing, GuardSigner, RedisFencingStore,
    verifyLeaseGrant, TSK_CREDENTIAL_AUTHORITY_SCHEMA, PgHaTumblerMapStore,
    HmacCredentialMutationTicketSigner, assertCredentialAuthorityReady,
    provisionCredentialRuntimeMutationBoundary,
    assertCredentialRuntimeMutationBoundary, assertSchemaReady,
  } = tsk;

  for (const [name, value] of Object.entries({
    PgTskDurableOutbox, NodePostgresTransactor, provisionSchemaVersion,
    emitSourceFrozenReceipt, buildSourceExportManifest,
    stageAndFinalizeReceiverGeneration, activateFinalizedReceiverAsSource,
    HaControlFencing,
    PgHaTumblerMapStore, HmacCredentialMutationTicketSigner,
    provisionCredentialRuntimeMutationBoundary, assertCredentialRuntimeMutationBoundary,
    generateTumblerMap,
  })) {
    if (typeof value !== 'function') throw new Error(`pinned TSK export '${name}' is unavailable`);
  }

  const material = createMaterial();
  const keyIds = Object.freeze({
    guard: 'guard-live-1', source: 'source-live-1', aHead: 'head-a-live-1',
    aReceipt: 'receipt-a-live-1', bSource: 'source-b-live-1',
    sourceCredentialHead: 'credential-head-a-live-1',
    bHead: 'head-b-live-1', credentialHead: 'credential-head-b-live-1',
    returnCredentialHead: 'credential-head-a-return-live-1',
    bReceipt: 'receipt-b-live-1', control: 'control-live-1',
  });
  const publicKeys = new Map([
    [keyIds.guard, material.guard.publicKey],
    [keyIds.source, material.source.publicKey],
    [keyIds.aHead, material.aHead.publicKey],
    [keyIds.aReceipt, material.aReceipt.publicKey],
    [keyIds.sourceCredentialHead, material.sourceCredentialHead.publicKey],
    [keyIds.bHead, material.bHead.publicKey],
    [keyIds.bSource, material.bSource.publicKey],
    [keyIds.credentialHead, material.credentialHead.publicKey],
    [keyIds.returnCredentialHead, material.returnCredentialHead.publicKey],
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
  const returnCredentialSigner = hexDigestSigner(
    keyIds.returnCredentialHead, material.returnCredentialHead.privateKey,
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
  const redis = createRedisClient(options.redis);
  redis.on('error', () => {});

  const redisKey = `enterprise28:tsk-live:${options.streamId}`;
  const aDb = new NodePostgresTransactor(aPool);
  const bDb = new NodePostgresTransactor(bPool);
  const controlDb = new NodePostgresTransactor(controlPool);
  const sourceEpoch = 'e1';
  const commandId = options.commandId;
  const targetEpoch = 1;
  // The source holder is a verifiable signing identity so the same physical
  // authority can later be ratified as the return target.
  const aNodeId = keyIds.aReceipt;
  const leaseId = 'enterprise28-source-lease-1';
  const bNodeId = keyIds.bReceipt;
  const credentialStreamId = derivedId('tsk:credential', options.streamId);
  const credentialAgentPublicKeyHex = Buffer.from(
    material.agent.publicKey.export({ format: 'jwk' }).x, 'base64url',
  ).toString('hex');
  const credentialAgentKeyDigest = createHash('sha256').update(
    Buffer.from(credentialAgentPublicKeyHex, 'hex'),
  ).digest('hex');
  const credentialCanonicalId = `SCID-${credentialAgentKeyDigest}`;
  const credentialDisplayAgentId = `SC-${credentialAgentKeyDigest.slice(0, 8).toUpperCase()}`;
  const credentialAgentIdentity = Object.freeze({
    agentId: credentialDisplayAgentId,
    agentPublicKeyHex: credentialAgentPublicKeyHex,
    canonicalId: credentialCanonicalId,
  });
  const credentialPairId = 'enterprise28-pair-1';
  const sourceCredentialLeaseId = derivedId('lease-a', options.commandId);
  const targetCredentialLeaseId = derivedId('lease-b', options.commandId);
  const returnCredentialStreamId = derivedId('tsk:credential:return', options.streamId);
  const returnCredentialLeaseId = derivedId('lease-a-return', options.commandId);
  const repeatForwardCredentialStreamId = derivedId(
    'tsk:credential:repeat-forward', options.streamId,
  );
  const repeatReturnCredentialStreamId = derivedId(
    'tsk:credential:repeat-return', options.streamId,
  );
  const recoveredCredentialStreamId = derivedId(
    'tsk:credential:recovered', options.streamId,
  );
  const runtimeRole = 'tsk_enterprise28_runtime';
  const aRuntimePassword = randomBytes(24).toString('hex');
  const bRuntimePassword = randomBytes(24).toString('hex');
  let aRuntimePool;
  let bRuntimePool;
  let protectedRuntimeDir;
  const repeatDatabases = [];
  const postHealRestartProbeConfigs = new Map();
  const postHealCleanup = createCleanupTransfer();

  const createRepeatAuthority = async (adminPool, connectionString, databaseName) => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(databaseName)) {
      throw new Error('repeat authority database name is invalid');
    }
    await adminPool.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await adminPool.query(`CREATE DATABASE ${databaseName}`);
    const url = new URL(connectionString);
    url.pathname = `/${databaseName}`;
    const pool = new pg.Pool({
      connectionString: url.toString(), max: 4, connectionTimeoutMillis: 10_000,
    });
    pool.on('error', () => {});
    const db = new NodePostgresTransactor(pool);
    await executeSchema(pool, TSK_OUTBOX_PG_SCHEMA);
    await executeSchema(pool, TSK_SOURCE_LEASE_SCHEMA);
    await executeSchema(pool, TSK_SOURCE_WITNESS_SCHEMA);
    await executeSchema(pool, TSK_RECEIVER_SCHEMA);
    repeatDatabases.push({ adminPool, adminUrl: connectionString, databaseName, pool });
    return Object.freeze({
      pool,
      db,
      schemaReady: await provisionSchemaVersion(db, 'public'),
      receiverReady: await assertReceiverReady(db, 'public'),
    });
  };

  try {
    const sourceDrop = 'DROP TABLE IF EXISTS tsk_outbox_rows, tsk_outbox_applied, ' +
      'tsk_outbox_fence, tsk_outbox_source_checkpoint, tsk_outbox_receiver_checkpoint, ' +
      'tsk_outbox_publisher_lease, tsk_outbox_quarantine, tsk_hotp_consumed, ' +
      'tsk_outbox_stream_halted, tsk_outbox_meta, tsk_source_lease, ' +
      'tsk_source_lease_history, tsk_source_witness, tsk_source_witness_history, ' +
      'tsk_credential_mutation_nonce, tsk_credential_mutation_key, ' +
      'tsk_credential_replica_maps, tsk_credential_maps CASCADE';
    const resetRepeatAuthority = async (entry) => {
      await entry.pool.query(
        `DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`,
      );
      await entry.pool.query(sourceDrop);
      await executeSchema(entry.pool, TSK_OUTBOX_PG_SCHEMA);
      await executeSchema(entry.pool, TSK_SOURCE_LEASE_SCHEMA);
      await executeSchema(entry.pool, TSK_SOURCE_WITNESS_SCHEMA);
      await executeSchema(entry.pool, TSK_RECEIVER_SCHEMA);
      const db = new NodePostgresTransactor(entry.pool);
      return Object.freeze({
        pool: entry.pool,
        db,
        schemaReady: await provisionSchemaVersion(db, 'public'),
        receiverReady: await assertReceiverReady(db, 'public'),
      });
    };
    const installSource = async (pool) => {
      await pool.query(sourceDrop);
      await executeSchema(pool, TSK_OUTBOX_PG_SCHEMA);
      await executeSchema(pool, TSK_SOURCE_LEASE_SCHEMA);
      await executeSchema(pool, TSK_SOURCE_WITNESS_SCHEMA);
    };
    await aPool.query(`DROP TABLE IF EXISTS ${TSK_RECEIVER_TABLES.join(', ')} CASCADE`);
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
      leaseExpiresAtMs: await dbClockMs(aPool) + ACCEPTANCE_SOURCE_LEASE_MS,
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
    sourceCredentialMap.label = `agent:${credentialCanonicalId}`;
    sourceCredentialMap.status = 'active';
    await sourceCredentialStore.set(sourceCredentialMap.clientId, sourceCredentialMap);
    const sourceCredentialProof = await readPublicCredentialProof(
      aPool, credentialStreamId, sourceCredentialMap.clientId, 1, sourceCredentialGrant,
      { ...credentialAgentIdentity, pairId: credentialPairId,
        commandId: sourceCredentialGrant.commandId },
    );
    const publicCredentialSource = publicCredentialSummary(sourceCredentialProof);
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

    assert.equal(
      await dbClockMs(aPool) < aGrant.leaseExpiresAtMs,
      true,
      'A source operations must finish before the signed source lease expires',
    );

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
    const bReceiverReady = await assertReceiverReady(bDb, 'public');
    const bFinalizedReceipt = await stageAndFinalizeReceiverGeneration(
      bDb, 'public', bReceiverReady,
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
          activationTtlMs: ACCEPTANCE_SOURCE_LEASE_MS,
        },
      },
    );
    const controlNow = () => dbClockMs(controlPool);
    await control.provision(options.streamId, 'enterprise28-genesis');
    await control.writeLease({
      streamId: options.streamId, leaseId, holderNodeId: aNodeId, epoch: 0,
      status: 'active', grantedMaxExpiryMs: aGrant.leaseExpiresAtMs,
      grantCommandId: 'enterprise28-control-grant-1',
    });
    await control.beginPromotionIntent(options.streamId, commandId, targetEpoch);
    await control.bindSourceFenced(
      options.streamId, commandId, targetEpoch, sourceFrozenReceipt, resolver,
    );
    await control.writeLease({
      streamId: options.streamId, leaseId, holderNodeId: aNodeId, epoch: 0,
      status: 'revoked', grantedMaxExpiryMs: aGrant.leaseExpiresAtMs,
      grantCommandId: 'enterprise28-control-revoke-1',
    });
    const fenceStore = new RedisFencingStore(redis, redisKey,
      options.redis.kind === 'sentinel' ? { waitReplicas: 1, waitTimeoutMs: 3_000 } : undefined);
    const firstClaimExpiresAtMs = await controlNow() + HOUR_MS;
    await assert.rejects(() => control.advanceEpoch(
      options.streamId, commandId, targetEpoch, bNodeId, fenceStore, {
        safetyMarginMs: 0, claimExpiresAtMs: firstClaimExpiresAtMs,
      },
    ), /not expired|safety margin/i);
    await awaitControlLeaseExpiry(controlPool, aGrant.leaseExpiresAtMs);
    await control.advanceEpoch(options.streamId, commandId, targetEpoch, bNodeId, fenceStore, {
      safetyMarginMs: 0,
      claimExpiresAtMs: firstClaimExpiresAtMs,
    });
    assert.deepEqual(await fenceStore.current(), {
      nodeId: bNodeId,
      fenceEpoch: targetEpoch,
      expiresAt: firstClaimExpiresAtMs,
      commandId,
      active: true,
    }, 'epoch-1 Redis authority must byte-bind the ratified B identity');
    await control.markImporting(options.streamId, commandId, targetEpoch);
    await control.markReady(
      options.streamId, commandId, targetEpoch, bFinalizedReceipt, resolver,
    );
    await control.activate(options.streamId, commandId, targetEpoch);
    const activationLeaseGrant = await control.activateSource(
      options.streamId, commandId, targetEpoch, bFinalizedReceipt, resolver, resolver,
    );
    verifyLeaseGrant(resolver, activationLeaseGrant);
    assert.equal(activationLeaseGrant.holderNodeId, bNodeId);

    const bSchemaReady = await provisionSchemaVersion(bDb, 'public');
    const bSourceActivation = await activateFinalizedReceiverAsSource(
      bDb, bSchemaReady, bReceiverReady, options.streamId,
      'enterprise28-generation-1', {
        sanitizer, sourceResolver: resolver, guardResolver: resolver,
        headResolver: resolver, frozenResolver: resolver,
        bReceiptResolver: resolver, leaseResolver: resolver,
        frozenReceipt: sourceFrozenReceipt,
        finalizedReceipt: bFinalizedReceipt,
        activationLease: activationLeaseGrant,
        targetEpoch,
      },
    );
    assert.equal(bSourceActivation.n, n);
    assert.equal(bSourceActivation.headDigest, bFinalizedReceipt.signedHeadDigestAtN);
    assert.equal(bSourceActivation.targetEpoch, targetEpoch);
    assert.equal(bSourceActivation.activationGrantDigest, activationLeaseGrant.grantDigest);
    const bFenceReady = await assertSourceFenceReady(bDb, 'public', resolver, {
      streamId: options.streamId,
      holderNodeId: activationLeaseGrant.holderNodeId,
      leaseId: activationLeaseGrant.leaseId,
      grantDigest: activationLeaseGrant.grantDigest,
    });
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
    protectedRuntimeDir = await mkdtemp(join(tmpdir(), 'enterprise28-tsk-runtime-'));
    const mutationSecretFile = join(protectedRuntimeDir, 'mutation.bin');
    const headPrivateFile = join(protectedRuntimeDir, 'credential-head.pk8.pem');
    const headPublicFile = join(protectedRuntimeDir, 'credential-head.spki.pem');
    const guardPublicFile = join(protectedRuntimeDir, 'guard.spki.pem');
    const descriptorFile = join(protectedRuntimeDir, 'runtime.json');
    await Promise.all([
      writeFile(mutationSecretFile, mutationSecret, { flag: 'wx', mode: 0o600 }),
      writeFile(headPrivateFile, material.credentialHead.privateKey.export({
        type: 'pkcs8', format: 'pem',
      }), { flag: 'wx', mode: 0o600 }),
      writeFile(headPublicFile, material.credentialHead.publicKey.export({
        type: 'spki', format: 'pem',
      }), { flag: 'wx', mode: 0o600 }),
      writeFile(guardPublicFile, material.guard.publicKey.export({
        type: 'spki', format: 'pem',
      }), { flag: 'wx', mode: 0o600 }),
    ]);
    await writeFile(descriptorFile, JSON.stringify({
      activationLease: credentialActivationLeaseGrant,
      controlToASkewBoundMs: 0,
      grantDigest: credentialActivationLeaseGrant.grantDigest,
      holderNodeId: credentialActivationLeaseGrant.holderNodeId,
      leaseId: credentialActivationLeaseGrant.leaseId,
      maxPendingRows: 100_000,
      mutationKeyId: mutationTicketSigner.keyId,
      mutationSecretFile,
      runtimeDatabaseUrl: runtimePostgresUrl(
        options.bPostgresUrl, runtimeRole, bRuntimePassword,
      ),
      schema: 'public',
      sourceEpoch: targetEpoch,
      sourceLeasePublicKeyFiles: { [keyIds.guard]: guardPublicFile },
      streamHeadKeyId: keyIds.credentialHead,
      streamHeadPrivateKeyFile: headPrivateFile,
      streamHeadPublicKeyFiles: { [keyIds.credentialHead]: headPublicFile },
      streamId: credentialStreamId,
    }), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
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
    credentialMap.label = promotedTskCredentialLabel({
      commandId, pairId: credentialPairId, ...credentialAgentIdentity,
    });
    credentialMap.status = 'active';
    await credentialStore.set(credentialMap.clientId, credentialMap);
    const persistedCredential = await credentialStore.get(credentialMap.clientId);
    assert.equal(persistedCredential?.clientId, credentialMap.clientId);
    assert.equal(persistedCredential?.status, 'active');
    const targetCredentialProof = await readPublicCredentialProof(
      bPool, credentialStreamId, credentialMap.clientId, 1,
      credentialActivationLeaseGrant,
      { ...credentialAgentIdentity, pairId: credentialPairId, commandId },
    );
    const publicCredentialTarget = publicCredentialSummary(targetCredentialProof);
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
    const loadedPromotedRuntime = await loadPromotedTskCredentialRuntime(descriptorFile);
    try {
      const resumedCredential = await loadedPromotedRuntime.provision({
        ...credentialAgentIdentity,
        pairId: credentialPairId,
        commandId,
        sourceClientId: publicCredentialSource.clientId,
        sourceSecretDigest: publicCredentialSource.secretDigest,
      });
      assert.equal(resumedCredential.created, false);
      assert.equal(resumedCredential.targetClientId, publicCredentialTarget.clientId);
      assert.equal(resumedCredential.targetProof.head.headDigest,
        targetCredentialProof.head.headDigest);
    } finally {
      await loadedPromotedRuntime.close();
    }

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

    // Governed same-stream return: freeze B after N+1, independently replay the
    // complete signed ledger onto A, then ratify A as source at epoch 2.
    // The Enterprise return bundle requires BPC and TSK to attest the same
    // governed command. BPC's reviewed failback path uses this exact suffix.
    const returnCommandId = `${commandId}-failback`;
    const returnTargetEpoch = targetEpoch + 1;
    assert.equal(
      await dbClockMs(bPool) < activationLeaseGrant.leaseExpiresAtMs,
      true,
      'B source operations must finish before the signed activation lease expires',
    );
    const bRevokedGrant = signLeaseGrant(keyIds.guard, material.guard.privateKey, {
      streamId: options.streamId,
      leaseEpoch: targetEpoch,
      leaseStatus: 'revoked',
      holderNodeId: activationLeaseGrant.holderNodeId,
      leaseId: activationLeaseGrant.leaseId,
      commandId: returnCommandId,
      leaseExpiresAtMs: activationLeaseGrant.leaseExpiresAtMs,
      leaseGrantSeq: activationLeaseGrant.leaseGrantSeq + 1,
      prevGrantDigest: activationLeaseGrant.grantDigest,
    });
    await bDb.transaction((exec) => installLeaseGrant(exec, resolver, bRevokedGrant));

    const returnFrozenReceipt = await emitSourceFrozenReceipt(bDb, 'public', {
      sourceKeyId: keyIds.bSource,
      sourcePrivateKey: material.bSource.privateKey,
      leaseResolver: resolver,
      headResolver: resolver,
    }, {
      streamId: options.streamId,
      commandId: returnCommandId,
      epoch: targetEpoch,
      sourceNodeId: bNodeId,
    });
    assert.equal(returnFrozenReceipt.n, n + 1);
    const returnExport = await buildSourceExportManifest(bDb, 'public', {
      streamId: options.streamId,
      epoch: targetEpoch,
      commandId: returnCommandId,
      sourceNodeId: bNodeId,
    }, {
      sourceKeyId: keyIds.bSource,
      sourcePrivateKey: material.bSource.privateKey,
      sanitizer,
      leaseResolver: resolver,
      headResolver: resolver,
      frozenReceipt: returnFrozenReceipt,
      maxChunkItems: 4,
    });
    const returnCountersigned = guardCountersignSourceExport(
      returnExport.bundle, returnExport.manifest, {
        guardKeyId: keyIds.guard,
        guardPrivateKey: material.guard.privateKey,
        sanitizer,
        sourceManifestResolver: resolver,
        headResolver: resolver,
        frozenResolver: resolver,
        frozenReceipt: returnFrozenReceipt,
        expectedCommandId: returnCommandId,
      },
    );
    await executeSchema(aPool, TSK_RECEIVER_SCHEMA);
    const aReceiverReady = await assertReceiverReady(aDb, 'public');
    const returnFinalizedReceipt = await stageAndFinalizeReceiverGeneration(
      aDb, 'public', aReceiverReady, 'enterprise28-return-generation-2',
      returnExport.bundle, returnCountersigned, {
        sanitizer,
        sourceResolver: resolver,
        guardResolver: resolver,
        headResolver: resolver,
        frozenResolver: resolver,
        bVerifyResolver: resolver,
        frozenReceipt: returnFrozenReceipt,
        expectedCommandId: returnCommandId,
        bKeyId: keyIds.aReceipt,
        bPrivateKey: material.aReceipt.privateKey,
      },
    );
    verifyBFinalizedReceipt(resolver, returnFinalizedReceipt);
    assert.equal(returnFinalizedReceipt.n, n + 1);

    await control.writeLease({
      streamId: options.streamId,
      leaseId: activationLeaseGrant.leaseId,
      holderNodeId: activationLeaseGrant.holderNodeId,
      epoch: targetEpoch,
      status: 'active',
      grantedMaxExpiryMs: activationLeaseGrant.leaseExpiresAtMs,
      grantCommandId: derivedId('control-return-active', commandId),
    });
    await control.beginPromotionIntent(
      options.streamId, returnCommandId, returnTargetEpoch,
    );
    await control.bindSourceFenced(
      options.streamId, returnCommandId, returnTargetEpoch,
      returnFrozenReceipt, resolver,
    );
    await control.writeLease({
      streamId: options.streamId,
      leaseId: activationLeaseGrant.leaseId,
      holderNodeId: activationLeaseGrant.holderNodeId,
      epoch: targetEpoch,
      status: 'revoked',
      grantedMaxExpiryMs: activationLeaseGrant.leaseExpiresAtMs,
      grantCommandId: derivedId('control-return-revoke', commandId),
    });
    const returnClaimExpiresAtMs = await controlNow() + HOUR_MS;
    await assert.rejects(() => control.advanceEpoch(
      options.streamId, returnCommandId, returnTargetEpoch, aNodeId,
      fenceStore, {
        safetyMarginMs: 0,
        claimExpiresAtMs: returnClaimExpiresAtMs,
      },
    ), /not expired|safety margin/i);
    await awaitControlLeaseExpiry(
      controlPool, activationLeaseGrant.leaseExpiresAtMs,
    );
    await control.advanceEpoch(
      options.streamId, returnCommandId, returnTargetEpoch, aNodeId,
      fenceStore, {
        safetyMarginMs: 0,
        claimExpiresAtMs: returnClaimExpiresAtMs,
      },
    );
    assert.deepEqual(await fenceStore.current(), {
      nodeId: aNodeId,
      fenceEpoch: returnTargetEpoch,
      expiresAt: returnClaimExpiresAtMs,
      commandId: returnCommandId,
      active: true,
    }, 'return Redis authority must byte-bind the ratified A identity');
    await control.markImporting(
      options.streamId, returnCommandId, returnTargetEpoch,
    );
    await control.markReady(
      options.streamId, returnCommandId, returnTargetEpoch,
      returnFinalizedReceipt, resolver,
    );
    await control.activate(
      options.streamId, returnCommandId, returnTargetEpoch,
    );
    const returnActivationLeaseGrant = await control.activateSource(
      options.streamId, returnCommandId, returnTargetEpoch,
      returnFinalizedReceipt, resolver, resolver, [aGrant, revokedGrant],
    );
    verifyLeaseGrant(resolver, returnActivationLeaseGrant);
    assert.equal(returnActivationLeaseGrant.holderNodeId, aNodeId);
    assert.equal(returnActivationLeaseGrant.leaseEpoch, returnTargetEpoch);
    assert.equal(returnActivationLeaseGrant.leaseGrantSeq, 3);
    assert.equal(returnActivationLeaseGrant.prevGrantDigest, revokedGrant.grantDigest);

    const returnSourceActivation = await activateFinalizedReceiverAsSource(
      aDb, aSchemaReady, aReceiverReady, options.streamId,
      'enterprise28-return-generation-2', {
        sanitizer,
        sourceResolver: resolver,
        guardResolver: resolver,
        headResolver: resolver,
        frozenResolver: resolver,
        bReceiptResolver: resolver,
        leaseResolver: resolver,
        frozenReceipt: returnFrozenReceipt,
        finalizedReceipt: returnFinalizedReceipt,
        activationLease: returnActivationLeaseGrant,
        targetEpoch: returnTargetEpoch,
      },
    );
    assert.equal(returnSourceActivation.n, n + 1);
    assert.equal(
      returnSourceActivation.headDigest,
      returnFinalizedReceipt.signedHeadDigestAtN,
    );
    assert.equal(
      returnSourceActivation.activationGrantDigest,
      returnActivationLeaseGrant.grantDigest,
    );
    assert.deepEqual(
      await control.activateSource(
        options.streamId, returnCommandId, returnTargetEpoch,
        returnFinalizedReceipt, resolver, resolver, [aGrant, revokedGrant],
      ),
      returnActivationLeaseGrant,
    );
    assert.deepEqual(
      await activateFinalizedReceiverAsSource(
        aDb, aSchemaReady, aReceiverReady, options.streamId,
        'enterprise28-return-generation-2', {
          sanitizer,
          sourceResolver: resolver,
          guardResolver: resolver,
          headResolver: resolver,
          frozenResolver: resolver,
          bReceiptResolver: resolver,
          leaseResolver: resolver,
          frozenReceipt: returnFrozenReceipt,
          finalizedReceipt: returnFinalizedReceipt,
          activationLease: returnActivationLeaseGrant,
          targetEpoch: returnTargetEpoch,
        },
      ),
      returnSourceActivation,
    );

    const returnFenceReady = await assertSourceFenceReady(
      aDb, 'public', resolver, {
        streamId: options.streamId,
        holderNodeId: returnActivationLeaseGrant.holderNodeId,
        leaseId: returnActivationLeaseGrant.leaseId,
        grantDigest: returnActivationLeaseGrant.grantDigest,
      },
    );
    const returnedAOutbox = new PgTskDurableOutbox(aDb, aSchemaReady, {
      streamId: options.streamId,
      sanitizer,
      signer: aSigner,
      maxPendingRows: 100_000,
      backpressure: 'fail-authoritative-mutation',
    }, { resolver, controlToASkewBoundMs: 0, ready: returnFenceReady });
    const returnAppend = await returnedAOutbox.withOutboxTx(
      (tx) => returnedAOutbox.appendInTx(tx, {
        streamId: options.streamId,
        rawMutation: { tumblerId: 'T10', counter: 2 },
        fenceToken: BigInt(returnTargetEpoch),
      }),
    );
    assert.equal(returnAppend.head.sequence, n + 2);
    assert.equal(
      returnAppend.head.prevHeadDigest,
      returnFinalizedReceipt.signedHeadDigestAtN,
    );

    const executeRepeatedSourceHandoff = async ({
      sourceDb, sourcePool, sourceNodeId, sourceKeyId, sourcePrivateKey,
      sourceLease, sourceOutbox, targetDb, targetNodeId,
      targetSchemaReady, targetReceiverReady, targetGenerationId,
      targetReceiptKeyId, targetReceiptPrivateKey, targetSigner,
      targetLeaseChain, handoffCommandId, handoffTargetEpoch, mutation,
      sourceDatabaseUrl, sourceHeadKeyId, sourceHeadPrivateKey, restartCut,
    }) => {
      assert.equal(
        await dbClockMs(sourcePool) < sourceLease.leaseExpiresAtMs,
        true,
        'source handoff must begin before its signed lease expires',
      );
      for (const historicalGrant of targetLeaseChain) {
        try {
          await targetDb.transaction((exec) => installLeaseGrant(
            exec, resolver, historicalGrant,
          ));
        } catch (error) {
          throw new Error(
            `target lease history install failed at epoch ${historicalGrant.leaseEpoch} ` +
            `sequence ${historicalGrant.leaseGrantSeq} command ${historicalGrant.commandId}`,
            { cause: error },
          );
        }
      }
      const revokedSourceLease = signLeaseGrant(
        keyIds.guard, material.guard.privateKey, {
          streamId: options.streamId,
          leaseEpoch: sourceLease.leaseEpoch,
          leaseStatus: 'revoked',
          holderNodeId: sourceLease.holderNodeId,
          leaseId: sourceLease.leaseId,
          commandId: handoffCommandId,
          leaseExpiresAtMs: sourceLease.leaseExpiresAtMs,
          leaseGrantSeq: sourceLease.leaseGrantSeq + 1,
          prevGrantDigest: sourceLease.grantDigest,
        },
      );
      await sourceDb.transaction((exec) => installLeaseGrant(
        exec, resolver, revokedSourceLease,
      ));
      const frozenReceipt = await emitSourceFrozenReceipt(sourceDb, 'public', {
        sourceKeyId,
        sourcePrivateKey,
        leaseResolver: resolver,
        headResolver: resolver,
      }, {
        streamId: options.streamId,
        commandId: handoffCommandId,
        epoch: sourceLease.leaseEpoch,
        sourceNodeId,
      });
      const sourceExport = await buildSourceExportManifest(sourceDb, 'public', {
        streamId: options.streamId,
        epoch: sourceLease.leaseEpoch,
        commandId: handoffCommandId,
        sourceNodeId,
      }, {
        sourceKeyId,
        sourcePrivateKey,
        sanitizer,
        leaseResolver: resolver,
        headResolver: resolver,
        frozenReceipt,
        maxChunkItems: 4,
      });
      const countersignedExport = guardCountersignSourceExport(
        sourceExport.bundle, sourceExport.manifest, {
          guardKeyId: keyIds.guard,
          guardPrivateKey: material.guard.privateKey,
          sanitizer,
          sourceManifestResolver: resolver,
          headResolver: resolver,
          frozenResolver: resolver,
          frozenReceipt,
          expectedCommandId: handoffCommandId,
        },
      );
      const finalizedReceipt = await stageAndFinalizeReceiverGeneration(
        targetDb, 'public', targetReceiverReady, targetGenerationId,
        sourceExport.bundle, countersignedExport, {
          sanitizer,
          sourceResolver: resolver,
          guardResolver: resolver,
          headResolver: resolver,
          frozenResolver: resolver,
          bVerifyResolver: resolver,
          frozenReceipt,
          expectedCommandId: handoffCommandId,
          bKeyId: targetReceiptKeyId,
          bPrivateKey: targetReceiptPrivateKey,
        },
      );
      verifyBFinalizedReceipt(resolver, finalizedReceipt);
      await control.writeLease({
        streamId: options.streamId,
        leaseId: sourceLease.leaseId,
        holderNodeId: sourceLease.holderNodeId,
        epoch: sourceLease.leaseEpoch,
        status: 'active',
        grantedMaxExpiryMs: sourceLease.leaseExpiresAtMs,
        grantCommandId: derivedId('control-repeat-active', handoffCommandId),
      });
      await control.beginPromotionIntent(
        options.streamId, handoffCommandId, handoffTargetEpoch,
      );
      await control.bindSourceFenced(
        options.streamId, handoffCommandId, handoffTargetEpoch,
        frozenReceipt, resolver,
      );
      await control.writeLease({
        streamId: options.streamId,
        leaseId: sourceLease.leaseId,
        holderNodeId: sourceLease.holderNodeId,
        epoch: sourceLease.leaseEpoch,
        status: 'revoked',
        grantedMaxExpiryMs: sourceLease.leaseExpiresAtMs,
        grantCommandId: derivedId('control-repeat-revoke', handoffCommandId),
      });
      const claimExpiresAtMs = await controlNow() + HOUR_MS;
      await assert.rejects(() => control.advanceEpoch(
        options.streamId, handoffCommandId, handoffTargetEpoch,
        targetNodeId, fenceStore, {
          safetyMarginMs: 0,
          claimExpiresAtMs,
        },
      ), /not expired|safety margin/i);
      await awaitControlLeaseExpiry(controlPool, sourceLease.leaseExpiresAtMs);
      await control.advanceEpoch(
        options.streamId, handoffCommandId, handoffTargetEpoch,
        targetNodeId, fenceStore, {
          safetyMarginMs: 0,
          claimExpiresAtMs,
        },
      );
      assert.deepEqual(await fenceStore.current(), {
        nodeId: targetNodeId,
        fenceEpoch: handoffTargetEpoch,
        expiresAt: claimExpiresAtMs,
        commandId: handoffCommandId,
        active: true,
      });
      await control.markImporting(
        options.streamId, handoffCommandId, handoffTargetEpoch,
      );
      await control.markReady(
        options.streamId, handoffCommandId, handoffTargetEpoch,
        finalizedReceipt, resolver,
      );
      await control.activate(
        options.streamId, handoffCommandId, handoffTargetEpoch,
      );
      const activationLease = await control.activateSource(
        options.streamId, handoffCommandId, handoffTargetEpoch,
        finalizedReceipt, resolver, resolver, targetLeaseChain,
      );
      verifyLeaseGrant(resolver, activationLease);
      const sourceActivation = await activateFinalizedReceiverAsSource(
        targetDb, targetSchemaReady, targetReceiverReady, options.streamId,
        targetGenerationId, {
          sanitizer,
          sourceResolver: resolver,
          guardResolver: resolver,
          headResolver: resolver,
          frozenResolver: resolver,
          bReceiptResolver: resolver,
          leaseResolver: resolver,
          frozenReceipt,
          finalizedReceipt,
          activationLease,
          targetEpoch: handoffTargetEpoch,
        },
      );
      const targetFenceReady = await assertSourceFenceReady(
        targetDb, 'public', resolver, {
          streamId: options.streamId,
          holderNodeId: activationLease.holderNodeId,
          leaseId: activationLease.leaseId,
          grantDigest: activationLease.grantDigest,
        },
      );
      const targetOutbox = new PgTskDurableOutbox(
        targetDb, targetSchemaReady, {
          streamId: options.streamId,
          sanitizer,
          signer: targetSigner,
          maxPendingRows: 100_000,
          backpressure: 'fail-authoritative-mutation',
        }, { resolver, controlToASkewBoundMs: 0, ready: targetFenceReady },
      );
      const append = await targetOutbox.withOutboxTx(
        (tx) => targetOutbox.appendInTx(tx, {
          streamId: options.streamId,
          rawMutation: mutation,
          fenceToken: BigInt(handoffTargetEpoch),
        }),
      );
      assert.equal(append.head.sequence, frozenReceipt.n + 1);
      assert.equal(append.head.prevHeadDigest, frozenReceipt.signedHeadDigestAtN);
      let staleWriterDenied = false;
      try {
        await sourceOutbox.withOutboxTx((tx) => sourceOutbox.appendInTx(tx, {
          streamId: options.streamId,
          rawMutation: mutation,
          fenceToken: BigInt(sourceLease.leaseEpoch),
        }));
      } catch (error) {
        if (!/revoked|not writable|lease|fence/i.test(
          String(error?.message ?? error),
        )) throw error;
        staleWriterDenied = true;
      }
      assert.equal(staleWriterDenied, true);
      const restartProbeConfig = {
        tskDistFile: resolve(options.tskRoot, 'packages', 'server', 'dist', 'index.js'),
        databaseUrl: sourceDatabaseUrl,
        publicKeys: Object.fromEntries([...publicKeys.entries()].map(([keyId, key]) => [
          keyId, key.export({ type: 'spki', format: 'pem' }).toString(),
        ])),
        headPrivateKey: sourceHeadPrivateKey.export({
          type: 'pkcs8', format: 'pem',
        }).toString(),
        headKeyId: sourceHeadKeyId,
        streamId: options.streamId,
        fenceToken: String(sourceLease.leaseEpoch),
        authorizedLease: {
          streamId: options.streamId,
          holderNodeId: sourceLease.holderNodeId,
          leaseId: sourceLease.leaseId,
          grantDigest: sourceLease.grantDigest,
        },
        mutation,
      };
      postHealRestartProbeConfigs.set(restartCut, restartProbeConfig);
      const restartDenial = await proveStaleTskWriterDeniedAfterRestart(restartProbeConfig);
      return Object.freeze({
        commandId: handoffCommandId,
        sourceEpoch: sourceLease.leaseEpoch,
        targetEpoch: handoffTargetEpoch,
        frozenReceipt,
        finalizedReceipt,
        revokedSourceLease,
        activationLease,
        sourceActivation,
        append,
        staleWriterDenied,
        restartDenial,
      });
    };

    const repeatB = await createRepeatAuthority(
      bPool, options.bPostgresUrl, 'enterprise28_tsk_repeat_b3',
    );
    assert.equal(await systemId(repeatB.pool), systemIds.receiverB);
    const repeatForward = await executeRepeatedSourceHandoff({
      sourceDb: aDb,
      sourcePool: aPool,
      sourceNodeId: aNodeId,
      sourceKeyId: keyIds.source,
      sourcePrivateKey: material.source.privateKey,
      sourceLease: returnActivationLeaseGrant,
      sourceOutbox: returnedAOutbox,
      targetDb: repeatB.db,
      targetNodeId: bNodeId,
      targetSchemaReady: repeatB.schemaReady,
      targetReceiverReady: repeatB.receiverReady,
      targetGenerationId: 'enterprise28-repeat-generation-3',
      targetReceiptKeyId: keyIds.bReceipt,
      targetReceiptPrivateKey: material.bReceipt.privateKey,
      targetSigner: bSigner,
      targetLeaseChain: [activationLeaseGrant, bRevokedGrant],
      handoffCommandId: `${commandId}-cycle-2-promote`,
      handoffTargetEpoch: returnTargetEpoch + 1,
      mutation: { tumblerId: 'T11', counter: 3 },
      sourceDatabaseUrl: options.aPostgresUrl,
      sourceHeadKeyId: keyIds.aHead,
      sourceHeadPrivateKey: material.aHead.privateKey,
      restartCut: 'repeatForward',
    });
    const repeatA = await createRepeatAuthority(
      aPool, options.aPostgresUrl, 'enterprise28_tsk_repeat_a4',
    );
    assert.equal(await systemId(repeatA.pool), systemIds.sourceA);
    const repeatForwardReady = await assertSourceFenceReady(
      repeatB.db, 'public', resolver, {
        streamId: options.streamId,
        holderNodeId: repeatForward.activationLease.holderNodeId,
        leaseId: repeatForward.activationLease.leaseId,
        grantDigest: repeatForward.activationLease.grantDigest,
      },
    );
    const repeatForwardOutbox = new PgTskDurableOutbox(
      repeatB.db, repeatB.schemaReady, {
        streamId: options.streamId,
        sanitizer,
        signer: bSigner,
        maxPendingRows: 100_000,
        backpressure: 'fail-authoritative-mutation',
      }, {
        resolver,
        controlToASkewBoundMs: 0,
        ready: repeatForwardReady,
      },
    );
    const repeatReturn = await executeRepeatedSourceHandoff({
      sourceDb: repeatB.db,
      sourcePool: repeatB.pool,
      sourceNodeId: bNodeId,
      sourceKeyId: keyIds.bSource,
      sourcePrivateKey: material.bSource.privateKey,
      sourceLease: repeatForward.activationLease,
      sourceOutbox: repeatForwardOutbox,
      targetDb: repeatA.db,
      targetNodeId: aNodeId,
      targetSchemaReady: repeatA.schemaReady,
      targetReceiverReady: repeatA.receiverReady,
      targetGenerationId: 'enterprise28-repeat-generation-4',
      targetReceiptKeyId: keyIds.aReceipt,
      targetReceiptPrivateKey: material.aReceipt.privateKey,
      targetSigner: aSigner,
      targetLeaseChain: [
        aGrant, revokedGrant, returnActivationLeaseGrant,
        repeatForward.revokedSourceLease,
      ],
      handoffCommandId: `${commandId}-cycle-2-failback`,
      handoffTargetEpoch: returnTargetEpoch + 2,
      mutation: { tumblerId: 'T12', counter: 4 },
      sourceDatabaseUrl: (() => { const value = new URL(options.bPostgresUrl);
        value.pathname = '/enterprise28_tsk_repeat_b3'; return value.toString(); })(),
      sourceHeadKeyId: keyIds.bHead,
      sourceHeadPrivateKey: material.bHead.privateKey,
      restartCut: 'repeatFailback',
    });
    const repeatReturnReady = await assertSourceFenceReady(
      repeatA.db, 'public', resolver, {
        streamId: options.streamId,
        holderNodeId: repeatReturn.activationLease.holderNodeId,
        leaseId: repeatReturn.activationLease.leaseId,
        grantDigest: repeatReturn.activationLease.grantDigest,
      },
    );
    const repeatReturnOutbox = new PgTskDurableOutbox(
      repeatA.db, repeatA.schemaReady, {
        streamId: options.streamId,
        sanitizer,
        signer: aSigner,
        maxPendingRows: 100_000,
        backpressure: 'fail-authoritative-mutation',
      }, { resolver, controlToASkewBoundMs: 0, ready: repeatReturnReady },
    );
    const recoveredB = await resetRepeatAuthority(repeatB);
    assert.equal(await systemId(recoveredB.pool), systemIds.receiverB);
    const recoveredForward = await executeRepeatedSourceHandoff({
      sourceDb: repeatA.db,
      sourcePool: repeatA.pool,
      sourceNodeId: aNodeId,
      sourceKeyId: keyIds.source,
      sourcePrivateKey: material.source.privateKey,
      sourceLease: repeatReturn.activationLease,
      sourceOutbox: repeatReturnOutbox,
      targetDb: recoveredB.db,
      targetNodeId: bNodeId,
      targetSchemaReady: recoveredB.schemaReady,
      targetReceiverReady: recoveredB.receiverReady,
      targetGenerationId: 'enterprise28-recovered-generation-5',
      targetReceiptKeyId: keyIds.bReceipt,
      targetReceiptPrivateKey: material.bReceipt.privateKey,
      targetSigner: bSigner,
      targetLeaseChain: [
        activationLeaseGrant, bRevokedGrant, repeatForward.activationLease,
        repeatReturn.revokedSourceLease,
      ],
      handoffCommandId: `${commandId}-recovered-site-promote`,
      handoffTargetEpoch: returnTargetEpoch + 3,
      mutation: { tumblerId: 'T13', counter: 5 },
      sourceDatabaseUrl: (() => { const value = new URL(options.aPostgresUrl);
        value.pathname = '/enterprise28_tsk_repeat_a4'; return value.toString(); })(),
      sourceHeadKeyId: keyIds.aHead,
      sourceHeadPrivateKey: material.aHead.privateKey,
      restartCut: 'recoveredSite',
    });

    // Return the independently reprovisioned credential authority as well as
    // the generic source stream. B's credential lease is terminally revoked
    // before A mints a fresh credential under the return command/epoch. The
    // old B runtime keeps its original capability so its next commit proves
    // that the database gate, rather than caller cooperation, denies it.
    const targetCredentialRevocation = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: credentialStreamId,
        leaseEpoch: targetEpoch,
        leaseStatus: 'revoked',
        holderNodeId: credentialActivationLeaseGrant.holderNodeId,
        leaseId: credentialActivationLeaseGrant.leaseId,
        commandId: returnCommandId,
        leaseExpiresAtMs: credentialActivationLeaseGrant.leaseExpiresAtMs,
        leaseGrantSeq: credentialActivationLeaseGrant.leaseGrantSeq + 1,
        prevGrantDigest: credentialActivationLeaseGrant.grantDigest,
      },
    );
    await bDb.transaction((exec) => installLeaseGrant(
      exec, resolver, targetCredentialRevocation,
    ));

    let staleReturnedCredentialWriterDenied = false;
    try {
      await credentialStore.set(credentialMap.clientId, credentialMap);
    } catch (error) {
      if (!/revoked|not writable|lease|fence|grant digest/i.test(
        String(error?.message ?? error),
      )) throw error;
      staleReturnedCredentialWriterDenied = true;
    }
    assert.equal(staleReturnedCredentialWriterDenied, true,
      'old B credential writer must be denied after return');

    await aPool.query(
      'INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1, $2)',
      [returnCredentialStreamId, returnTargetEpoch],
    );
    await aPool.query(
      'INSERT INTO tsk_outbox_source_checkpoint ' +
      '(stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
      [returnCredentialStreamId, 'credential-e3'],
    );
    const returnCredentialActivationLeaseGrant = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: returnCredentialStreamId,
        leaseEpoch: returnTargetEpoch,
        leaseStatus: 'active',
        holderNodeId: aNodeId,
        leaseId: returnCredentialLeaseId,
        commandId: returnCommandId,
        leaseExpiresAtMs: await dbClockMs(aPool) + HOUR_MS,
        leaseGrantSeq: 1,
        prevGrantDigest: null,
      },
    );
    verifyLeaseGrant(resolver, returnCredentialActivationLeaseGrant);
    await aDb.transaction((exec) => installLeaseGrant(
      exec, resolver, returnCredentialActivationLeaseGrant,
    ));
    const returnCredentialFenceReady = await assertSourceFenceReady(
      aRuntimeDb, 'public', resolver, {
        streamId: returnCredentialStreamId,
        holderNodeId: returnCredentialActivationLeaseGrant.holderNodeId,
        leaseId: returnCredentialActivationLeaseGrant.leaseId,
        grantDigest: returnCredentialActivationLeaseGrant.grantDigest,
      },
    );
    const returnCredentialStore = new PgHaTumblerMapStore(
      aRuntimeDb,
      aRuntimeOutboxReady,
      aRuntimeCredentialReady,
      aMutationBoundary,
      aTicketSigner,
      {
        streamId: returnCredentialStreamId,
        sourceEpoch: returnTargetEpoch,
        signer: returnCredentialSigner,
      },
      { resolver, controlToASkewBoundMs: 0, ready: returnCredentialFenceReady },
    );
    const returnCredentialMap = generateTumblerMap({
      keyLength: 64, minTumblers: 2, maxTumblers: 2,
    });
    returnCredentialMap.label = promotedTskCredentialLabel({
      commandId: returnCommandId,
      pairId: credentialPairId,
      ...credentialAgentIdentity,
    });
    returnCredentialMap.status = 'active';
    await returnCredentialStore.set(returnCredentialMap.clientId, returnCredentialMap);
    const returnCredentialProof = await readPublicCredentialProof(
      aPool, returnCredentialStreamId, returnCredentialMap.clientId, 1,
      returnCredentialActivationLeaseGrant,
      { ...credentialAgentIdentity, pairId: credentialPairId,
        commandId: returnCommandId },
    );
    const publicCredentialReturn = publicCredentialSummary(returnCredentialProof);
    assert.notEqual(publicCredentialReturn.clientId, publicCredentialTarget.clientId,
      'failback must mint a fresh returned credential identity');
    assert.notEqual(publicCredentialReturn.secretDigest, publicCredentialTarget.secretDigest,
      'failback must mint fresh returned credential secret material');
    assert.equal(JSON.stringify(publicCredentialReturn).includes(
      returnCredentialMap.sharedSecret), false);

    const mintRepeatedCredential = async ({
      pool, db, runtimeDb: credentialRuntimeDb, outboxReady,
      credentialReady, mutationBoundary: credentialMutationBoundary,
      ticketSigner, streamId, epoch, sourceEpoch: credentialSourceEpoch,
      holderNodeId, leaseId: credentialLeaseId,
      credentialCommandId, streamSigner,
    }) => {
      await pool.query(
        'INSERT INTO tsk_outbox_fence (stream_id, fence_token) VALUES ($1, $2)',
        [streamId, epoch],
      );
      await pool.query(
        'INSERT INTO tsk_outbox_source_checkpoint ' +
        '(stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
        [streamId, credentialSourceEpoch],
      );
      const leaseGrant = signLeaseGrant(
        keyIds.guard, material.guard.privateKey, {
          streamId,
          leaseEpoch: epoch,
          leaseStatus: 'active',
          holderNodeId,
          leaseId: credentialLeaseId,
          commandId: credentialCommandId,
          leaseExpiresAtMs: await dbClockMs(pool) + HOUR_MS,
          leaseGrantSeq: 1,
          prevGrantDigest: null,
        },
      );
      await db.transaction((exec) => installLeaseGrant(exec, resolver, leaseGrant));
      const ready = await assertSourceFenceReady(
        credentialRuntimeDb, 'public', resolver, {
          streamId,
          holderNodeId,
          leaseId: credentialLeaseId,
          grantDigest: leaseGrant.grantDigest,
        },
      );
      const store = new PgHaTumblerMapStore(
        credentialRuntimeDb,
        outboxReady,
        credentialReady,
        credentialMutationBoundary,
        ticketSigner,
        {
          streamId,
          sourceEpoch: epoch,
          signer: streamSigner,
        },
        { resolver, controlToASkewBoundMs: 0, ready },
      );
      const map = generateTumblerMap({
        keyLength: 64, minTumblers: 2, maxTumblers: 2,
      });
      map.label = promotedTskCredentialLabel({
        commandId: credentialCommandId,
        pairId: credentialPairId,
        ...credentialAgentIdentity,
      });
      map.status = 'active';
      await store.set(map.clientId, map);
      const proof = await readPublicCredentialProof(
        pool, streamId, map.clientId, 1, leaseGrant, {
          ...credentialAgentIdentity,
          pairId: credentialPairId,
          commandId: credentialCommandId,
        },
      );
      return Object.freeze({
        streamId,
        leaseGrant,
        store,
        map,
        proof,
        publicCredential: publicCredentialSummary(proof),
      });
    };

    const returnCredentialRevocation = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: returnCredentialStreamId,
        leaseEpoch: returnTargetEpoch,
        leaseStatus: 'revoked',
        holderNodeId: returnCredentialActivationLeaseGrant.holderNodeId,
        leaseId: returnCredentialActivationLeaseGrant.leaseId,
        commandId: repeatForward.commandId,
        leaseExpiresAtMs: returnCredentialActivationLeaseGrant.leaseExpiresAtMs,
        leaseGrantSeq: returnCredentialActivationLeaseGrant.leaseGrantSeq + 1,
        prevGrantDigest: returnCredentialActivationLeaseGrant.grantDigest,
      },
    );
    await aDb.transaction((exec) => installLeaseGrant(
      exec, resolver, returnCredentialRevocation,
    ));
    let staleRepeatForwardCredentialDenied = false;
    try {
      await returnCredentialStore.set(returnCredentialMap.clientId, returnCredentialMap);
    } catch (error) {
      if (!/revoked|not writable|lease|fence|grant digest/i.test(
        String(error?.message ?? error),
      )) throw error;
      staleRepeatForwardCredentialDenied = true;
    }
    assert.equal(staleRepeatForwardCredentialDenied, true);

    const repeatForwardCredential = await mintRepeatedCredential({
      pool: bPool,
      db: bDb,
      runtimeDb,
      outboxReady: runtimeOutboxReady,
      credentialReady: runtimeCredentialReady,
      mutationBoundary,
      ticketSigner: mutationTicketSigner,
      streamId: repeatForwardCredentialStreamId,
      epoch: repeatForward.targetEpoch,
      sourceEpoch: 'credential-e4',
      holderNodeId: bNodeId,
      leaseId: derivedId('lease-b-repeat', options.commandId),
      credentialCommandId: repeatForward.commandId,
      streamSigner: credentialSigner,
    });
    const repeatForwardCredentialRevocation = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: repeatForwardCredential.streamId,
        leaseEpoch: repeatForward.targetEpoch,
        leaseStatus: 'revoked',
        holderNodeId: repeatForwardCredential.leaseGrant.holderNodeId,
        leaseId: repeatForwardCredential.leaseGrant.leaseId,
        commandId: repeatReturn.commandId,
        leaseExpiresAtMs: repeatForwardCredential.leaseGrant.leaseExpiresAtMs,
        leaseGrantSeq: 2,
        prevGrantDigest: repeatForwardCredential.leaseGrant.grantDigest,
      },
    );
    await bDb.transaction((exec) => installLeaseGrant(
      exec, resolver, repeatForwardCredentialRevocation,
    ));
    let staleRepeatReturnCredentialDenied = false;
    try {
      await repeatForwardCredential.store.set(
        repeatForwardCredential.map.clientId, repeatForwardCredential.map,
      );
    } catch (error) {
      if (!/revoked|not writable|lease|fence|grant digest/i.test(
        String(error?.message ?? error),
      )) throw error;
      staleRepeatReturnCredentialDenied = true;
    }
    assert.equal(staleRepeatReturnCredentialDenied, true);

    const repeatReturnCredential = await mintRepeatedCredential({
      pool: aPool,
      db: aDb,
      runtimeDb: aRuntimeDb,
      outboxReady: aRuntimeOutboxReady,
      credentialReady: aRuntimeCredentialReady,
      mutationBoundary: aMutationBoundary,
      ticketSigner: aTicketSigner,
      streamId: repeatReturnCredentialStreamId,
      epoch: repeatReturn.targetEpoch,
      sourceEpoch: 'credential-e5',
      holderNodeId: aNodeId,
      leaseId: derivedId('lease-a-repeat', options.commandId),
      credentialCommandId: repeatReturn.commandId,
      streamSigner: returnCredentialSigner,
    });
    assert.notEqual(
      repeatForwardCredential.publicCredential.clientId,
      repeatReturnCredential.publicCredential.clientId,
    );
    assert.notEqual(
      repeatForwardCredential.publicCredential.secretDigest,
      repeatReturnCredential.publicCredential.secretDigest,
    );
    const recoveredCredentialRevocation = signLeaseGrant(
      keyIds.guard, material.guard.privateKey, {
        streamId: repeatReturnCredential.streamId,
        leaseEpoch: repeatReturn.targetEpoch,
        leaseStatus: 'revoked',
        holderNodeId: repeatReturnCredential.leaseGrant.holderNodeId,
        leaseId: repeatReturnCredential.leaseGrant.leaseId,
        commandId: recoveredForward.commandId,
        leaseExpiresAtMs: repeatReturnCredential.leaseGrant.leaseExpiresAtMs,
        leaseGrantSeq: 2,
        prevGrantDigest: repeatReturnCredential.leaseGrant.grantDigest,
      },
    );
    await aDb.transaction((exec) => installLeaseGrant(
      exec, resolver, recoveredCredentialRevocation,
    ));
    let staleRecoveredCredentialDenied = false;
    try {
      await repeatReturnCredential.store.set(
        repeatReturnCredential.map.clientId, repeatReturnCredential.map,
      );
    } catch (error) {
      if (!/revoked|not writable|lease|fence|grant digest/i.test(
        String(error?.message ?? error),
      )) throw error;
      staleRecoveredCredentialDenied = true;
    }
    assert.equal(staleRecoveredCredentialDenied, true);
    const recoveredCredential = await mintRepeatedCredential({
      pool: bPool,
      db: bDb,
      runtimeDb,
      outboxReady: runtimeOutboxReady,
      credentialReady: runtimeCredentialReady,
      mutationBoundary,
      ticketSigner: mutationTicketSigner,
      streamId: recoveredCredentialStreamId,
      epoch: recoveredForward.targetEpoch,
      sourceEpoch: 'credential-e6',
      holderNodeId: bNodeId,
      leaseId: derivedId('lease-b-recovered', options.commandId),
      credentialCommandId: recoveredForward.commandId,
      streamSigner: credentialSigner,
    });
    assert.notEqual(
      recoveredCredential.publicCredential.clientId,
      repeatReturnCredential.publicCredential.clientId,
    );
    assert.notEqual(
      recoveredCredential.publicCredential.secretDigest,
      repeatReturnCredential.publicCredential.secretDigest,
    );

    let staleTargetWriterDenied = false;
    try {
      await bOutbox.withOutboxTx((tx) => bOutbox.appendInTx(tx, {
        streamId: options.streamId,
        rawMutation: { tumblerId: 'T9', counter: 2 },
        fenceToken: BigInt(targetEpoch),
      }));
    } catch (error) {
      if (!/revoked|not writable|lease|fence/i.test(
        String(error?.message ?? error),
      )) throw error;
      staleTargetWriterDenied = true;
    }
    assert.equal(staleTargetWriterDenied, true, 'old B writer must be denied after return');

    const restartProbeConfig = ({ databaseUrl, lease, headKeyId,
      headPrivateKey, mutation }) => ({
      tskDistFile: resolve(options.tskRoot, 'packages', 'server', 'dist', 'index.js'),
      databaseUrl,
      publicKeys: Object.fromEntries([...publicKeys.entries()].map(([keyId, key]) => [
        keyId, key.export({ type: 'spki', format: 'pem' }).toString(),
      ])),
      headPrivateKey: headPrivateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      headKeyId,
      streamId: options.streamId,
      fenceToken: String(lease.leaseEpoch),
      authorizedLease: {
        streamId: options.streamId,
        holderNodeId: lease.holderNodeId,
        leaseId: lease.leaseId,
        grantDigest: lease.grantDigest,
      },
      mutation,
    });
    const initialRestartConfig = restartProbeConfig({
      databaseUrl: options.aPostgresUrl, lease: aGrant,
      headKeyId: keyIds.aHead, headPrivateKey: material.aHead.privateKey,
      mutation: { tumblerId: 'T15', counter: 7 },
    });
    const failbackRestartConfig = restartProbeConfig({
      databaseUrl: options.bPostgresUrl, lease: activationLeaseGrant,
      headKeyId: keyIds.bHead, headPrivateKey: material.bHead.privateKey,
      mutation: { tumblerId: 'T16', counter: 8 },
    });
    postHealRestartProbeConfigs.set('initial', initialRestartConfig);
    postHealRestartProbeConfigs.set('failback', failbackRestartConfig);
    const [initialRestartDenial, failbackRestartDenial] = await Promise.all([
      proveStaleTskWriterDeniedAfterRestart(initialRestartConfig),
      proveStaleTskWriterDeniedAfterRestart(failbackRestartConfig),
    ]);

    const redisRecord = await redis.get(redisKey);
    if (redisRecord === null) throw new Error('TSK Redis authority record disappeared');
    const redisAuthority = Object.freeze({ key: redisKey,
      record: Object.freeze(JSON.parse(redisRecord)) });
    const result = Object.freeze({
      sourceFrozenReceipt,
      bFinalizedReceipt,
      activationLeaseGrant,
      bSourceActivation,
      returnFrozenReceipt,
      returnFinalizedReceipt,
      returnActivationLeaseGrant,
      returnSourceActivation,
      repeatedCycle: Object.freeze({
        forward: repeatForward,
        failback: repeatReturn,
      }),
      recoveredSite: Object.freeze({
        handoff: recoveredForward,
        restartDenial: recoveredForward.restartDenial,
        staleCredentialDenied: staleRecoveredCredentialDenied,
        sourceCredentialRevocation: recoveredCredentialRevocation,
        credential: Object.freeze({
          streamId: recoveredCredential.streamId,
          leaseGrant: recoveredCredential.leaseGrant,
          proof: recoveredCredential.proof,
          publicCredential: recoveredCredential.publicCredential,
        }),
      }),
      restartDenials: Object.freeze({
        initial: initialRestartDenial,
        failback: failbackRestartDenial,
        repeatForward: repeatForward.restartDenial,
        repeatFailback: repeatReturn.restartDenial,
        recoveredSite: recoveredForward.restartDenial,
      }),
      returnCommandId,
      systemIds,
      n,
      nextSequence: bAppend.head.sequence,
      nextHeadDigest: bAppend.head.streamHeadDigest,
      returnSequence: returnAppend.head.sequence,
      returnHeadDigest: returnAppend.head.streamHeadDigest,
      staleWriterDenied,
      staleTargetWriterDenied,
      staleCredentialWriterDenied,
      staleReturnedCredentialWriterDenied,
      credentialStreamId,
      returnCredentialStreamId,
      credentialSourceLeaseGrant: sourceCredentialGrant,
      credentialSourceRevocation: sourceCredentialRevocation,
      credentialActivationLeaseGrant,
      targetCredentialRevocation,
      returnCredentialActivationLeaseGrant,
      returnCredentialRevocation,
      repeatForwardCredentialRevocation,
      staleRepeatForwardCredentialDenied,
      staleRepeatReturnCredentialDenied,
      repeatForwardCredential: Object.freeze({
        streamId: repeatForwardCredential.streamId,
        leaseGrant: repeatForwardCredential.leaseGrant,
        proof: repeatForwardCredential.proof,
        publicCredential: repeatForwardCredential.publicCredential,
      }),
      repeatReturnCredential: Object.freeze({
        streamId: repeatReturnCredential.streamId,
        leaseGrant: repeatReturnCredential.leaseGrant,
        proof: repeatReturnCredential.proof,
        publicCredential: repeatReturnCredential.publicCredential,
      }),
      publicCredentialSource,
      publicCredentialTarget,
      publicCredentialReturn,
      agentIdentity: credentialAgentIdentity,
      sourceCredentialProof,
      targetCredentialProof,
      returnCredentialProof,
      redisAuthority,
      // Backward-compatible alias for the promoted target credential.
      publicCredential: publicCredentialTarget,
      tskCommit: reviewed.actualCommit,
      publicKeys: Object.freeze({
        guard: material.guard.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        source: material.source.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        aHead: material.aHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        aReceipt: material.aReceipt.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        sourceCredentialHead: material.sourceCredentialHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        bHead: material.bHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        bSource: material.bSource.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        credentialHead: material.credentialHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        returnCredentialHead: material.returnCredentialHead.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        bReceipt: material.bReceipt.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      }),
      publicVerificationKeys: Object.freeze(Object.fromEntries(
        [...publicKeys.entries()].map(([keyId, key]) => [
          keyId,
          key.export({ type: 'spki', format: 'pem' }).toString(),
        ]),
      )),
    });
    if (options.preservePostHealProbes) {
      const expectedCuts = [
        'initial', 'failback', 'repeatForward', 'repeatFailback', 'recoveredSite',
      ];
      assert.deepEqual([...postHealRestartProbeConfigs.keys()].sort(),
        [...expectedCuts].sort());
      const cleanupEntries = repeatDatabases.map(({ adminUrl, databaseName }) =>
        Object.freeze({ adminUrl, databaseName }));
      const lifecycle = {
        async run() {
          const evidence = {};
          for (const cut of expectedCuts) {
            evidence[cut] = await proveStaleTskWriterDeniedAfterRestart(
              postHealRestartProbeConfigs.get(cut),
            );
          }
          return Object.freeze(evidence);
        },
        async cleanup() {
          await runExhaustiveCleanup(cleanupEntries.map(({
            adminUrl, databaseName,
          }) => async () => {
            const cleanupPool = new pg.Pool({
              connectionString: adminUrl, max: 1, connectionTimeoutMillis: 10_000,
            });
            cleanupPool.on('error', () => {});
            try {
              await cleanupPool.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
            } finally {
              await cleanupPool.end().catch(() => {});
            }
          }), 'failed to clean one or more retained TSK authority databases');
        },
      };
      postHealCleanup.transfer(() => POST_HEAL_RESTART_PROBES.set(result, lifecycle));
    }
    return result;
  } finally {
    for (const entry of repeatDatabases.reverse()) {
      await entry.pool.end().catch(() => {});
      if (!postHealCleanup.transferred) {
        await entry.adminPool.query(
          `DROP DATABASE IF EXISTS ${entry.databaseName} WITH (FORCE)`,
        ).catch(() => {});
      }
    }
    await Promise.allSettled([
      options.preserveRedisAuthority ? Promise.resolve() : redis.del(redisKey),
      redis.quit(),
      aPool.end(),
      bPool.end(),
      controlPool.end(),
      aRuntimePool?.end(),
      bRuntimePool?.end(),
    ]);
    if (protectedRuntimeDir) {
      await rm(protectedRuntimeDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}
