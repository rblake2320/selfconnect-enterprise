import {
  createHash,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { verifyPromotionReadinessAttestation } from '@bpc/server';
import { verifyBFinalizedReceipt, verifyLeaseGrant } from '@tsk/server';
import {
  verifyPromotedTskCredentialProof,
  verifySourceTskCredentialProof,
} from './promoted-tsk-authority.js';

const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,128}$/;
const STREAM_IDENTIFIER = /^[A-Za-z0-9_.:/-]{1,128}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SECRET_FIELD = /(?:secret|token|password|private|credential|provisionpayload)/i;
const INDEPENDENT_STATE_SCHEMA = 'public';
const INDEPENDENT_STATE_SCHEMA_VERSION = 1;
const INDEPENDENT_STATE_TABLES = Object.freeze([
  'ultra_tumbler_maps',
  'ultra_identity_bindings',
  'ultra_idempotency',
  'ultra_idempotency_redaction',
  'ultra_nonce_tombstones',
  'ultra_ha_import_head',
  'ultra_ha_tsk_reprovision',
]);
const INDEPENDENT_STATE_LOCK_LIST = INDEPENDENT_STATE_TABLES.join(', ');

// Compiled from ULTRA_PG_SCHEMA + ULTRA_INDEPENDENT_STATE_SCHEMA on PostgreSQL 16.
// There is deliberately no environment override: changing the authority schema requires a
// reviewed source change and a new pin.
export const ULTRA_INDEPENDENT_STATE_MANIFEST_DIGEST =
  'd917df185baf879664b9724fb5f6b9518f55a0a6344c3f5bebec8b409c2c300b';

export const ULTRA_INDEPENDENT_STATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS ultra_nonce_tombstones (
  nonce_hash TEXT PRIMARY KEY CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ultra_nonce_tombstones_expiry_idx
  ON ultra_nonce_tombstones (expires_at);

CREATE TABLE IF NOT EXISTS ultra_idempotency_redaction (
  idempotency_key UUID PRIMARY KEY REFERENCES ultra_idempotency(idempotency_key) ON DELETE CASCADE,
  original_response_digest TEXT NOT NULL CHECK (original_response_digest ~ '^[0-9a-f]{64}$'),
  source_manifest_digest TEXT NOT NULL CHECK (source_manifest_digest ~ '^[0-9a-f]{64}$'),
  source_system_id TEXT NOT NULL,
  command_id TEXT NOT NULL,
  source_epoch BIGINT NOT NULL CHECK (source_epoch >= 1),
  source_signature_digest TEXT NOT NULL CHECK (source_signature_digest ~ '^[0-9a-f]{64}$'),
  guard_signature_digest TEXT NOT NULL CHECK (guard_signature_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS ultra_ha_import_head (
  cluster_id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL,
  source_epoch BIGINT NOT NULL CHECK (source_epoch >= 1),
  source_system_id TEXT NOT NULL,
  target_system_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  authority_digest TEXT NOT NULL CHECK (authority_digest ~ '^[0-9a-f]{64}$'),
  imported_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS ultra_ha_tsk_reprovision (
  cluster_id TEXT NOT NULL REFERENCES ultra_ha_import_head(cluster_id) ON DELETE CASCADE,
  pair_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  source_client_id TEXT NOT NULL,
  source_secret_digest TEXT NOT NULL CHECK (source_secret_digest ~ '^[0-9a-f]{64}$'),
  target_client_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'complete')),
  target_proof JSONB,
  target_proof_digest TEXT CHECK (target_proof_digest IS NULL OR target_proof_digest ~ '^[0-9a-f]{64}$'),
  activation_grant_digest TEXT CHECK (activation_grant_digest IS NULL OR activation_grant_digest ~ '^[0-9a-f]{64}$'),
  receipt_digest TEXT CHECK (receipt_digest IS NULL OR receipt_digest ~ '^[0-9a-f]{64}$'),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (cluster_id, pair_id),
  UNIQUE (cluster_id, source_client_id),
  UNIQUE (cluster_id, target_client_id)
);
`;

function requiredIdentifier(value, name) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new Error(`${name} must match ${IDENTIFIER}`);
  }
  return value;
}

function positiveSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('canonical numbers must be safe integers');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(',')}}`;
  }
  throw new Error('value is not canonical JSON data');
}

function digest(value) {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

function containsSecret(value, key = '') {
  if (SECRET_FIELD.test(key)) return true;
  if (Array.isArray(value)) return value.some((item) => containsSecret(item));
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([childKey, child]) => containsSecret(child, childKey));
  }
  return false;
}

function strictKeys(value, allowed, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object`);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key)) || keys.length !== allowed.size) {
    throw new Error(`${name} has an invalid shape`);
  }
}

function requiredDigest(value, name) {
  if (typeof value !== 'string' || !DIGEST.test(value)) throw new Error(`${name} must be a SHA-256 digest`);
  return value;
}

export function loadIndependentStateRuntimeConfig(env, haConfig, runtimeMode) {
  const mode = env.ULTRA_HA_STATE_MODE ?? 'shared';
  if (!['shared', 'independent'].includes(mode)) {
    throw new Error('ULTRA_HA_STATE_MODE must be shared or independent');
  }
  if (mode === 'shared') return Object.freeze({ mode, expected: null });
  if (runtimeMode !== 'production' || !haConfig?.enabled) {
    throw new Error('ULTRA_HA_STATE_MODE=independent requires production HA mode');
  }
  const raw = [
    env.ULTRA_HA_REQUIRED_COMMAND_ID,
    env.ULTRA_HA_REQUIRED_SOURCE_EPOCH,
    env.ULTRA_HA_REQUIRED_MANIFEST_DIGEST,
  ];
  if (raw.every((value) => value === undefined || value === '')) {
    return Object.freeze({ mode, expected: null });
  }
  if (raw.some((value) => value === undefined || value === '')) {
    throw new Error('independent-state promotion pins must be configured together');
  }
  return Object.freeze({
    mode,
    expected: Object.freeze({
      clusterId: requiredIdentifier(haConfig.clusterId, 'clusterId'),
      commandId: requiredIdentifier(raw[0], 'ULTRA_HA_REQUIRED_COMMAND_ID'),
      sourceEpoch: positiveSafeInteger(Number(raw[1]), 'ULTRA_HA_REQUIRED_SOURCE_EPOCH'),
      manifestDigest: requiredDigest(raw[2], 'ULTRA_HA_REQUIRED_MANIFEST_DIGEST'),
    }),
  });
}

export function independentStateAllowsWrites(mode, ready) {
  return mode !== 'independent' || ready !== null;
}

function requirePublicEd25519(key, name) {
  if (!key || key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${name} must be a public Ed25519 KeyObject`);
  }
  return key;
}

function requirePrivateEd25519(key, name) {
  if (!key || key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${name} must be a private Ed25519 KeyObject`);
  }
  return key;
}

function keyFingerprint(key) {
  return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
}

function signatureMessage(domain, keyId, value) {
  return Buffer.from(canonicalJson({ domain, keyId, value }), 'utf8');
}

function signDigest(privateKey, value, domain, keyId) {
  return cryptoSign(
    null, signatureMessage(domain, keyId, value), requirePrivateEd25519(privateKey, 'signing key'),
  ).toString('base64url');
}

function verifyDigest(publicKey, value, signature, domain, keyId) {
  return typeof signature === 'string' && cryptoVerify(
    null,
    signatureMessage(domain, keyId, value),
    requirePublicEd25519(publicKey, 'verification key'),
    Buffer.from(signature, 'base64url'),
  );
}

async function withSerializable(pool, callback, { attest = true } = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    if (attest) await enterIndependentStateAuthority(client);
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* discard below */ }
    throw error;
  } finally {
    client.release();
  }
}

async function systemIdentifier(exec) {
  const { rows } = await exec.query('SELECT system_identifier::text FROM pg_control_system()');
  const value = rows[0]?.system_identifier;
  if (typeof value !== 'string' || value.length === 0) throw new Error('PostgreSQL system identifier unavailable');
  return value;
}

/** Durable replay authority for independent-state mode. Raw nonces never persist. */
export class PgNonceTombstoneStore {
  constructor(pool) { this.pool = pool; }

  async checkAndConsume(nonce, ttlMs) {
    positiveSafeInteger(ttlMs, 'ttlMs');
    if (typeof nonce !== 'string' || nonce.length < 1 || nonce.length > 4096) {
      throw new Error('nonce must contain 1..4096 characters');
    }
    const nonceHash = createHash('sha256').update(nonce, 'utf8').digest('hex');
    return withSerializable(this.pool, async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`ultra-nonce:${nonceHash}`]);
      await client.query(
        'DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1 AND expires_at <= clock_timestamp()',
        [nonceHash],
      );
      const inserted = await client.query(
        `INSERT INTO ultra_nonce_tombstones (nonce_hash, expires_at)
         VALUES ($1, clock_timestamp() + ($2::bigint * interval '1 millisecond'))
         ON CONFLICT DO NOTHING RETURNING nonce_hash`,
        [nonceHash, ttlMs],
      );
      return inserted.rowCount === 0;
    });
  }
}

function redactionProvenance(row) {
  if (row.original_response_digest === null || row.original_response_digest === undefined) return null;
  return {
    commandId: row.redaction_command_id,
    guardSignatureDigest: row.guard_signature_digest,
    sourceEpoch: Number(row.redaction_source_epoch),
    sourceManifestDigest: row.source_manifest_digest,
    sourceSignatureDigest: row.source_signature_digest,
    sourceSystemId: row.redaction_source_system_id,
  };
}

function requiredStreamIdentifier(value, name) {
  if (typeof value !== 'string' || !STREAM_IDENTIFIER.test(value)) {
    throw new Error(`${name} must match ${STREAM_IDENTIFIER}`);
  }
  return value;
}

function isRedactionPlaceholder(response, responseDigest) {
  const keys = response && typeof response === 'object' && !Array.isArray(response)
    ? Object.keys(response).sort() : [];
  return keys.join(',') === 'error,ok,originalResponseDigest' &&
    response.ok === false && response.error === 'SECRET_REPROVISION_REQUIRED' &&
    response.originalResponseDigest === responseDigest;
}

function snapshotFromRows({ bindings, idempotency, nonces }) {
  const safeIdempotency = idempotency.map((row) => {
    const response = typeof row.response === 'string' ? JSON.parse(row.response) : row.response;
    const provenance = redactionProvenance(row);
    if (provenance) {
      if (!isRedactionPlaceholder(response, row.original_response_digest)) {
        throw new Error('redaction placeholder does not match durable import provenance');
      }
      return {
        agentId: row.agent_id,
        idempotencyKey: row.idempotency_key,
        operation: row.operation,
        redactionProvenance: provenance,
        response: null,
        responseDigest: row.original_response_digest,
        secretReprovisionRequired: true,
      };
    }
    const sensitive = containsSecret(response);
    return {
      agentId: row.agent_id,
      idempotencyKey: row.idempotency_key,
      operation: row.operation,
      redactionProvenance: null,
      response: sensitive ? null : response,
      responseDigest: digest(response),
      secretReprovisionRequired: sensitive,
    };
  });
  return {
    identityBindings: bindings.map((row) => ({
      agentId: row.agent_id,
      pairId: row.pair_id,
      tskClientId: row.tsk_client_id,
    })),
    idempotency: safeIdempotency,
    nonceTombstones: nonces.map((row) => ({
      expiresAt: new Date(row.expires_at).toISOString(),
      nonceHash: row.nonce_hash,
    })),
  };
}

function targetIdempotencyRecord(row) {
  const response = typeof row.response === 'string' ? JSON.parse(row.response) : row.response;
  const provenance = redactionProvenance(row);
  if (provenance) {
    if (!isRedactionPlaceholder(response, row.original_response_digest)) {
      throw new Error('redaction placeholder does not match durable import provenance');
    }
    return {
      agentId: row.agent_id,
      idempotencyKey: row.idempotency_key,
      operation: row.operation,
      redactionProvenance: provenance,
      response: null,
      responseDigest: row.original_response_digest,
      secretReprovisionRequired: true,
    };
  }
  return {
    agentId: row.agent_id,
    idempotencyKey: row.idempotency_key,
    operation: row.operation,
    redactionProvenance: null,
    response,
    responseDigest: digest(response),
    secretReprovisionRequired: false,
  };
}

async function readTargetAuthorityState(exec) {
  const bindings = await exec.query(
    'SELECT pair_id, tsk_client_id, agent_id FROM ultra_identity_bindings ORDER BY pair_id COLLATE "C"',
  );
  const idempotency = await exec.query(
    `SELECT i.idempotency_key::text, i.operation, i.agent_id, i.response,
            r.original_response_digest, r.source_manifest_digest,
            r.source_system_id AS redaction_source_system_id,
            r.command_id AS redaction_command_id, r.source_epoch AS redaction_source_epoch,
            r.source_signature_digest, r.guard_signature_digest
       FROM ultra_idempotency i
       LEFT JOIN ultra_idempotency_redaction r USING (idempotency_key)
      WHERE i.state='complete'
      ORDER BY i.idempotency_key::text COLLATE "C"`,
  );
  const identityBindings = bindings.rows.map((row) => ({
      agentId: row.agent_id, pairId: row.pair_id, tskClientId: row.tsk_client_id,
  }));
  const proofRows = await exec.query(
    `SELECT cluster_id,pair_id,target_client_id,target_proof_digest,activation_grant_digest
       FROM ultra_ha_tsk_reprovision
      WHERE status='complete'
      ORDER BY cluster_id COLLATE "C",pair_id COLLATE "C"`,
  );
  const tskCredentials = [];
  for (const binding of identityBindings) {
    const maps = await exec.query('SELECT map FROM ultra_tumbler_maps WHERE client_id=$1', [binding.tskClientId]);
    if (maps.rows[0]) {
      tskCredentials.push({
        clientId: binding.tskClientId,
        credentialDigest: digest(maps.rows[0].map),
      });
    }
  }
  return {
    identityBindings,
    idempotency: idempotency.rows.map(targetIdempotencyRecord),
    tskCredentials,
    tskCredentialProofs: proofRows.rows.map((row) => ({
      activationGrantDigest: row.activation_grant_digest,
      clusterId: row.cluster_id,
      pairId: row.pair_id,
      targetClientId: row.target_client_id,
      targetProofDigest: row.target_proof_digest,
    })),
  };
}

function byteSort(values) {
  return values.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

async function independentStateCatalogManifest(exec) {
  const tables = [...INDEPENDENT_STATE_TABLES];
  const cols = (await exec.query(
    `SELECT table_name, ordinal_position, column_name, data_type, is_nullable,
            COALESCE(column_default, '') AS column_default
       FROM information_schema.columns
      WHERE table_schema=$1 AND table_name=ANY($2)`,
    [INDEPENDENT_STATE_SCHEMA, tables],
  )).rows;
  const constraints = (await exec.query(
    `SELECT rel.relname AS table_name, con.contype,
            pg_catalog.pg_get_constraintdef(con.oid) AS definition
       FROM pg_catalog.pg_constraint con
       JOIN pg_catalog.pg_class rel ON rel.oid=con.conrelid
       JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
      WHERE ns.nspname=$1 AND rel.relname=ANY($2)
        AND con.contype IN ('p','c','u','f')`,
    [INDEPENDENT_STATE_SCHEMA, tables],
  )).rows;
  const indexes = (await exec.query(
    `SELECT tablename AS table_name, indexname, indexdef
       FROM pg_catalog.pg_indexes
      WHERE schemaname=$1 AND tablename=ANY($2)`,
    [INDEPENDENT_STATE_SCHEMA, tables],
  )).rows;
  const triggers = (await exec.query(
    `SELECT rel.relname AS table_name, trigger.tgname, trigger.tgenabled,
            pg_catalog.pg_get_triggerdef(trigger.oid) AS definition
       FROM pg_catalog.pg_trigger trigger
       JOIN pg_catalog.pg_class rel ON rel.oid=trigger.tgrelid
       JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
      WHERE ns.nspname=$1 AND rel.relname=ANY($2) AND NOT trigger.tgisinternal`,
    [INDEPENDENT_STATE_SCHEMA, tables],
  )).rows;
  const relations = (await exec.query(
    `SELECT rel.relname AS table_name, rel.relkind, rel.relpersistence,
            rel.relrowsecurity, rel.relforcerowsecurity
       FROM pg_catalog.pg_class rel
       JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
      WHERE ns.nspname=$1 AND rel.relname=ANY($2)`,
    [INDEPENDENT_STATE_SCHEMA, tables],
  )).rows;
  const policies = (await exec.query(
    `SELECT tablename AS table_name, policyname, permissive, roles::text AS roles,
            cmd, COALESCE(qual, '') AS qual, COALESCE(with_check, '') AS with_check
       FROM pg_catalog.pg_policies
      WHERE schemaname=$1 AND tablename=ANY($2)`,
    [INDEPENDENT_STATE_SCHEMA, tables],
  )).rows;
  const lines = [
    `V|${INDEPENDENT_STATE_SCHEMA_VERSION}|${INDEPENDENT_STATE_SCHEMA}`,
    ...cols.map((row) => `C|${row.table_name}|${row.ordinal_position}|${row.column_name}|${row.data_type}|${row.is_nullable}|${row.column_default}`),
    ...constraints.map((row) => `K|${row.table_name}|${row.contype}|${row.definition}`),
    ...indexes.map((row) => `I|${row.table_name}|${row.indexname}|${row.indexdef}`),
    ...triggers.map((row) => `T|${row.table_name}|${row.tgname}|${row.tgenabled}|${row.definition}`),
    ...relations.map((row) => `R|${row.table_name}|${row.relkind}|${row.relpersistence}|${row.relrowsecurity}|${row.relforcerowsecurity}`),
    ...policies.map((row) => `P|${row.table_name}|${row.policyname}|${row.permissive}|${row.roles}|${row.cmd}|${row.qual}|${row.with_check}`),
  ];
  return [lines[0], ...byteSort(lines.slice(1))].join('\n');
}

async function enterIndependentStateAuthority(exec) {
  const isolation = String((await exec.query('SHOW transaction_isolation')).rows[0]?.transaction_isolation ?? '').toLowerCase();
  if (isolation !== 'serializable') throw new Error(`independent-state authority requires SERIALIZABLE; got '${isolation}'`);
  await exec.query('SELECT pg_catalog.set_config($1,$2,true)', ['search_path', `${INDEPENDENT_STATE_SCHEMA}, pg_temp`]);
  const schema = (await exec.query('SELECT pg_catalog.current_schema() AS schema')).rows[0]?.schema;
  if (schema !== INDEPENDENT_STATE_SCHEMA) throw new Error('independent-state schema context mismatch');
  await exec.query(`LOCK TABLE ${INDEPENDENT_STATE_LOCK_LIST} IN ACCESS SHARE MODE`);
  const manifest = await independentStateCatalogManifest(exec);
  const liveDigest = createHash('sha256').update(manifest, 'utf8').digest('hex');
  if (liveDigest !== ULTRA_INDEPENDENT_STATE_MANIFEST_DIGEST) {
    throw new Error(
      `independent-state schema attestation failed: live catalog digest ${liveDigest} != pinned ${ULTRA_INDEPENDENT_STATE_MANIFEST_DIGEST}`,
    );
  }
  return liveDigest;
}

export async function attestIndependentStateSchema(pool) {
  return withSerializable(pool, enterIndependentStateAuthority, { attest: false });
}

async function assertNoActiveUnboundCredentials(exec) {
  const { rows } = await exec.query(
    `SELECT COUNT(*)::int AS count FROM ultra_tumbler_maps m
     WHERE m.map->>'status' IN ('active','expiring')
       AND NOT EXISTS (
         SELECT 1 FROM ultra_identity_bindings b WHERE b.tsk_client_id=m.client_id
       )`,
  );
  if (rows[0].count !== 0) throw new Error('active unbound TSK credential detected');
}

function publicTskMapDigest(map) {
  const publicMap = structuredClone(map);
  delete publicMap.sharedSecret;
  if (Array.isArray(publicMap.segments)) {
    for (const segment of publicMap.segments) {
      delete segment.secret;
      delete segment.key;
    }
  }
  return digest(publicMap);
}

export async function exportIndependentState(pool, input) {
  const clusterId = requiredIdentifier(input.clusterId, 'clusterId');
  const commandId = requiredIdentifier(input.commandId, 'commandId');
  const sourceEpoch = positiveSafeInteger(input.sourceEpoch, 'sourceEpoch');
  const protocolEvidence = structuredClone(input.protocolEvidence);
  const bpcPromotionDigest = requiredDigest(
    protocolEvidence?.bpcPromotionAttestation?.attestationDigest, 'bpcPromotionDigest',
  );
  const tskFinalizedDigest = requiredDigest(
    protocolEvidence?.tskFinalizedReceipt?.receiptDigest, 'tskFinalizedDigest',
  );
  const tskActivationDigest = requiredDigest(
    protocolEvidence?.tskActivationLease?.grantDigest, 'tskActivationDigest',
  );
  const sourceKeyId = requiredIdentifier(input.sourceKeyId, 'sourceKeyId');
  const maxItems = positiveSafeInteger(input.maxItems ?? 100_000, 'maxItems');
  const maxBytes = positiveSafeInteger(input.maxBytes ?? 64 * 1024 * 1024, 'maxBytes');
  if (!Array.isArray(input.sourceCredentialProofs)) {
    throw new Error('sourceCredentialProofs must be an array');
  }
  const proofPropertyNames = Object.getOwnPropertyNames(input.sourceCredentialProofs);
  if (Object.getOwnPropertySymbols(input.sourceCredentialProofs).length !== 0 ||
      proofPropertyNames.length !== input.sourceCredentialProofs.length + 1 ||
      !proofPropertyNames.includes('length') || input.sourceCredentialProofs.length > maxItems) {
    throw new Error('sourceCredentialProofs must be a bounded dense data array');
  }
  // Start every proof snapshot/verification synchronously, before the first
  // database await. Each entry carries an opaque authority capability plus the
  // exact principal the signed source credential is expected to bind.
  const verifiedSourceCredentialPromise = Promise.all(input.sourceCredentialProofs.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        Object.getPrototypeOf(entry) !== Object.prototype ||
        Object.getOwnPropertySymbols(entry).length !== 0 ||
        Object.keys(entry).sort().join(',') !== 'authorityCapability,expected,proof') {
      throw new Error(`sourceCredentialProofs[${index}] has an invalid shape`);
    }
    for (const key of ['authorityCapability', 'expected', 'proof']) {
      const descriptor = Object.getOwnPropertyDescriptor(entry, key);
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
        throw new Error(`sourceCredentialProofs[${index}].${key} must be an enumerable data property`);
      }
    }
    return verifySourceTskCredentialProof(
      entry.authorityCapability, entry.proof, entry.expected,
    );
  }));
  const verifiedSourceCredentials = await verifiedSourceCredentialPromise;
  const verifiedSourceCredentialByPair = new Map();
  for (const verified of verifiedSourceCredentials) {
    if (verifiedSourceCredentialByPair.has(verified.pairId)) {
      throw new Error('signed source TSK credential inventory contains duplicate pairs');
    }
    verifiedSourceCredentialByPair.set(verified.pairId, verified);
  }
  return withSerializable(pool, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.advisoryLockKey]);
    const processing = await client.query("SELECT COUNT(*)::int AS count FROM ultra_idempotency WHERE state='processing'");
    if (processing.rows[0].count !== 0) throw new Error('cannot export while idempotency work is processing');
    await client.query('DELETE FROM ultra_nonce_tombstones WHERE expires_at <= clock_timestamp()');
    const bindings = await client.query(
      'SELECT pair_id, tsk_client_id, agent_id FROM ultra_identity_bindings ORDER BY pair_id COLLATE "C"',
    );
    if (verifiedSourceCredentials.length !== bindings.rows.length) {
      throw new Error('signed source TSK credential inventory does not match identity bindings');
    }
    const credentialBindings = [];
    for (const binding of bindings.rows) {
      const verified = verifiedSourceCredentialByPair.get(binding.pair_id);
      if (!verified || verified.commandId !== commandId ||
          verified.agentId !== binding.agent_id || verified.pairId !== binding.pair_id ||
          verified.sourceClientId !== binding.tsk_client_id) {
        throw new Error('signed source TSK credential does not match identity binding');
      }
      credentialBindings.push({
        agentId: binding.agent_id,
        pairId: binding.pair_id,
        sourceClientId: binding.tsk_client_id,
        sourceSecretDigest: verified.secretDigest,
      });
    }
    const idempotency = await client.query(
      `SELECT i.idempotency_key::text, i.operation, i.agent_id, i.response,
              r.original_response_digest, r.source_manifest_digest,
              r.source_system_id AS redaction_source_system_id,
              r.command_id AS redaction_command_id, r.source_epoch AS redaction_source_epoch,
              r.source_signature_digest, r.guard_signature_digest
         FROM ultra_idempotency i
         LEFT JOIN ultra_idempotency_redaction r USING (idempotency_key)
        WHERE i.state='complete'
        ORDER BY i.idempotency_key::text COLLATE "C"`,
    );
    const nonces = await client.query(
      'SELECT nonce_hash, expires_at FROM ultra_nonce_tombstones ORDER BY nonce_hash COLLATE "C"',
    );
    const state = {
      ...snapshotFromRows({ bindings: bindings.rows, idempotency: idempotency.rows, nonces: nonces.rows }),
      credentialBindings,
    };
    const itemCount = state.identityBindings.length + state.idempotency.length +
      state.nonceTombstones.length + state.credentialBindings.length;
    const stateBytes = Buffer.byteLength(canonicalJson(state), 'utf8');
    if (itemCount > maxItems || stateBytes > maxBytes) throw new Error('independent state exceeds export bounds');
    const manifest = {
      authorityDigest: digest({
        identityBindings: state.identityBindings,
        idempotency: state.idempotency,
        tskCredentials: [],
      }),
      bpcPromotionDigest,
      bpcStreamId: requiredStreamIdentifier(
        protocolEvidence.bpcPromotionAttestation.streamId, 'bpcStreamId',
      ),
      bpcTargetEpoch: positiveSafeInteger(
        protocolEvidence.bpcPromotionAttestation.targetEpoch, 'bpcTargetEpoch',
      ),
      clusterId,
      commandId,
      format: 'selfconnect-ultra-independent-state-v2',
      itemCount,
      sourceEpoch,
      sourceSystemId: await systemIdentifier(client),
      state,
      stateBytes,
      stateDigest: digest(state),
      tskActivationDigest,
      tskStreamId: requiredStreamIdentifier(
        protocolEvidence.tskFinalizedReceipt.streamId, 'tskStreamId',
      ),
      tskTargetEpoch: positiveSafeInteger(
        protocolEvidence.tskActivationLease.leaseEpoch, 'tskTargetEpoch',
      ),
      tskFinalizedDigest,
    };
    const manifestDigest = digest(manifest);
    return {
      manifest,
      manifestDigest,
      protocolEvidence,
      sourceKeyId,
      sourceSignature: signDigest(
        input.sourcePrivateKey, manifestDigest, 'selfconnect-ultra-independent-source-v1', sourceKeyId,
      ),
    };
  });
}

export function guardCountersignIndependentState(sourceBundle, input) {
  verifySourceBundle(sourceBundle, input.sourcePublicKey);
  verifyProtocolEvidence(sourceBundle.protocolEvidence, sourceBundle.manifest, input);
  validateState(sourceBundle.manifest.state);
  if (sourceBundle.manifest.commandId !== input.expectedCommandId) throw new Error('source command mismatch');
  const guardDigest = digest({
    domain: 'selfconnect-ultra-independent-state-guard-v1',
    manifestDigest: sourceBundle.manifestDigest,
    sourceKeyId: sourceBundle.sourceKeyId,
    sourceSignature: sourceBundle.sourceSignature,
  });
  const guardKeyId = requiredIdentifier(input.guardKeyId, 'guardKeyId');
  const guardPrivateKey = requirePrivateEd25519(input.guardPrivateKey, 'guard signing key');
  const guardPublicKey = createPublicKey(guardPrivateKey);
  if (keyFingerprint(guardPublicKey) === keyFingerprint(requirePublicEd25519(
    input.sourcePublicKey, 'source verification key',
  ))) throw new Error('source and guard custody keys must be distinct');
  return {
    ...structuredClone(sourceBundle),
    guardDigest,
    guardKeyId,
    guardSignature: signDigest(
      guardPrivateKey, guardDigest, 'selfconnect-ultra-independent-guard-v1', guardKeyId,
    ),
  };
}

function verifySourceBundle(bundle, sourcePublicKey) {
  strictKeys(bundle, new Set([
    'manifest', 'manifestDigest', 'protocolEvidence', 'sourceKeyId', 'sourceSignature',
  ]), 'source bundle');
  if (digest(bundle.manifest) !== bundle.manifestDigest || !DIGEST.test(bundle.manifestDigest)) {
    throw new Error('source manifest digest mismatch');
  }
  requiredIdentifier(bundle.sourceKeyId, 'sourceKeyId');
  if (!verifyDigest(
    sourcePublicKey, bundle.manifestDigest, bundle.sourceSignature,
    'selfconnect-ultra-independent-source-v1', bundle.sourceKeyId,
  )) {
    throw new Error('source signature invalid');
  }
  validateManifest(bundle.manifest);
  if (digest(bundle.manifest.state) !== bundle.manifest.stateDigest) throw new Error('source state digest mismatch');
}

export function verifyIndependentStateBundle(bundle, keys) {
  strictKeys(bundle, new Set([
    'guardDigest', 'guardKeyId', 'guardSignature', 'manifest', 'manifestDigest',
    'protocolEvidence', 'sourceKeyId', 'sourceSignature',
  ]), 'independent state bundle');
  verifySourceBundle({
    manifest: bundle.manifest,
    manifestDigest: bundle.manifestDigest,
    protocolEvidence: bundle.protocolEvidence,
    sourceKeyId: bundle.sourceKeyId,
    sourceSignature: bundle.sourceSignature,
  }, keys.sourcePublicKey);
  requiredIdentifier(bundle.guardKeyId, 'guardKeyId');
  if (keyFingerprint(requirePublicEd25519(keys.sourcePublicKey, 'source verification key')) ===
      keyFingerprint(requirePublicEd25519(keys.guardPublicKey, 'guard verification key'))) {
    throw new Error('source and guard custody keys must be distinct');
  }
  verifyProtocolEvidence(bundle.protocolEvidence, bundle.manifest, keys);
  const expectedGuardDigest = digest({
    domain: 'selfconnect-ultra-independent-state-guard-v1',
    manifestDigest: bundle.manifestDigest,
    sourceKeyId: bundle.sourceKeyId,
    sourceSignature: bundle.sourceSignature,
  });
  if (bundle.guardDigest !== expectedGuardDigest || !verifyDigest(
    keys.guardPublicKey, bundle.guardDigest, bundle.guardSignature,
    'selfconnect-ultra-independent-guard-v1', bundle.guardKeyId,
  )) throw new Error('guard signature invalid');
  return true;
}

function validateState(state) {
  strictKeys(state, new Set([
    'credentialBindings', 'identityBindings', 'idempotency', 'nonceTombstones',
  ]), 'state');
  if (!state || !Array.isArray(state.identityBindings) || !Array.isArray(state.idempotency) ||
      !Array.isArray(state.nonceTombstones) || !Array.isArray(state.credentialBindings)) {
    throw new Error('state inventory invalid');
  }
  const unique = (values, name) => {
    if (new Set(values).size !== values.length) throw new Error(`${name} contains duplicates`);
  };
  unique(state.identityBindings.map((item) => item.pairId), 'identity bindings');
  unique(state.idempotency.map((item) => item.idempotencyKey), 'idempotency');
  unique(state.nonceTombstones.map((item) => item.nonceHash), 'nonce tombstones');
  unique(state.credentialBindings.map((item) => item.pairId), 'credential bindings');
  if (state.credentialBindings.length !== state.identityBindings.length) {
    throw new Error('credential binding inventory mismatch');
  }
  for (let index = 0; index < state.identityBindings.length; index += 1) {
    const binding = state.identityBindings[index];
    const credential = state.credentialBindings[index];
    strictKeys(binding, new Set(['agentId', 'pairId', 'tskClientId']), 'identity binding');
    strictKeys(credential, new Set([
      'agentId', 'pairId', 'sourceClientId', 'sourceSecretDigest',
    ]), 'credential binding');
    requiredIdentifier(binding.agentId, 'identityBindings.agentId');
    requiredIdentifier(binding.pairId, 'identityBindings.pairId');
    requiredIdentifier(binding.tskClientId, 'identityBindings.tskClientId');
    requiredIdentifier(credential.agentId, 'credentialBindings.agentId');
    requiredIdentifier(credential.pairId, 'credentialBindings.pairId');
    requiredIdentifier(credential.sourceClientId, 'credentialBindings.sourceClientId');
    requiredDigest(credential.sourceSecretDigest, 'credentialBindings.sourceSecretDigest');
    if (binding.agentId !== credential.agentId || binding.pairId !== credential.pairId ||
        binding.tskClientId !== credential.sourceClientId) {
      throw new Error('credential binding does not match identity binding');
    }
  }
  for (const item of state.idempotency) {
    strictKeys(item, new Set([
      'agentId', 'idempotencyKey', 'operation', 'response', 'responseDigest',
      'redactionProvenance', 'secretReprovisionRequired',
    ]), 'idempotency record');
    requiredIdentifier(item.agentId, 'idempotency.agentId');
    requiredIdentifier(item.idempotencyKey, 'idempotency.idempotencyKey');
    requiredIdentifier(item.operation, 'idempotency.operation');
    if (typeof item.secretReprovisionRequired !== 'boolean' || !DIGEST.test(item.responseDigest)) {
      throw new Error('idempotency record invalid');
    }
    if (item.secretReprovisionRequired ? item.response !== null : digest(item.response) !== item.responseDigest) {
      throw new Error('idempotency response digest mismatch');
    }
    if (item.redactionProvenance !== null) {
      strictKeys(item.redactionProvenance, new Set([
        'commandId', 'guardSignatureDigest', 'sourceEpoch', 'sourceManifestDigest',
        'sourceSignatureDigest', 'sourceSystemId',
      ]), 'redaction provenance');
      requiredIdentifier(item.redactionProvenance.commandId, 'redactionProvenance.commandId');
      requiredIdentifier(item.redactionProvenance.sourceSystemId, 'redactionProvenance.sourceSystemId');
      positiveSafeInteger(item.redactionProvenance.sourceEpoch, 'redactionProvenance.sourceEpoch');
      requiredDigest(item.redactionProvenance.sourceManifestDigest, 'redactionProvenance.sourceManifestDigest');
      requiredDigest(item.redactionProvenance.sourceSignatureDigest, 'redactionProvenance.sourceSignatureDigest');
      requiredDigest(item.redactionProvenance.guardSignatureDigest, 'redactionProvenance.guardSignatureDigest');
      if (!item.secretReprovisionRequired) throw new Error('redaction provenance requires a redacted record');
    }
  }
  for (const nonce of state.nonceTombstones) {
    strictKeys(nonce, new Set(['expiresAt', 'nonceHash']), 'nonce tombstone');
    if (!DIGEST.test(nonce.nonceHash) || !Number.isFinite(Date.parse(nonce.expiresAt)) ||
        new Date(nonce.expiresAt).toISOString() !== nonce.expiresAt) {
      throw new Error('nonce tombstone invalid');
    }
  }
}

function validateManifest(manifest) {
  strictKeys(manifest, new Set([
    'authorityDigest', 'bpcPromotionDigest', 'bpcStreamId', 'bpcTargetEpoch', 'clusterId', 'commandId', 'format', 'itemCount', 'sourceEpoch',
    'sourceSystemId', 'state', 'stateBytes', 'stateDigest', 'tskActivationDigest',
    'tskFinalizedDigest', 'tskStreamId', 'tskTargetEpoch',
  ]), 'independent state manifest');
  if (manifest.format !== 'selfconnect-ultra-independent-state-v2') throw new Error('manifest format invalid');
  requiredIdentifier(manifest.clusterId, 'manifest.clusterId');
  requiredIdentifier(manifest.commandId, 'manifest.commandId');
  positiveSafeInteger(manifest.sourceEpoch, 'manifest.sourceEpoch');
  requiredDigest(manifest.bpcPromotionDigest, 'manifest.bpcPromotionDigest');
  requiredStreamIdentifier(manifest.bpcStreamId, 'manifest.bpcStreamId');
  positiveSafeInteger(manifest.bpcTargetEpoch, 'manifest.bpcTargetEpoch');
  requiredDigest(manifest.authorityDigest, 'manifest.authorityDigest');
  requiredDigest(manifest.tskActivationDigest, 'manifest.tskActivationDigest');
  requiredStreamIdentifier(manifest.tskStreamId, 'manifest.tskStreamId');
  positiveSafeInteger(manifest.tskTargetEpoch, 'manifest.tskTargetEpoch');
  requiredDigest(manifest.tskFinalizedDigest, 'manifest.tskFinalizedDigest');
  requiredDigest(manifest.stateDigest, 'manifest.stateDigest');
  validateState(manifest.state);
  const itemCount = manifest.state.identityBindings.length + manifest.state.idempotency.length +
    manifest.state.nonceTombstones.length + manifest.state.credentialBindings.length;
  if (manifest.itemCount !== itemCount || manifest.stateBytes !== Buffer.byteLength(canonicalJson(manifest.state), 'utf8')) {
    throw new Error('manifest inventory mismatch');
  }
  if (manifest.authorityDigest !== digest({
    identityBindings: manifest.state.identityBindings,
    idempotency: manifest.state.idempotency,
    tskCredentials: [],
  })) throw new Error('manifest authority digest mismatch');
}

function verifyProtocolEvidence(evidence, manifest, resolvers) {
  strictKeys(evidence, new Set([
    'bpcPromotionAttestation', 'tskActivationLease', 'tskFinalizedReceipt',
  ]), 'protocol evidence');
  if (!resolvers.bpcResolver || !resolvers.tskBResolver || !resolvers.tskGuardResolver) {
    throw new Error('BPC, TSK B, and TSK guard public-key resolvers are required');
  }
  verifyPromotionReadinessAttestation(resolvers.bpcResolver, evidence.bpcPromotionAttestation);
  verifyBFinalizedReceipt(resolvers.tskBResolver, evidence.tskFinalizedReceipt);
  verifyLeaseGrant(resolvers.tskGuardResolver, evidence.tskActivationLease);
  const bpc = evidence.bpcPromotionAttestation;
  const finalized = evidence.tskFinalizedReceipt;
  const lease = evidence.tskActivationLease;
  if (bpc.attestationDigest !== manifest.bpcPromotionDigest ||
      finalized.receiptDigest !== manifest.tskFinalizedDigest ||
      lease.grantDigest !== manifest.tskActivationDigest) {
    throw new Error('protocol evidence digest mismatch');
  }
  if (bpc.commandId !== manifest.commandId || finalized.commandId !== manifest.commandId ||
      lease.commandId !== manifest.commandId || bpc.targetEpoch !== manifest.bpcTargetEpoch ||
      lease.leaseEpoch !== manifest.tskTargetEpoch || finalized.epoch !== manifest.tskTargetEpoch - 1 ||
      lease.leaseStatus !== 'active' || lease.holderNodeId !== finalized.bKeyId ||
      bpc.targetSystemId === finalized.bSystemId || finalized.sourceSystemId !== manifest.sourceSystemId ||
      bpc.streamId !== manifest.bpcStreamId || finalized.streamId !== manifest.tskStreamId ||
      finalized.streamId !== lease.streamId) {
    throw new Error('protocol evidence promotion binding mismatch');
  }
}

export async function importIndependentState(pool, bundle, input) {
  verifyIndependentStateBundle(bundle, input);
  const manifest = bundle.manifest;
  if (manifest.clusterId !== input.clusterId || manifest.commandId !== input.commandId ||
      manifest.sourceEpoch !== input.sourceEpoch ||
      manifest.bpcPromotionDigest !== input.bpcPromotionDigest ||
      manifest.tskActivationDigest !== input.tskActivationDigest ||
      manifest.tskFinalizedDigest !== input.tskFinalizedDigest) throw new Error('promotion binding mismatch');
  validateState(manifest.state);
  return withSerializable(pool, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.advisoryLockKey]);
    const targetSystemId = await systemIdentifier(client);
    if (targetSystemId === manifest.sourceSystemId) throw new Error('source and target PostgreSQL authorities are not independent');
    if (targetSystemId !== bundle.protocolEvidence.tskFinalizedReceipt.bSystemId) {
      throw new Error('protocol evidence belongs to a different target PostgreSQL authority');
    }
    const current = await client.query('SELECT * FROM ultra_ha_import_head WHERE cluster_id=$1 FOR UPDATE', [manifest.clusterId]);
    if (current.rows[0]) {
      const row = current.rows[0];
      if (Number(row.source_epoch) > manifest.sourceEpoch) throw new Error('state rollback refused');
      if (Number(row.source_epoch) === manifest.sourceEpoch) {
        if (row.manifest_digest !== bundle.manifestDigest || row.command_id !== manifest.commandId) {
          throw new Error('same-epoch state fork refused');
        }
        if (row.target_system_id !== targetSystemId || row.source_system_id !== manifest.sourceSystemId ||
            digest(await readTargetAuthorityState(client)) !== row.authority_digest) {
          throw new Error('same-epoch imported authority was rolled back or tampered');
        }
        await assertNoActiveUnboundCredentials(client);
        for (const item of manifest.state.nonceTombstones) {
          await client.query(
            `INSERT INTO ultra_nonce_tombstones (nonce_hash, expires_at)
             SELECT $1,$2::timestamptz WHERE $2::timestamptz > clock_timestamp()
             ON CONFLICT (nonce_hash) DO UPDATE SET expires_at=GREATEST(
               ultra_nonce_tombstones.expires_at, EXCLUDED.expires_at
             )`,
            [item.nonceHash, item.expiresAt],
          );
        }
        return { idempotent: true, manifestDigest: bundle.manifestDigest, targetSystemId };
      }
    }
    const processing = await client.query("SELECT COUNT(*)::int AS count FROM ultra_idempotency WHERE state='processing'");
    if (processing.rows[0].count !== 0) throw new Error('target contains in-flight idempotency work');
    await client.query('DELETE FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1', [manifest.clusterId]);
    await client.query('DELETE FROM ultra_identity_bindings');
    await client.query('DELETE FROM ultra_idempotency');
    await client.query('DELETE FROM ultra_nonce_tombstones');
    await client.query('DELETE FROM ultra_tumbler_maps');
    for (const item of manifest.state.identityBindings) {
      await client.query(
        'INSERT INTO ultra_identity_bindings (pair_id, tsk_client_id, agent_id) VALUES ($1,$2,$3)',
        [item.pairId, item.tskClientId, item.agentId],
      );
    }
    for (const item of manifest.state.idempotency) {
      const response = item.secretReprovisionRequired
        ? { ok: false, error: 'SECRET_REPROVISION_REQUIRED', originalResponseDigest: item.responseDigest }
        : item.response;
      if (item.secretReprovisionRequired
        ? item.response !== null || !DIGEST.test(item.responseDigest)
        : digest(response) !== item.responseDigest) {
        throw new Error('idempotency response digest mismatch');
      }
      await client.query(
        `INSERT INTO ultra_idempotency
           (idempotency_key, operation, agent_id, state, response)
         VALUES ($1,$2,$3,'complete',$4::jsonb)`,
        [item.idempotencyKey, item.operation, item.agentId, JSON.stringify(response)],
      );
      if (item.secretReprovisionRequired) {
        await client.query(
          `INSERT INTO ultra_idempotency_redaction
             (idempotency_key, original_response_digest, source_manifest_digest,
              source_system_id, command_id, source_epoch,
              source_signature_digest, guard_signature_digest)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [item.idempotencyKey, item.responseDigest, bundle.manifestDigest,
           manifest.sourceSystemId, manifest.commandId, manifest.sourceEpoch,
           createHash('sha256').update(bundle.sourceSignature, 'utf8').digest('hex'),
           createHash('sha256').update(bundle.guardSignature, 'utf8').digest('hex')],
        );
      }
    }
    for (const item of manifest.state.nonceTombstones) {
      await client.query(
        `INSERT INTO ultra_nonce_tombstones (nonce_hash, expires_at)
         SELECT $1,$2::timestamptz WHERE $2::timestamptz > clock_timestamp()`,
        [item.nonceHash, item.expiresAt],
      );
    }
    await client.query(
      `INSERT INTO ultra_ha_import_head
         (cluster_id, command_id, source_epoch, source_system_id, target_system_id,
          manifest_digest, authority_digest)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (cluster_id) DO UPDATE SET
         command_id=EXCLUDED.command_id, source_epoch=EXCLUDED.source_epoch,
         source_system_id=EXCLUDED.source_system_id, target_system_id=EXCLUDED.target_system_id,
         manifest_digest=EXCLUDED.manifest_digest, authority_digest=EXCLUDED.authority_digest,
         imported_at=clock_timestamp()`,
      [manifest.clusterId, manifest.commandId, manifest.sourceEpoch, manifest.sourceSystemId,
      targetSystemId, bundle.manifestDigest, manifest.authorityDigest],
    );
    for (const item of manifest.state.credentialBindings) {
      await client.query(
        `INSERT INTO ultra_ha_tsk_reprovision
           (cluster_id, pair_id, agent_id, source_client_id, source_secret_digest, status)
         VALUES ($1,$2,$3,$4,$5,'pending')`,
        [manifest.clusterId, item.pairId, item.agentId, item.sourceClientId,
          item.sourceSecretDigest],
      );
    }
    const importedAuthorityDigest = digest(await readTargetAuthorityState(client));
    await client.query(
      'UPDATE ultra_ha_import_head SET authority_digest=$2 WHERE cluster_id=$1',
      [manifest.clusterId, importedAuthorityDigest],
    );
    return { idempotent: false, manifestDigest: bundle.manifestDigest, targetSystemId };
  });
}

export async function completeImportedTskReprovision(pool, input) {
  const targetMap = JSON.parse(JSON.stringify(input.targetMap));
  requiredIdentifier(input.clusterId, 'clusterId');
  requiredIdentifier(input.commandId, 'commandId');
  positiveSafeInteger(input.sourceEpoch, 'sourceEpoch');
  requiredIdentifier(input.pairId, 'pairId');
  requiredIdentifier(input.agentId, 'agentId');
  requiredIdentifier(input.sourceClientId, 'sourceClientId');
  requiredIdentifier(targetMap?.clientId, 'targetMap.clientId');
  if (targetMap.clientId === input.sourceClientId || targetMap.label !== `agent:${input.agentId}` ||
      targetMap.status !== 'active' || typeof targetMap.sharedSecret !== 'string' ||
      targetMap.sharedSecret.length < 32 || !Array.isArray(targetMap.segments) ||
      targetMap.segments.length === 0) {
    throw new Error('target TSK credential is not a fresh active owned credential');
  }
  if (typeof input.assertWritable !== 'function') {
    throw new Error('TSK reprovision requires a live writer-fence assertion');
  }
  return withSerializable(pool, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.advisoryLockKey]);
    const head = (await client.query(
      `SELECT command_id, source_epoch, authority_digest FROM ultra_ha_import_head
       WHERE cluster_id=$1 FOR UPDATE`, [input.clusterId],
    )).rows[0];
    if (!head || head.command_id !== input.commandId || Number(head.source_epoch) !== input.sourceEpoch) {
      throw new Error('TSK reprovision does not match the imported promotion');
    }
    const pending = (await client.query(
      `SELECT agent_id, source_client_id, source_secret_digest, target_client_id,
              status, receipt_digest, target_proof_digest, activation_grant_digest
       FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1 AND pair_id=$2 FOR UPDATE`,
      [input.clusterId, input.pairId],
    )).rows[0];
    if (!pending || pending.agent_id !== input.agentId || pending.source_client_id !== input.sourceClientId) {
      throw new Error('TSK reprovision binding mismatch');
    }
    if (digest(await readTargetAuthorityState(client)) !== head.authority_digest) {
      throw new Error('imported authority was rolled back or tampered before TSK reprovision');
    }
    await assertNoActiveUnboundCredentials(client);
    const receipt = {
      agentId: input.agentId,
      clusterId: input.clusterId,
      commandId: input.commandId,
      pairId: input.pairId,
      publicMapDigest: publicTskMapDigest(targetMap),
      sourceClientId: input.sourceClientId,
      sourceEpoch: input.sourceEpoch,
      targetClientId: targetMap.clientId,
    };
    const receiptDigest = digest(receipt);
    if (pending.status === 'complete') {
      if (pending.target_client_id !== targetMap.clientId || pending.receipt_digest !== receiptDigest) {
        throw new Error('TSK reprovision retry conflicts with completed receipt');
      }
      const stored = (await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1', [targetMap.clientId],
      )).rows[0]?.map;
      if (!stored || digest(stored) !== digest(targetMap)) {
        throw new Error('completed TSK reprovision authority was rolled back or tampered');
      }
      const writable = await input.assertWritable();
      if (!writable?.ok || Number(writable.fenceEpoch) !== input.sourceEpoch) {
        throw new Error('TSK reprovision writer fence is not current');
      }
      return Object.freeze({ ...receipt, receiptDigest, idempotent: true });
    }
    await client.query(
      'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
      [targetMap.clientId, JSON.stringify(targetMap)],
    );
    const rebound = await client.query(
      `UPDATE ultra_identity_bindings SET tsk_client_id=$3, updated_at=clock_timestamp()
       WHERE pair_id=$1 AND agent_id=$2 AND tsk_client_id=$4`,
      [input.pairId, input.agentId, targetMap.clientId, input.sourceClientId],
    );
    if (rebound.rowCount !== 1) throw new Error('imported identity rebind failed');
    await client.query(
      `UPDATE ultra_ha_tsk_reprovision SET target_client_id=$3, status='complete',
         receipt_digest=$4, updated_at=clock_timestamp()
       WHERE cluster_id=$1 AND pair_id=$2`,
      [input.clusterId, input.pairId, targetMap.clientId, receiptDigest],
    );
    const authorityDigest = digest(await readTargetAuthorityState(client));
    await client.query(
      'UPDATE ultra_ha_import_head SET authority_digest=$2 WHERE cluster_id=$1',
      [input.clusterId, authorityDigest],
    );
    const writable = await input.assertWritable();
    if (!writable?.ok || Number(writable.fenceEpoch) !== input.sourceEpoch) {
      throw new Error('TSK reprovision writer fence was lost before commit');
    }
    return Object.freeze({ ...receipt, receiptDigest, idempotent: false });
  });
}

/**
 * Complete an independent-site credential handoff using only a signed public
 * PgHaTumblerMapStore ledger proof and an opaque configured authority
 * capability. No shared secret or caller-provided writability callback enters
 * the Enterprise database.
 */
export async function completeImportedPromotedTskCredential(pool, authorityCapability, input) {
  const targetProof = structuredClone(input.targetProof);
  requiredIdentifier(input.clusterId, 'clusterId');
  requiredIdentifier(input.commandId, 'commandId');
  positiveSafeInteger(input.sourceEpoch, 'sourceEpoch');
  requiredIdentifier(input.pairId, 'pairId');
  requiredIdentifier(input.agentId, 'agentId');
  requiredIdentifier(input.sourceClientId, 'sourceClientId');
  requiredDigest(input.sourceSecretDigest, 'sourceSecretDigest');
  const verified = await verifyPromotedTskCredentialProof(
    authorityCapability,
    targetProof,
    {
      agentId: input.agentId,
      pairId: input.pairId,
      sourceClientId: input.sourceClientId,
      sourceSecretDigest: input.sourceSecretDigest,
    },
  );
  if (verified.commandId !== input.commandId || verified.sourceEpoch !== input.sourceEpoch) {
    throw new Error('promoted TSK credential proof does not match the imported epoch/command');
  }
  const targetProofDigest = digest(targetProof);
  const receipt = Object.freeze({
    activationGrantDigest: verified.activationGrantDigest,
    agentId: input.agentId,
    clusterId: input.clusterId,
    commandId: input.commandId,
    headDigest: verified.headDigest,
    pairId: input.pairId,
    publicMapDigest: verified.publicMapDigest,
    sourceClientId: input.sourceClientId,
    sourceEpoch: input.sourceEpoch,
    targetClientId: verified.targetClientId,
    targetProofDigest,
  });
  const receiptDigest = digest(receipt);
  return withSerializable(pool, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.advisoryLockKey]);
    const head = (await client.query(
      `SELECT command_id, source_epoch, authority_digest FROM ultra_ha_import_head
       WHERE cluster_id=$1 FOR UPDATE`, [input.clusterId],
    )).rows[0];
    if (!head || head.command_id !== input.commandId || Number(head.source_epoch) !== input.sourceEpoch) {
      throw new Error('TSK reprovision does not match the imported promotion');
    }
    const pending = (await client.query(
      `SELECT agent_id,source_client_id,source_secret_digest,target_client_id,status,
              target_proof,target_proof_digest,activation_grant_digest,receipt_digest
         FROM ultra_ha_tsk_reprovision
        WHERE cluster_id=$1 AND pair_id=$2 FOR UPDATE`,
      [input.clusterId, input.pairId],
    )).rows[0];
    if (!pending || pending.agent_id !== input.agentId ||
        pending.source_client_id !== input.sourceClientId ||
        pending.source_secret_digest !== input.sourceSecretDigest) {
      throw new Error('TSK reprovision binding mismatch');
    }
    if (digest(await readTargetAuthorityState(client)) !== head.authority_digest) {
      throw new Error('imported authority was rolled back or tampered before TSK reprovision');
    }
    if (pending.status === 'complete') {
      if (pending.target_client_id !== verified.targetClientId ||
          pending.target_proof_digest !== targetProofDigest ||
          pending.activation_grant_digest !== verified.activationGrantDigest ||
          pending.receipt_digest !== receiptDigest ||
          canonicalJson(pending.target_proof) !== canonicalJson(targetProof)) {
        throw new Error('TSK reprovision retry conflicts with completed public proof');
      }
      return Object.freeze({ ...receipt, receiptDigest, idempotent: true });
    }
    const rebound = await client.query(
      `UPDATE ultra_identity_bindings SET tsk_client_id=$3, updated_at=clock_timestamp()
       WHERE pair_id=$1 AND agent_id=$2 AND tsk_client_id=$4`,
      [input.pairId, input.agentId, verified.targetClientId, input.sourceClientId],
    );
    if (rebound.rowCount !== 1) throw new Error('imported identity rebind failed');
    await client.query(
      `UPDATE ultra_ha_tsk_reprovision
          SET target_client_id=$3,status='complete',target_proof=$4::jsonb,
              target_proof_digest=$5,activation_grant_digest=$6,receipt_digest=$7,
              updated_at=clock_timestamp()
        WHERE cluster_id=$1 AND pair_id=$2`,
      [input.clusterId, input.pairId, verified.targetClientId,
        JSON.stringify(targetProof), targetProofDigest, verified.activationGrantDigest,
        receiptDigest],
    );
    const authorityDigest = digest(await readTargetAuthorityState(client));
    await client.query(
      'UPDATE ultra_ha_import_head SET authority_digest=$2 WHERE cluster_id=$1',
      [input.clusterId, authorityDigest],
    );
    return Object.freeze({ ...receipt, receiptDigest, idempotent: false });
  });
}

export async function readImportedTskReprovision(pool, input) {
  requiredIdentifier(input.clusterId, 'clusterId');
  requiredIdentifier(input.pairId, 'pairId');
  return withSerializable(pool, async (client) => {
    const { rows } = await client.query(
      `SELECT agent_id, source_client_id, source_secret_digest, target_client_id,
              status, receipt_digest, target_proof_digest, activation_grant_digest
       FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1 AND pair_id=$2`,
      [input.clusterId, input.pairId],
    );
    if (!rows[0]) return null;
    return Object.freeze({
      agentId: rows[0].agent_id,
      pairId: input.pairId,
      receiptDigest: rows[0].receipt_digest,
      sourceClientId: rows[0].source_client_id,
      sourceSecretDigest: rows[0].source_secret_digest,
      status: rows[0].status,
      targetClientId: rows[0].target_client_id,
      targetProofDigest: rows[0].target_proof_digest,
      activationGrantDigest: rows[0].activation_grant_digest,
    });
  });
}

export async function assertIndependentStateReady(pool, expected) {
  return withSerializable(pool, async (client) => {
    const { rows } = await client.query(
      `SELECT command_id, source_epoch, source_system_id, target_system_id,
              manifest_digest, authority_digest
       FROM ultra_ha_import_head WHERE cluster_id=$1 FOR SHARE`,
      [expected.clusterId],
    );
    const row = rows[0];
    if (!row || row.command_id !== expected.commandId || Number(row.source_epoch) !== expected.sourceEpoch ||
        row.manifest_digest !== expected.manifestDigest) throw new Error('independent state is not ready');
    const processing = await client.query(
      "SELECT COUNT(*)::int AS count FROM ultra_idempotency WHERE state='processing'",
    );
    if (processing.rows[0].count !== 0) {
      throw new Error('independent state contains in-flight idempotency work');
    }
    const pending = await client.query(
      "SELECT COUNT(*)::int AS count FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1 AND status='pending'",
      [expected.clusterId],
    );
    if (pending.rows[0].count !== 0) {
      throw new Error('independent state requires TSK credential reprovisioning');
    }
    await assertNoActiveUnboundCredentials(client);
    const liveSystemId = await systemIdentifier(client);
    if (row.target_system_id !== liveSystemId || row.source_system_id === liveSystemId) {
      throw new Error('independent state authority mismatch');
    }
    if (digest(await readTargetAuthorityState(client)) !== row.authority_digest) {
      throw new Error('independent state authority was rolled back or tampered');
    }
    return Object.freeze({
      clusterId: expected.clusterId,
      commandId: expected.commandId,
      manifestDigest: expected.manifestDigest,
      sourceEpoch: expected.sourceEpoch,
      targetSystemId: liveSystemId,
    });
  });
}
