import {
  createHash,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { verifyPromotionReadinessAttestation } from '@bpc/server';
import { verifyBFinalizedReceipt, verifyLeaseGrant } from '@tsk/server';

const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,128}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SECRET_FIELD = /(?:secret|token|password|private|credential|provisionpayload)/i;

export const ULTRA_INDEPENDENT_STATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS ultra_nonce_tombstones (
  nonce_hash TEXT PRIMARY KEY CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ultra_nonce_tombstones_expiry_idx
  ON ultra_nonce_tombstones (expires_at);

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
  target_client_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'complete')),
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

async function withSerializable(pool, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
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

function snapshotFromRows({ bindings, idempotency, nonces }) {
  const safeIdempotency = idempotency.map((row) => {
    const response = typeof row.response === 'string' ? JSON.parse(row.response) : row.response;
    const sensitive = containsSecret(response);
    return {
      agentId: row.agent_id,
      idempotencyKey: row.idempotency_key,
      operation: row.operation,
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
  const keys = response && typeof response === 'object' && !Array.isArray(response)
    ? Object.keys(response).sort() : [];
  if (keys.join(',') === 'error,ok,originalResponseDigest' &&
      response.ok === false && response.error === 'SECRET_REPROVISION_REQUIRED' &&
      DIGEST.test(response.originalResponseDigest)) {
    return {
      agentId: row.agent_id,
      idempotencyKey: row.idempotency_key,
      operation: row.operation,
      response: null,
      responseDigest: response.originalResponseDigest,
      secretReprovisionRequired: true,
    };
  }
  return {
    agentId: row.agent_id,
    idempotencyKey: row.idempotency_key,
    operation: row.operation,
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
    "SELECT idempotency_key::text, operation, agent_id, response FROM ultra_idempotency WHERE state='complete' ORDER BY idempotency_key::text COLLATE \"C\"",
  );
  const identityBindings = bindings.rows.map((row) => ({
      agentId: row.agent_id, pairId: row.pair_id, tskClientId: row.tsk_client_id,
    }));
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
  };
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
  return withSerializable(pool, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.advisoryLockKey]);
    const processing = await client.query("SELECT COUNT(*)::int AS count FROM ultra_idempotency WHERE state='processing'");
    if (processing.rows[0].count !== 0) throw new Error('cannot export while idempotency work is processing');
    await client.query('DELETE FROM ultra_nonce_tombstones WHERE expires_at <= clock_timestamp()');
    const bindings = await client.query(
      'SELECT pair_id, tsk_client_id, agent_id FROM ultra_identity_bindings ORDER BY pair_id COLLATE "C"',
    );
    const credentialBindings = [];
    const boundClientIds = new Set(bindings.rows.map((binding) => binding.tsk_client_id));
    const allMaps = await client.query('SELECT client_id, map FROM ultra_tumbler_maps ORDER BY client_id COLLATE "C"');
    for (const row of allMaps.rows) {
      const map = row.map;
      if (!boundClientIds.has(row.client_id) && ['active', 'expiring'].includes(map?.status)) {
        throw new Error('cannot export with an active unbound TSK credential');
      }
    }
    for (const binding of bindings.rows) {
      const maps = await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1', [binding.tsk_client_id],
      );
      const map = maps.rows[0]?.map;
      const ownedLabel = map?.label === `agent:${binding.agent_id}` ||
        map?.label?.startsWith(`rotation:${binding.agent_id}:${binding.pair_id}:`);
      if (!map || map.clientId !== binding.tsk_client_id || !ownedLabel || map.status !== 'active') {
        throw new Error('identity binding does not reference an active owned TSK credential');
      }
      credentialBindings.push({
        agentId: binding.agent_id,
        pairId: binding.pair_id,
        sourceClientId: binding.tsk_client_id,
      });
    }
    const idempotency = await client.query(
      "SELECT idempotency_key::text, operation, agent_id, response FROM ultra_idempotency WHERE state='complete' ORDER BY idempotency_key::text COLLATE \"C\"",
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
    requiredIdentifier(binding.agentId, 'identityBindings.agentId');
    requiredIdentifier(binding.pairId, 'identityBindings.pairId');
    requiredIdentifier(binding.tskClientId, 'identityBindings.tskClientId');
    requiredIdentifier(credential.agentId, 'credentialBindings.agentId');
    requiredIdentifier(credential.pairId, 'credentialBindings.pairId');
    requiredIdentifier(credential.sourceClientId, 'credentialBindings.sourceClientId');
    if (binding.agentId !== credential.agentId || binding.pairId !== credential.pairId ||
        binding.tskClientId !== credential.sourceClientId) {
      throw new Error('credential binding does not match identity binding');
    }
  }
  for (const item of state.idempotency) {
    if (typeof item.secretReprovisionRequired !== 'boolean' || !DIGEST.test(item.responseDigest)) {
      throw new Error('idempotency record invalid');
    }
    if (item.secretReprovisionRequired ? item.response !== null : digest(item.response) !== item.responseDigest) {
      throw new Error('idempotency response digest mismatch');
    }
  }
  for (const nonce of state.nonceTombstones) {
    if (!DIGEST.test(nonce.nonceHash) || !Number.isFinite(Date.parse(nonce.expiresAt))) {
      throw new Error('nonce tombstone invalid');
    }
  }
}

function validateManifest(manifest) {
  strictKeys(manifest, new Set([
    'authorityDigest', 'bpcPromotionDigest', 'clusterId', 'commandId', 'format', 'itemCount', 'sourceEpoch',
    'sourceSystemId', 'state', 'stateBytes', 'stateDigest', 'tskActivationDigest',
    'tskFinalizedDigest',
  ]), 'independent state manifest');
  if (manifest.format !== 'selfconnect-ultra-independent-state-v2') throw new Error('manifest format invalid');
  requiredIdentifier(manifest.clusterId, 'manifest.clusterId');
  requiredIdentifier(manifest.commandId, 'manifest.commandId');
  positiveSafeInteger(manifest.sourceEpoch, 'manifest.sourceEpoch');
  requiredDigest(manifest.bpcPromotionDigest, 'manifest.bpcPromotionDigest');
  requiredDigest(manifest.authorityDigest, 'manifest.authorityDigest');
  requiredDigest(manifest.tskActivationDigest, 'manifest.tskActivationDigest');
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
      lease.commandId !== manifest.commandId || bpc.targetEpoch !== manifest.sourceEpoch ||
      lease.leaseEpoch !== manifest.sourceEpoch || finalized.epoch !== manifest.sourceEpoch - 1 ||
      lease.leaseStatus !== 'active' || lease.holderNodeId !== finalized.bKeyId ||
      bpc.targetSystemId !== finalized.bSystemId || finalized.sourceSystemId !== manifest.sourceSystemId ||
      bpc.streamId !== finalized.streamId || finalized.streamId !== lease.streamId) {
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
    if (targetSystemId !== bundle.protocolEvidence.bpcPromotionAttestation.targetSystemId ||
        targetSystemId !== bundle.protocolEvidence.tskFinalizedReceipt.bSystemId) {
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
           (cluster_id, pair_id, agent_id, source_client_id, status)
         VALUES ($1,$2,$3,$4,'pending')`,
        [manifest.clusterId, item.pairId, item.agentId, item.sourceClientId],
      );
    }
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
      `SELECT command_id, source_epoch FROM ultra_ha_import_head
       WHERE cluster_id=$1 FOR UPDATE`, [input.clusterId],
    )).rows[0];
    if (!head || head.command_id !== input.commandId || Number(head.source_epoch) !== input.sourceEpoch) {
      throw new Error('TSK reprovision does not match the imported promotion');
    }
    const pending = (await client.query(
      `SELECT agent_id, source_client_id, target_client_id, status, receipt_digest
       FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1 AND pair_id=$2 FOR UPDATE`,
      [input.clusterId, input.pairId],
    )).rows[0];
    if (!pending || pending.agent_id !== input.agentId || pending.source_client_id !== input.sourceClientId) {
      throw new Error('TSK reprovision binding mismatch');
    }
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

export async function readImportedTskReprovision(pool, input) {
  requiredIdentifier(input.clusterId, 'clusterId');
  requiredIdentifier(input.pairId, 'pairId');
  const { rows } = await pool.query(
    `SELECT agent_id, source_client_id, target_client_id, status, receipt_digest
     FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1 AND pair_id=$2`,
    [input.clusterId, input.pairId],
  );
  if (!rows[0]) return null;
  return Object.freeze({
    agentId: rows[0].agent_id,
    pairId: input.pairId,
    receiptDigest: rows[0].receipt_digest,
    sourceClientId: rows[0].source_client_id,
    status: rows[0].status,
    targetClientId: rows[0].target_client_id,
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
