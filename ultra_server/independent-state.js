import {
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

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

function signDigest(privateKey, value) {
  return cryptoSign(null, Buffer.from(value, 'hex'), privateKey).toString('base64url');
}

function verifyDigest(publicKey, value, signature) {
  return typeof signature === 'string' && cryptoVerify(
    null,
    Buffer.from(value, 'hex'),
    publicKey,
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
  return {
    identityBindings: bindings.rows.map((row) => ({
      agentId: row.agent_id, pairId: row.pair_id, tskClientId: row.tsk_client_id,
    })),
    idempotency: idempotency.rows.map(targetIdempotencyRecord),
  };
}

export async function exportIndependentState(pool, input) {
  const clusterId = requiredIdentifier(input.clusterId, 'clusterId');
  const commandId = requiredIdentifier(input.commandId, 'commandId');
  const sourceEpoch = positiveSafeInteger(input.sourceEpoch, 'sourceEpoch');
  const bpcPromotionDigest = requiredDigest(input.bpcPromotionDigest, 'bpcPromotionDigest');
  const tskActivationDigest = requiredDigest(input.tskActivationDigest, 'tskActivationDigest');
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
    const idempotency = await client.query(
      "SELECT idempotency_key::text, operation, agent_id, response FROM ultra_idempotency WHERE state='complete' ORDER BY idempotency_key::text COLLATE \"C\"",
    );
    const nonces = await client.query(
      'SELECT nonce_hash, expires_at FROM ultra_nonce_tombstones ORDER BY nonce_hash COLLATE "C"',
    );
    const state = snapshotFromRows({ bindings: bindings.rows, idempotency: idempotency.rows, nonces: nonces.rows });
    const itemCount = state.identityBindings.length + state.idempotency.length + state.nonceTombstones.length;
    const stateBytes = Buffer.byteLength(canonicalJson(state), 'utf8');
    if (itemCount > maxItems || stateBytes > maxBytes) throw new Error('independent state exceeds export bounds');
    const manifest = {
      authorityDigest: digest({ identityBindings: state.identityBindings, idempotency: state.idempotency }),
      bpcPromotionDigest,
      clusterId,
      commandId,
      format: 'selfconnect-ultra-independent-state-v1',
      itemCount,
      sourceEpoch,
      sourceSystemId: await systemIdentifier(client),
      state,
      stateBytes,
      stateDigest: digest(state),
      tskActivationDigest,
    };
    const manifestDigest = digest(manifest);
    return {
      manifest,
      manifestDigest,
      sourceKeyId: requiredIdentifier(input.sourceKeyId, 'sourceKeyId'),
      sourceSignature: signDigest(input.sourcePrivateKey, manifestDigest),
    };
  });
}

export function guardCountersignIndependentState(sourceBundle, input) {
  verifySourceBundle(sourceBundle, input.sourcePublicKey);
  validateState(sourceBundle.manifest.state);
  if (sourceBundle.manifest.commandId !== input.expectedCommandId) throw new Error('source command mismatch');
  const guardDigest = digest({
    domain: 'selfconnect-ultra-independent-state-guard-v1',
    manifestDigest: sourceBundle.manifestDigest,
    sourceKeyId: sourceBundle.sourceKeyId,
    sourceSignature: sourceBundle.sourceSignature,
  });
  return {
    ...structuredClone(sourceBundle),
    guardDigest,
    guardKeyId: requiredIdentifier(input.guardKeyId, 'guardKeyId'),
    guardSignature: signDigest(input.guardPrivateKey, guardDigest),
  };
}

function verifySourceBundle(bundle, sourcePublicKey) {
  strictKeys(bundle, new Set(['manifest', 'manifestDigest', 'sourceKeyId', 'sourceSignature']), 'source bundle');
  if (digest(bundle.manifest) !== bundle.manifestDigest || !DIGEST.test(bundle.manifestDigest)) {
    throw new Error('source manifest digest mismatch');
  }
  if (!verifyDigest(sourcePublicKey, bundle.manifestDigest, bundle.sourceSignature)) {
    throw new Error('source signature invalid');
  }
  validateManifest(bundle.manifest);
  if (digest(bundle.manifest.state) !== bundle.manifest.stateDigest) throw new Error('source state digest mismatch');
}

export function verifyIndependentStateBundle(bundle, keys) {
  strictKeys(bundle, new Set([
    'guardDigest', 'guardKeyId', 'guardSignature', 'manifest', 'manifestDigest',
    'sourceKeyId', 'sourceSignature',
  ]), 'independent state bundle');
  verifySourceBundle({
    manifest: bundle.manifest,
    manifestDigest: bundle.manifestDigest,
    sourceKeyId: bundle.sourceKeyId,
    sourceSignature: bundle.sourceSignature,
  }, keys.sourcePublicKey);
  const expectedGuardDigest = digest({
    domain: 'selfconnect-ultra-independent-state-guard-v1',
    manifestDigest: bundle.manifestDigest,
    sourceKeyId: bundle.sourceKeyId,
    sourceSignature: bundle.sourceSignature,
  });
  if (bundle.guardDigest !== expectedGuardDigest || !verifyDigest(
    keys.guardPublicKey, bundle.guardDigest, bundle.guardSignature,
  )) throw new Error('guard signature invalid');
  return true;
}

function validateState(state) {
  if (!state || !Array.isArray(state.identityBindings) || !Array.isArray(state.idempotency) ||
      !Array.isArray(state.nonceTombstones)) throw new Error('state inventory invalid');
  const unique = (values, name) => {
    if (new Set(values).size !== values.length) throw new Error(`${name} contains duplicates`);
  };
  unique(state.identityBindings.map((item) => item.pairId), 'identity bindings');
  unique(state.idempotency.map((item) => item.idempotencyKey), 'idempotency');
  unique(state.nonceTombstones.map((item) => item.nonceHash), 'nonce tombstones');
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
  ]), 'independent state manifest');
  if (manifest.format !== 'selfconnect-ultra-independent-state-v1') throw new Error('manifest format invalid');
  requiredIdentifier(manifest.clusterId, 'manifest.clusterId');
  requiredIdentifier(manifest.commandId, 'manifest.commandId');
  positiveSafeInteger(manifest.sourceEpoch, 'manifest.sourceEpoch');
  requiredDigest(manifest.bpcPromotionDigest, 'manifest.bpcPromotionDigest');
  requiredDigest(manifest.authorityDigest, 'manifest.authorityDigest');
  requiredDigest(manifest.tskActivationDigest, 'manifest.tskActivationDigest');
  requiredDigest(manifest.stateDigest, 'manifest.stateDigest');
  validateState(manifest.state);
  const itemCount = manifest.state.identityBindings.length + manifest.state.idempotency.length +
    manifest.state.nonceTombstones.length;
  if (manifest.itemCount !== itemCount || manifest.stateBytes !== Buffer.byteLength(canonicalJson(manifest.state), 'utf8')) {
    throw new Error('manifest inventory mismatch');
  }
  if (manifest.authorityDigest !== digest({
    identityBindings: manifest.state.identityBindings,
    idempotency: manifest.state.idempotency,
  })) throw new Error('manifest authority digest mismatch');
}

export async function importIndependentState(pool, bundle, input) {
  verifyIndependentStateBundle(bundle, input);
  const manifest = bundle.manifest;
  if (manifest.clusterId !== input.clusterId || manifest.commandId !== input.commandId ||
      manifest.sourceEpoch !== input.sourceEpoch ||
      manifest.bpcPromotionDigest !== input.bpcPromotionDigest ||
      manifest.tskActivationDigest !== input.tskActivationDigest) throw new Error('promotion binding mismatch');
  validateState(manifest.state);
  return withSerializable(pool, async (client) => {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [input.advisoryLockKey]);
    const targetSystemId = await systemIdentifier(client);
    if (targetSystemId === manifest.sourceSystemId) throw new Error('source and target PostgreSQL authorities are not independent');
    const current = await client.query('SELECT * FROM ultra_ha_import_head WHERE cluster_id=$1 FOR UPDATE', [manifest.clusterId]);
    if (current.rows[0]) {
      const row = current.rows[0];
      if (Number(row.source_epoch) > manifest.sourceEpoch) throw new Error('state rollback refused');
      if (Number(row.source_epoch) === manifest.sourceEpoch) {
        if (row.manifest_digest !== bundle.manifestDigest || row.command_id !== manifest.commandId) {
          throw new Error('same-epoch state fork refused');
        }
        if (row.target_system_id !== targetSystemId || row.source_system_id !== manifest.sourceSystemId ||
            row.authority_digest !== manifest.authorityDigest ||
            digest(await readTargetAuthorityState(client)) !== manifest.authorityDigest) {
          throw new Error('same-epoch imported authority was rolled back or tampered');
        }
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
    await client.query('DELETE FROM ultra_identity_bindings');
    await client.query('DELETE FROM ultra_idempotency');
    await client.query('DELETE FROM ultra_nonce_tombstones');
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
    return { idempotent: false, manifestDigest: bundle.manifestDigest, targetSystemId };
  });
}

export async function assertIndependentStateReady(pool, expected) {
  const { rows } = await pool.query(
    `SELECT command_id, source_epoch, source_system_id, target_system_id,
            manifest_digest, authority_digest
     FROM ultra_ha_import_head WHERE cluster_id=$1`,
    [expected.clusterId],
  );
  const row = rows[0];
  if (!row || row.command_id !== expected.commandId || Number(row.source_epoch) !== expected.sourceEpoch ||
      row.manifest_digest !== expected.manifestDigest) throw new Error('independent state is not ready');
  const liveSystemId = await systemIdentifier(pool);
  if (row.target_system_id !== liveSystemId || row.source_system_id === liveSystemId) {
    throw new Error('independent state authority mismatch');
  }
  if (digest(await readTargetAuthorityState(pool)) !== row.authority_digest) {
    throw new Error('independent state authority was rolled back or tampered');
  }
  return Object.freeze({
    clusterId: expected.clusterId,
    commandId: expected.commandId,
    manifestDigest: expected.manifestDigest,
    sourceEpoch: expected.sourceEpoch,
    targetSystemId: liveSystemId,
  });
}
