import { createHash, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import {
  ContractValidationError,
  HttpOutboxTransport,
  PgDurableOutbox,
  PgDurablePublisher,
  PgReceiverCheckpoint,
  canonicalize,
  createHttpOutboxReceiver,
} from '@bpc/server';
import {
  assertSourceLeaseWritable,
  fenceTokenForEpoch,
  requireSourceFenceReady,
} from '@tsk/server';

import { validateIdentityBinding } from './runtime-stores.js';

const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const SECRET_FIELD = /(?:secret|token|password|private|credential|provisionpayload)/i;

function plain(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ContractValidationError(`${name} must be plain data`);
  }
  return value;
}

function exactKeys(value, keys, name) {
  plain(value, name);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ContractValidationError(`${name} has an invalid shape`);
  }
}

function id(value, name) {
  if (typeof value !== 'string' || !ID.test(value)) throw new ContractValidationError(`${name} invalid`);
  return value;
}

function uuid(value, name) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new ContractValidationError(`${name} invalid`);
  return value.toLowerCase();
}

function digest(value) {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

function ackMessage(receipt) {
  return Buffer.from(canonicalize({
    domain: 'selfconnect-ultra-state-ack/v1',
    streamId: receipt.streamId,
    sourceEpoch: receipt.sourceEpoch,
    sequence: receipt.sequence,
    opDigest: receipt.opDigest,
    decision: receipt.decision,
    receiverId: receipt.receiverId,
    keyId: receipt.keyId,
    issuedAt: receipt.issuedAt,
  }), 'utf8');
}

export function signUltraStateAck(record, decision, options) {
  const privateKey = options.privateKey;
  if (!privateKey || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new ContractValidationError('Ultra ACK signer requires a private Ed25519 KeyObject');
  }
  const receipt = {
    streamId: id(record.streamId, 'record.streamId'),
    sourceEpoch: id(record.sourceEpoch, 'record.sourceEpoch'),
    sequence: record.sequence,
    opDigest: record.opDigest,
    decision,
    receiverId: id(options.receiverId, 'receiverId'),
    keyId: id(options.keyId, 'keyId'),
    issuedAt: new Date(options.now?.() ?? Date.now()).toISOString(),
  };
  if (!Number.isSafeInteger(receipt.sequence) || receipt.sequence < 1 ||
      !HEX64.test(receipt.opDigest) || typeof receipt.decision !== 'string') {
    throw new ContractValidationError('Ultra ACK fields invalid');
  }
  return Object.freeze({
    ...receipt,
    signature: cryptoSign(null, ackMessage(receipt), privateKey).toString('base64url'),
  });
}

export function createUltraStateAckVerifier(resolvePublicKey, expectedReceiverId) {
  if (typeof resolvePublicKey !== 'function') throw new ContractValidationError('Ultra ACK key resolver required');
  id(expectedReceiverId, 'expectedReceiverId');
  return Object.freeze({
    async verify(receipt, record) {
      const publicKey = resolvePublicKey(receipt.keyId);
      if (!publicKey || publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
        throw new ContractValidationError('Ultra ACK key is unknown or not public Ed25519');
      }
      if (receipt.receiverId !== expectedReceiverId ||
          receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch ||
          receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest ||
          !cryptoVerify(null, ackMessage(receipt), publicKey, Buffer.from(receipt.signature, 'base64url'))) {
        throw new ContractValidationError('Ultra ACK is forged or not bound to the record');
      }
    },
  });
}

export function createUltraStateHttpReceiver(options) {
  const ackVerifier = createUltraStateAckVerifier(options.resolveAckPublicKey, options.receiverId);
  const checkpoint = new PgReceiverCheckpoint(
    options.db, id(options.streamId, 'streamId'), ultraStateMutationSanitizer,
    new UltraStateMutationApplier(), options.ready,
  );
  const handler = createHttpOutboxReceiver({
    expectedPath: options.expectedPath,
    resolveRequestKey: options.resolveRequestKey,
    responseKeyId: options.responseKeyId,
    responseSecret: options.responseSecret,
    nonceStore: options.nonceStore,
    freshnessMs: options.freshnessMs,
    nonceSafetyMs: options.nonceSafetyMs,
    maxBodyBytes: options.maxBodyBytes,
    bodyReadMs: options.bodyReadMs,
    receive: async (record) => signUltraStateAck(
      record,
      await checkpoint.verifyAndApplyDelivered(record),
      {
        receiverId: options.receiverId,
        keyId: options.ackKeyId,
        privateKey: options.ackPrivateKey,
        now: options.now,
      },
    ),
  });
  return Object.freeze({ ackVerifier, checkpoint, handler });
}

export function createUltraStateHttpPublisher(options) {
  const ackVerifier = createUltraStateAckVerifier(
    options.resolveAckPublicKey, options.expectedReceiverId,
  );
  const transport = new HttpOutboxTransport({
    url: options.url,
    fetch: options.fetch,
    requestKeyId: options.requestKeyId,
    requestSecret: options.requestSecret,
    resolveResponseKey: options.resolveResponseKey,
    ackVerifier,
    timeoutMs: options.timeoutMs,
    maxRequestBytes: options.maxRequestBytes,
    maxResponseBytes: options.maxResponseBytes,
  });
  const publisher = new PgDurablePublisher(
    options.db, id(options.streamId, 'streamId'), transport,
    'fail-authoritative-mutation', ultraStateMutationSanitizer,
    ackVerifier, options.ready, { leaseMs: options.leaseMs ?? 30_000 },
  );
  return Object.freeze({ ackVerifier, publisher, transport });
}

/**
 * Compose the BPC atomic outbox with TSK's signed source-lease authority.
 * The readiness capability proves the complete lease chain once; every
 * authoritative Ultra mutation then rechecks the exact live lease head both
 * during append and at the outbox pre-commit boundary.
 */
export async function createGovernedUltraStateAuthority(options) {
  const streamId = id(options.streamId, 'streamId');
  const sourceEpoch = options.sourceEpoch;
  if (!Number.isSafeInteger(sourceEpoch) || sourceEpoch < 0 || sourceEpoch > 2 ** 40) {
    throw new ContractValidationError('sourceEpoch must be a safe integer in the TSK epoch range');
  }
  const schema = options.schema ?? 'public';
  const bound = requireSourceFenceReady(options.sourceFenceReady, {
    db: options.db, schema, streamId,
  });
  if (!options.sourceLeaseResolver || typeof options.sourceLeaseResolver.resolve !== 'function') {
    throw new ContractValidationError('sourceLeaseResolver required');
  }
  const skew = options.controlToASkewBoundMs;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 3_600_000) {
    throw new ContractValidationError('controlToASkewBoundMs invalid');
  }
  const fenceToken = BigInt(fenceTokenForEpoch(sourceEpoch));
  const outbox = new PgDurableOutbox(options.db, options.outboxReady, {
    streamId,
    sanitizer: ultraStateMutationSanitizer,
    maxPendingRows: options.maxPendingRows ?? 10_000,
    backpressure: 'fail-authoritative-mutation',
    preCommitCheck: (exec) => assertSourceLeaseWritable(
      exec, options.sourceLeaseResolver, streamId, sourceEpoch, skew, bound,
    ),
  });
  // Use the outbox-owned, schema-pinned serializable scope for startup checks;
  // never perform authority reads through an ambient pool/search_path.
  await outbox.withOutboxTx(async (_tx, exec) => {
    const checkpoint = (await exec.query(
      'SELECT source_epoch,sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId],
    )).rows[0];
    const fence = (await exec.query(
      'SELECT fence_token::text FROM ha_outbox_fence WHERE stream_id=$1', [streamId],
    )).rows[0];
    if (!checkpoint || checkpoint.source_epoch !== String(sourceEpoch) || !fence ||
        fence.fence_token !== fenceToken.toString()) {
      throw new ContractValidationError('Ultra outbox checkpoint/fence does not match the governed source epoch');
    }
    await assertSourceLeaseWritable(
      exec, options.sourceLeaseResolver, streamId, sourceEpoch, skew, bound,
    );
  });
  return Object.freeze({
    outbox,
    identityBinding: new PgReplicatedIdentityBindingStore(outbox, streamId, fenceToken),
    idempotencyStore: new PgReplicatedIdempotencyStore(options.pool, outbox, streamId, fenceToken),
    nonceBackend: new PgReplicatedNonceTombstoneStore(outbox, streamId, fenceToken),
  });
}

function containsSecret(value, key = '') {
  if (SECRET_FIELD.test(key)) return true;
  if (Array.isArray(value)) return value.some((item) => containsSecret(item));
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([childKey, child]) => containsSecret(child, childKey));
  }
  return false;
}

function jsonSnapshot(value, name) {
  try {
    return JSON.parse(canonicalize(value));
  } catch (error) {
    throw new ContractValidationError(`${name} is not bounded canonical JSON`, { cause: error });
  }
}

function iso(value, name) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString() !== value) throw new ContractValidationError(`${name} invalid`);
  return value;
}

function sanitizeMutation(raw) {
  raw = jsonSnapshot(raw, 'Ultra state mutation');
  switch (raw.kind) {
    case 'ultra.binding.set.v2': { // v1 omitted the full-key principal and is unsafe to replay
      exactKeys(raw, [
        'agentId', 'agentPublicKeyHex', 'canonicalId', 'kind', 'pairId', 'tskClientId',
      ], raw.kind);
      const binding = validateIdentityBinding({
        tskClientId: id(raw.tskClientId, 'tskClientId'),
        agentId: raw.agentId,
        canonicalId: raw.canonicalId,
        agentPublicKeyHex: raw.agentPublicKeyHex,
      });
      return { kind: raw.kind, pairId: id(raw.pairId, 'pairId'), ...binding };
    }
    case 'ultra.binding.swap.v2': { // ownership is immutable; only the credential may CAS
      exactKeys(raw, [
        'agentId', 'agentPublicKeyHex', 'canonicalId', 'expectedClientId', 'kind',
        'pairId', 'tskClientId',
      ], raw.kind);
      const binding = validateIdentityBinding({
        tskClientId: id(raw.tskClientId, 'tskClientId'),
        agentId: raw.agentId,
        canonicalId: raw.canonicalId,
        agentPublicKeyHex: raw.agentPublicKeyHex,
      });
      return { kind: raw.kind, pairId: id(raw.pairId, 'pairId'),
        expectedClientId: id(raw.expectedClientId, 'expectedClientId'), ...binding };
    }
    case 'ultra.idempotency.claim.v1':
      exactKeys(raw, ['agentId', 'idempotencyKey', 'kind', 'operation'], raw.kind);
      return { kind: raw.kind, idempotencyKey: uuid(raw.idempotencyKey, 'idempotencyKey'),
        operation: id(raw.operation, 'operation'), agentId: id(raw.agentId, 'agentId') };
    case 'ultra.idempotency.complete.v1': { // source response may contain a secret; the record never does
      const alreadySanitized = Object.hasOwn(raw, 'responseDigest');
      exactKeys(raw, alreadySanitized
        ? ['agentId', 'idempotencyKey', 'kind', 'operation', 'response', 'responseDigest', 'secretReprovisionRequired']
        : ['agentId', 'idempotencyKey', 'kind', 'operation', 'response'], raw.kind);
      if (alreadySanitized) {
        if (!HEX64.test(raw.responseDigest) || typeof raw.secretReprovisionRequired !== 'boolean' ||
            (raw.secretReprovisionRequired
              ? raw.response !== null
              : digest(raw.response) !== raw.responseDigest)) {
          throw new ContractValidationError('sanitized idempotency response invalid');
        }
        return { kind: raw.kind, idempotencyKey: uuid(raw.idempotencyKey, 'idempotencyKey'),
          operation: id(raw.operation, 'operation'), agentId: id(raw.agentId, 'agentId'),
          response: raw.response, responseDigest: raw.responseDigest,
          secretReprovisionRequired: raw.secretReprovisionRequired };
      }
      const response = jsonSnapshot(raw.response, 'idempotency response');
      const secretReprovisionRequired = containsSecret(response);
      return { kind: raw.kind, idempotencyKey: uuid(raw.idempotencyKey, 'idempotencyKey'),
        operation: id(raw.operation, 'operation'), agentId: id(raw.agentId, 'agentId'),
        response: secretReprovisionRequired ? null : response,
        responseDigest: digest(response), secretReprovisionRequired };
    }
    case 'ultra.nonce.consume.v1':
      exactKeys(raw, ['expiresAt', 'kind', 'nonceHash'], raw.kind);
      if (!HEX64.test(raw.nonceHash)) throw new ContractValidationError('nonceHash invalid');
      return { kind: raw.kind, nonceHash: raw.nonceHash, expiresAt: iso(raw.expiresAt, 'expiresAt') };
    default:
      throw new ContractValidationError('unsupported Ultra state mutation');
  }
}

export const ultraStateMutationSanitizer = Object.freeze({
  sanitize: sanitizeMutation,
  assertSanitized(candidate) {
    const clean = sanitizeMutation(candidate);
    if (canonicalize(clean) !== canonicalize(candidate)) {
      throw new ContractValidationError('Ultra state mutation is not exactly sanitized');
    }
  },
});

function parseJson(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

export class PgReplicatedIdentityBindingStore {
  constructor(outbox, streamId, fenceToken) {
    this.outbox = outbox; this.streamId = id(streamId, 'streamId'); this.fenceToken = fenceToken;
  }

  async get(pairId) {
    id(pairId, 'pairId');
    return this.outbox.withOutboxTx(async (_tx, exec) => {
      const row = (await exec.query(
        `SELECT tsk_client_id,agent_id,canonical_id,agent_public_key_hex
           FROM ultra_identity_bindings WHERE pair_id=$1`, [pairId],
      )).rows[0];
      return row ? validateIdentityBinding({
        tskClientId: row.tsk_client_id,
        agentId: row.agent_id,
        canonicalId: row.canonical_id,
        agentPublicKeyHex: row.agent_public_key_hex,
      }) : null;
    });
  }

  async set(pairId, binding) {
    const mutation = sanitizeMutation({ kind: 'ultra.binding.set.v2', pairId, ...binding });
    return this.outbox.withOutboxTx(async (tx, exec) => {
      await this.outbox.appendInTx(tx, { streamId: this.streamId, rawMutation: mutation, fenceToken: this.fenceToken });
      const inserted = await exec.query(
        `INSERT INTO ultra_identity_bindings
           (pair_id,tsk_client_id,agent_id,canonical_id,agent_public_key_hex)
         VALUES($1,$2,$3,$4,$5) ON CONFLICT(pair_id) DO NOTHING`,
        [mutation.pairId, mutation.tskClientId, mutation.agentId, mutation.canonicalId,
          mutation.agentPublicKeyHex],
      );
      if (inserted.rowCount === 1) return;
      const current = (await exec.query(
        `SELECT tsk_client_id,agent_id,canonical_id,agent_public_key_hex
           FROM ultra_identity_bindings WHERE pair_id=$1 FOR UPDATE`, [mutation.pairId],
      )).rows[0];
      if (current?.tsk_client_id === mutation.tskClientId &&
          current.agent_id === mutation.agentId && current.canonical_id === mutation.canonicalId &&
          current.agent_public_key_hex === mutation.agentPublicKeyHex) return;
      throw new ContractValidationError('identity binding set conflicts with existing owner');
    });
  }

  async compareAndSwap(pairId, expectedClientId, binding) {
    const mutation = sanitizeMutation({
      kind: 'ultra.binding.swap.v2', pairId, expectedClientId, ...binding,
    });
    return this.outbox.withOutboxTx(async (tx, exec) => {
      const current = (await exec.query(
        `SELECT tsk_client_id,agent_id,canonical_id,agent_public_key_hex
           FROM ultra_identity_bindings WHERE pair_id=$1 FOR UPDATE`,
        [mutation.pairId],
      )).rows[0];
      if (!current) return 'missing';
      if (current.tsk_client_id === mutation.tskClientId && current.agent_id === mutation.agentId &&
          current.canonical_id === mutation.canonicalId &&
          current.agent_public_key_hex === mutation.agentPublicKeyHex) return 'already';
      if (current.tsk_client_id !== mutation.expectedClientId ||
          current.agent_id !== mutation.agentId || current.canonical_id !== mutation.canonicalId ||
          current.agent_public_key_hex !== mutation.agentPublicKeyHex) return 'conflict';
      await this.outbox.appendInTx(tx, { streamId: this.streamId, rawMutation: mutation, fenceToken: this.fenceToken });
      const updated = await exec.query(
        `UPDATE ultra_identity_bindings SET tsk_client_id=$2,updated_at=pg_catalog.clock_timestamp()
         WHERE pair_id=$1 AND tsk_client_id=$3 AND agent_id=$4 AND canonical_id=$5
           AND agent_public_key_hex=$6`,
        [mutation.pairId, mutation.tskClientId, mutation.expectedClientId, mutation.agentId,
          mutation.canonicalId, mutation.agentPublicKeyHex],
      );
      if (updated.rowCount !== 1) throw new ContractValidationError('identity binding CAS lost its row lock');
      return 'updated';
    });
  }

  async count() {
    return this.outbox.withOutboxTx(async (_tx, exec) =>
      Number((await exec.query('SELECT COUNT(*)::int AS count FROM ultra_identity_bindings')).rows[0].count));
  }
}

export class PgReplicatedIdempotencyStore {
  constructor(pool, outbox, streamId, fenceToken) {
    this.pool = pool; this.outbox = outbox; this.streamId = id(streamId, 'streamId'); this.fenceToken = fenceToken;
  }

  async claim(key, operation, agentId) {
    const mutation = sanitizeMutation({ kind: 'ultra.idempotency.claim.v1', idempotencyKey: key, operation, agentId });
    return this.outbox.withOutboxTx(async (tx, exec) => {
      const inserted = await exec.query(
        `INSERT INTO ultra_idempotency(idempotency_key,operation,agent_id,state)
         VALUES($1,$2,$3,'processing') ON CONFLICT DO NOTHING RETURNING idempotency_key`,
        [mutation.idempotencyKey, mutation.operation, mutation.agentId],
      );
      if (inserted.rowCount === 1) {
        await this.outbox.appendInTx(tx, { streamId: this.streamId, rawMutation: mutation, fenceToken: this.fenceToken });
        return { kind: 'claimed' };
      }
      const existing = (await exec.query(
        'SELECT operation,agent_id,state,response FROM ultra_idempotency WHERE idempotency_key=$1 FOR UPDATE',
        [mutation.idempotencyKey],
      )).rows[0];
      if (!existing || existing.operation !== mutation.operation || existing.agent_id !== mutation.agentId) return { kind: 'conflict' };
      return existing.state === 'complete'
        ? { kind: 'complete', response: parseJson(existing.response) } : { kind: 'processing' };
    });
  }

  async complete(key, response) {
    // Detach caller-owned data before the first await; the exact source value
    // persisted below is the same value whose digest/stripped form is appended.
    const responseSnapshot = jsonSnapshot(response, 'idempotency response');
    const current = await this.outbox.withOutboxTx(async (tx, exec) => {
      const row = (await exec.query(
        'SELECT operation,agent_id,state,response FROM ultra_idempotency WHERE idempotency_key=$1 FOR UPDATE', [key],
      )).rows[0];
      if (!row) throw new ContractValidationError('idempotency key was not claimed');
      if (row.state === 'complete') {
        if (canonicalize(parseJson(row.response)) !== canonicalize(responseSnapshot)) throw new ContractValidationError('idempotency response conflict');
        return;
      }
      const mutation = sanitizeMutation({ kind: 'ultra.idempotency.complete.v1',
        idempotencyKey: key, operation: row.operation, agentId: row.agent_id, response: responseSnapshot });
      await this.outbox.appendInTx(tx, { streamId: this.streamId, rawMutation: mutation, fenceToken: this.fenceToken });
      const updated = await exec.query(
        `UPDATE ultra_idempotency SET state='complete',response=$2::jsonb,
           updated_at=pg_catalog.clock_timestamp() WHERE idempotency_key=$1 AND state='processing'`,
        [mutation.idempotencyKey, JSON.stringify(responseSnapshot)],
      );
      if (updated.rowCount !== 1) throw new ContractValidationError('idempotency completion lost its row lock');
    });
    return current;
  }

  async _withAdvisoryLock(key, callback, { shared }) {
    const client = await this.pool.connect();
    const lock = shared ? 'pg_advisory_lock_shared' : 'pg_advisory_lock';
    const unlock = shared ? 'pg_advisory_unlock_shared' : 'pg_advisory_unlock';
    try {
      await client.query(`SELECT pg_catalog.${lock}(pg_catalog.hashtextextended($1,0))`, [key]);
      return await callback();
    } finally {
      try { await client.query(`SELECT pg_catalog.${unlock}(pg_catalog.hashtextextended($1,0))`, [key]); }
      finally { client.release(); }
    }
  }
  async withLock(key, callback) { return this._withAdvisoryLock(key, callback, { shared: false }); }
  async withSharedLock(key, callback) { return this._withAdvisoryLock(key, callback, { shared: true }); }
}

export class PgReplicatedNonceTombstoneStore {
  constructor(outbox, streamId, fenceToken) {
    this.outbox = outbox; this.streamId = id(streamId, 'streamId'); this.fenceToken = fenceToken;
  }

  async checkAndConsume(nonce, ttlMs) {
    if (typeof nonce !== 'string' || nonce.length < 1 || nonce.length > 4096 ||
        !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 2_147_483_647) {
      throw new ContractValidationError('nonce or ttl invalid');
    }
    const nonceHash = createHash('sha256').update(nonce, 'utf8').digest('hex');
    return this.outbox.withOutboxTx(async (tx, exec) => {
      await exec.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))', [`ultra-nonce:${nonceHash}`]);
      await exec.query('DELETE FROM ultra_nonce_tombstones WHERE nonce_hash=$1 AND expires_at<=pg_catalog.clock_timestamp()', [nonceHash]);
      const expiresAt = (await exec.query(
        "SELECT (pg_catalog.clock_timestamp()+($1::bigint*interval '1 millisecond'))::text AS value", [ttlMs],
      )).rows[0].value;
      const mutation = sanitizeMutation({ kind: 'ultra.nonce.consume.v1', nonceHash,
        expiresAt: new Date(expiresAt).toISOString() });
      const inserted = await exec.query(
        'INSERT INTO ultra_nonce_tombstones(nonce_hash,expires_at) VALUES($1,$2::timestamptz) ON CONFLICT DO NOTHING',
        [mutation.nonceHash, mutation.expiresAt],
      );
      if (inserted.rowCount === 0) return true;
      await this.outbox.appendInTx(tx, { streamId: this.streamId, rawMutation: mutation, fenceToken: this.fenceToken });
      return false;
    });
  }
}

export class UltraStateMutationApplier {
  async applyInTx(exec, record) {
    const mutation = sanitizeMutation(record.mutation);
    if (canonicalize(mutation) !== canonicalize(record.mutation)) throw new ContractValidationError('receiver mutation not exactly sanitized');
    switch (mutation.kind) {
      case 'ultra.binding.set.v2': {
        const result = await exec.query(
          `INSERT INTO ultra_identity_bindings
             (pair_id,tsk_client_id,agent_id,canonical_id,agent_public_key_hex)
           VALUES($1,$2,$3,$4,$5) ON CONFLICT(pair_id) DO NOTHING`,
          [mutation.pairId, mutation.tskClientId, mutation.agentId, mutation.canonicalId,
            mutation.agentPublicKeyHex],
        );
        if (result.rowCount === 1) return;
        const row = (await exec.query(
          `SELECT tsk_client_id,agent_id,canonical_id,agent_public_key_hex
             FROM ultra_identity_bindings WHERE pair_id=$1 FOR UPDATE`, [mutation.pairId],
        )).rows[0];
        if (row?.tsk_client_id === mutation.tskClientId && row?.agent_id === mutation.agentId &&
            row?.canonical_id === mutation.canonicalId &&
            row?.agent_public_key_hex === mutation.agentPublicKeyHex) return;
        throw new ContractValidationError('replica identity binding owner conflicts');
      }
      case 'ultra.binding.swap.v2': {
        const row = (await exec.query(
          `SELECT tsk_client_id,agent_id,canonical_id,agent_public_key_hex
             FROM ultra_identity_bindings WHERE pair_id=$1 FOR UPDATE`, [mutation.pairId],
        )).rows[0];
        if (row?.tsk_client_id === mutation.tskClientId && row?.agent_id === mutation.agentId &&
            row?.canonical_id === mutation.canonicalId &&
            row?.agent_public_key_hex === mutation.agentPublicKeyHex) return;
        const result = await exec.query(
          `UPDATE ultra_identity_bindings SET tsk_client_id=$2,updated_at=pg_catalog.clock_timestamp()
           WHERE pair_id=$1 AND tsk_client_id=$3 AND agent_id=$4 AND canonical_id=$5
             AND agent_public_key_hex=$6`,
          [mutation.pairId, mutation.tskClientId, mutation.expectedClientId, mutation.agentId,
            mutation.canonicalId, mutation.agentPublicKeyHex],
        );
        if (result.rowCount !== 1) throw new ContractValidationError('replica identity binding precondition failed');
        return;
      }
      case 'ultra.idempotency.claim.v1': {
        const inserted = await exec.query(
          `INSERT INTO ultra_idempotency(idempotency_key,operation,agent_id,state)
           VALUES($1,$2,$3,'processing') ON CONFLICT DO NOTHING`,
          [mutation.idempotencyKey, mutation.operation, mutation.agentId],
        );
        if (inserted.rowCount === 1) return;
        const row = (await exec.query(
          'SELECT operation,agent_id FROM ultra_idempotency WHERE idempotency_key=$1', [mutation.idempotencyKey],
        )).rows[0];
        if (row?.operation !== mutation.operation || row?.agent_id !== mutation.agentId) {
          throw new ContractValidationError('replica idempotency claim conflicts');
        }
        return;
      }
      case 'ultra.idempotency.complete.v1': {
        const response = mutation.secretReprovisionRequired
          ? { ok: false, error: 'SECRET_REPROVISION_REQUIRED', originalResponseDigest: mutation.responseDigest }
          : mutation.response;
        const result = await exec.query(
          `UPDATE ultra_idempotency SET state='complete',response=$2::jsonb,
             updated_at=pg_catalog.clock_timestamp()
           WHERE idempotency_key=$1 AND operation=$3 AND agent_id=$4 AND state='processing'`,
          [mutation.idempotencyKey, JSON.stringify(response), mutation.operation, mutation.agentId],
        );
        if (result.rowCount !== 1) throw new ContractValidationError('replica idempotency completion precondition failed');
        return;
      }
      case 'ultra.nonce.consume.v1':
        await exec.query(
          `INSERT INTO ultra_nonce_tombstones(nonce_hash,expires_at) VALUES($1,$2::timestamptz)
           ON CONFLICT(nonce_hash) DO UPDATE SET expires_at=GREATEST(
             ultra_nonce_tombstones.expires_at,EXCLUDED.expires_at)`,
          [mutation.nonceHash, mutation.expiresAt],
        ); return;
      default: throw new ContractValidationError('unsupported receiver mutation');
    }
  }
}
