import { verifyGuardCommandSignature } from '@tsk/server';

const VALID_ROLES = new Set(['primary', 'replica']);
const VALID_COMMANDS = new Set(['activate', 'promote', 'demote']);
const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,128}$/;
const COMMAND_ID = /^[A-Za-z0-9_.:-]{8,128}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43}$/;
const ALLOWED_COMMAND_FIELDS = new Set([
  'by',
  'clusterId',
  'command',
  'commandId',
  'expiresAt',
  'fenceEpoch',
  'issuedAt',
  'nodeId',
  'reason',
  'signature',
]);

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

function requiredIdentifier(value, name) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new Error(`${name} must match ${IDENTIFIER}`);
  }
  return value;
}

function parseEnabled(value) {
  if (value === undefined || value === '') return false;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error('ULTRA_HA_ENABLED must be true or false');
}

export function loadUltraHaConfig(env, runtimeMode) {
  const enabled = parseEnabled(env.ULTRA_HA_ENABLED);
  if (!enabled) return { enabled: false };
  if (runtimeMode !== 'production') {
    throw new Error('ULTRA_HA_ENABLED requires ULTRA_RUNTIME_MODE=production');
  }

  const nodeId = requiredIdentifier(env.ULTRA_HA_NODE_ID, 'ULTRA_HA_NODE_ID');
  const clusterId = requiredIdentifier(env.ULTRA_HA_CLUSTER_ID, 'ULTRA_HA_CLUSTER_ID');
  const role = env.ULTRA_HA_NODE_ROLE;
  if (!VALID_ROLES.has(role)) {
    throw new Error('ULTRA_HA_NODE_ROLE must be primary or replica');
  }
  const guardSecret = env.ULTRA_HA_GUARD_SECRET;
  if (typeof guardSecret !== 'string' || Buffer.byteLength(guardSecret, 'utf8') < 32) {
    throw new Error('ULTRA_HA_GUARD_SECRET must contain at least 32 bytes');
  }
  for (const [name, value] of [
    ['ULTRA_ADMIN_TOKEN', env.ULTRA_ADMIN_TOKEN],
    ['ULTRA_ADMIN_TOKEN_PREVIOUS', env.ULTRA_ADMIN_TOKEN_PREVIOUS],
    ['ULTRA_RECOVERY_HMAC_KEY', env.ULTRA_RECOVERY_HMAC_KEY],
    ['ULTRA_RECOVERY_HMAC_KEY_PREVIOUS', env.ULTRA_RECOVERY_HMAC_KEY_PREVIOUS],
  ]) {
    if (guardSecret === value) {
      throw new Error(`ULTRA_HA_GUARD_SECRET must differ from ${name}`);
    }
  }

  const maxCommandAgeMs = positiveInteger(
    Number(env.ULTRA_HA_MAX_COMMAND_AGE_MS ?? 60_000),
    'ULTRA_HA_MAX_COMMAND_AGE_MS',
  );
  const maxLeaseMs = positiveInteger(
    Number(env.ULTRA_HA_MAX_LEASE_MS ?? 300_000),
    'ULTRA_HA_MAX_LEASE_MS',
  );
  const minLeaseRemainingMs = positiveInteger(
    Number(env.ULTRA_HA_MIN_LEASE_REMAINING_MS ?? 5_000),
    'ULTRA_HA_MIN_LEASE_REMAINING_MS',
  );
  if (minLeaseRemainingMs >= maxLeaseMs) {
    throw new Error('ULTRA_HA_MIN_LEASE_REMAINING_MS must be less than ULTRA_HA_MAX_LEASE_MS');
  }
  const fenceKey = `ultra:ha:${clusterId}:writer`;
  const advisoryLockKey = `ultra-ha:${clusterId}:transition`;

  return {
    enabled: true,
    advisoryLockKey,
    clusterId,
    fenceKey,
    guardSecret,
    maxCommandAgeMs,
    maxLeaseMs,
    minLeaseRemainingMs,
    nodeId,
    role,
  };
}

function commandShapeError(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'invalid_body';
  const command = value;
  if (Object.keys(command).some((key) => !ALLOWED_COMMAND_FIELDS.has(key))) {
    return 'unexpected_command_field';
  }
  if (!VALID_COMMANDS.has(command.command)) return 'invalid_command';
  if (typeof command.commandId !== 'string' || !COMMAND_ID.test(command.commandId)) return 'invalid_command_id';
  if (typeof command.nodeId !== 'string' || !IDENTIFIER.test(command.nodeId)) return 'invalid_node_id';
  if (typeof command.clusterId !== 'string' || !IDENTIFIER.test(command.clusterId)) return 'invalid_cluster_id';
  if (!Number.isSafeInteger(command.fenceEpoch) || command.fenceEpoch < 1) return 'invalid_fence_epoch';
  if (!Number.isSafeInteger(command.issuedAt) || !Number.isSafeInteger(command.expiresAt)) return 'invalid_time';
  if (typeof command.by !== 'string' || command.by.length < 1 || command.by.length > 128) return 'invalid_actor';
  if (command.reason !== undefined && (typeof command.reason !== 'string' || command.reason.length > 1024)) {
    return 'invalid_reason';
  }
  if (typeof command.signature !== 'string' || !SIGNATURE.test(command.signature)) return 'invalid_signature';
  return null;
}

export class UltraHaController {
  constructor({
    clusterId,
    fenceStore,
    guardSecret,
    maxCommandAgeMs = 60_000,
    maxLeaseMs = 300_000,
    minLeaseRemainingMs = 5_000,
    nodeId,
    now = Date.now,
    role,
  }) {
    this.clusterId = requiredIdentifier(clusterId, 'clusterId');
    this.nodeId = requiredIdentifier(nodeId, 'nodeId');
    if (!VALID_ROLES.has(role)) throw new Error('role must be primary or replica');
    if (!fenceStore || typeof fenceStore.current !== 'function' || typeof fenceStore.claim !== 'function' ||
        typeof fenceStore.release !== 'function') {
      throw new Error('fenceStore must implement current, claim, and release');
    }
    if (typeof guardSecret !== 'string' || Buffer.byteLength(guardSecret, 'utf8') < 32) {
      throw new Error('guardSecret must contain at least 32 bytes');
    }
    this.role = role;
    this.fenceStore = fenceStore;
    this.guardSecret = guardSecret;
    this.maxCommandAgeMs = positiveInteger(maxCommandAgeMs, 'maxCommandAgeMs');
    this.maxLeaseMs = positiveInteger(maxLeaseMs, 'maxLeaseMs');
    this.minLeaseRemainingMs = positiveInteger(minLeaseRemainingMs, 'minLeaseRemainingMs');
    if (this.minLeaseRemainingMs >= this.maxLeaseMs) {
      throw new Error('minLeaseRemainingMs must be less than maxLeaseMs');
    }
    this.now = now;
    this.lease = null;
  }

  freshnessError(command) {
    const now = this.now();
    if (command.issuedAt > now || now - command.issuedAt > this.maxCommandAgeMs) return 'command_stale';
    if (command.expiresAt <= now || command.expiresAt - command.issuedAt > this.maxLeaseMs) {
      return 'invalid_lease_window';
    }
    if (command.expiresAt - now < this.minLeaseRemainingMs) return 'lease_window_too_short';
    return null;
  }

  async applyCommand(body) {
    const shapeError = commandShapeError(body);
    if (shapeError) return { status: 400, result: { ok: false, error: shapeError } };
    if (!verifyGuardCommandSignature(body, this.guardSecret)) {
      return { status: 401, result: { ok: false, error: 'signature_invalid' } };
    }
    if (body.clusterId !== this.clusterId || body.nodeId !== this.nodeId) {
      return { status: 409, result: { ok: false, error: 'wrong_cluster_or_node' } };
    }
    const freshnessError = this.freshnessError(body);
    if (freshnessError) return { status: 401, result: { ok: false, error: freshnessError } };

    const expected = this.role === 'primary' ? 'activate' : 'promote';
    if (body.command !== 'demote' && body.command !== expected) {
      return { status: 409, result: { ok: false, error: 'wrong_command_for_role' } };
    }

    try {
      if (body.command === 'demote') {
        const lease = this.lease;
        if (!lease || lease.fenceEpoch !== body.fenceEpoch) {
          return { status: 409, result: { ok: false, error: 'lease_mismatch' } };
        }
        const released = await this.fenceStore.release(this.nodeId, lease.fenceEpoch, lease.commandId);
        if (!released) return { status: 409, result: { ok: false, error: 'fence_release_failed' } };
        this.lease = null;
      } else {
        const claimed = await this.fenceStore.claim({
          nodeId: this.nodeId,
          fenceEpoch: body.fenceEpoch,
          expiresAt: body.expiresAt,
          commandId: body.commandId,
        });
        if (!claimed) return { status: 409, result: { ok: false, error: 'fence_epoch_not_monotonic' } };
        this.lease = { ...body };
      }
      return { status: 200, result: { ok: true, snapshot: await this.snapshot() } };
    } catch {
      return { status: 503, result: { ok: false, error: 'fencing_authority_unavailable' } };
    }
  }

  async assertWritable({ minRemainingMs = 0 } = {}) {
    try {
      const lease = this.lease;
      if (!Number.isSafeInteger(minRemainingMs) || minRemainingMs < 0) {
        throw new Error('minRemainingMs must be a non-negative safe integer');
      }
      if (!lease || lease.expiresAt - this.now() < minRemainingMs) {
        return { ok: false, status: 503, error: 'writer_lease_missing_stale_or_fenced' };
      }
      const current = await this.fenceStore.current();
      const writable = Boolean(
        current?.active &&
        current.nodeId === this.nodeId &&
        current.fenceEpoch === lease.fenceEpoch &&
        current.commandId === lease.commandId &&
        current.expiresAt === lease.expiresAt &&
        current.expiresAt > this.now(),
      );
      return writable
        ? { ok: true, fenceEpoch: lease.fenceEpoch }
        : { ok: false, status: 503, error: 'writer_lease_missing_stale_or_fenced' };
    } catch {
      return { ok: false, status: 503, error: 'writer_lease_missing_stale_or_fenced' };
    }
  }

  async isWritable() {
    return (await this.assertWritable()).ok;
  }

  async snapshot() {
    const writable = await this.assertWritable();
    const accepting = await this.assertWritable({ minRemainingMs: this.minLeaseRemainingMs });
    return {
      acceptingWrites: accepting.ok,
      clusterId: this.clusterId,
      fenceEpoch: writable.ok ? writable.fenceEpoch : this.lease?.fenceEpoch ?? null,
      leaseExpiresAt: this.lease?.expiresAt ?? null,
      leaseRemainingMs: this.lease ? Math.max(0, this.lease.expiresAt - this.now()) : null,
      nodeId: this.nodeId,
      role: this.role,
      writable: writable.ok,
    };
  }
}
