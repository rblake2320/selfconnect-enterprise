import { commitValidationToMap } from '@tsk/server';

export const ULTRA_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS ultra_tumbler_maps (
  client_id TEXT PRIMARY KEY,
  map JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ultra_identity_bindings (
  pair_id TEXT PRIMARY KEY,
  tsk_client_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ultra_idempotency (
  idempotency_key UUID PRIMARY KEY,
  operation TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('processing', 'complete')),
  response JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

function parseMap(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

export class MemoryIdentityBindingStore {
  constructor() { this.bindings = new Map(); }
  async get(pairId) { return this.bindings.get(pairId) ?? null; }
  async set(pairId, binding) { this.bindings.set(pairId, { ...binding }); }
  async compareAndSwap(pairId, expectedClientId, binding) {
    const current = this.bindings.get(pairId);
    if (!current) return 'missing';
    if (current.tskClientId === binding.tskClientId && current.agentId === binding.agentId) {
      return 'already';
    }
    if (current.tskClientId !== expectedClientId || current.agentId !== binding.agentId) {
      return 'conflict';
    }
    this.bindings.set(pairId, { ...binding });
    return 'updated';
  }
  async count() { return this.bindings.size; }
}

export class PgIdentityBindingStore {
  constructor(pool) { this.pool = pool; }
  async get(pairId) {
    const { rows } = await this.pool.query(
      'SELECT tsk_client_id, agent_id FROM ultra_identity_bindings WHERE pair_id=$1', [pairId],
    );
    return rows[0] ? { tskClientId: rows[0].tsk_client_id, agentId: rows[0].agent_id } : null;
  }
  async set(pairId, binding) {
    await this.pool.query(
      `INSERT INTO ultra_identity_bindings (pair_id, tsk_client_id, agent_id)
       VALUES ($1,$2,$3)
       ON CONFLICT (pair_id) DO UPDATE SET
         tsk_client_id=EXCLUDED.tsk_client_id, agent_id=EXCLUDED.agent_id, updated_at=NOW()`,
      [pairId, binding.tskClientId, binding.agentId],
    );
  }
  async compareAndSwap(pairId, expectedClientId, binding) {
    const updated = await this.pool.query(
      `UPDATE ultra_identity_bindings SET
         tsk_client_id=$3, updated_at=NOW()
       WHERE pair_id=$1 AND tsk_client_id=$2 AND agent_id=$4
       RETURNING pair_id`,
      [pairId, expectedClientId, binding.tskClientId, binding.agentId],
    );
    if (updated.rows[0]) return 'updated';
    const current = await this.get(pairId);
    if (!current) return 'missing';
    if (current.tskClientId === binding.tskClientId && current.agentId === binding.agentId) {
      return 'already';
    }
    return 'conflict';
  }
  async count() {
    const { rows } = await this.pool.query('SELECT COUNT(*)::int AS count FROM ultra_identity_bindings');
    return rows[0].count;
  }
}

export class PgTumblerStore {
  constructor(pool) { this.pool = pool; }
  async get(clientId) {
    const { rows } = await this.pool.query(
      'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1', [clientId],
    );
    return rows[0] ? parseMap(rows[0].map) : null;
  }
  async set(clientId, map) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1 FOR UPDATE', [clientId],
      );
      const merged = structuredClone(map);
      if (rows[0]) {
        const current = parseMap(rows[0].map);
        const counters = new Map(
          current.segments
            .filter((segment) => segment.type === 'hotp')
            .map((segment) => [segment.segmentId, segment.counter ?? 0]),
        );
        for (const segment of merged.segments) {
          if (segment.type === 'hotp' && counters.has(segment.segmentId)) {
            segment.counter = Math.max(segment.counter ?? 0, counters.get(segment.segmentId));
          }
        }

        const currentCount = current.requestCount ?? 0;
        const incomingCount = merged.requestCount ?? 0;
        const currentUsed = current.lastUsedAt ?? 0;
        const incomingUsed = merged.lastUsedAt ?? 0;
        merged.requestCount = incomingUsed > currentUsed
          ? Math.max(incomingCount, currentCount + 1)
          : Math.max(incomingCount, currentCount);
        if (currentUsed > incomingUsed) merged.lastUsedAt = current.lastUsedAt;

        await client.query(
          'UPDATE ultra_tumbler_maps SET map=$2::jsonb, updated_at=NOW() WHERE client_id=$1',
          [clientId, JSON.stringify(merged)],
        );
      } else {
        await client.query(
          'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
          [clientId, JSON.stringify(merged)],
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  async delete(clientId) {
    await this.pool.query('DELETE FROM ultra_tumbler_maps WHERE client_id=$1', [clientId]);
  }
  async list() {
    const { rows } = await this.pool.query('SELECT client_id FROM ultra_tumbler_maps ORDER BY client_id');
    return rows.map((row) => row.client_id);
  }
  async updateCounters(clientId, updates) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1 FOR UPDATE', [clientId],
      );
      if (!rows[0]) { await client.query('ROLLBACK'); return; }
      const map = parseMap(rows[0].map);
      for (const segment of map.segments) {
        if (segment.type === 'hotp' && updates.has(segment.segmentId)) {
          segment.counter = updates.get(segment.segmentId);
        }
      }
      await client.query(
        'UPDATE ultra_tumbler_maps SET map=$2::jsonb, updated_at=NOW() WHERE client_id=$1',
        [clientId, JSON.stringify(map)],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  async consumeCounter(clientId, segmentId, matchedCounter) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1 FOR UPDATE', [clientId],
      );
      if (!rows[0]) { await client.query('ROLLBACK'); return false; }
      const map = parseMap(rows[0].map);
      const segment = map.segments.find((item) => item.segmentId === segmentId);
      if (!segment || segment.type !== 'hotp' || (segment.counter ?? 0) > matchedCounter) {
        await client.query('ROLLBACK');
        return false;
      }
      segment.counter = matchedCounter + 1;
      await client.query(
        'UPDATE ultra_tumbler_maps SET map=$2::jsonb, updated_at=NOW() WHERE client_id=$1',
        [clientId, JSON.stringify(map)],
      );
      await client.query('COMMIT');
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  async commitValidation(clientId, input) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1 FOR UPDATE', [clientId],
      );
      if (!rows[0]) {
        await client.query('ROLLBACK');
        return { ok: false, error: 'TSK_KEY_EXPIRED' };
      }
      const map = parseMap(rows[0].map);
      const result = commitValidationToMap(map, input);
      await client.query(
        'UPDATE ultra_tumbler_maps SET map=$2::jsonb, updated_at=NOW() WHERE client_id=$1',
        [clientId, JSON.stringify(map)],
      );
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  async replaceCredential(oldClientId, replacement) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        'SELECT map FROM ultra_tumbler_maps WHERE client_id=$1 FOR UPDATE', [oldClientId],
      );
      if (!rows[0]) {
        await client.query('ROLLBACK');
        return false;
      }
      const current = parseMap(rows[0].map);
      if (current.status !== undefined && current.status !== 'active' && current.status !== 'expiring') {
        await client.query('ROLLBACK');
        return false;
      }
      const existing = await client.query(
        'SELECT 1 FROM ultra_tumbler_maps WHERE client_id=$1', [replacement.clientId],
      );
      if (existing.rows[0]) {
        await client.query('ROLLBACK');
        return false;
      }
      current.status = 'revoked';
      await client.query(
        'UPDATE ultra_tumbler_maps SET map=$2::jsonb, updated_at=NOW() WHERE client_id=$1',
        [oldClientId, JSON.stringify(current)],
      );
      await client.query(
        'INSERT INTO ultra_tumbler_maps (client_id, map) VALUES ($1,$2::jsonb)',
        [replacement.clientId, JSON.stringify(replacement)],
      );
      await client.query('COMMIT');
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}

export class MemoryIdempotencyStore {
  constructor() {
    this.entries = new Map();
    this.locks = new Map();
  }
  async claim(key, operation, agentId) {
    const existing = this.entries.get(key);
    if (existing) {
      if (existing.operation !== operation || existing.agentId !== agentId) return { kind: 'conflict' };
      return existing.state === 'complete'
        ? { kind: 'complete', response: structuredClone(existing.response) }
        : { kind: 'processing' };
    }
    this.entries.set(key, { operation, agentId, state: 'processing', response: null });
    return { kind: 'claimed' };
  }
  async complete(key, response) {
    const existing = this.entries.get(key);
    if (!existing) throw new Error('idempotency key was not claimed');
    if (existing.state === 'complete') {
      if (canonicalJson(existing.response) !== canonicalJson(response)) {
        throw new Error('idempotency response conflict');
      }
      return;
    }
    existing.state = 'complete';
    existing.response = structuredClone(response);
  }
  async withLock(key, callback) {
    const previous = this.locks.get(key) ?? Promise.resolve();
    let release;
    const current = new Promise((resolve) => { release = resolve; });
    const tail = previous.then(() => current);
    this.locks.set(key, tail);
    await previous;
    try {
      return await callback();
    } finally {
      release();
      if (this.locks.get(key) === tail) this.locks.delete(key);
    }
  }
}

export class PgIdempotencyStore {
  constructor(pool) { this.pool = pool; }
  async claim(key, operation, agentId) {
    const inserted = await this.pool.query(
      `INSERT INTO ultra_idempotency (idempotency_key, operation, agent_id, state)
       VALUES ($1,$2,$3,'processing') ON CONFLICT DO NOTHING RETURNING idempotency_key`,
      [key, operation, agentId],
    );
    if (inserted.rows[0]) return { kind: 'claimed' };
    const { rows } = await this.pool.query(
      'SELECT operation, agent_id, state, response FROM ultra_idempotency WHERE idempotency_key=$1', [key],
    );
    const existing = rows[0];
    if (!existing || existing.operation !== operation || existing.agent_id !== agentId) {
      return { kind: 'conflict' };
    }
    return existing.state === 'complete'
      ? { kind: 'complete', response: parseMap(existing.response) }
      : { kind: 'processing' };
  }
  async complete(key, response) {
    const result = await this.pool.query(
      `UPDATE ultra_idempotency SET state='complete', response=$2::jsonb, updated_at=NOW()
       WHERE idempotency_key=$1 AND state='processing'`,
      [key, JSON.stringify(response)],
    );
    if (result.rowCount === 1) return;
    const { rows } = await this.pool.query(
      'SELECT state, response FROM ultra_idempotency WHERE idempotency_key=$1', [key],
    );
    const existing = rows[0];
    if (
      existing?.state === 'complete' &&
      canonicalJson(parseMap(existing.response)) === canonicalJson(response)
    ) return;
    throw new Error(existing ? 'idempotency response conflict' : 'idempotency key was not claimed');
  }
  async withLock(key, callback) {
    const client = await this.pool.connect();
    try {
      await client.query('SELECT pg_advisory_lock(hashtextextended($1, 0))', [key]);
      return await callback();
    } finally {
      try {
        await client.query('SELECT pg_advisory_unlock(hashtextextended($1, 0))', [key]);
      } finally {
        client.release();
      }
    }
  }
}
