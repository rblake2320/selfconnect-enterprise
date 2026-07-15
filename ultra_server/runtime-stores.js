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

export class MemoryIdentityBindingStore {
  constructor() { this.bindings = new Map(); }
  async get(pairId) { return this.bindings.get(pairId) ?? null; }
  async set(pairId, binding) { this.bindings.set(pairId, { ...binding }); }
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
}

export class MemoryIdempotencyStore {
  constructor() { this.entries = new Map(); }
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
    existing.state = 'complete';
    existing.response = structuredClone(response);
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
    if (result.rowCount !== 1) throw new Error('idempotency key was not claimed');
  }
}
