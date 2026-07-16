/**
 * ultra_server.js — BPC+TSK 7-layer identity verification sidecar.
 *
 * Listens on localhost:7777 (port configurable via ULTRA_SERVER_PORT env var).
 * Imports @bpc/server and @tsk/server packages directly — no custom crypto,
 * no modified BPC/TSK code.
 *
 * Routes:
 *   POST /register-pair     — register BPC pair (auto-approved for local mesh)
 *   POST /provision-tsk     — provision TSK client, return clientId + provisionPayload
 *   POST /bind-identity     — bind BPC pairId to TSK clientId
 *   POST /verify            — full 7-layer verification via verifyUltraRequest()
 *   GET  /status            — health check + pair count + anomaly state
 *   GET  /pubkeys/:pairId   — return public key JWK for a registered pair
 *   GET  /metrics           — Prometheus metrics (prom-client)
 *
 * Security: binds to 127.0.0.1 only. Not exposed to LAN/WAN.
 *
 * Version: 1.3.0  Signed lifecycle and durable production runtime
 */
import express from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { createAdminAuthMiddleware, createAgentAuthMiddleware } from './agent-auth.js';
import {
  createRecoveryKeyring,
  issueRecoveryToken,
  verifyRecoveryToken,
} from './recovery-token.js';
import { enforceBpcAuthorization } from './security-boundary.js';
import { UltraHaController, loadUltraHaConfig } from './ha-controller.js';
import {
  createMetricsAuthMiddleware,
  metricAuthFailureLabel,
  metricMethodLabel,
  metricRouteLabel,
  validateMetricsTokenConfiguration,
} from './monitoring-security.js';
import {
  MemoryIdempotencyStore,
  MemoryIdentityBindingStore,
  PgIdempotencyStore,
  PgIdentityBindingStore,
  PgTumblerStore,
  ULTRA_PG_SCHEMA,
  initializePgSchemas,
} from './runtime-stores.js';

// ── BPC imports ───────────────────────────────────────────────────────────────
import {
  PairRegistry,
  ServerNonceStore,
  AnomalyEngine,
  MemoryPairStore,
  MemoryNonceBackend,
  MemoryAnomalyStore,
  PgPairStore,
  PG_SCHEMA,
  RedisAnomalyStore,
  RedisNonceStore,
  RedisRateLimiter,
  MemoryRateLimiter,
  verifyBPCRequest,
} from '@bpc/server';

// ── Prometheus metrics ────────────────────────────────────────────────────────
import { register, Counter, collectDefaultMetrics } from 'prom-client';
collectDefaultMetrics({ prefix: 'ultra_node_' });

const cHttpRequests = new Counter({
  name: 'ultra_http_requests_total',
  help: 'Total HTTP requests by method, route, and status code',
  labelNames: ['method', 'route', 'status'],
});
const cAuthFailures = new Counter({
  name: 'ultra_auth_failures_total',
  help: 'Total authentication failures from /verify',
  labelNames: ['reason'],
});
const cTskProvisions = new Counter({
  name: 'ultra_tsk_provisions_total',
  help: 'Total successful TSK provisioning events',
});
const cBpcRegistrations = new Counter({
  name: 'ultra_bpc_registrations_total',
  help: 'Total successful BPC pair registrations',
});

// ── TSK imports ───────────────────────────────────────────────────────────────
import {
  FencedTumblerStore,
  MemoryTumblerStore,
  RedisFencingStore,
  TSKProvisioner,
} from '@tsk/server';
import { toProvisionPayload } from '@tsk/core';

// ── Bridge import ─────────────────────────────────────────────────────────────
import { verifyUltraRequest } from '@tsk/bpc-bridge';

const PORT = parseInt(process.env.ULTRA_SERVER_PORT ?? '7777', 10);
const SIG_WINDOW_MS = 60_000;
const ULTRA_VERSION = '1.3.0';
const RUNTIME_MODE = process.env.ULTRA_RUNTIME_MODE ?? 'development';
if (!['development', 'production'].includes(RUNTIME_MODE)) {
  throw new Error('ULTRA_RUNTIME_MODE must be development or production');
}
const HA_CONFIG = loadUltraHaConfig(process.env, RUNTIME_MODE);

// Operator authorization is separate from the per-agent Ed25519 proof.
// LIFECYCLE_SECRET remains a development compatibility alias only.
const ADMIN_TOKEN = process.env.ULTRA_ADMIN_TOKEN ?? process.env.LIFECYCLE_SECRET ?? null;
const ADMIN_TOKEN_PREVIOUS = process.env.ULTRA_ADMIN_TOKEN_PREVIOUS ?? null;
const METRICS_TOKEN = process.env.ULTRA_METRICS_TOKEN ?? null;
const METRICS_TOKEN_PREVIOUS = process.env.ULTRA_METRICS_TOKEN_PREVIOUS ?? null;
validateMetricsTokenConfiguration({
  runtimeMode: RUNTIME_MODE,
  current: METRICS_TOKEN,
  previous: METRICS_TOKEN_PREVIOUS,
  adminTokens: [
    ['ULTRA_ADMIN_TOKEN', ADMIN_TOKEN],
    ['ULTRA_ADMIN_TOKEN_PREVIOUS', ADMIN_TOKEN_PREVIOUS],
  ],
});

// ── Stores ───────────────────────────────────────────────────────────────────
let pairStore;
let anomalyStore;
let nonceBackend;
let tskStore;
let identityBinding;
let idempotencyStore;
let nonceBackendType;
let rateLimiter;
let ipRateLimiter;
let haController = null;

const RATE_LIMIT_WINDOW_MS = parseInt(process.env.BPC_RATE_LIMIT_WINDOW_MS ?? '60000', 10);
const IP_RATE_LIMIT = parseInt(process.env.BPC_IP_RATE_LIMIT ?? '200', 10);
const PAIR_RATE_LIMIT = parseInt(process.env.BPC_PAIR_RATE_LIMIT ?? '100', 10);
for (const [name, value] of [
  ['BPC_RATE_LIMIT_WINDOW_MS', RATE_LIMIT_WINDOW_MS],
  ['BPC_IP_RATE_LIMIT', IP_RATE_LIMIT],
  ['BPC_PAIR_RATE_LIMIT', PAIR_RATE_LIMIT],
]) {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
}

if (RUNTIME_MODE === 'production') {
  const required = [
    'DATABASE_URL',
    'REDIS_URL',
    'ULTRA_ADMIN_TOKEN',
    'ULTRA_METRICS_TOKEN',
    'ULTRA_RECOVERY_HMAC_KEY',
  ];
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length > 0) throw new Error(`production mode missing required settings: ${missing.join(', ')}`);
  if (Buffer.byteLength(process.env.ULTRA_ADMIN_TOKEN, 'utf8') < 32) {
    throw new Error('ULTRA_ADMIN_TOKEN must contain at least 32 bytes in production');
  }
  if (Buffer.byteLength(process.env.ULTRA_RECOVERY_HMAC_KEY, 'utf8') < 32) {
    throw new Error('ULTRA_RECOVERY_HMAC_KEY must contain at least 32 bytes in production');
  }
  for (const name of [
    'ULTRA_ADMIN_TOKEN_PREVIOUS',
    'ULTRA_RECOVERY_HMAC_KEY_PREVIOUS',
  ]) {
    if (process.env[name] && Buffer.byteLength(process.env[name], 'utf8') < 32) {
      throw new Error(`${name} must contain at least 32 bytes when configured in production`);
    }
  }
  if (process.env.ULTRA_ADMIN_TOKEN_PREVIOUS === process.env.ULTRA_ADMIN_TOKEN) {
    throw new Error('ULTRA_ADMIN_TOKEN_PREVIOUS must differ from ULTRA_ADMIN_TOKEN');
  }
  const [{ Pool }, { default: Redis }] = await Promise.all([import('pg'), import('ioredis')]);
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  await pool.query('SELECT 1');
  await initializePgSchemas(pool, PG_SCHEMA, ULTRA_PG_SCHEMA);

  const redisClient = new Redis(process.env.REDIS_URL, {
    lazyConnect: true,
    ...(HA_CONFIG.enabled ? {
      commandTimeout: 2_000,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
    } : {}),
  });
  await redisClient.connect();
  pairStore = new PgPairStore(pool);
  anomalyStore = new RedisAnomalyStore(redisClient, 'ultra:anomaly:');
  nonceBackend = new RedisNonceStore(redisClient, 'ultra:nonce:');
  const pgTskStore = new PgTumblerStore(pool);
  if (HA_CONFIG.enabled) {
    const fenceStore = new RedisFencingStore(redisClient, HA_CONFIG.fenceKey);
    haController = new UltraHaController({
      clusterId: HA_CONFIG.clusterId,
      fenceStore,
      guardSecret: HA_CONFIG.guardSecret,
      maxCommandAgeMs: HA_CONFIG.maxCommandAgeMs,
      maxLeaseMs: HA_CONFIG.maxLeaseMs,
      minLeaseRemainingMs: HA_CONFIG.minLeaseRemainingMs,
      nodeId: HA_CONFIG.nodeId,
      role: HA_CONFIG.role,
    });
    tskStore = new FencedTumblerStore(pgTskStore, haController);
  } else {
    tskStore = pgTskStore;
  }
  identityBinding = new PgIdentityBindingStore(pool);
  idempotencyStore = new PgIdempotencyStore(pool);
  nonceBackendType = 'redis';
  ipRateLimiter = new RedisRateLimiter(redisClient, IP_RATE_LIMIT, RATE_LIMIT_WINDOW_MS, 'ultra:rate:ip:');
  rateLimiter = new RedisRateLimiter(redisClient, PAIR_RATE_LIMIT, RATE_LIMIT_WINDOW_MS, 'ultra:rate:pair:');
} else {
  pairStore = new MemoryPairStore();
  anomalyStore = new MemoryAnomalyStore();
  nonceBackend = new MemoryNonceBackend();
  tskStore = new MemoryTumblerStore();
  identityBinding = new MemoryIdentityBindingStore();
  idempotencyStore = new MemoryIdempotencyStore();
  nonceBackendType = 'memory';
  ipRateLimiter = new MemoryRateLimiter(IP_RATE_LIMIT, RATE_LIMIT_WINDOW_MS);
  rateLimiter = new MemoryRateLimiter(PAIR_RATE_LIMIT, RATE_LIMIT_WINDOW_MS);
}

const registry   = new PairRegistry(pairStore);
const nonceStore = new ServerNonceStore(nonceBackend, SIG_WINDOW_MS * 2 + 10_000);
const anomaly    = new AnomalyEngine(anomalyStore);
const provisioner = new TSKProvisioner(tskStore, {
  lifecycleAuthorizer: async ({ clientId, requestorId, reason, action }) => {
    if (action !== 'update') return false;
    if (requestorId === 'ultra-admin' && reason === 'operator-admin-lifecycle') {
      return true;
    }
    if (reason !== 'rotation-commit') return false;
    const map = await tskStore.get(clientId);
    return map?.label === `agent:${requestorId}` && map.status === 'active';
  },
});

// Only this server process can issue recovery tokens. Production supports one
// bounded previous key so operators can rotate without invalidating in-flight
// tokens; removing the previous key retires it immediately.
const RECOVERY_SECRET_CURRENT = process.env.ULTRA_RECOVERY_HMAC_KEY
  ?? randomBytes(32).toString('hex');
const recoveryKeyring = createRecoveryKeyring(
  RECOVERY_SECRET_CURRENT,
  process.env.ULTRA_RECOVERY_HMAC_KEY_PREVIOUS ?? null,
);
const RECOVERY_TOKEN_TTL_SEC = parseInt(process.env.SC_RECOVERY_WINDOW_SEC ?? '60', 10);

const bpcConfig = {
  sigWindowMs:      SIG_WINDOW_MS,
  lockoutCount:     10,
  enableShadowMode: true,
  enableTarpit:     true,
  ipRateLimiter,
  rateLimiter,
};

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({
  limit: '64kb',
  verify: (req, _res, buffer) => { req.rawBody = Buffer.from(buffer); },
}));
const requireAgentAuth = createAgentAuthMiddleware({ nonceStore, windowMs: 30_000 });
const requireAdminAuth = createAdminAuthMiddleware([ADMIN_TOKEN, ADMIN_TOKEN_PREVIOUS]);
const requireMetricsAuth = createMetricsAuthMiddleware([METRICS_TOKEN, METRICS_TOKEN_PREVIOUS]);
const registrationGuards = RUNTIME_MODE === 'production'
  ? [requireAdminAuth, requireAgentAuth]
  : [requireAgentAuth];

function waitForResponse(res, next) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      res.off('finish', done);
      res.off('close', done);
      resolve();
    };
    res.once('finish', done);
    res.once('close', done);
    try {
      next();
    } catch (error) {
      res.off('finish', done);
      res.off('close', done);
      reject(error);
    }
  });
}

function haLockMiddleware({ lockMode, requireWriter }) {
  return function fencedHaBoundary(req, res, next) {
    if (!HA_CONFIG.enabled) return next();
    const withLock = lockMode === 'shared'
      ? idempotencyStore.withSharedLock.bind(idempotencyStore)
      : idempotencyStore.withLock.bind(idempotencyStore);
    void withLock(HA_CONFIG.advisoryLockKey, async () => {
      if (requireWriter) {
        const writable = await haController.assertWritable({
          minRemainingMs: HA_CONFIG.minLeaseRemainingMs,
        });
        if (!writable.ok) {
          return res.status(503).json({ ok: false, error: 'ULTRA_WRITER_FENCED' });
        }
        req.scFenceEpoch = writable.fenceEpoch;
      }
      await waitForResponse(res, next);
      return undefined;
    }).catch((error) => {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'ERROR',
        event: 'ha_boundary_error',
        error: String(error),
      }));
      if (!res.headersSent) {
        res.status(503).json({ ok: false, error: 'ULTRA_HA_BOUNDARY_UNAVAILABLE' });
      } else if (!res.writableEnded) {
        res.destroy();
      }
    });
  };
}

const requireWriterLease = haLockMiddleware({ lockMode: 'shared', requireWriter: true });
const serializeHaTransition = haLockMiddleware({ lockMode: 'exclusive', requireWriter: false });

async function claimIdempotency(req, res, operation) {
  const headerKey = req.get('X-Idempotency-Key') ?? '';
  const bodyKey = req.body?.idempotencyKey ?? '';
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(headerKey) ||
      headerKey !== bodyKey) {
    res.status(400).json({ ok: false, error: 'INVALID_IDEMPOTENCY_KEY' });
    return null;
  }
  const claim = await idempotencyStore.claim(headerKey, operation, req.scAgent.agentId);
  if (claim.kind === 'conflict') {
    res.status(409).json({ ok: false, error: 'IDEMPOTENCY_KEY_CONFLICT' });
    return null;
  }
  return {
    key: headerKey,
    cached: claim.kind === 'complete' ? claim.response : null,
    recovering: claim.kind === 'processing',
  };
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

async function findTskMaps(predicate) {
  const ids = await tskStore.list();
  const maps = await Promise.all(ids.map((id) => tskStore.get(id)));
  return maps.filter((map) => map && predicate(map));
}

async function finishIdempotent(idem, response) {
  await idempotencyStore.complete(idem.key, response);
  return response;
}

// Count every request after response is sent
app.use((req, res, next) => {
  res.on('finish', () => {
    cHttpRequests.inc({
      method: metricMethodLabel(req.method),
      route: metricRouteLabel(req.route?.path),
      status: String(res.statusCode),
    });
  });
  next();
});

// ── Route: POST /register-pair ────────────────────────────────────────────────
app.post('/register-pair', requireWriterLease, ...registrationGuards, async (req, res) => {
  try {
    const { name, pubJwk, secretHash, scope, fingerprint } = req.body;
    if (!name || !pubJwk || !secretHash) {
      return res.status(400).json({ error: 'missing name, pubJwk, or secretHash' });
    }
    if (name !== req.scAgent.agentId) {
      return res.status(403).json({ ok: false, error: 'AGENT_OWNERSHIP_MISMATCH' });
    }
    const idem = await claimIdempotency(req, res, 'register-pair');
    if (!idem) return;
    if (idem.cached) return res.json(idem.cached);
    return idempotencyStore.withLock(`register-pair:${name}`, async () => {
      const forAgent = (await registry.list()).filter((pair) => pair.name === name);
      const activeForAgent = forAgent.filter((pair) => pair.status === 'active');
      const exact = forAgent.filter(
        (pair) =>
          pair.scope === (scope ?? 'read-write') &&
          pair.mode === RUNTIME_MODE &&
          pair.secretHash === secretHash &&
          canonicalJson(pair.pubJwk) === canonicalJson(pubJwk),
      );
      if (exact.length > 1) {
        return res.status(409).json({ ok: false, error: 'AMBIGUOUS_PAIR_RECOVERY' });
      }
      if (exact.length === 1) {
        if (exact[0].status !== 'active') {
          return res.status(409).json({ ok: false, error: 'PAIR_RECOVERY_STATE_NOT_ACTIVE' });
        }
        return res.json(await finishIdempotent(idem, { pairId: exact[0].id }));
      }
      if (activeForAgent.length > 0) {
        return res.status(409).json({ ok: false, error: 'ACTIVE_AGENT_PAIR_CONFLICT' });
      }

      // registerDirect(PairRegistration) — returns the assigned pairId
      const pairId = await registry.registerDirect({
        name,
        scope: scope ?? 'read-write',
        mode: RUNTIME_MODE,
        secretHash,
        pubJwk,
      });

      console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'pair_registered', pairId, name }));
      cBpcRegistrations.inc();
      return res.json(await finishIdempotent(idem, { pairId }));
    });
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'register_pair_error', error: String(err) }));
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /provision-tsk ────────────────────────────────────────────────
app.post('/provision-tsk', requireWriterLease, requireAgentAuth, async (req, res) => {
  try {
    const { requestorId, minTumblers, maxTumblers, keyLength } = req.body;
    if (!requestorId) {
      return res.status(400).json({ error: 'missing requestorId' });
    }
    if (requestorId !== req.scAgent.agentId) {
      return res.status(403).json({ ok: false, error: 'AGENT_OWNERSHIP_MISMATCH' });
    }
    if (RUNTIME_MODE === 'production') {
      const enrolled = (await registry.list()).some(
        (pair) => pair.name === requestorId && pair.status === 'active',
      );
      if (!enrolled) {
        return res.status(403).json({ ok: false, error: 'AGENT_NOT_ENROLLED' });
      }
    }
    const idem = await claimIdempotency(req, res, 'provision-tsk');
    if (!idem) return;
    if (idem.cached) {
      const currentMap = await tskStore.get(idem.cached.clientId);
      if (!currentMap || currentMap.label !== `agent:${requestorId}`) {
        return res.status(409).json({ ok: false, error: 'IDEMPOTENT_TSK_STATE_MISSING' });
      }
      return res.json({
        clientId: currentMap.clientId,
        sharedSecret: currentMap.sharedSecret,
        provisionPayload: toProvisionPayload(currentMap),
      });
    }

    return idempotencyStore.withLock(`provision-tsk:${requestorId}`, async () => {
      const existing = await findTskMaps((map) => map.label === `agent:${requestorId}`);
      if (existing.length > 1) {
        return res.status(409).json({ ok: false, error: 'AMBIGUOUS_TSK_RECOVERY' });
      }
      if (existing.length === 1) {
        if (existing[0].status !== 'active') {
          return res.status(409).json({ ok: false, error: 'TSK_RECOVERY_STATE_NOT_ACTIVE' });
        }
        return res.json(await finishIdempotent(idem, owningClientResponse(existing[0])));
      }

      // provision(TumblerMapOptions, requestorId?) — options has no segmentCount/totpWindowSec
      const result = await provisioner.provision(
        {
          ...(keyLength   ? { keyLength }   : {}),
          ...(minTumblers ? { minTumblers } : {}),
          ...(maxTumblers ? { maxTumblers } : {}),
        },
        requestorId,
        { label: `agent:${requestorId}` },
      );

      if (!result.ok) {
        return res.status(500).json({ error: result.error ?? 'PROVISION_FAILED' });
      }

      // sharedSecret is returned only to the authenticated owning client. The
      // reusable provisionPayload remains reduced and contains no secret.
      const { clientId, provisionPayload, tumblerMap } = result;
      const sharedSecret = tumblerMap?.sharedSecret ?? '';

      console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'tsk_provisioned', clientId, requestorId }));
      cTskProvisions.inc();
      return res.json(await finishIdempotent(idem, { clientId, sharedSecret, provisionPayload }));
    });
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'provision_tsk_error', error: String(err) }));
    return res.status(500).json({ error: String(err) });
  }
});

function owningClientResponse(map) {
  return {
    clientId: map.clientId,
    sharedSecret: map.sharedSecret,
    provisionPayload: toProvisionPayload(map),
  };
}

function rotationLabel(agentId, pairId, oldClientId) {
  return `rotation:${agentId}:${pairId}:${oldClientId}`;
}

function bpcActivityLock(pairId) {
  const digest = createHash('sha256').update(String(pairId), 'utf8').digest('hex');
  return `bpc-activity:${digest}`;
}

// Resume the currently bound TSK client after a process restart. Production
// requires both the agent's body-bound proof and the operator authorization
// because the response contains the owning client's shared secret.
app.post('/resume-identity', requireWriterLease, ...registrationGuards, async (req, res) => {
  try {
    const { pairId, agentId } = req.body ?? {};
    if (!pairId || agentId !== req.scAgent.agentId) {
      return res.status(400).json({ ok: false, error: 'INVALID_RESUME_REQUEST' });
    }
    const pair = await registry.get(pairId);
    const binding = await identityBinding.get(pairId);
    if (!pair || pair.name !== agentId || !binding || binding.agentId !== agentId) {
      return res.status(404).json({ ok: false, error: 'BOUND_IDENTITY_NOT_FOUND' });
    }
    const map = await tskStore.get(binding.tskClientId);
    const ownedLabel = map?.label === `agent:${agentId}`
      || map?.label?.startsWith(`rotation:${agentId}:${pairId}:`);
    if (!map || !ownedLabel || map.status !== 'active') {
      return res.status(409).json({ ok: false, error: 'BOUND_TSK_STATE_INVALID' });
    }
    return res.json({ ok: true, ...owningClientResponse(map) });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// Phase 1 of TSK rotation: create and return a new unbound key. Idempotency
// makes a lost response safe to retry without producing multiple candidates.
app.post('/rotate-tsk/prepare', requireWriterLease, ...registrationGuards, async (req, res) => {
  try {
    const { pairId, oldClientId, agentId } = req.body ?? {};
    if (!pairId || !oldClientId || agentId !== req.scAgent.agentId) {
      return res.status(400).json({ ok: false, error: 'INVALID_ROTATION_REQUEST' });
    }
    const pair = await registry.get(pairId);
    const binding = await identityBinding.get(pairId);
    if (
      !pair || pair.name !== agentId || !binding ||
      binding.agentId !== agentId || binding.tskClientId !== oldClientId
    ) {
      return res.status(409).json({ ok: false, error: 'ROTATION_SOURCE_MISMATCH' });
    }
    const idem = await claimIdempotency(req, res, 'rotate-tsk-prepare');
    if (!idem) return;
    const expectedLabel = rotationLabel(agentId, pairId, oldClientId);
    if (idem.cached) {
      const cachedMap = await tskStore.get(idem.cached.clientId);
      if (!cachedMap || cachedMap.label !== expectedLabel || cachedMap.status !== 'active') {
        return res.status(409).json({ ok: false, error: 'ROTATION_CANDIDATE_MISSING' });
      }
      return res.json({ ok: true, ...owningClientResponse(cachedMap) });
    }
    return idempotencyStore.withLock(`rotate-tsk:${pairId}:${oldClientId}`, async () => {
      const existing = await findTskMaps((map) => map.label === expectedLabel);
      if (existing.length > 1) {
        return res.status(409).json({ ok: false, error: 'AMBIGUOUS_ROTATION_RECOVERY' });
      }
      if (existing.length === 1) {
        if (existing[0].status !== 'active') {
          return res.status(409).json({ ok: false, error: 'ROTATION_RECOVERY_STATE_NOT_ACTIVE' });
        }
        const recovered = { ok: true, ...owningClientResponse(existing[0]) };
        return res.json(await finishIdempotent(idem, recovered));
      }

      const result = await provisioner.provision({}, agentId, { label: expectedLabel });
      if (!result.ok || !result.tumblerMap) {
        return res.status(500).json({ ok: false, error: result.error ?? 'ROTATION_PREPARE_FAILED' });
      }
      const response = { ok: true, ...owningClientResponse(result.tumblerMap) };
      await finishIdempotent(idem, response);
      console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'INFO',
        event: 'tsk_rotation_prepared',
        pairId,
        oldClientId,
        newClientId: result.tumblerMap.clientId,
        agentId,
      }));
      return res.json(response);
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// Phase 2: atomically move the pair binding to the prepared key, then revoke
// the old key. The binding CAS makes retries safe after a lost response.
app.post('/rotate-tsk/commit', requireWriterLease, ...registrationGuards, async (req, res) => {
  try {
    const { pairId, oldClientId, newClientId, agentId } = req.body ?? {};
    if (
      !pairId || !oldClientId || !newClientId || oldClientId === newClientId ||
      agentId !== req.scAgent.agentId
    ) {
      return res.status(400).json({ ok: false, error: 'INVALID_ROTATION_REQUEST' });
    }
    const pair = await registry.get(pairId);
    const oldMap = await tskStore.get(oldClientId);
    const newMap = await tskStore.get(newClientId);
    if (
      !pair || pair.name !== agentId || !oldMap || !newMap ||
      newMap.label !== rotationLabel(agentId, pairId, oldClientId) ||
      newMap.status !== 'active'
    ) {
      return res.status(409).json({ ok: false, error: 'ROTATION_CANDIDATE_MISMATCH' });
    }
    const swap = await identityBinding.compareAndSwap(
      pairId,
      oldClientId,
      { tskClientId: newClientId, agentId },
    );
    if (swap === 'missing' || swap === 'conflict') {
      return res.status(409).json({ ok: false, error: 'ROTATION_BINDING_CONFLICT' });
    }
    const revoked = oldMap.status === 'revoked'
      || await provisioner.updateKey(
        oldClientId,
        { status: 'revoked' },
        agentId,
        'rotation-commit',
      );
    if (!revoked) {
      return res.status(500).json({ ok: false, error: 'ROTATION_OLD_KEY_REVOCATION_FAILED' });
    }
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      event: 'tsk_rotation_committed',
      pairId,
      oldClientId,
      newClientId,
      agentId,
      idempotent: swap === 'already',
    }));
    return res.json({ ok: true, pairId, oldClientId, newClientId, idempotent: swap === 'already' });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: POST /bind-identity ────────────────────────────────────────────────
app.post('/bind-identity', requireWriterLease, requireAgentAuth, async (req, res) => {
  try {
    const { pairId, tskClientId, agentId } = req.body;
    if (!pairId || !tskClientId) {
      return res.status(400).json({ error: 'missing pairId or tskClientId' });
    }
    if (agentId !== req.scAgent.agentId) {
      return res.status(403).json({ ok: false, error: 'AGENT_OWNERSHIP_MISMATCH' });
    }
    const idem = await claimIdempotency(req, res, 'bind-identity');
    if (!idem) return;
    if (idem.cached) return res.json(idem.cached);
    return idempotencyStore.withLock(`bind-identity:${pairId}`, async () => {
      const pair = await registry.get(pairId);
      const tskMap = await tskStore.get(tskClientId);
      if (
        !pair || pair.name !== agentId || pair.status !== 'active' || !tskMap ||
        tskMap.label !== `agent:${agentId}` || tskMap.status !== 'active'
      ) {
        return res.status(403).json({ ok: false, error: 'IDENTITY_BINDING_MISMATCH' });
      }
      const existing = await identityBinding.get(pairId);
      if (existing) {
        if (existing.tskClientId !== tskClientId || existing.agentId !== agentId) {
          return res.status(409).json({ ok: false, error: 'IDENTITY_BINDING_CONFLICT' });
        }
        return res.json(await finishIdempotent(idem, { ok: true }));
      }
      await identityBinding.set(pairId, { tskClientId, agentId });
      console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'identity_bound', pairId, clientId: tskClientId }));
      return res.json(await finishIdempotent(idem, { ok: true }));
    });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /verify (full 7-layer) ────────────────────────────────────────
app.post('/verify', requireWriterLease, async (req, res) => {
  try {
    const { headers: reqHeaders, bodyHash } = req.body;
    if (!reqHeaders || !bodyHash) {
      return res.status(400).json({ error: 'missing headers or bodyHash' });
    }

    // verifyUltraRequest expects TSKRequestData: { headers: Record<string, string> }
    // The bridge passes this to verifyTSKRequest AND to the bpcVerify callback.
    // The bpcVerify callback must extract BPC fields from the headers map.
    const tskReqData = {
      headers: {
        // BPC headers (normalise to lowercase)
        'x-bpc-pair-id':     String(reqHeaders['X-BPC-Pair-ID']     ?? reqHeaders['x-bpc-pair-id']     ?? ''),
        'x-bpc-signed-data': String(reqHeaders['X-BPC-Signed-Data'] ?? reqHeaders['x-bpc-signed-data'] ?? ''),
        'x-bpc-signature':   String(reqHeaders['X-BPC-Signature']   ?? reqHeaders['x-bpc-signature']   ?? ''),
        'x-bpc-version':     String(reqHeaders['X-BPC-Version']     ?? reqHeaders['x-bpc-version']     ?? '1.0'),
        // TSK headers
        'x-tsk-client-id':   String(reqHeaders['X-TSK-Client-ID']   ?? reqHeaders['x-tsk-client-id']   ?? ''),
        'x-tsk-key':         String(reqHeaders['X-TSK-Key']         ?? reqHeaders['x-tsk-key']         ?? ''),
        'x-tsk-version':     String(reqHeaders['X-TSK-Version']     ?? reqHeaders['x-tsk-version']     ?? '1'),
        // Target path
        'x-target-path':     String(reqHeaders['X-Target-Path']     ?? reqHeaders['x-target-path']     ?? '/terminal/unknown'),
      },
    };

    const verifyRequest = () => verifyUltraRequest(
      tskReqData,
      // bpcVerify callback: extract BPC fields from the headers map → BPCRequestData
      (r) => {
        const h = r.headers;
        return verifyBPCRequest(
          {
            pairId:     h['x-bpc-pair-id']     || null,
            signedData: h['x-bpc-signed-data'] || null,
            signature:  h['x-bpc-signature']   || null,
            method:     'POST',  // INJECT is not in BPC ALLOWED_METHODS; POST is the correct wire method
            path:       h['x-target-path']     || '/terminal/unknown',
            version:    h['x-bpc-version']     || null,
            bodyHash:   bodyHash,
            ip:         req.ip ?? 'unknown',
          },
          registry,
          nonceStore,
          anomaly,
          bpcConfig,
        ).then(enforceBpcAuthorization);
      },
      {
        tskStore,
        identityBinding: {
          resolve: async (pairId) => {
            const b = await identityBinding.get(pairId);
            return b ? b.tskClientId : null;
          },
        },
      },
    );
    const pairId = tskReqData.headers['x-bpc-pair-id'];
    const result = pairId
      ? await idempotencyStore.withLock(bpcActivityLock(pairId), verifyRequest)
      : await verifyRequest();

    if (!result.ok) {
      cAuthFailures.inc({ reason: metricAuthFailureLabel(result.error) });
    }
    return res.json(result);
  } catch (err) {
    cAuthFailures.inc({ reason: 'exception' });
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'verify_exception', error: String(err) }));
    return res.status(500).json({ ok: false, error: String(err), layers: [] });
  }
});

// ── Route: GET /pubkeys/:pairId ───────────────────────────────────────────────
app.get('/pubkeys/:pairId', requireAdminAuth, async (req, res) => {
  try {
    const pair = await registry.get(req.params.pairId);
    if (!pair) {
      return res.status(404).json({ error: 'pair not found' });
    }
    return res.json({ pairId: pair.id, pubJwk: pair.pubJwk, fingerprint: pair.fingerprint });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /confirm-recovery (Gap 2 fix) ───────────────────────────────
// Called by RecoveryManager after generating a new keypair.
// Returns a server-signed HMAC token that peers must verify before accepting.
app.post('/confirm-recovery', requireWriterLease, requireAdminAuth, requireAgentAuth, (req, res) => {
  try {
    const { agentName, agentId, newPubHex, challengeHash } = req.body ?? {};
    if (!agentName || !agentId || !newPubHex || !challengeHash) {
      return res.status(400).json({ error: 'missing required fields' });
    }
    if (typeof agentName !== 'string' || agentName.length > 128) {
      return res.status(400).json({ error: 'invalid agentName' });
    }
    if (typeof newPubHex !== 'string' || !/^[0-9a-f]{64}$/i.test(newPubHex)) {
      return res.status(400).json({ error: 'invalid newPubHex' });
    }
    if (agentId !== req.scAgent.agentId || newPubHex.toLowerCase() !== req.scAgent.publicKeyHex) {
      return res.status(403).json({ ok: false, error: 'RECOVERY_IDENTITY_MISMATCH' });
    }
    const token = issueRecoveryToken({
      agentName,
      agentId,
      newPubHex,
      challengeHash,
    }, recoveryKeyring);
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'recovery_confirmed', agentName, pubkeyPrefix: newPubHex.slice(0,16) }));
    return res.json({ ok: true, token });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /verify-recovery-token (Gap 2 fix) ───────────────────────────
// Called by peers when they detect SCRECOVERY=1 on a peer's HWND.
// Verifies the HMAC signature and TTL of a recovery token.
app.post('/verify-recovery-token', (req, res) => {
  try {
    const { token } = req.body ?? {};
    if (!token || typeof token !== 'object') {
      return res.status(400).json({ valid: false, error: 'missing token' });
    }
    return res.json(verifyRecoveryToken(token, recoveryKeyring, {
      ttlSec: RECOVERY_TOKEN_TTL_SEC,
    }));
  } catch (err) {
    return res.status(500).json({ valid: false, error: String(err) });
  }
});

// Guard-signed, operator-authorized writer transition. An exclusive PostgreSQL
// advisory lock is held across this transition. Governed requests hold the
// shared form of the same lock, so requests may overlap each other but cannot
// overlap a fence epoch change.
app.post('/ha/command', requireAdminAuth, serializeHaTransition, async (req, res) => {
  if (!HA_CONFIG.enabled) {
    return res.status(409).json({ ok: false, error: 'ULTRA_HA_DISABLED' });
  }
  const outcome = await haController.applyCommand(req.body);
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: outcome.status === 200 ? 'INFO' : 'WARN',
    event: 'ha_guard_command',
    command: req.body?.command ?? null,
    commandId: req.body?.commandId ?? null,
    fenceEpoch: req.body?.fenceEpoch ?? null,
    nodeId: HA_CONFIG.nodeId,
    accepted: outcome.status === 200,
    result: outcome.result?.error ?? 'ok',
  }));
  return res.status(outcome.status).json(outcome.result);
});

app.get('/ha/status', requireAdminAuth, async (_req, res) => {
  if (!HA_CONFIG.enabled) return res.json({ ok: true, enabled: false });
  return res.json({ ok: true, enabled: true, ...(await haController.snapshot()) });
});

// ── Route: GET /health ────────────────────────────────────────────────────────
// Simple liveness probe for load balancers and monitoring systems.
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'ultra-server', version: ULTRA_VERSION, ts: Date.now() });
});

// Readiness is deliberately stricter than liveness. In HA mode only the node
// holding the current shared writer lease is eligible for governed traffic.
app.get('/ready', async (_req, res) => {
  if (!HA_CONFIG.enabled) {
    return res.json({ ok: true, haEnabled: false, writable: true });
  }
  const writable = await haController.assertWritable({
    minRemainingMs: HA_CONFIG.minLeaseRemainingMs,
  });
  if (!writable.ok) {
    return res.status(503).json({ ok: false, haEnabled: true, writable: false, error: 'ULTRA_WRITER_FENCED' });
  }
  return res.json({
    ok: true,
    haEnabled: true,
    writable: true,
    fenceEpoch: writable.fenceEpoch,
    nodeId: HA_CONFIG.nodeId,
  });
});

// ── Route: GET /tsk/keys ─────────────────────────────────────────────────────
// List all provisioned TSK keys with lifecycle metadata. No secrets returned.
app.get('/tsk/keys', requireAdminAuth, async (_req, res) => {
  try {
    const keys = await provisioner.listKeys();
    return res.json({ ok: true, count: keys.length, keys });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: GET /tsk/keys/:clientId ───────────────────────────────────────────
// Get a single TSK key's lifecycle metadata.
app.get('/tsk/keys/:clientId', requireAdminAuth, async (req, res) => {
  try {
    const key = await provisioner.getKey(req.params.clientId);
    if (!key) return res.status(404).json({ ok: false, error: 'KEY_NOT_FOUND' });
    return res.json({ ok: true, key });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: PATCH /tsk/keys/:clientId ─────────────────────────────────────────
// Update TSK key lifecycle: label, expiresAt, maxRequests, status.
// Does NOT modify cryptographic material — re-provision to change keys.
app.patch('/tsk/keys/:clientId', requireWriterLease, requireAdminAuth, async (req, res) => {
  try {
    const { label, expiresAt, maxRequests, status } = req.body ?? {};
    const updates = {};
    if (label !== undefined) updates.label = label;
    if (expiresAt !== undefined) updates.expiresAt = expiresAt;
    if (maxRequests !== undefined) updates.maxRequests = maxRequests;
    if (status !== undefined) {
      if (!['active', 'revoked', 'expired'].includes(status)) {
        return res.status(400).json({ ok: false, error: 'INVALID_STATUS' });
      }
      updates.status = status;
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ ok: false, error: 'NO_UPDATES_PROVIDED' });
    }
    const found = await provisioner.updateKey(
      req.params.clientId,
      updates,
      'ultra-admin',
      'operator-admin-lifecycle',
    );
    if (!found) return res.status(404).json({ ok: false, error: 'KEY_NOT_FOUND' });
    const updated = await provisioner.getKey(req.params.clientId);
    console.log(`[ultra-server] TSK key ${req.params.clientId} updated: ${JSON.stringify(updates)}`);
    return res.json({ ok: true, key: updated });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: GET /bpc/pairs ─────────────────────────────────────────────────────
// List all BPC pairs with redacted lifecycle metadata (no secrets, no keys).
app.get('/bpc/pairs', requireAdminAuth, async (_req, res) => {
  try {
    const pairs = await registry.listRedacted();
    return res.json({ ok: true, count: pairs.length, pairs });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: PATCH /bpc/pairs/:pairId ──────────────────────────────────────────
// Update BPC pair lifecycle: scope, expiresAt, maxRequests, name.
app.patch('/bpc/pairs/:pairId', requireWriterLease, requireAdminAuth, async (req, res) => {
  try {
    const { scope, expiresAt, maxRequests, name } = req.body ?? {};
    const updates = {};
    if (scope !== undefined) updates.scope = scope;
    if (expiresAt !== undefined) updates.expiresAt = expiresAt;
    if (maxRequests !== undefined) updates.maxRequests = maxRequests;
    if (name !== undefined) updates.name = name;
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ ok: false, error: 'NO_UPDATES_PROVIDED' });
    }
    return idempotencyStore.withLock(bpcActivityLock(req.params.pairId), async () => {
      const found = await registry.updatePair(req.params.pairId, updates);
      if (!found) return res.status(404).json({ ok: false, error: 'PAIR_NOT_FOUND' });
      console.log(`[ultra-server] BPC pair ${req.params.pairId} updated: ${JSON.stringify(updates)}`);
      return res.json({ ok: true });
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: GET /metrics ───────────────────────────────────────────────────────
app.get('/metrics', requireMetricsAuth, async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ── Route: GET /status ────────────────────────────────────────────────────────
app.get('/status', requireAdminAuth, async (req, res) => {
  try {
    const pairs = await registry.list();
    const ha = HA_CONFIG.enabled
      ? { enabled: true, ...(await haController.snapshot()) }
      : { enabled: false };
    return res.json({
      ok:           true,
      version:      ULTRA_VERSION,
      pairs:        pairs.length,
      bindings:     await identityBinding.count(),
      sigWindowMs:  SIG_WINDOW_MS,
      nonceBackend: nonceBackendType,
      runtimeMode:  RUNTIME_MODE,
      ha,
      keyRotation: {
        adminVerificationKeys: [ADMIN_TOKEN, ADMIN_TOKEN_PREVIOUS].filter(Boolean).length,
        recoveryVerificationKeys: recoveryKeyring.verificationKeys.size,
      },
      layer8: {
        shadowMode: bpcConfig.enableShadowMode,
        tarpit:     bpcConfig.enableTarpit,
        authorizationBoundary: 'fail-closed',
      },
      rateLimits: {
        windowMs: RATE_LIMIT_WINDOW_MS,
        perIp: IP_RATE_LIMIT,
        perPair: PAIR_RATE_LIMIT,
      },
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(), level: 'INFO', event: 'server_start', port: PORT,
    runtimeMode: RUNTIME_MODE,
    ha: HA_CONFIG.enabled ? {
      enabled: true,
      clusterId: HA_CONFIG.clusterId,
      nodeId: HA_CONFIG.nodeId,
      role: HA_CONFIG.role,
      writableAtStart: false,
    } : { enabled: false },
  }));
  if (RUNTIME_MODE === 'development') {
    console.warn(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'WARN',
      event: 'development_store_warning',
      message: 'Development memory stores are active; lifecycle state is not restart-durable.',
    }));
  } else {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'INFO',
      event: 'durable_stores_active',
      stores: ['postgresql-pair', 'postgresql-tumbler', 'postgresql-binding', 'postgresql-idempotency', 'redis-nonce', 'redis-anomaly'],
    }));
  }
});
