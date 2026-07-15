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
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { createAdminAuthMiddleware, createAgentAuthMiddleware } from './agent-auth.js';
import {
  MemoryIdempotencyStore,
  MemoryIdentityBindingStore,
  PgIdempotencyStore,
  PgIdentityBindingStore,
  PgTumblerStore,
  ULTRA_PG_SCHEMA,
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
  MemoryTumblerStore,
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

// Operator authorization is separate from the per-agent Ed25519 proof.
// LIFECYCLE_SECRET remains a development compatibility alias only.
const ADMIN_TOKEN = process.env.ULTRA_ADMIN_TOKEN ?? process.env.LIFECYCLE_SECRET ?? null;

// ── Stores ───────────────────────────────────────────────────────────────────
let pairStore;
let anomalyStore;
let nonceBackend;
let tskStore;
let identityBinding;
let idempotencyStore;
let nonceBackendType;

if (RUNTIME_MODE === 'production') {
  const required = ['DATABASE_URL', 'REDIS_URL', 'ULTRA_ADMIN_TOKEN', 'ULTRA_RECOVERY_HMAC_KEY'];
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length > 0) throw new Error(`production mode missing required settings: ${missing.join(', ')}`);
  if (Buffer.byteLength(process.env.ULTRA_ADMIN_TOKEN, 'utf8') < 32) {
    throw new Error('ULTRA_ADMIN_TOKEN must contain at least 32 bytes in production');
  }
  if (Buffer.byteLength(process.env.ULTRA_RECOVERY_HMAC_KEY, 'utf8') < 32) {
    throw new Error('ULTRA_RECOVERY_HMAC_KEY must contain at least 32 bytes in production');
  }

  const [{ Pool }, { default: Redis }] = await Promise.all([import('pg'), import('ioredis')]);
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  await pool.query('SELECT 1');
  await pool.query(PG_SCHEMA);
  await pool.query(ULTRA_PG_SCHEMA);

  const redisClient = new Redis(process.env.REDIS_URL, { lazyConnect: true });
  await redisClient.connect();
  pairStore = new PgPairStore(pool);
  anomalyStore = new RedisAnomalyStore(redisClient, 'ultra:anomaly:');
  nonceBackend = new RedisNonceStore(redisClient, 'ultra:nonce:');
  tskStore = new PgTumblerStore(pool);
  identityBinding = new PgIdentityBindingStore(pool);
  idempotencyStore = new PgIdempotencyStore(pool);
  nonceBackendType = 'redis';
} else {
  pairStore = new MemoryPairStore();
  anomalyStore = new MemoryAnomalyStore();
  nonceBackend = new MemoryNonceBackend();
  tskStore = new MemoryTumblerStore();
  identityBinding = new MemoryIdentityBindingStore();
  idempotencyStore = new MemoryIdempotencyStore();
  nonceBackendType = 'memory';
}

const registry   = new PairRegistry(pairStore);
const nonceStore = new ServerNonceStore(nonceBackend, SIG_WINDOW_MS * 2 + 10_000);
const anomaly    = new AnomalyEngine(anomalyStore);
const provisioner = new TSKProvisioner(tskStore);

// ── Recovery HMAC key (Gap 2 fix) ────────────────────────────────────────────
// Generated fresh at startup. Never written to disk. Rotated on restart.
// Only this server process can sign or verify recovery tokens.
const RECOVERY_HMAC_KEY = RUNTIME_MODE === 'production'
  ? createHash('sha256').update(process.env.ULTRA_RECOVERY_HMAC_KEY, 'utf8').digest()
  : randomBytes(32);
const RECOVERY_TOKEN_TTL_SEC = parseInt(process.env.SC_RECOVERY_WINDOW_SEC ?? '60', 10);

const bpcConfig = {
  sigWindowMs:      SIG_WINDOW_MS,
  lockoutCount:     10,
  enableShadowMode: true,
  enableTarpit:     true,
};

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({
  limit: '64kb',
  verify: (req, _res, buffer) => { req.rawBody = Buffer.from(buffer); },
}));
const requireAgentAuth = createAgentAuthMiddleware({ nonceStore, windowMs: 30_000 });
const requireAdminAuth = createAdminAuthMiddleware(ADMIN_TOKEN);
const registrationGuards = RUNTIME_MODE === 'production'
  ? [requireAdminAuth, requireAgentAuth]
  : [requireAgentAuth];

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
  if (claim.kind === 'processing') {
    res.status(409).json({ ok: false, error: 'IDEMPOTENCY_REQUEST_IN_PROGRESS' });
    return null;
  }
  return { key: headerKey, cached: claim.kind === 'complete' ? claim.response : null };
}

// Count every request after response is sent
app.use((req, res, next) => {
  res.on('finish', () => {
    const route = req.route?.path ?? req.path;
    cHttpRequests.inc({ method: req.method, route, status: String(res.statusCode) });
  });
  next();
});

// ── Route: POST /register-pair ────────────────────────────────────────────────
app.post('/register-pair', ...registrationGuards, async (req, res) => {
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

    // registerDirect(PairRegistration) — returns the assigned pairId
    const pairId = await registry.registerDirect({
      name,
      scope: scope ?? 'read-write',
      mode:  RUNTIME_MODE,
      secretHash,
      pubJwk,
    });

    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'pair_registered', pairId, name }));
    cBpcRegistrations.inc();
    const response = { pairId };
    await idempotencyStore.complete(idem.key, response);
    return res.json(response);
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'register_pair_error', error: String(err) }));
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /provision-tsk ────────────────────────────────────────────────
app.post('/provision-tsk', requireAgentAuth, async (req, res) => {
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

    // sharedSecret is on result.tumblerMap.
    // The provisionPayload is the safe public payload (no positions, no secret).
    // We DO send sharedSecret to the owning client (the requestor) because:
    //   1. The connection is localhost-only (sidecar architecture, not public API)
    //   2. The client MUST have the secret to generate valid TSK keys
    //   3. The client MUST have the secret to compute the checksum for self-verification
    // We do NOT embed it in provisionPayload because that struct may be shared with
    // third-party verifiers who should not have the secret.
    const { clientId, provisionPayload, tumblerMap } = result;
    const sharedSecret = tumblerMap?.sharedSecret ?? '';

    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'tsk_provisioned', clientId, requestorId }));
    cTskProvisions.inc();
    const response = { clientId, sharedSecret, provisionPayload };
    await idempotencyStore.complete(idem.key, response);
    return res.json(response);
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'provision_tsk_error', error: String(err) }));
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /bind-identity ────────────────────────────────────────────────
app.post('/bind-identity', requireAgentAuth, async (req, res) => {
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
    const pair = await registry.get(pairId);
    const tskMap = await tskStore.get(tskClientId);
    if (!pair || pair.name !== agentId || !tskMap || tskMap.label !== `agent:${agentId}`) {
      return res.status(403).json({ ok: false, error: 'IDENTITY_BINDING_MISMATCH' });
    }
    await identityBinding.set(pairId, { tskClientId, agentId });
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'identity_bound', pairId, clientId: tskClientId }));
    const response = { ok: true };
    await idempotencyStore.complete(idem.key, response);
    return res.json(response);
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /verify (full 7-layer) ────────────────────────────────────────
app.post('/verify', async (req, res) => {
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

    const result = await verifyUltraRequest(
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
        );
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

    if (!result.ok) {
      const failedLayer = result.layers?.find(l => !l.ok);
      cAuthFailures.inc({ reason: failedLayer?.layer ?? 'unknown' });
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
app.post('/confirm-recovery', requireAdminAuth, requireAgentAuth, (req, res) => {
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
    const issuedAt = Math.floor(Date.now() / 1000);
    const sigData  = `${agentName}:${agentId}:${newPubHex}:${issuedAt}`;
    const sig = createHmac('sha256', RECOVERY_HMAC_KEY).update(sigData).digest('hex');
    const token = { agentName, agentId, newPubHex, issuedAt, sig };
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
    const { agentName, agentId, newPubHex, issuedAt, sig } = token;
    if (!agentName || !agentId || !newPubHex || !issuedAt || !sig) {
      return res.status(400).json({ valid: false, error: 'incomplete token' });
    }
    const age = Math.floor(Date.now() / 1000) - issuedAt;
    if (age < 0 || age > RECOVERY_TOKEN_TTL_SEC) {
      return res.json({ valid: false, error: 'token expired' });
    }
    const sigData  = `${agentName}:${agentId}:${newPubHex}:${issuedAt}`;
    const expected = createHmac('sha256', RECOVERY_HMAC_KEY).update(sigData).digest('hex');
    const eBuf = Buffer.from(expected, 'hex');
    const aBuf = Buffer.from(sig,      'hex');
    if (eBuf.length !== aBuf.length) return res.json({ valid: false, error: 'sig length mismatch' });
    let diff = 0;
    for (let i = 0; i < eBuf.length; i++) diff |= eBuf[i] ^ aBuf[i];
    return res.json({ valid: diff === 0 });
  } catch (err) {
    return res.status(500).json({ valid: false, error: String(err) });
  }
});

// ── Route: GET /health ────────────────────────────────────────────────────────
// Simple liveness probe for load balancers and monitoring systems.
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'ultra-server', version: ULTRA_VERSION, ts: Date.now() });
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
app.patch('/tsk/keys/:clientId', requireAdminAuth, async (req, res) => {
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
    const found = await provisioner.updateKey(req.params.clientId, updates);
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
app.patch('/bpc/pairs/:pairId', requireAdminAuth, async (req, res) => {
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
    const found = await registry.updatePair(req.params.pairId, updates);
    if (!found) return res.status(404).json({ ok: false, error: 'PAIR_NOT_FOUND' });
    console.log(`[ultra-server] BPC pair ${req.params.pairId} updated: ${JSON.stringify(updates)}`);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: GET /metrics ───────────────────────────────────────────────────────
app.get('/metrics', requireAdminAuth, async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ── Route: GET /status ────────────────────────────────────────────────────────
app.get('/status', requireAdminAuth, async (req, res) => {
  try {
    const pairs = await registry.list();
    return res.json({
      ok:           true,
      version:      ULTRA_VERSION,
      pairs:        pairs.length,
      bindings:     await identityBinding.count(),
      sigWindowMs:  SIG_WINDOW_MS,
      nonceBackend: nonceBackendType,
      runtimeMode:  RUNTIME_MODE,
      layer8: {
        shadowMode: bpcConfig.enableShadowMode,
        tarpit:     bpcConfig.enableTarpit,
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
