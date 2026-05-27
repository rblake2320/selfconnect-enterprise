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
 * Version: 1.1.0  BPC+TSK integration — API-correct rewrite
 */
import express from 'express';
import { createHmac, randomBytes } from 'node:crypto';

// ── BPC imports ───────────────────────────────────────────────────────────────
import {
  PairRegistry,
  ServerNonceStore,
  AnomalyEngine,
  MemoryPairStore,
  MemoryNonceBackend,
  MemoryAnomalyStore,
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

// ── Bridge import ─────────────────────────────────────────────────────────────
import { verifyUltraRequest } from '@tsk/bpc-bridge';

const PORT = parseInt(process.env.ULTRA_SERVER_PORT ?? '7777', 10);
const SIG_WINDOW_MS = 60_000;

// ── Stores — Redis nonce backend when REDIS_URL is set ───────────────────────
const pairStore    = new MemoryPairStore();
const anomalyStore = new MemoryAnomalyStore();

let nonceBackend;
let nonceBackendType = 'memory';
if (process.env.REDIS_URL) {
  try {
    const { default: Redis } = await import('ioredis');
    const redisClient = new Redis(process.env.REDIS_URL, { lazyConnect: true });
    await redisClient.connect();
    nonceBackend = new RedisNonceStore(redisClient);
    nonceBackendType = 'redis';
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'redis_nonce_backend', url: process.env.REDIS_URL }));
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'redis_connect_failed', error: String(err), fallback: 'memory' }));
    nonceBackend = new MemoryNonceBackend();
  }
} else {
  nonceBackend = new MemoryNonceBackend();
}

const registry   = new PairRegistry(pairStore);
const nonceStore = new ServerNonceStore(nonceBackend, SIG_WINDOW_MS * 2 + 10_000);
const anomaly    = new AnomalyEngine(anomalyStore);
const tskStore   = new MemoryTumblerStore();
const provisioner = new TSKProvisioner(tskStore);

// Identity binding: pairId → tskClientId
const identityBinding = new Map();

// ── Recovery HMAC key (Gap 2 fix) ────────────────────────────────────────────
// Generated fresh at startup. Never written to disk. Rotated on restart.
// Only this server process can sign or verify recovery tokens.
const RECOVERY_HMAC_KEY = randomBytes(32);
const RECOVERY_TOKEN_TTL_SEC = parseInt(process.env.SC_RECOVERY_WINDOW_SEC ?? '60', 10);

const bpcConfig = {
  sigWindowMs:      SIG_WINDOW_MS,
  lockoutCount:     10,
  enableShadowMode: true,
  enableTarpit:     true,
};

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '64kb' }));

// Count every request after response is sent
app.use((req, res, next) => {
  res.on('finish', () => {
    const route = req.route?.path ?? req.path;
    cHttpRequests.inc({ method: req.method, route, status: String(res.statusCode) });
  });
  next();
});

// ── Route: POST /register-pair ────────────────────────────────────────────────
app.post('/register-pair', async (req, res) => {
  try {
    const { name, pubJwk, secretHash, scope, fingerprint } = req.body;
    if (!name || !pubJwk || !secretHash) {
      return res.status(400).json({ error: 'missing name, pubJwk, or secretHash' });
    }

    // registerDirect(PairRegistration) — returns the assigned pairId
    const pairId = await registry.registerDirect({
      name,
      scope: scope ?? 'read-write',
      mode:  'development',
      secretHash,
      pubJwk,
    });

    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'pair_registered', pairId, name }));
    cBpcRegistrations.inc();
    return res.json({ pairId });
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'register_pair_error', error: String(err) }));
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /provision-tsk ────────────────────────────────────────────────
app.post('/provision-tsk', async (req, res) => {
  try {
    const { requestorId, minTumblers, maxTumblers, keyLength } = req.body;
    if (!requestorId) {
      return res.status(400).json({ error: 'missing requestorId' });
    }

    // provision(TumblerMapOptions, requestorId?) — options has no segmentCount/totpWindowSec
    const result = await provisioner.provision(
      {
        ...(keyLength   ? { keyLength }   : {}),
        ...(minTumblers ? { minTumblers } : {}),
        ...(maxTumblers ? { maxTumblers } : {}),
      },
      requestorId,
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
    return res.json({ clientId, sharedSecret, provisionPayload });
  } catch (err) {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', event: 'provision_tsk_error', error: String(err) }));
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /bind-identity ────────────────────────────────────────────────
app.post('/bind-identity', (req, res) => {
  try {
    const { pairId, tskClientId, agentId } = req.body;
    if (!pairId || !tskClientId) {
      return res.status(400).json({ error: 'missing pairId or tskClientId' });
    }
    identityBinding.set(pairId, { tskClientId, agentId: agentId ?? '' });
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'identity_bound', pairId, clientId: tskClientId }));
    return res.json({ ok: true });
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
            const b = identityBinding.get(pairId);
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
app.get('/pubkeys/:pairId', async (req, res) => {
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
app.post('/confirm-recovery', (req, res) => {
  try {
    const { agentName, newPubHex, challengeHash } = req.body ?? {};
    if (!agentName || !newPubHex || !challengeHash) {
      return res.status(400).json({ error: 'missing required fields' });
    }
    if (typeof agentName !== 'string' || agentName.length > 128) {
      return res.status(400).json({ error: 'invalid agentName' });
    }
    if (typeof newPubHex !== 'string' || !/^[0-9a-f]{64,132}$/i.test(newPubHex)) {
      return res.status(400).json({ error: 'invalid newPubHex' });
    }
    const issuedAt = Math.floor(Date.now() / 1000);
    const sigData  = `${agentName}:${newPubHex}:${issuedAt}`;
    const sig = createHmac('sha256', RECOVERY_HMAC_KEY).update(sigData).digest('hex');
    const token = { agentName, newPubHex, issuedAt, sig };
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
    const { agentName, newPubHex, issuedAt, sig } = token;
    if (!agentName || !newPubHex || !issuedAt || !sig) {
      return res.status(400).json({ valid: false, error: 'incomplete token' });
    }
    const age = Math.floor(Date.now() / 1000) - issuedAt;
    if (age > RECOVERY_TOKEN_TTL_SEC) {
      return res.json({ valid: false, error: 'token expired' });
    }
    const sigData  = `${agentName}:${newPubHex}:${issuedAt}`;
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
  res.json({ ok: true, service: 'ultra-server', version: '1.1.0', ts: Date.now() });
});

// ── Route: GET /tsk/keys ─────────────────────────────────────────────────────
// List all provisioned TSK keys with lifecycle metadata. No secrets returned.
app.get('/tsk/keys', async (_req, res) => {
  try {
    const keys = await provisioner.listKeys();
    return res.json({ ok: true, count: keys.length, keys });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: GET /tsk/keys/:clientId ───────────────────────────────────────────
// Get a single TSK key's lifecycle metadata.
app.get('/tsk/keys/:clientId', async (req, res) => {
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
app.patch('/tsk/keys/:clientId', async (req, res) => {
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
app.get('/bpc/pairs', async (_req, res) => {
  try {
    const pairs = await registry.listRedacted();
    return res.json({ ok: true, count: pairs.length, pairs });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Route: PATCH /bpc/pairs/:pairId ──────────────────────────────────────────
// Update BPC pair lifecycle: scope, expiresAt, maxRequests, name.
app.patch('/bpc/pairs/:pairId', async (req, res) => {
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
app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// ── Route: GET /status ────────────────────────────────────────────────────────
app.get('/status', async (req, res) => {
  try {
    const pairs = await registry.list();
    return res.json({
      ok:           true,
      version:      '1.2.0',
      pairs:        pairs.length,
      bindings:     identityBinding.size,
      sigWindowMs:  SIG_WINDOW_MS,
      nonceBackend: nonceBackendType,
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
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', event: 'server_start', port: PORT }));
  console.warn(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'WARN',
    event: 'production_warning',
    message: `Using MemoryPairStore, MemoryTumblerStore, and ${nonceBackendType === 'redis' ? 'RedisNonceStore (nonce dedup shared across instances)' : 'MemoryNonceBackend (set REDIS_URL for HA deployments)'}. Pair/TSK data will be lost on restart without PostgreSQL.`
  }));
});
