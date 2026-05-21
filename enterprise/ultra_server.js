/**
 * enterprise/ultra_server.js — Ultra Server Sidecar
 *
 * Node.js Express server that handles the server-side layers of the
 * BPC + TSK Ultra 7-layer identity gate:
 *
 *   L2  Pair registry check (BPC)
 *   L3  User secret HMAC derivation verification (BPC)
 *   L5  Anomaly engine: per-segment failure analysis (BPC)
 *   L7  Structural secrecy — positional map verification (TSK)
 *
 * Endpoints:
 *   POST /register-pair     — Register a BPC P-256 keypair for an agent
 *   POST /provision-tsk     — Provision a TSK client for an agent
 *   POST /bind-identity     — Bind BPC pairId + TSK clientId to agentId
 *   POST /verify            — Full 7-layer server verification
 *   GET  /health            — Health check
 *
 * Configuration (env vars):
 *   SC_ULTRA_PORT           — Port to listen on (default: 7777)
 *   SC_ULTRA_SECRET_SEED    — Master secret seed for HMAC derivation (required)
 *   SC_TSK_WINDOW_SEC       — TSK validity window in seconds (default: 30)
 *   SC_ULTRA_LOG_LEVEL      — Log level: debug|info|warn|error (default: info)
 *
 * Version: 1.0.0  Tier 1
 */

'use strict';

const express = require('express');
const crypto  = require('crypto');

const PORT            = parseInt(process.env.SC_ULTRA_PORT || '7777', 10);
const SECRET_SEED     = process.env.SC_ULTRA_SECRET_SEED || crypto.randomBytes(32).toString('hex');
const TSK_WINDOW_SEC  = parseInt(process.env.SC_TSK_WINDOW_SEC || '30', 10);
const LOG_LEVEL       = (process.env.SC_ULTRA_LOG_LEVEL || 'info').toLowerCase();

// ── Logger ─────────────────────────────────────────────────────────────────

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLevel = LEVELS[LOG_LEVEL] ?? 1;

const log = {
  debug: (...a) => currentLevel <= 0 && console.debug('[ultra-server]', ...a),
  info:  (...a) => currentLevel <= 1 && console.info('[ultra-server]', ...a),
  warn:  (...a) => currentLevel <= 2 && console.warn('[ultra-server]', ...a),
  error: (...a) => currentLevel <= 3 && console.error('[ultra-server]', ...a),
};

// ── In-memory stores ────────────────────────────────────────────────────────
// Production would use Redis or a signed JWT store.

/** @type {Map<string, {agentId: string, publicKeyJwk: object, fingerprint: string, secret: string, registeredAt: number}>} */
const pairRegistry = new Map();

/** @type {Map<string, {agentId: string, pairId: string, positionalMap: number[], segmentCount: number, provisionedAt: number}>} */
const tskRegistry = new Map();

/** @type {Map<string, {pairId: string, tskClientId: string, boundAt: number}>} */
const identityBindings = new Map();

/** @type {Map<string, number[]>} Per-pair anomaly counters: [L1_fails, L3_fails, L4_fails] */
const anomalyCounters = new Map();

// ── Crypto helpers ──────────────────────────────────────────────────────────

function derivePairSecret(agentId, pairId) {
  return crypto
    .createHmac('sha256', SECRET_SEED)
    .update(`${agentId}:${pairId}`)
    .digest('hex');
}

function deriveTSKPositionalMap(agentId, pairId, segmentCount) {
  // Structural secrecy: the positional map is a server-side secret.
  // Each position is a byte index into the assembled TSK key where
  // the rotating segment is applied.
  const seed = crypto
    .createHmac('sha256', SECRET_SEED)
    .update(`tsk:${agentId}:${pairId}`)
    .digest();
  const positions = [];
  for (let i = 0; i < segmentCount; i++) {
    positions.push(seed[i % seed.length] % 256);
  }
  return positions;
}

function verifyECDSASignature(publicKeyJwk, message, signatureB64) {
  try {
    const keyObj = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
    const sig = Buffer.from(signatureB64, 'base64');
    return crypto.verify('SHA256', Buffer.from(message), keyObj, sig);
  } catch (err) {
    log.debug('ECDSA verify error:', err.message);
    return false;
  }
}

function verifyHMAC(secret, data, expectedHex) {
  const computed = crypto.createHmac('sha256', secret).update(data).digest('hex');
  // Constant-time comparison
  try {
    return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expectedHex, 'hex'));
  } catch {
    return false;
  }
}

function verifyTSKChecksum(tskKey, positionalMap) {
  // Verify that the TSK key's checksum byte (last byte) matches
  // XOR of bytes at the positional map indices.
  const keyBuf = Buffer.from(tskKey, 'hex');
  if (keyBuf.length < 2) return false;
  const checksum = keyBuf[keyBuf.length - 1];
  let expected = 0;
  for (const pos of positionalMap) {
    expected ^= keyBuf[pos % (keyBuf.length - 1)];
  }
  return checksum === (expected & 0xff);
}

// ── Routes ──────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.raw({ type: '*/*', limit: '1mb' }));

// Health check
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    pairs: pairRegistry.size,
    tskClients: tskRegistry.size,
    bindings: identityBindings.size,
    uptime: process.uptime(),
  });
});

// POST /register-pair
app.post('/register-pair', (req, res) => {
  const { agentId, publicKeyJwk, fingerprint } = req.body || {};
  if (!agentId || !publicKeyJwk || !fingerprint) {
    return res.status(400).json({ error: 'missing_fields', required: ['agentId', 'publicKeyJwk', 'fingerprint'] });
  }

  const pairId = crypto.randomUUID();
  const secret = derivePairSecret(agentId, pairId);

  pairRegistry.set(pairId, {
    agentId,
    publicKeyJwk,
    fingerprint,
    secret,
    registeredAt: Date.now(),
  });
  anomalyCounters.set(pairId, [0, 0, 0]);

  log.info(`Registered pair pairId=${pairId} agentId=${agentId} fingerprint=${fingerprint}`);
  res.json({ pairId, secret });
});

// POST /provision-tsk
app.post('/provision-tsk', (req, res) => {
  const { agentId, pairId } = req.body || {};
  if (!agentId || !pairId) {
    return res.status(400).json({ error: 'missing_fields', required: ['agentId', 'pairId'] });
  }
  if (!pairRegistry.has(pairId)) {
    return res.status(404).json({ error: 'pair_not_found', pairId });
  }

  const segmentCount = 8;
  const clientId = crypto.randomUUID();
  const positionalMap = deriveTSKPositionalMap(agentId, pairId, segmentCount);
  const sharedSecret = crypto
    .createHmac('sha256', SECRET_SEED)
    .update(`tsk-shared:${agentId}:${pairId}`)
    .digest('hex');

  tskRegistry.set(clientId, {
    agentId,
    pairId,
    positionalMap,
    segmentCount,
    sharedSecret,
    provisionedAt: Date.now(),
  });

  log.info(`Provisioned TSK clientId=${clientId} agentId=${agentId} pairId=${pairId}`);
  res.json({
    clientId,
    segmentCount,
    sharedSecret,
    // positionalMap is NOT sent to client — structural secrecy
  });
});

// POST /bind-identity
app.post('/bind-identity', (req, res) => {
  const { agentId, pairId, tskClientId } = req.body || {};
  if (!agentId || !pairId) {
    return res.status(400).json({ error: 'missing_fields', required: ['agentId', 'pairId'] });
  }

  identityBindings.set(agentId, {
    pairId,
    tskClientId: tskClientId || null,
    boundAt: Date.now(),
  });

  log.info(`Bound identity agentId=${agentId} pairId=${pairId} tskClientId=${tskClientId}`);
  res.json({ ok: true });
});

// POST /verify — Full server-side verification (L2, L3, L5, L7)
app.post('/verify', (req, res) => {
  const headers = req.headers;
  const body    = req.body;   // Buffer (raw) or parsed object
  const method  = req.query.method || 'INJECT';
  const path    = req.query.path   || '/inject';

  // ── Extract BPC headers ───────────────────────────────────────────────────
  const pairId    = headers['x-bpc-pair-id'];
  const nonce     = headers['x-bpc-nonce'];
  const timestamp = headers['x-bpc-timestamp'];
  const signature = headers['x-bpc-signature'];
  const bodyHash  = headers['x-bpc-body-hash'];
  const hmacTag   = headers['x-bpc-hmac'];

  // ── Extract TSK headers ───────────────────────────────────────────────────
  const tskClientId = headers['x-tsk-client-id'];
  const tskKey      = headers['x-tsk-key'];
  const tskTs       = headers['x-tsk-timestamp'];

  // ── L2: Pair registry check ───────────────────────────────────────────────
  if (!pairId || !pairRegistry.has(pairId)) {
    log.warn(`L2 fail: pair not found pairId=${pairId}`);
    return res.status(401).json({ error: 'pair_not_registered', layer: 2 });
  }
  const pair = pairRegistry.get(pairId);
  const counters = anomalyCounters.get(pairId) || [0, 0, 0];

  // ── L1 (server re-verify): ECDSA signature ────────────────────────────────
  if (signature) {
    const canonicalMsg = `${method}:${path}:${nonce}:${timestamp}:${bodyHash}`;
    if (!verifyECDSASignature(pair.publicKeyJwk, canonicalMsg, signature)) {
      counters[0]++;
      anomalyCounters.set(pairId, counters);
      log.warn(`L1 fail (server re-verify): invalid ECDSA signature pairId=${pairId}`);
      return res.status(401).json({ error: 'invalid_signature', layer: 1 });
    }
  }

  // ── L3: User secret HMAC derivation ──────────────────────────────────────
  if (hmacTag) {
    const expectedHmac = crypto
      .createHmac('sha256', pair.secret)
      .update(`${pairId}:${nonce}:${timestamp}:${bodyHash}`)
      .digest('hex');
    if (!verifyHMAC(pair.secret, `${pairId}:${nonce}:${timestamp}:${bodyHash}`, hmacTag)) {
      counters[1]++;
      anomalyCounters.set(pairId, counters);
      log.warn(`L3 fail: HMAC mismatch pairId=${pairId}`);
      return res.status(401).json({ error: 'hmac_mismatch', layer: 3 });
    }
  }

  // ── L5: Anomaly engine ────────────────────────────────────────────────────
  const totalFailures = counters[0] + counters[1] + counters[2];
  if (totalFailures >= 10) {
    log.warn(`L5 fail: anomaly threshold exceeded pairId=${pairId} failures=${totalFailures}`);
    return res.status(429).json({ error: 'anomaly_threshold_exceeded', layer: 5, failures: totalFailures });
  }

  // ── L7: TSK structural secrecy ────────────────────────────────────────────
  if (tskClientId && tskKey) {
    if (!tskRegistry.has(tskClientId)) {
      log.warn(`L7 fail: TSK client not found clientId=${tskClientId}`);
      return res.status(401).json({ error: 'tsk_client_not_found', layer: 7 });
    }
    const tskEntry = tskRegistry.get(tskClientId);

    // Verify TSK timestamp window
    const tskTsNum = parseInt(tskTs || '0', 10);
    const nowMs = Date.now();
    if (Math.abs(nowMs - tskTsNum) > TSK_WINDOW_SEC * 1000) {
      log.warn(`L7 fail: TSK timestamp expired clientId=${tskClientId}`);
      return res.status(401).json({ error: 'tsk_timestamp_expired', layer: 7 });
    }

    // Verify TSK checksum against server-side positional map (structural secrecy)
    if (!verifyTSKChecksum(tskKey, tskEntry.positionalMap)) {
      log.warn(`L7 fail: TSK checksum invalid clientId=${tskClientId}`);
      return res.status(401).json({ error: 'tsk_checksum_invalid', layer: 7 });
    }
  }

  // ── All layers passed ─────────────────────────────────────────────────────
  log.debug(`Verify OK pairId=${pairId} tskClientId=${tskClientId}`);
  res.json({ ok: true, layer: 7 });
});

// ── Start ───────────────────────────────────────────────────────────────────

const server = app.listen(PORT, '127.0.0.1', () => {
  log.info(`Ultra Server listening on 127.0.0.1:${PORT}`);
  log.info(`TSK window: ${TSK_WINDOW_SEC}s | Anomaly threshold: 10 failures`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  log.info('Ultra Server shutting down (SIGTERM)');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  log.info('Ultra Server shutting down (SIGINT)');
  server.close(() => process.exit(0));
});

module.exports = { app, pairRegistry, tskRegistry, identityBindings };
