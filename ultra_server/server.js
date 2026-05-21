/**
 * ultra_server.js — BPC+TSK 7-layer identity verification sidecar.
 *
 * Listens on localhost:7777 (port configurable via ULTRA_SERVER_PORT env var).
 * Imports @bpc/server and @tsk/server packages directly — no custom crypto,
 * no modified BPC/TSK code.
 *
 * Routes:
 *   POST /register-pair     — register BPC pair (auto-approved for local mesh)
 *   POST /provision-tsk     — provision TSK client, return shared secret + payload
 *   POST /bind-identity     — bind BPC pairId to TSK clientId
 *   POST /verify            — full 7-layer verification via verifyUltraRequest()
 *   GET  /status            — health check + pair count + anomaly state
 *   GET  /pubkeys/:pairId   — return public key JWK for a registered pair
 *
 * Security: binds to 127.0.0.1 only. Not exposed to LAN/WAN.
 *
 * Version: 1.0.0  BPC+TSK integration
 */

import express from 'express';
import { randomBytes } from 'node:crypto';
import { PairRegistry, ServerNonceStore, AnomalyEngine, verifyBPCRequest } from '@bpc/server';
import { MemoryTumblerMapStore, TSKProvisioner, verifyTSKRequest } from '@tsk/server';
import { verifyUltraRequest } from '@tsk/bpc-bridge';

const PORT = parseInt(process.env.ULTRA_SERVER_PORT ?? '7777', 10);
const SIG_WINDOW_MS = 60_000;

// ── In-memory stores (replace with Redis/PostgreSQL for multi-machine mesh) ──

const registry    = new PairRegistry();
const nonceStore  = new ServerNonceStore({ windowMs: 120_000 });
const anomaly     = new AnomalyEngine();
const tskStore    = new MemoryTumblerMapStore();
const provisioner = new TSKProvisioner(tskStore);

// Identity binding: pairId → tskClientId
const identityBinding = new Map();

const bpcConfig = {
  sigWindowMs:    SIG_WINDOW_MS,
  lockoutCount:   10,
  enableShadowMode: true,
  enableTarpit:   true,
};

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: '64kb' }));

// ── Route: POST /register-pair ────────────────────────────────────────────────
app.post('/register-pair', async (req, res) => {
  try {
    const { name, pubJwk, secretHash, scope, fingerprint } = req.body;
    if (!name || !pubJwk || !secretHash) {
      return res.status(400).json({ error: 'missing name, pubJwk, or secretHash' });
    }
    const pairId = `pair_${randomBytes(8).toString('hex')}`;

    // Register directly (auto-approved for local machine mesh).
    // In production, this would trigger owner approval before status = 'active'.
    await registry.registerDirect({
      id: pairId,
      name,
      scope: scope ?? 'read-write',
      mode: 'development',
      secretHash,
      pubJwk,
      fingerprint: fingerprint ?? '',
      status: 'active',
      created: Date.now(),
      lastActive: null,
      requests: 0,
      failedSigs: 0,
    });

    console.log(`[ultra-server] registered pair ${pairId} for agent ${name}`);
    return res.json({ pairId });
  } catch (err) {
    console.error('[ultra-server] register-pair error:', err);
    return res.status(500).json({ error: String(err) });
  }
});

// ── Route: POST /provision-tsk ────────────────────────────────────────────────
app.post('/provision-tsk', async (req, res) => {
  try {
    const { requestorId } = req.body;
    if (!requestorId) {
      return res.status(400).json({ error: 'missing requestorId' });
    }

    // Provision a new TSK client. TSKProvisioner generates:
    // - A 256-bit hex shared secret
    // - A tumbler map with 3 segments (static + totp + hotp) by default
    // - The provision payload (segment configs without positional map)
    const result = await provisioner.provision({
      requestorId,
      segmentCount: 3,
      totpWindowSec: 60,
    });

    const clientId = result.clientId;
    const sharedSecret = result.sharedSecret;
    const provisionPayload = result.provisionPayload;

    console.log(`[ultra-server] provisioned TSK client ${clientId} for ${requestorId}`);
    return res.json({ clientId, sharedSecret, provisionPayload });
  } catch (err) {
    console.error('[ultra-server] provision-tsk error:', err);
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
    console.log(`[ultra-server] bound pairId=${pairId} → tskClientId=${tskClientId}`);
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

    // Build the request data shape expected by BPC + TSK middlewares
    const pairId    = reqHeaders['X-BPC-Pair-ID'] ?? null;
    const signedData = reqHeaders['X-BPC-Signed-Data'] ?? null;
    const signature  = reqHeaders['X-BPC-Signature'] ?? null;
    const version    = reqHeaders['X-BPC-Version'] ?? null;
    const tskClientId = reqHeaders['X-TSK-Client-ID'] ?? null;
    const tskKey     = reqHeaders['X-TSK-Key'] ?? null;
    const tskVersion = reqHeaders['X-TSK-Version'] ?? null;

    const reqData = {
      pairId,
      signedData,
      signature,
      method: 'INJECT',
      path: reqHeaders['X-Target-Path'] ?? '/terminal/unknown',
      version,
      bodyHash,
      // TSK fields
      clientId: tskClientId,
      key: tskKey,
      tskVersion,
    };

    // Resolve identity binding: BPC pairId → expected TSK clientId
    const binding = identityBinding.get(pairId);

    const result = await verifyUltraRequest(
      reqData,
      (r) => verifyBPCRequest(r, registry, nonceStore, anomaly, bpcConfig),
      {
        tskStore,
        identityBinding: {
          resolve: async (pid) => {
            const b = identityBinding.get(pid);
            return b ? b.tskClientId : null;
          },
        },
      }
    );

    return res.json(result);
  } catch (err) {
    console.error('[ultra-server] verify error:', err);
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

// ── Route: GET /status ────────────────────────────────────────────────────────
app.get('/status', async (req, res) => {
  try {
    const pairCount = await registry.count();
    return res.json({
      ok: true,
      version: '1.0.0',
      pairs: pairCount,
      bindings: identityBinding.size,
      sigWindowMs: SIG_WINDOW_MS,
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err) });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[ultra-server] listening on http://127.0.0.1:${PORT}`);
  console.log('[ultra-server] BPC + TSK + ultra-bridge loaded. 7-layer verification ready.');
});
