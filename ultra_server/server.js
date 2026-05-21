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
  verifyBPCRequest,
} from '@bpc/server';

// ── TSK imports ───────────────────────────────────────────────────────────────
import {
  MemoryTumblerStore,
  TSKProvisioner,
} from '@tsk/server';

// ── Bridge import ─────────────────────────────────────────────────────────────
import { verifyUltraRequest } from '@tsk/bpc-bridge';

const PORT = parseInt(process.env.ULTRA_SERVER_PORT ?? '7777', 10);
const SIG_WINDOW_MS = 60_000;

// ── In-memory stores (replace with Redis/PostgreSQL for multi-machine mesh) ──
const pairStore    = new MemoryPairStore();
const nonceBackend = new MemoryNonceBackend();
const anomalyStore = new MemoryAnomalyStore();

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

    console.log(`[ultra-server] registered pair ${pairId} (${name})`);
    return res.json({ pairId });
  } catch (err) {
    console.error('[ultra-server] register-pair error:', err);
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
    console.log(`[ultra-server] recovery confirmed for agent '${agentName}' (pubkey: ${newPubHex.slice(0,16)}...)`);
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

// ── Route: GET /status ────────────────────────────────────────────────────────
app.get('/status', async (req, res) => {
  try {
    const pairs = await registry.list();
    return res.json({
      ok:       true,
      version:  '1.1.0',
      pairs:    pairs.length,
      bindings: identityBinding.size,
      sigWindowMs: SIG_WINDOW_MS,
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
  console.log(`[ultra-server] listening on http://127.0.0.1:${PORT}`);
  console.log('[ultra-server] BPC + TSK + ultra-bridge loaded. 7-layer verification ready.');
  console.log('[ultra-server] Layer 8 Active Defense: Shadow Mode ON, Tarpit ON');
});
