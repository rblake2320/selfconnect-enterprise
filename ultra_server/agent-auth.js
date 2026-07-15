import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const AGENT_ID_PATTERN = /^SC-[0-9A-F]{8}$/;
const NONCE_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function reject(res, status, error) {
  return res.status(status).json({ ok: false, error });
}

export function agentIdFromPublicKey(publicKey) {
  return `SC-${createHash('sha256').update(publicKey).digest('hex').slice(0, 8).toUpperCase()}`;
}

export function signedAgentMaterial(rawBody, timestamp, nonce) {
  return Buffer.concat([
    createHash('sha256').update(rawBody).digest(),
    Buffer.from(timestamp, 'utf8'),
    Buffer.from(nonce, 'utf8'),
  ]);
}

export function createAgentAuthMiddleware({ nonceStore, windowMs = 30_000 }) {
  if (!nonceStore || typeof nonceStore.checkAndConsume !== 'function') {
    throw new TypeError('nonceStore.checkAndConsume is required');
  }

  return async function requireAgentAuth(req, res, next) {
    try {
      const rawHeader = req.get('X-SC-Agent-Auth');
      if (!rawHeader || rawHeader.length > 4096) {
        return reject(res, 401, 'AGENT_AUTH_REQUIRED');
      }

      let auth;
      try {
        auth = JSON.parse(rawHeader);
      } catch {
        return reject(res, 401, 'AGENT_AUTH_MALFORMED');
      }
      if (!auth || typeof auth !== 'object' || Array.isArray(auth)) {
        return reject(res, 401, 'AGENT_AUTH_MALFORMED');
      }

      const { agent_id: agentId, pubkey_hex: pubHex, ts, nonce, sig } = auth;
      if (
        typeof agentId !== 'string' || !AGENT_ID_PATTERN.test(agentId) ||
        typeof pubHex !== 'string' || !/^[0-9a-f]{64}$/i.test(pubHex) ||
        typeof ts !== 'string' || ts.length > 32 ||
        typeof nonce !== 'string' || !NONCE_PATTERN.test(nonce) ||
        typeof sig !== 'string' || sig.length > 128
      ) {
        return reject(res, 401, 'AGENT_AUTH_MALFORMED');
      }

      const timestampMs = Number(ts) * 1000;
      if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > windowMs) {
        return reject(res, 401, 'AGENT_AUTH_EXPIRED');
      }

      const publicKey = Buffer.from(pubHex, 'hex');
      if (agentIdFromPublicKey(publicKey) !== agentId) {
        return reject(res, 401, 'AGENT_ID_MISMATCH');
      }

      let signature;
      try {
        signature = Buffer.from(sig, 'base64');
      } catch {
        return reject(res, 401, 'AGENT_AUTH_MALFORMED');
      }
      if (signature.length !== 64) {
        return reject(res, 401, 'AGENT_AUTH_MALFORMED');
      }

      const rawBody = Buffer.isBuffer(req.rawBody) ? req.rawBody : Buffer.alloc(0);
      const spki = Buffer.concat([ED25519_SPKI_PREFIX, publicKey]);
      const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      const material = signedAgentMaterial(rawBody, ts, nonce);
      if (!verifySignature(null, material, key, signature)) {
        return reject(res, 401, 'AGENT_AUTH_INVALID_SIGNATURE');
      }

      if (await nonceStore.checkAndConsume(`agent-lifecycle:${nonce}`)) {
        return reject(res, 409, 'AGENT_AUTH_REPLAY');
      }

      req.scAgent = { agentId, publicKeyHex: pubHex.toLowerCase() };
      return next();
    } catch (error) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'ERROR',
        event: 'agent_auth_error',
        error: String(error),
      }));
      return reject(res, 503, 'AGENT_AUTH_UNAVAILABLE');
    }
  };
}

export function createAdminAuthMiddleware(adminToken) {
  return function requireAdminAuth(req, res, next) {
    if (!adminToken) return reject(res, 503, 'ADMIN_AUTH_UNCONFIGURED');
    const header = req.get('Authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const expected = Buffer.from(adminToken, 'utf8');
    const actual = Buffer.from(token, 'utf8');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return reject(res, 401, 'ADMIN_AUTH_REQUIRED');
    }
    return next();
  };
}
