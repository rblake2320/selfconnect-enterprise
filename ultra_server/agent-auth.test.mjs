import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';

import {
  agentIdFromPublicKey,
  canonicalAgentIdFromPublicKey,
  createAdminAuthMiddleware,
  createAgentAuthMiddleware,
  signedAgentMaterial,
} from './agent-auth.js';

function signedRequest(body = { action: 'register' }, overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const rawBody = Buffer.from(JSON.stringify(body));
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const publicRaw = publicDer.subarray(-32);
  const timestamp = String(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const signature = sign(null, signedAgentMaterial(rawBody, timestamp, nonce), privateKey);
  const auth = {
    agent_id: agentIdFromPublicKey(publicRaw),
    pubkey_hex: publicRaw.toString('hex'),
    ts: timestamp,
    nonce,
    sig: signature.toString('base64'),
    ...overrides,
  };
  return { rawBody, auth };
}

function responseCapture() {
  return {
    statusCode: 200,
    payload: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
  };
}

function requestCapture(rawBody, auth, authorization = '') {
  return {
    rawBody,
    get(name) {
      if (name.toLowerCase() === 'x-sc-agent-auth') return JSON.stringify(auth);
      if (name.toLowerCase() === 'authorization') return authorization;
      return undefined;
    },
  };
}

function nonceStore() {
  const seen = new Set();
  return {
    async checkAndConsume(nonce) {
      if (seen.has(nonce)) return true;
      seen.add(nonce);
      return false;
    },
  };
}

test('agent auth accepts a valid body-bound Ed25519 proof once', async () => {
  const signed = signedRequest();
  const req = requestCapture(signed.rawBody, signed.auth);
  const res = responseCapture();
  let called = false;
  await createAgentAuthMiddleware({ nonceStore: nonceStore() })(req, res, () => { called = true; });
  assert.equal(called, true);
  assert.equal(req.scAgent.agentId, signed.auth.agent_id);
  assert.equal(
    req.scAgent.canonicalId,
    canonicalAgentIdFromPublicKey(Buffer.from(signed.auth.pubkey_hex, 'hex')),
  );
});

test('agent auth rejects replay', async () => {
  const store = nonceStore();
  const middleware = createAgentAuthMiddleware({ nonceStore: store });
  const signed = signedRequest();
  await middleware(requestCapture(signed.rawBody, signed.auth), responseCapture(), () => {});
  const res = responseCapture();
  await middleware(requestCapture(signed.rawBody, signed.auth), res, () => assert.fail('replay accepted'));
  assert.equal(res.statusCode, 409);
  assert.equal(res.payload.error, 'AGENT_AUTH_REPLAY');
});

test('agent auth rejects body tampering', async () => {
  const signed = signedRequest();
  const res = responseCapture();
  await createAgentAuthMiddleware({ nonceStore: nonceStore() })(
    requestCapture(Buffer.from('{"action":"different"}'), signed.auth),
    res,
    () => assert.fail('tampered body accepted'),
  );
  assert.equal(res.statusCode, 401);
  assert.equal(res.payload.error, 'AGENT_AUTH_INVALID_SIGNATURE');
});

test('agent auth rejects stale proof and forged agent id', async () => {
  const stale = signedRequest({}, { ts: String((Date.now() - 60_000) / 1000) });
  const staleRes = responseCapture();
  await createAgentAuthMiddleware({ nonceStore: nonceStore() })(
    requestCapture(stale.rawBody, stale.auth), staleRes, () => assert.fail('stale proof accepted'),
  );
  assert.equal(staleRes.payload.error, 'AGENT_AUTH_EXPIRED');

  const forged = signedRequest({}, { agent_id: 'SC-00000000' });
  const forgedRes = responseCapture();
  await createAgentAuthMiddleware({ nonceStore: nonceStore() })(
    requestCapture(forged.rawBody, forged.auth), forgedRes, () => assert.fail('forged id accepted'),
  );
  assert.equal(forgedRes.payload.error, 'AGENT_ID_MISMATCH');
});

test('agent id derivation matches the documented SHA-256 fingerprint', () => {
  const raw = Buffer.alloc(32, 0xab);
  const expected = `SC-${createHash('sha256').update(raw).digest('hex').slice(0, 8).toUpperCase()}`;
  assert.equal(agentIdFromPublicKey(raw), expected);
});

test('colliding display ids retain distinct canonical authorization principals', () => {
  const left = Buffer.from('67bc101981dfd63eaf5af3c05448a9f8e40902ffe4d6c1d3813fad97f99c8b1f', 'hex');
  const right = Buffer.from('3a1a9a9ab515f2baa029ee9df63f93cb65b97a446fb86b13da8824433bbb874b', 'hex');
  assert.equal(agentIdFromPublicKey(left), agentIdFromPublicKey(right));
  assert.notEqual(canonicalAgentIdFromPublicKey(left), canonicalAgentIdFromPublicKey(right));
});

test('admin auth fails closed and accepts only the exact bearer', () => {
  const unconfigured = responseCapture();
  createAdminAuthMiddleware(null)(requestCapture(null, null), unconfigured, () => assert.fail());
  assert.equal(unconfigured.statusCode, 503);

  const wrong = responseCapture();
  createAdminAuthMiddleware('correct-token')(
    requestCapture(null, null, 'Bearer wrong-token'), wrong, () => assert.fail(),
  );
  assert.equal(wrong.statusCode, 401);

  let called = false;
  createAdminAuthMiddleware('correct-token')(
    requestCapture(null, null, 'Bearer correct-token'), responseCapture(), () => { called = true; },
  );
  assert.equal(called, true);
});

test('admin auth supports a bounded current/previous rotation overlap', () => {
  const middleware = createAdminAuthMiddleware(['new-current-token', 'old-previous-token']);
  for (const token of ['new-current-token', 'old-previous-token']) {
    let called = false;
    middleware(
      requestCapture(null, null, `Bearer ${token}`),
      responseCapture(),
      () => { called = true; },
    );
    assert.equal(called, true, `${token} was not accepted during overlap`);
  }

  const retired = responseCapture();
  createAdminAuthMiddleware('new-current-token')(
    requestCapture(null, null, 'Bearer old-previous-token'),
    retired,
    () => assert.fail('retired token was accepted'),
  );
  assert.equal(retired.statusCode, 401);
});
