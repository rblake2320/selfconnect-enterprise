/** Live HTTP contract test. Python test_e2e_ultra_gate.py owns full BPC+TSK verification. */
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';

import { agentIdFromPublicKey, signedAgentMaterial } from './agent-auth.js';

const BASE = process.env.ULTRA_SERVER_URL ?? 'http://127.0.0.1:7777';
const ADMIN_TOKEN = process.env.ULTRA_ADMIN_TOKEN ?? '';
if (!ADMIN_TOKEN) throw new Error('ULTRA_ADMIN_TOKEN is required');

const identity = generateKeyPairSync('ed25519');
const publicDer = identity.publicKey.export({ format: 'der', type: 'spki' });
const publicRaw = publicDer.subarray(-32);
const agentId = agentIdFromPublicKey(publicRaw);

function agentHeaders(rawBody) {
  const ts = String(Date.now() / 1000);
  const nonce = randomUUID();
  const sig = sign(null, signedAgentMaterial(rawBody, ts, nonce), identity.privateKey);
  return {
    'X-SC-Agent-Auth': JSON.stringify({
      agent_id: agentId,
      pubkey_hex: publicRaw.toString('hex'),
      ts,
      nonce,
      sig: sig.toString('base64'),
    }),
  };
}

async function request(method, path, body, headers = {}) {
  const rawBody = body === undefined ? undefined : JSON.stringify(body);
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    ...(rawBody === undefined ? {} : { body: rawBody }),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function p256Jwk() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
}

async function signedPost(path, body, idempotencyKey) {
  const raw = Buffer.from(JSON.stringify(body));
  return request('POST', path, body, {
    ...agentHeaders(raw),
    ...(idempotencyKey ? { 'X-Idempotency-Key': idempotencyKey } : {}),
  });
}

const health = await request('GET', '/health');
assert(health.status === 200 && health.body.ok, 'health failed');

const unauthStatus = await request('GET', '/status');
assert(unauthStatus.status === 401, 'status disclosed without admin authorization');
const admin = { Authorization: `Bearer ${ADMIN_TOKEN}` };
const status = await request('GET', '/status', undefined, admin);
assert(status.status === 200 && status.body.ok, 'authorized status failed');

const registerKey = randomUUID();
const registerBody = {
  name: agentId,
  pubJwk: p256Jwk(),
  secretHash: createHash('sha256').update(randomBytes(32)).digest('base64url'),
  scope: 'read-write',
  idempotencyKey: registerKey,
};
if (status.body.runtimeMode === 'production') {
  const enrollmentWithoutAdmin = await signedPost('/register-pair', registerBody, registerKey);
  assert(enrollmentWithoutAdmin.status === 401, 'production enrollment accepted without operator authorization');
}
const registerRaw = Buffer.from(JSON.stringify(registerBody));
const pair = await request('POST', '/register-pair', registerBody, {
  ...agentHeaders(registerRaw),
  'X-Idempotency-Key': registerKey,
  ...admin,
});
assert(pair.status === 200 && pair.body.pairId, 'signed pair registration failed');
const pairRetry = await request('POST', '/register-pair', registerBody, {
  ...agentHeaders(registerRaw),
  'X-Idempotency-Key': registerKey,
  ...admin,
});
assert(pairRetry.body.pairId === pair.body.pairId, 'pair registration was not idempotent');

const provisionKey = randomUUID();
const provisionBody = { requestorId: agentId, idempotencyKey: provisionKey };
const tsk = await signedPost('/provision-tsk', provisionBody, provisionKey);
assert(tsk.status === 200 && tsk.body.clientId && tsk.body.sharedSecret, 'TSK provisioning failed');
assert(Array.isArray(tsk.body.provisionPayload?.clientSegments), 'reduced TSK provisioning view missing');
assert(!('sharedSecret' in tsk.body.provisionPayload), 'shared secret leaked into reusable provisioning payload');
assert(
  tsk.body.provisionPayload.clientSegments.every((segment) => !('position' in segment)),
  'literal tumbler positions disclosed in provisioning payload',
);
assert(
  tsk.body.provisionPayload.clientSegments.every(
    (segment) => Number.isInteger(segment.segmentLength) && segment.segmentLength > 0,
  ),
  'client-required segment lengths missing from provisioning payload',
);
const tskRetry = await signedPost('/provision-tsk', provisionBody, provisionKey);
assert(tskRetry.body.clientId === tsk.body.clientId, 'TSK provisioning was not idempotent');

const bindKey = randomUUID();
const bindBody = {
  pairId: pair.body.pairId,
  tskClientId: tsk.body.clientId,
  agentId,
  idempotencyKey: bindKey,
};
const binding = await signedPost('/bind-identity', bindBody, bindKey);
assert(binding.status === 200 && binding.body.ok, 'identity binding failed');

const recoveryBody = {
  agentName: 'live-contract-agent',
  agentId,
  newPubHex: publicRaw.toString('hex'),
  challengeHash: createHash('sha256').update('live-contract').digest('hex'),
};
const recoveryWithoutAdmin = await signedPost('/confirm-recovery', recoveryBody);
assert(recoveryWithoutAdmin.status === 401, 'recovery accepted without operator authorization');
const recoveryRaw = Buffer.from(JSON.stringify(recoveryBody));
const recovery = await request('POST', '/confirm-recovery', recoveryBody, {
  ...agentHeaders(recoveryRaw),
  ...admin,
});
assert(recovery.status === 200 && recovery.body.token, 'authorized recovery token issuance failed');
const verifiedRecovery = await request('POST', '/verify-recovery-token', { token: recovery.body.token });
assert(verifiedRecovery.status === 200 && verifiedRecovery.body.valid, 'recovery token did not verify');

const pairs = await request('GET', '/bpc/pairs', undefined, admin);
const keys = await request('GET', '/tsk/keys', undefined, admin);
assert(pairs.status === 200 && pairs.body.pairs.some((item) => item.id === pair.body.pairId), 'pair absent');
assert(keys.status === 200 && keys.body.keys.some((item) => item.clientId === tsk.body.clientId), 'TSK key absent');

console.log(JSON.stringify({
  ok: true,
  agentId,
  pairId: pair.body.pairId,
  tskClientId: tsk.body.clientId,
  checks: 14,
}));
