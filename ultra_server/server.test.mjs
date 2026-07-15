/** Live HTTP contract test. Python test_e2e_ultra_gate.py owns full BPC+TSK verification. */
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { Pool } from 'pg';

import { agentIdFromPublicKey, signedAgentMaterial } from './agent-auth.js';

const BASE = process.env.ULTRA_SERVER_URL ?? 'http://127.0.0.1:7777';
const ADMIN_TOKEN = process.env.ULTRA_ADMIN_TOKEN ?? '';
if (!ADMIN_TOKEN) throw new Error('ULTRA_ADMIN_TOKEN is required');
const hasDatabase = Boolean(process.env.DATABASE_URL);

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

let checkCount = 0;
function assert(condition, message) {
  checkCount += 1;
  if (!condition) throw new Error(message);
}

function p256Jwk() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
}

async function signedPost(path, body, idempotencyKey, extraHeaders = {}) {
  const raw = Buffer.from(JSON.stringify(body));
  return request('POST', path, body, {
    ...agentHeaders(raw),
    ...(idempotencyKey ? { 'X-Idempotency-Key': idempotencyKey } : {}),
    ...extraHeaders,
  });
}

async function simulateCrashAfterSideEffect(idempotencyKey) {
  if (!hasDatabase) return;
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const result = await pool.query(
      `UPDATE ultra_idempotency
       SET state='processing', response=NULL, updated_at=NOW()
       WHERE idempotency_key=$1 AND state='complete'`,
      [idempotencyKey],
    );
    assert(result.rowCount === 1, `could not prepare crash-recovery fixture ${idempotencyKey}`);
  } finally {
    await pool.end();
  }
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
await simulateCrashAfterSideEffect(registerKey);
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
await simulateCrashAfterSideEffect(provisionKey);
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
await simulateCrashAfterSideEffect(bindKey);
const bindingRetry = await signedPost('/bind-identity', bindBody, bindKey);
assert(bindingRetry.status === 200 && bindingRetry.body.ok, 'identity binding crash recovery failed');

const resumed = await signedPost('/resume-identity', {
  pairId: pair.body.pairId,
  agentId,
}, undefined, admin);
assert(
  resumed.status === 200 && resumed.body.clientId === tsk.body.clientId,
  'bound TSK state did not resume',
);

const rotationKey = randomUUID();
const rotationPrepareBody = {
  pairId: pair.body.pairId,
  oldClientId: tsk.body.clientId,
  agentId,
  idempotencyKey: rotationKey,
};
const prepared = await signedPost(
  '/rotate-tsk/prepare', rotationPrepareBody, rotationKey, admin,
);
assert(
  prepared.status === 200 && prepared.body.clientId &&
  prepared.body.clientId !== tsk.body.clientId,
  'TSK rotation prepare failed',
);
await simulateCrashAfterSideEffect(rotationKey);
const preparedRetry = await signedPost(
  '/rotate-tsk/prepare', rotationPrepareBody, rotationKey, admin,
);
assert(
  preparedRetry.body.clientId === prepared.body.clientId,
  'TSK rotation prepare was not idempotent',
);
const rotationCommitBody = {
  pairId: pair.body.pairId,
  oldClientId: tsk.body.clientId,
  newClientId: prepared.body.clientId,
  agentId,
};
const committed = await signedPost('/rotate-tsk/commit', rotationCommitBody, undefined, admin);
assert(committed.status === 200 && committed.body.ok, 'TSK rotation commit failed');
const committedRetry = await signedPost('/rotate-tsk/commit', rotationCommitBody, undefined, admin);
assert(
  committedRetry.status === 200 && committedRetry.body.idempotent === true,
  'TSK rotation commit was not retry safe',
);
const resumedAfterRotation = await signedPost('/resume-identity', {
  pairId: pair.body.pairId,
  agentId,
}, undefined, admin);
assert(
  resumedAfterRotation.status === 200 &&
  resumedAfterRotation.body.clientId === prepared.body.clientId,
  'rotated TSK state did not resume',
);

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
const challengeTamper = await request('POST', '/verify-recovery-token', {
  token: { ...recovery.body.token, challengeHash: '00'.repeat(32) },
});
assert(
  challengeTamper.status === 200 && challengeTamper.body.valid === false,
  'recovery token accepted a tampered challenge',
);

if (process.env.ULTRA_ADMIN_TOKEN_PREVIOUS) {
  const previousAdmin = {
    Authorization: `Bearer ${process.env.ULTRA_ADMIN_TOKEN_PREVIOUS}`,
  };
  const previousStatus = await request('GET', '/status', undefined, previousAdmin);
  assert(previousStatus.status === 200, 'previous admin token not accepted during overlap');
}

const pairs = await request('GET', '/bpc/pairs', undefined, admin);
const keys = await request('GET', '/tsk/keys', undefined, admin);
assert(pairs.status === 200 && pairs.body.pairs.some((item) => item.id === pair.body.pairId), 'pair absent');
assert(keys.status === 200 && keys.body.keys.some((item) => item.clientId === tsk.body.clientId), 'TSK key absent');
assert(
  pairs.body.pairs.filter((item) => item.name === agentId && item.status === 'active').length === 1,
  'idempotency recovery duplicated the active pair',
);
assert(
  keys.body.keys.filter((item) => item.label === `agent:${agentId}`).length === 1,
  'idempotency recovery duplicated the initial TSK key',
);
assert(
  keys.body.keys.filter(
    (item) => item.label === `rotation:${agentId}:${pair.body.pairId}:${tsk.body.clientId}`,
  ).length === 1,
  'idempotency recovery duplicated the rotation candidate',
);
assert(
  keys.body.keys.some((item) => item.clientId === tsk.body.clientId && item.status === 'revoked'),
  'old TSK key was not revoked after rotation',
);
assert(
  keys.body.keys.some((item) => item.clientId === prepared.body.clientId && item.status === 'active'),
  'new TSK key was not active after rotation',
);

if (hasDatabase) {
  await simulateCrashAfterSideEffect(provisionKey);
  const inactiveRecovery = await signedPost('/provision-tsk', provisionBody, provisionKey);
  assert(
    inactiveRecovery.status === 409 && inactiveRecovery.body.error === 'TSK_RECOVERY_STATE_NOT_ACTIVE',
    'processing recovery replaced or accepted a revoked TSK resource',
  );
  const keysAfterRefusal = await request('GET', '/tsk/keys', undefined, admin);
  assert(
    keysAfterRefusal.body.keys.filter((item) => item.label === `agent:${agentId}`).length === 1,
    'inactive recovery created a replacement TSK resource',
  );
}

console.log(JSON.stringify({
  ok: true,
  agentId,
  pairId: pair.body.pairId,
  tskClientId: prepared.body.clientId,
  checks: checkCount,
}));
