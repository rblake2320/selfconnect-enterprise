/**
 * Ultra Server — Automated Test Suite
 * Covers: /health, /status, /tsk/keys, /bpc/pairs lifecycle API endpoints,
 *         /register-pair, /provision-tsk, /bind-identity, /verify
 *
 * Run: node server.test.mjs
 * Requires: Ultra Server running on http://127.0.0.1:7777
 */

import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';

const BASE = 'http://127.0.0.1:7777';
let passed = 0;
let failed = 0;

function assert(name, condition, detail = '') {
  if (condition) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.error(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
    failed++;
  }
}

async function req(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, opts);
  const json = await res.json().catch(() => ({}));
  return { status: res.status, body: json };
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeKeyPair() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function pubJwkFrom(keyPair) {
  return keyPair.publicKey.export({ format: 'jwk' });
}

function hashSecret(secret) {
  // mirrors BPC hashSecret: HKDF-SHA256 — for tests we use a simple HMAC approximation
  // that matches what the BPC client SDK produces via prepareRegistration
  // We call /register-pair with a pre-hashed value using the same logic as the SDK
  return createHmac('sha256', 'bpc-hmac-key-v1').update(secret).digest('base64url');
}

// ─── test groups ──────────────────────────────────────────────────────────────

async function testHealth() {
  console.log('\n[1] GET /health');
  const { status, body } = await req('GET', '/health');
  assert('returns 200', status === 200);
  assert('ok is true', body.ok === true);
  assert('service field present', typeof body.service === 'string');
  assert('version field present', typeof body.version === 'string');
  assert('ts field present', typeof body.ts === 'number');
}

async function testStatus() {
  console.log('\n[2] GET /status');
  const { status, body } = await req('GET', '/status');
  assert('returns 200', status === 200);
  assert('ok is true', body.ok === true);
  assert('pairs count is number', typeof body.pairs === 'number');
  assert('bindings count is number', typeof body.bindings === 'number');
  assert('version field present', typeof body.version === 'string');
}

async function testBpcPairsList() {
  console.log('\n[3] GET /bpc/pairs — empty list');
  const { status, body } = await req('GET', '/bpc/pairs');
  assert('returns 200', status === 200);
  assert('ok is true', body.ok === true);
  assert('pairs is array', Array.isArray(body.pairs));
  assert('count matches pairs.length', body.count === body.pairs.length);
}

async function testBpcPairsNotFound() {
  console.log('\n[4] PATCH /bpc/pairs/:pairId — not found');
  const { status, body } = await req('PATCH', '/bpc/pairs/nonexistent_pair_xyz', { name: 'test' });
  assert('returns 404', status === 404);
  assert('error is PAIR_NOT_FOUND', body.error === 'PAIR_NOT_FOUND');
}

async function testBpcPairsNoUpdates() {
  console.log('\n[5] PATCH /bpc/pairs/:pairId — no updates provided');
  const { status, body } = await req('PATCH', '/bpc/pairs/any_id', {});
  assert('returns 400', status === 400);
  assert('error is NO_UPDATES_PROVIDED', body.error === 'NO_UPDATES_PROVIDED');
}

async function testTskKeysList() {
  console.log('\n[6] GET /tsk/keys — list');
  const { status, body } = await req('GET', '/tsk/keys');
  assert('returns 200', status === 200);
  assert('ok is true', body.ok === true);
  assert('keys is array', Array.isArray(body.keys));
  assert('count matches keys.length', body.count === body.keys.length);
}

async function testTskKeyNotFound() {
  console.log('\n[7] GET /tsk/keys/:clientId — not found');
  const { status, body } = await req('GET', '/tsk/keys/tsk_nonexistent_xyz');
  assert('returns 404', status === 404);
  assert('error is KEY_NOT_FOUND', body.error === 'KEY_NOT_FOUND');
}

async function testTskKeyPatchNotFound() {
  console.log('\n[8] PATCH /tsk/keys/:clientId — not found');
  const { status, body } = await req('PATCH', '/tsk/keys/tsk_nonexistent_xyz', { label: 'test' });
  assert('returns 404', status === 404);
  assert('error is KEY_NOT_FOUND', body.error === 'KEY_NOT_FOUND');
}

async function testTskKeyPatchNoUpdates() {
  console.log('\n[9] PATCH /tsk/keys/:clientId — no updates');
  const { status, body } = await req('PATCH', '/tsk/keys/any_id', {});
  assert('returns 400', status === 400);
  assert('error is NO_UPDATES_PROVIDED', body.error === 'NO_UPDATES_PROVIDED');
}

async function testTskKeyPatchInvalidStatus() {
  console.log('\n[10] PATCH /tsk/keys/:clientId — invalid status');
  const { status, body } = await req('PATCH', '/tsk/keys/any_id', { status: 'banana' });
  assert('returns 400', status === 400);
  assert('error is INVALID_STATUS', body.error === 'INVALID_STATUS');
}

async function testProvisionTsk() {
  console.log('\n[11] POST /provision-tsk — valid');
  const { status, body } = await req('POST', '/provision-tsk', {
    requestorId: 'test-agent-001',
    keyLength: 64,
    label: 'test-key',
  });
  assert('returns 200', status === 200);
  assert('clientId returned', typeof body.clientId === 'string' && body.clientId.startsWith('tsk_'));
  assert('sharedSecret returned', typeof body.sharedSecret === 'string' && body.sharedSecret.length > 0);
  assert('provisionPayload returned', typeof body.provisionPayload === 'object');
  return body.clientId;
}

async function testTskKeyLifecycle(clientId) {
  console.log('\n[12] GET /tsk/keys/:clientId — after provision');
  const { status, body } = await req('GET', `/tsk/keys/${clientId}`);
  assert('returns 200', status === 200);
  assert('ok is true', body.ok === true);
  assert('key.clientId matches', body.key?.clientId === clientId);
  assert('key.status is active', body.key?.status === 'active');
  assert('no secret in response', body.key?.sharedSecret === undefined);

  console.log('\n[13] PATCH /tsk/keys/:clientId — update label');
  const patch1 = await req('PATCH', `/tsk/keys/${clientId}`, { label: 'updated-label' });
  assert('returns 200', patch1.status === 200);
  assert('ok is true', patch1.body.ok === true);
  assert('label updated', patch1.body.key?.label === 'updated-label');

  console.log('\n[14] PATCH /tsk/keys/:clientId — set maxRequests');
  const patch2 = await req('PATCH', `/tsk/keys/${clientId}`, { maxRequests: 100 });
  assert('returns 200', patch2.status === 200);
  assert('maxRequests updated', patch2.body.key?.maxRequests === 100);

  console.log('\n[15] PATCH /tsk/keys/:clientId — revoke');
  const patch3 = await req('PATCH', `/tsk/keys/${clientId}`, { status: 'revoked' });
  assert('returns 200', patch3.status === 200);
  assert('status is revoked', patch3.body.key?.status === 'revoked');

  console.log('\n[16] GET /tsk/keys — revoked key appears in list');
  const list = await req('GET', '/tsk/keys');
  const found = list.body.keys?.find(k => k.clientId === clientId);
  assert('revoked key in list', found !== undefined);
  assert('revoked key has status=revoked', found?.status === 'revoked');
}

async function testRegisterPair() {
  console.log('\n[17] POST /register-pair — valid');
  const kp = makeKeyPair();
  const pubJwk = pubJwkFrom(kp);
  const secret = randomBytes(32).toString('base64url');
  const secretHash = hashSecret(secret);
  const pairId = `bpc_test_${randomBytes(8).toString('hex')}`;

  const { status, body } = await req('POST', '/register-pair', {
    name: 'test-pair',
    secretHash,
    pubJwk,
    scope: 'read',
  });
  assert('returns 200', status === 200);
  assert('pairId returned', typeof body.pairId === 'string' && body.pairId.length > 0);
  return body.pairId;
}

async function testBpcPairLifecycle(pairId) {
  console.log('\n[18] GET /bpc/pairs — registered pair appears');
  const list = await req('GET', '/bpc/pairs');
  const found = list.body.pairs?.find(p => p.id === pairId);
  assert('pair in list', found !== undefined);
  assert('no secretHash in listing', found?.secretHash === undefined);
  assert('no pubJwk in listing', found?.pubJwk === undefined);

  console.log('\n[19] PATCH /bpc/pairs/:pairId — update name');
  const patch = await req('PATCH', `/bpc/pairs/${pairId}`, { name: 'updated-name' });
  assert('returns 200', patch.status === 200);
  assert('ok is true', patch.body.ok === true);
}

async function testVerifyMissingFields() {
  console.log('\n[20] POST /verify — missing headers');
  const { status, body } = await req('POST', '/verify', { bodyHash: 'abc' });
  assert('returns 400', status === 400);
  assert('error about missing fields', typeof body.error === 'string');
}

async function testBindIdentity() {
  console.log('\n[21] POST /bind-identity — valid');
  const { status, body } = await req('POST', '/bind-identity', {
    pairId: 'test_pair_bind',
    tskClientId: 'tsk_test_bind',
    agentId: 'agent-001',
  });
  assert('returns 200', status === 200);
  assert('ok is true', body.ok === true);
}

async function testBindIdentityMissingFields() {
  console.log('\n[22] POST /bind-identity — missing fields');
  const { status, body } = await req('POST', '/bind-identity', { pairId: 'only_pair' });
  assert('returns 400', status === 400);
  assert('error about missing fields', typeof body.error === 'string');
}

async function testPubkeysNotFound() {
  console.log('\n[23] GET /pubkeys/:pairId — not found');
  const { status, body } = await req('GET', '/pubkeys/nonexistent_pair_xyz');
  assert('returns 404', status === 404);
  assert('error present', typeof body.error === 'string');
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('=== Ultra Server Test Suite ===');
  console.log(`Target: ${BASE}\n`);

  // Verify server is up
  try {
    await fetch(`${BASE}/health`);
  } catch {
    console.error('ERROR: Ultra Server is not running. Start it first.');
    process.exit(1);
  }

  await testHealth();
  await testStatus();
  await testBpcPairsList();
  await testBpcPairsNotFound();
  await testBpcPairsNoUpdates();
  await testTskKeysList();
  await testTskKeyNotFound();
  await testTskKeyPatchNotFound();
  await testTskKeyPatchNoUpdates();
  await testTskKeyPatchInvalidStatus();

  const clientId = await testProvisionTsk();
  if (clientId) await testTskKeyLifecycle(clientId);

  const pairId = await testRegisterPair();
  if (pairId) await testBpcPairLifecycle(pairId);

  await testVerifyMissingFields();
  await testBindIdentity();
  await testBindIdentityMissingFields();
  await testPubkeysNotFound();

  console.log(`\n${'='.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\nFAIL — ${failed} test(s) failed`);
    process.exit(1);
  } else {
    console.log('\nPASS — all tests green');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Unhandled error:', err);
  process.exit(1);
});
