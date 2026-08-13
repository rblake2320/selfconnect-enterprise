import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign,
} from 'node:crypto';
import { chmod, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  agentIdFromPublicKey,
  signedAgentMaterial,
} from '../ultra_server/agent-auth.js';

const BASE = process.env.ULTRA_SERVER_URL ?? 'http://127.0.0.1:7777';
const LIFECYCLE_AUDIENCE = 'selfconnect-ultra-lifecycle-v1';

function statePath() {
  const index = process.argv.indexOf('--state');
  if (index < 0 || !process.argv[index + 1]) throw new Error('--state is required');
  return resolve(process.argv[index + 1]);
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

export function buildAgentHeaders(rawBody, identity, publicRaw, method, path) {
  const ts = String(Date.now() / 1000);
  const nonce = randomUUID();
  const sig = sign(
    null,
    signedAgentMaterial(rawBody, ts, nonce, method, path, LIFECYCLE_AUDIENCE),
    identity.privateKey,
  );
  return {
    'X-SC-Agent-Auth': JSON.stringify({
      agent_id: agentIdFromPublicKey(publicRaw),
      pubkey_hex: publicRaw.toString('hex'),
      ts,
      nonce,
      method,
      path,
      aud: LIFECYCLE_AUDIENCE,
      sig: sig.toString('base64'),
    }),
  };
}

async function issue(path) {
  const adminToken = process.env.ULTRA_ADMIN_TOKEN;
  if (!adminToken) throw new Error('ULTRA_ADMIN_TOKEN is required');
  const identity = generateKeyPairSync('ed25519');
  const publicDer = identity.publicKey.export({ format: 'der', type: 'spki' });
  const publicRaw = publicDer.subarray(-32);
  const body = {
    agentName: 'rotation-conformance-agent',
    agentId: agentIdFromPublicKey(publicRaw),
    newPubHex: publicRaw.toString('hex'),
    challengeHash: createHash('sha256').update(randomUUID()).digest('hex'),
  };
  const raw = Buffer.from(JSON.stringify(body));
  const response = await request('POST', '/confirm-recovery', body, {
    Authorization: `Bearer ${adminToken}`,
    ...buildAgentHeaders(raw, identity, publicRaw, 'POST', '/confirm-recovery'),
  });
  if (response.status !== 200 || !response.body.token) {
    throw new Error(`recovery token issuance failed with HTTP ${response.status}`);
  }
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify({ token: response.body.token }), {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx',
  });
  await rename(temporary, path);
  await chmod(path, 0o600).catch(() => {});
  console.log(JSON.stringify({ ok: true, operation: 'issue', tokenPersisted: true }));
}

async function adminDecision(token) {
  if (!token) return null;
  const response = await request('GET', '/status', undefined, {
    Authorization: `Bearer ${token}`,
  });
  return response.status === 200 && response.body.ok === true;
}

async function verify(path) {
  const state = JSON.parse(await readFile(path, 'utf8'));
  const expectedRecovery = process.env.ULTRA_EXPECT_RECOVERY_VALID === '1';
  const recovery = await request('POST', '/verify-recovery-token', { token: state.token });
  const recoveryValid = recovery.status === 200 && recovery.body.valid === true;
  if (recoveryValid !== expectedRecovery) {
    throw new Error(`recovery validity was ${recoveryValid}, expected ${expectedRecovery}`);
  }

  const accepted = await adminDecision(process.env.ULTRA_EXPECT_ADMIN_ACCEPT);
  if (accepted !== true) throw new Error('expected accepted admin token was rejected');
  const rejected = await adminDecision(process.env.ULTRA_EXPECT_ADMIN_REJECT);
  if (rejected !== false) throw new Error('expected retired admin token was accepted');

  if (process.argv.includes('--delete')) await rm(path, { force: true });
  console.log(JSON.stringify({
    ok: true,
    operation: 'verify',
    recoveryValid,
    expectedAdminAccepted: accepted,
    retiredAdminRejected: !rejected,
  }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const command = process.argv[2];
  const path = statePath();
  if (command === 'issue') await issue(path);
  else if (command === 'verify') await verify(path);
  else throw new Error('command must be issue or verify');
}
