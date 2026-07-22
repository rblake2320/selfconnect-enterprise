import { createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import pg from 'pg';

import { completeImportedPromotedTskCredential } from './independent-state.js';
import { createPromotedTskAuthorityCapability } from './promoted-tsk-authority.js';

const { Pool } = pg;

const configPath = process.argv[2];
if (!configPath) throw new Error('worker config path is required');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const pool = new Pool({ connectionString: config.databaseUrl, max: 1 });

try {
  const guardKey = createPublicKey(config.guardPublicKey);
  const headKey = createPublicKey(config.headPublicKey);
  const authority = createPromotedTskAuthorityCapability({
    activationLease: config.activationLease,
    leaseResolver: { resolve: (keyId) =>
      keyId === config.activationLease.guardKeyId ? guardKey : null },
    headKeyResolver: { resolve: (keyId, algorithm) =>
      keyId === config.proof.head.keyId && algorithm === 'ed25519' ? headKey : null },
  });
  let denied = false;
  let reason = '';
  try {
    await completeImportedPromotedTskCredential(pool, authority, config.completion);
  } catch (error) {
    reason = String(error?.message ?? error);
    if (!/does not match the imported promotion|binding mismatch/i.test(reason)) {
      throw error;
    }
    denied = true;
  }
  if (!denied) throw new Error('stale completion unexpectedly succeeded after process restart');
  process.send?.({ kind: 'stale-completion-denied', pid: process.pid, reason });
} finally {
  await pool.end();
}
