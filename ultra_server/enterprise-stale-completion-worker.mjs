import { createHash, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import pg from 'pg';

import {
  completeImportedPromotedTskCredential,
  StaleImportedPromotionError,
} from './independent-state.js';
import { createPromotedTskAuthorityCapability } from './promoted-tsk-authority.js';

const { Pool } = pg;

const configPath = process.argv[2];
if (!configPath) throw new Error('worker config path is required');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const pool = new Pool({ connectionString: config.databaseUrl, max: 1 });

async function authorityDigest() {
  const { rows } = await pool.query(
    `SELECT
       (SELECT coalesce(row_to_json(h)::text, 'null') FROM ultra_ha_import_head h WHERE cluster_id=$1) import_head,
       (SELECT coalesce(row_to_json(r)::text, 'null') FROM ultra_ha_tsk_reprovision r WHERE cluster_id=$1 AND pair_id=$2) reprovision,
       (SELECT coalesce(row_to_json(b)::text, 'null') FROM ultra_identity_bindings b
         WHERE pair_id=$2 AND agent_id=$3 AND canonical_id=$4
           AND agent_public_key_hex=$5) binding,
       (SELECT count(*)::text FROM ultra_tumbler_maps WHERE client_id=$6) target_map_count`,
    [config.completion.clusterId, config.completion.pairId,
      config.completion.agentId, config.completion.canonicalId,
      config.completion.agentPublicKeyHex, config.proof.targetClientId],
  );
  return createHash('sha256').update(JSON.stringify(rows[0])).digest('hex');
}

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
  const beforeDigest = await authorityDigest();
  let denied = false;
  let reason = '';
  try {
    await completeImportedPromotedTskCredential(pool, authority, config.completion);
  } catch (error) {
    reason = String(error?.message ?? error);
    if (!(error instanceof StaleImportedPromotionError) ||
        error.code !== 'STALE_IMPORTED_PROMOTION') {
      throw error;
    }
    denied = true;
  }
  if (!denied) throw new Error('stale completion unexpectedly succeeded after process restart');
  const afterDigest = await authorityDigest();
  if (afterDigest !== beforeDigest) {
    throw new Error('stale Enterprise completion changed authoritative state before rejection');
  }
  process.send?.({ kind: 'stale-completion-denied', pid: process.pid,
    denialCode: 'import-binding-rejected', noCommittedEffect: true,
    authorityDigest: afterDigest });
} finally {
  await pool.end();
}
