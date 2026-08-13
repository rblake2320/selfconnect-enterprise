import { createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import pg from 'pg';

import { importIndependentState } from './independent-state.js';

const { Pool } = pg;
const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
const pool = new Pool({ connectionString: config.postgresUrl, max: 1 });
let staged = false;
const faultPool = {
  async connect() {
    const client = await pool.connect();
    return {
      async query(sql, params) {
        const result = await client.query(sql, params);
        if (!staged && /INSERT INTO ultra_ha_import_head/i.test(String(sql))) {
          staged = true;
          process.send?.({ kind: 'enterprise-import-effects-staged' });
          await new Promise(() => {});
        }
        return result;
      },
      release() { client.release(); },
    };
  },
};

const sourcePublicKey = createPublicKey(config.publicKeys.source);
const guardPublicKey = createPublicKey(config.publicKeys.guard);
const bpcKey = createPublicKey(config.publicKeys.bpc);
const tskBKey = createPublicKey(config.publicKeys.tskB);
const tskGuardKey = createPublicKey(config.publicKeys.tskGuard);
const bundle = config.bundle;
await importIndependentState(faultPool, bundle, {
  ...config.input,
  sourcePublicKey,
  guardPublicKey,
  bpcResolver: { resolve: (keyId) =>
    keyId === bundle.protocolEvidence.bpcPromotionAttestation.snapshotKeyId ? bpcKey : null },
  tskBResolver: { resolve: (keyId) =>
    keyId === bundle.protocolEvidence.tskFinalizedReceipt.bKeyId ? tskBKey : null },
  tskGuardResolver: { resolve: (keyId) =>
    keyId === bundle.protocolEvidence.tskActivationLease.guardKeyId ? tskGuardKey : null },
});
