import { createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import pg from 'pg';

const { Pool } = pg;
const configPath = process.argv[2];
if (!configPath) throw new Error('worker config path is required');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const tsk = await import(pathToFileURL(config.tskDistFile).href);
const pool = new Pool({ connectionString: config.databaseUrl, max: 1 });

try {
  const db = new tsk.NodePostgresTransactor(pool);
  const schemaReady = await tsk.assertSchemaReady(db, 'public');
  const keys = Object.fromEntries(Object.entries(config.publicKeys)
    .map(([keyId, pem]) => [keyId, createPublicKey(pem)]));
  const resolver = { resolve: (keyId) => keys[keyId] ?? null };
  const privateKey = createPrivateKey(config.headPrivateKey);
  const sanitizer = Object.freeze({
    sanitize(raw) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
          Object.keys(raw).sort().join(',') !== 'counter,tumblerId' ||
          typeof raw.tumblerId !== 'string' || !Number.isSafeInteger(raw.counter)) {
        throw new tsk.ContractValidationError('invalid HOTP mutation');
      }
      return Object.freeze({ tumblerId: raw.tumblerId, counter: raw.counter });
    },
    assertSanitized(value) { return this.sanitize(value); },
  });
  let denied = false;
  try {
    const ready = await tsk.assertSourceFenceReady(db, 'public', resolver,
      config.authorizedLease);
    const outbox = new tsk.PgTskDurableOutbox(db, schemaReady, {
      streamId: config.streamId,
      sanitizer,
      signer: {
        keyId: config.headKeyId,
        alg: 'ed25519',
        async sign(digest) {
          return edSign(null, Buffer.from(digest, 'utf8'), privateKey).toString('base64url');
        },
      },
      maxPendingRows: 100_000,
      backpressure: 'fail-authoritative-mutation',
    }, { resolver, controlToASkewBoundMs: 0, ready });
    await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, {
      streamId: config.streamId,
      rawMutation: config.mutation,
      fenceToken: BigInt(config.fenceToken),
    }));
  } catch (error) {
    const message = String(error?.message ?? error);
    if (!/revoked|not writable|lease|fence|grant digest|authorized grant/i.test(message)) {
      throw error;
    }
    denied = true;
  }
  if (!denied) throw new Error('stale TSK writer unexpectedly succeeded after restart');
  process.send?.({ kind: 'stale-tsk-writer-denied', pid: process.pid });
} finally {
  await pool.end();
}
