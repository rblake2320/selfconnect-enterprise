import { createHash, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import pg from 'pg';

const { Pool } = pg;
const configPath = process.argv[2];
if (!configPath) throw new Error('worker config path is required');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const tsk = await import(pathToFileURL(config.tskDistFile).href);
const pool = new Pool({ connectionString: config.databaseUrl, max: 1 });

async function authorityDigest() {
  const { rows } = await pool.query(
    `SELECT
       (SELECT coalesce(source_epoch || ':' || sequence::text, 'null') FROM public.tsk_outbox_source_checkpoint WHERE stream_id=$1) checkpoint,
       (SELECT count(*)::text FROM public.tsk_outbox_rows WHERE stream_id=$1) outbox_count,
       (SELECT coalesce(max(sequence)::text, 'null') FROM public.tsk_outbox_rows WHERE stream_id=$1) outbox_max,
       (SELECT coalesce(last_counter::text, 'null') FROM public.tsk_hotp_consumed WHERE stream_id=$1 AND tumbler_id=$2) hotp_counter`,
    [config.streamId, config.mutation.tumblerId],
  );
  return createHash('sha256').update(JSON.stringify(rows[0])).digest('hex');
}

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
  const beforeDigest = await authorityDigest();
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
    if (!(error instanceof tsk.ContractValidationError) ||
        !/revoked|not writable|lease|fence|grant digest|authorized grant/i.test(message)) {
      throw error;
    }
    denied = true;
  }
  if (!denied) throw new Error('stale TSK writer unexpectedly succeeded after restart');
  const afterDigest = await authorityDigest();
  if (afterDigest !== beforeDigest) {
    throw new Error('stale TSK attempt changed authoritative state before rejection');
  }
  process.send?.({ kind: 'stale-tsk-writer-denied', pid: process.pid,
    denialCode: 'source-fence-rejected', noCommittedEffect: true,
    authorityDigest: afterDigest });
} finally {
  await pool.end();
}
