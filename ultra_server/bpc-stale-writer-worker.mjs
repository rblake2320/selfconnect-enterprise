import { createHash, createHmac, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import Redis from 'ioredis';
import pg from 'pg';

const { Pool } = pg;
const configPath = process.argv[2];
if (!configPath) throw new Error('worker config path is required');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const bpc = await import(pathToFileURL(config.bpcDistFile).href);
const runtimePool = new Pool({ connectionString: config.runtimeUrl, max: 1 });
const controlPool = new Pool({ connectionString: config.controlUrl, max: 1 });
const redisMembers = config.redisUrls.map((url) => new Redis(url, {
  maxRetriesPerRequest: 1,
}));

async function authorityDigest() {
  const { rows } = await runtimePool.query(
    `SELECT
       (SELECT coalesce(row_to_json(p)::text, 'null') FROM public.bpc_pairs p WHERE id=$1) pair_row,
       (SELECT coalesce(sequence::text, 'null') FROM public.ha_outbox_source_checkpoint WHERE stream_id=$2) checkpoint,
       (SELECT count(*)::text FROM public.ha_outbox_rows WHERE stream_id=$2) outbox_count,
       (SELECT coalesce(max(sequence)::text, 'null') FROM public.ha_outbox_rows WHERE stream_id=$2) outbox_max`,
    [config.pair.id, config.streamId],
  );
  return createHash('sha256').update(JSON.stringify(rows[0])).digest('hex');
}

try {
  const db = new bpc.NodePostgresTransactor(runtimePool, {
    statementTimeoutMs: 3_000,
    transactionTimeoutMs: 5_000,
  });
  const controlDb = new bpc.NodePostgresTransactor(controlPool);
  const [ready, haReady, controlReady] = await Promise.all([
    bpc.assertSchemaReady(db, 'public'),
    bpc.assertBpcHaSchemaReady(db),
    bpc.assertBpcHaSchemaReady(controlDb),
  ]);
  const publicKeys = Object.fromEntries(Object.entries(config.publicKeys)
    .map(([keyId, pem]) => [keyId, createPublicKey(pem)]));
  const resolver = { resolve: (keyId) => publicKeys[keyId] ?? null };
  const witness = await bpc.PgRedisFenceWitness.open(
    controlDb, controlReady, resolver,
  );
  const fenceStore = await bpc.BpcRedisQuorumFenceStore.open(
    redisMembers, resolver, witness, config.redisKey,
  );
  const nodePrivateKey = createPrivateKey(config.nodePrivateKey);
  const nodeIdentity = {
    keyId: config.nodeKeyId,
    prove: async (challenge) => bpc.signNodeIdentityChallenge(
      config.nodeKeyId, nodePrivateKey, challenge,
    ),
  };
  const sealKey = Buffer.from(config.sealKey, 'base64');
  const mutationSecret = Buffer.from(config.mutationSecret, 'base64');
  const keyring = {
    activeKeyId: config.sealKeyId,
    resolveKey: (keyId) => {
      if (keyId !== config.sealKeyId) throw new Error('unknown pair seal key');
      return sealKey;
    },
  };
  const codec = new bpc.Aes256GcmPairPayloadCodec(
    config.sealKeyId, keyring.resolveKey,
  );
  const ticketSigner = {
    keyId: config.mutationKeyId,
    async signTicket(request, context) {
      bpc.validateDbMutationPolicyContext(request, context, codec);
      return createHmac('sha256', mutationSecret).update([
        request.domain, request.keyId, request.nonce, request.streamId,
        request.epoch, request.leaseId, request.grantDigest, request.txid,
        request.expiresAtMs, request.sourceEpoch, request.sequence,
        request.opDigest, request.action, request.maxPendingRows,
        request.payloadDigest, request.policyDigest,
      ].join('|')).digest('hex');
    },
  };
  const beforeDigest = await authorityDigest();
  let denied = false;
  let denialCode = '';
  try {
    const fence = await bpc.PgSourceLeaseFence.open(
      db, haReady, resolver, config.fence, fenceStore, nodeIdentity, ticketSigner,
    );
    const store = bpc.createHaPairAuthority(
      db, ready,
      { streamId: config.streamId, fenceToken: BigInt(config.fenceToken),
        keyring, maxPendingRows: 100 },
      fence,
    );
    await store.set(config.pair);
  } catch (error) {
    const message = String(error?.message ?? error);
    if (!(error instanceof bpc.ContractValidationError) ||
        !/revoked|not writable|stale source lease|fence authority|epoch|claim/i.test(message)) {
      throw error;
    }
    denied = true;
    denialCode = 'source-fence-rejected';
  }
  if (!denied) throw new Error('stale BPC writer unexpectedly succeeded after restart');
  const [leaseResult, currentFence, afterDigest] = await Promise.all([
    runtimePool.query(
      `SELECT
         count(*) FILTER (WHERE grant_digest=$2)::int authorized_grant_count,
         bool_or(epoch=$3 AND status='revoked') revoked_at_stale_epoch,
         max(epoch)::text max_epoch
       FROM bpc_ha.source_lease_history WHERE stream_id=$1`,
      [config.streamId, config.fence.grantDigest, config.fence.epoch],
    ),
    fenceStore.current(),
    authorityDigest(),
  ]);
  const lease = leaseResult.rows[0];
  const retainedTerminalRevocation = Number(lease?.authorized_grant_count) === 1 &&
    lease?.revoked_at_stale_epoch === true;
  const recoveredToNewerAuthority = Number(lease?.max_epoch) > config.fence.epoch;
  if (!retainedTerminalRevocation && !recoveredToNewerAuthority) {
    throw new Error(`stale BPC denial did not bind the expected terminal revocation (${config.cut}: count=${lease?.authorized_grant_count ?? 'missing'}, revoked=${lease?.revoked_at_stale_epoch ?? 'missing'}, maxEpoch=${lease?.max_epoch ?? 'missing'}, staleEpoch=${config.fence.epoch})`);
  }
  if (!currentFence || currentFence.epoch <= config.fence.epoch) {
    throw new Error('stale BPC denial did not observe a strictly newer Redis authority');
  }
  if (afterDigest !== beforeDigest) {
    throw new Error('stale BPC attempt changed authoritative state before rejection');
  }
  process.send?.({ kind: 'stale-bpc-writer-denied', pid: process.pid,
    denialCode, noCommittedEffect: true, authorityDigest: afterDigest });
} finally {
  await Promise.allSettled([runtimePool.end(), controlPool.end()]);
  for (const client of redisMembers) client.disconnect();
}
