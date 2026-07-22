import { createHmac, createPrivateKey, createPublicKey } from 'node:crypto';
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

try {
  const db = new bpc.NodePostgresTransactor(runtimePool, {
    statementTimeoutMs: 350,
    transactionTimeoutMs: 500,
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
  let denied = false;
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
    if (!/revoked|not writable|lease|fence|epoch|claim|authority/i.test(message)) {
      throw error;
    }
    denied = true;
  }
  if (!denied) throw new Error('stale BPC writer unexpectedly succeeded after restart');
  process.send?.({ kind: 'stale-bpc-writer-denied', pid: process.pid });
} finally {
  await Promise.allSettled([runtimePool.end(), controlPool.end()]);
  for (const client of redisMembers) client.disconnect();
}
