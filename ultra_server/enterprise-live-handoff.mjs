import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { createPublicKey, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import pg from 'pg';

import {
  ULTRA_INDEPENDENT_STATE_SCHEMA,
  assertIndependentStateReady,
  completeImportedPromotedTskCredential,
  exportIndependentState,
  guardCountersignIndependentState,
  importIndependentState,
} from './independent-state.js';
import { createPromotedTskAuthorityCapability } from './promoted-tsk-authority.js';
import { ULTRA_PG_SCHEMA, initializePgSchemas } from './runtime-stores.js';

const { Pool } = pg;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForPostgres(pool, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try { return await pool.query('SELECT 1'); } catch (error) { last = error; await sleep(250); }
  }
  throw new Error(`promoted PostgreSQL did not recover: ${String(last?.message ?? last)}`);
}

async function resetUltra(pool) {
  await pool.query(`DROP TABLE IF EXISTS
    ultra_idempotency_redaction,ultra_ha_tsk_reprovision,ultra_ha_import_head,
    ultra_nonce_tombstones,ultra_idempotency,ultra_identity_bindings,
    ultra_tumbler_maps CASCADE`);
  await initializePgSchemas(pool, ULTRA_PG_SCHEMA, ULTRA_INDEPENDENT_STATE_SCHEMA);
}

async function assertInterruptedImportRolledBack(pool, clusterId, pairId) {
  const [head, binding, pending] = await Promise.all([
    pool.query('SELECT COUNT(*)::int AS n FROM ultra_ha_import_head WHERE cluster_id=$1', [clusterId]),
    pool.query('SELECT COUNT(*)::int AS n FROM ultra_identity_bindings WHERE pair_id=$1', [pairId]),
    pool.query('SELECT COUNT(*)::int AS n FROM ultra_ha_tsk_reprovision WHERE cluster_id=$1', [clusterId]),
  ]);
  assert.equal(Number(head.rows[0].n), 0, 'interrupted import left a committed authority head');
  assert.equal(Number(binding.rows[0].n), 0, 'interrupted import left a committed identity binding');
  assert.equal(Number(pending.rows[0].n), 0, 'interrupted import left a committed credential handoff');
}

async function killImporterBeforeCommit(config) {
  const directory = await mkdtemp(join(tmpdir(), 'enterprise-import-fault-'));
  const configPath = join(directory, 'input.json');
  await writeFile(configPath, JSON.stringify(config), { encoding: 'utf8', mode: 0o600 });
  const startedAt = Date.now();
  try {
    await new Promise((resolvePromise, rejectPromise) => {
      const child = fork(new URL('./enterprise-import-worker.mjs', import.meta.url), [configPath], {
        cwd: new URL('.', import.meta.url),
        stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        rejectPromise(new Error('Enterprise importer did not reach the pre-commit fault point'));
      }, 30_000);
      let killed = false;
      child.once('message', (message) => {
        if (message?.kind !== 'enterprise-import-effects-staged') return;
        killed = true;
        child.kill('SIGKILL');
      });
      child.once('error', (error) => { clearTimeout(timer); rejectPromise(error); });
      child.once('close', (_code, signal) => {
        clearTimeout(timer);
        if (!killed || signal !== 'SIGKILL') {
          rejectPromise(new Error(`Enterprise importer did not exit by SIGKILL (signal=${signal ?? 'none'})`));
          return;
        }
        resolvePromise();
      });
    });
    return Date.now() - startedAt;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/**
 * Compose the Enterprise state authority with the already-completed real BPC
 * and TSK promotions. This uses the exact signed artifacts returned by those
 * reviewed authorities and never persists the promoted TSK shared secret.
 */
export async function runEnterpriseLiveHandoff(composition, env = process.env) {
  const aUrl = env.ULTRA_TEST_POSTGRES_URL_A;
  const bUrl = env.ULTRA_TEST_POSTGRES_URL_B;
  if (!aUrl || !bUrl || aUrl === bUrl) throw new Error('two distinct Ultra PostgreSQL URLs are required');
  const a = new Pool({ connectionString: aUrl, max: 4 });
  let b = new Pool({ connectionString: bUrl, max: 4 });
  const sourceSigning = generateKeyPairSync('ed25519');
  const guardSigning = generateKeyPairSync('ed25519');
  const clusterId = 'enterprise28-live-cluster';
  const pairId = composition.tsk.targetCredentialProof.pairId;
  const agentId = composition.tsk.targetCredentialProof.agentId;
  const sourceClientId = composition.tsk.publicCredentialSource.clientId;
  const sourceEpoch = composition.tsk.credentialActivationLeaseGrant.leaseEpoch;
  const advisoryLockKey = `enterprise28:${clusterId}:independent-state`;
  try {
    await Promise.all([resetUltra(a), resetUltra(b)]);
    await a.query(
      'INSERT INTO ultra_identity_bindings(pair_id,tsk_client_id,agent_id) VALUES($1,$2,$3)',
      [pairId, sourceClientId, agentId],
    );
    const safeId = randomUUID();
    const secretId = randomUUID();
    await a.query(
      `INSERT INTO ultra_idempotency(idempotency_key,operation,agent_id,state,response)
       VALUES($1,'status', $3,'complete',$4::jsonb),
             ($2,'provision-tsk',$3,'complete',$5::jsonb)`,
      [safeId, secretId, agentId, JSON.stringify({ ok: true, value: 'preserved' }),
        JSON.stringify({ ok: true, credentialProvisionPayload: 'redact-at-export' })],
    );
    const protocolEvidence = {
      bpcPromotionAttestation: composition.bpc.readinessAttestation,
      tskActivationLease: composition.tsk.activationLeaseGrant,
      tskFinalizedReceipt: composition.tsk.bFinalizedReceipt,
    };
    const sourceBundle = await exportIndependentState(a, {
      advisoryLockKey,
      clusterId,
      commandId: composition.commandId,
      protocolEvidence,
      sourceEpoch,
      sourceKeyId: 'enterprise28-source-key-1',
      sourcePrivateKey: sourceSigning.privateKey,
      sourceCredentialProofs: [{
        authorityCapability: composition.sourceCredentialAuthority,
        expected: {
          agentId,
          pairId,
          sourceClientId,
        },
        proof: composition.tsk.sourceCredentialProof,
      }],
    });
    const bundle = guardCountersignIndependentState(sourceBundle, {
      expectedCommandId: composition.commandId,
      guardKeyId: 'enterprise28-guard-key-1',
      guardPrivateKey: guardSigning.privateKey,
      sourcePublicKey: sourceSigning.publicKey,
      ...composition.resolvers,
    });
    assert.equal(bundle.manifest.state.credentialBindings[0].sourceSecretDigest,
      composition.verifiedSourceCredential.secretDigest);
    assert.equal(JSON.stringify(bundle).includes('redact-at-export'), false);
    const importerSigkillRtoMs = await killImporterBeforeCommit({
      postgresUrl: bUrl,
      bundle,
      input: {
        advisoryLockKey,
        clusterId,
        commandId: composition.commandId,
        sourceEpoch,
        bpcPromotionDigest: composition.bpc.readinessAttestation.attestationDigest,
        tskActivationDigest: composition.tsk.activationLeaseGrant.grantDigest,
        tskFinalizedDigest: composition.tsk.bFinalizedReceipt.receiptDigest,
      },
      publicKeys: {
        source: sourceSigning.publicKey.export({ type: 'spki', format: 'pem' }),
        guard: guardSigning.publicKey.export({ type: 'spki', format: 'pem' }),
        bpc: composition.bpc.publicKeys.source,
        tskB: composition.tsk.publicKeys.bReceipt,
        tskGuard: composition.tsk.publicKeys.guard,
      },
    });
    await assertInterruptedImportRolledBack(b, clusterId, pairId);
    const imported = await importIndependentState(b, bundle, {
      advisoryLockKey,
      clusterId,
      commandId: composition.commandId,
      sourceEpoch,
      bpcPromotionDigest: composition.bpc.readinessAttestation.attestationDigest,
      tskActivationDigest: composition.tsk.activationLeaseGrant.grantDigest,
      tskFinalizedDigest: composition.tsk.bFinalizedReceipt.receiptDigest,
      sourcePublicKey: sourceSigning.publicKey,
      guardPublicKey: guardSigning.publicKey,
      ...composition.resolvers,
    });
    const leaseResolver = { resolve: (keyId) =>
      keyId === composition.tsk.credentialActivationLeaseGrant.guardKeyId
        ? composition.resolvers.tskGuardResolver.resolve(keyId) : null };
    const headKeyResolver = { resolve: (keyId, alg) =>
      keyId === composition.tsk.targetCredentialProof.head.keyId && alg === 'ed25519'
        ? createPublicKey(composition.tsk.publicKeys.credentialHead) : null };
    const authority = createPromotedTskAuthorityCapability({
      activationLease: composition.tsk.credentialActivationLeaseGrant,
      leaseResolver,
      headKeyResolver,
    });
    const sourceSecretDigest = composition.verifiedSourceCredential.secretDigest;
    const reprovisioned = await completeImportedPromotedTskCredential(b, authority, {
      advisoryLockKey,
      agentId,
      clusterId,
      commandId: composition.commandId,
      pairId,
      sourceClientId,
      sourceEpoch,
      sourceSecretDigest,
      targetProof: composition.tsk.targetCredentialProof,
    });
    const ready = await assertIndependentStateReady(b, {
      clusterId,
      commandId: composition.commandId,
      manifestDigest: bundle.manifestDigest,
      sourceEpoch,
    });
    const binding = (await b.query(
      'SELECT pair_id,agent_id,tsk_client_id FROM ultra_identity_bindings WHERE pair_id=$1',
      [pairId],
    )).rows[0];
    const copiedTarget = Number((await b.query(
      'SELECT COUNT(*)::int AS n FROM ultra_tumbler_maps WHERE client_id=$1',
      [reprovisioned.targetClientId],
    )).rows[0].n);
    const redacted = (await b.query(
      `SELECT response FROM ultra_idempotency WHERE idempotency_key=$1`, [secretId],
    )).rows[0].response;
    assert.deepEqual(binding, { pair_id: pairId, agent_id: agentId,
      tsk_client_id: reprovisioned.targetClientId });
    assert.equal(copiedTarget, 0, 'promoted TSK secret/map must not be copied into Enterprise');
    assert.equal(redacted.error, 'SECRET_REPROVISION_REQUIRED');
    // Destroy and rebuild only the Enterprise authority tables on the exact
    // promoted B PostgreSQL instance. The independently governed TSK authority
    // remains intact, so the same signed bundle and public credential proof can
    // restore the Enterprise projection without copying a shared secret.
    const restoreStartedAt = Date.now();
    await resetUltra(b);
    const restoredImport = await importIndependentState(b, bundle, {
      advisoryLockKey,
      clusterId,
      commandId: composition.commandId,
      sourceEpoch,
      bpcPromotionDigest: composition.bpc.readinessAttestation.attestationDigest,
      tskActivationDigest: composition.tsk.activationLeaseGrant.grantDigest,
      tskFinalizedDigest: composition.tsk.bFinalizedReceipt.receiptDigest,
      sourcePublicKey: sourceSigning.publicKey,
      guardPublicKey: guardSigning.publicKey,
      ...composition.resolvers,
    });
    assert.equal(restoredImport.idempotent, false);
    const restoredProof = await completeImportedPromotedTskCredential(b, authority, {
      advisoryLockKey,
      agentId,
      clusterId,
      commandId: composition.commandId,
      pairId,
      sourceClientId,
      sourceEpoch,
      sourceSecretDigest,
      targetProof: composition.tsk.targetCredentialProof,
    });
    const restoredReady = await assertIndependentStateReady(b, {
      clusterId,
      commandId: composition.commandId,
      manifestDigest: bundle.manifestDigest,
      sourceEpoch,
    });
    assert.equal(restoredReady.targetSystemId, ready.targetSystemId);
    assert.equal(restoredProof.targetClientId, reprovisioned.targetClientId);
    assert.equal(restoredProof.receiptDigest, reprovisioned.receiptDigest);
    const restoredBinding = (await b.query(
      'SELECT pair_id,agent_id,tsk_client_id FROM ultra_identity_bindings WHERE pair_id=$1',
      [pairId],
    )).rows[0];
    assert.deepEqual(restoredBinding, binding);
    let databaseSigkill;
    const bContainer = env.ULTRA_TEST_POSTGRES_B_CONTAINER;
    if (bContainer) {
      if (!/^[a-f0-9]{12,64}$/.test(bContainer)) {
        throw new Error('ULTRA_TEST_POSTGRES_B_CONTAINER must be a Docker container id');
      }
      const databaseStartedAt = Date.now();
      await b.end();
      execFileSync('docker', ['kill', '-s', 'KILL', bContainer], {
        stdio: 'ignore', windowsHide: true,
      });
      execFileSync('docker', ['start', bContainer], { stdio: 'ignore', windowsHide: true });
      b = new Pool({ connectionString: bUrl, max: 4 });
      await waitForPostgres(b);
      const afterRestartReady = await assertIndependentStateReady(b, {
        clusterId,
        commandId: composition.commandId,
        manifestDigest: bundle.manifestDigest,
        sourceEpoch,
      });
      const afterRestartProof = (await b.query(
        `SELECT receipt_digest,target_client_id FROM ultra_ha_tsk_reprovision
         WHERE cluster_id=$1 AND pair_id=$2`, [clusterId, pairId],
      )).rows[0];
      assert.equal(afterRestartReady.targetSystemId, ready.targetSystemId);
      assert.equal(afterRestartProof.receipt_digest, reprovisioned.receiptDigest);
      assert.equal(afterRestartProof.target_client_id, reprovisioned.targetClientId);
      databaseSigkill = Object.freeze({
        fault: 'sigkill-exact-promoted-enterprise-postgres', resumed: true,
        sameTargetSystemId: true, sameCredentialReceipt: true, rpo: 0,
        rtoMs: Date.now() - databaseStartedAt,
      });
    }
    return Object.freeze({
      clusterId,
      manifestDigest: bundle.manifestDigest,
      sourceSystemId: bundle.manifest.sourceSystemId,
      targetSystemId: ready.targetSystemId,
      sourceClientId,
      targetClientId: reprovisioned.targetClientId,
      targetProofDigest: reprovisioned.targetProofDigest,
      receiptDigest: reprovisioned.receiptDigest,
      copiedTargetCredentialRows: copiedTarget,
      redactionPreserved: true,
      rpo: 0,
      faults: Object.freeze({
        childProcessSigkill: Object.freeze({
          fault: 'sigkill-enterprise-importer-before-commit',
          resumed: true,
          tornAuthorityRows: 0,
          rpo: 0,
          rtoMs: importerSigkillRtoMs,
        }),
        destructiveRestore: Object.freeze({
          fault: 'drop-and-rebuild-enterprise-authority-on-promoted-b',
          resumed: true,
          sameTargetSystemId: true,
          sameCredentialReceipt: true,
          rpo: 0,
          rtoMs: Date.now() - restoreStartedAt,
        }),
        ...(databaseSigkill ? { databaseSigkill } : {}),
      }),
    });
  } finally {
    await Promise.allSettled([a.end(), b.end()]);
  }
}
