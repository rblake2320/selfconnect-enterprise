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

async function proveStaleCompletionDeniedAfterRestart(config) {
  const directory = await mkdtemp(join(tmpdir(), 'enterprise-stale-restart-'));
  const configPath = join(directory, 'input.json');
  await writeFile(configPath, JSON.stringify(config), { encoding: 'utf8', mode: 0o600 });
  const startedAt = Date.now();
  try {
    return await new Promise((resolvePromise, rejectPromise) => {
      const child = fork(
        new URL('./enterprise-stale-completion-worker.mjs', import.meta.url),
        [configPath],
        {
          cwd: new URL('.', import.meta.url),
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          windowsHide: true,
        },
      );
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        rejectPromise(new Error('stale-completion restart probe timed out'));
      }, 30_000);
      let evidence = null;
      child.once('message', (message) => {
        if (message?.kind === 'stale-completion-denied') evidence = message;
      });
      child.once('error', (error) => {
        clearTimeout(timer);
        rejectPromise(error);
      });
      child.once('close', (code, signal) => {
        clearTimeout(timer);
        if (code !== 0 || signal || !evidence || evidence.pid === process.pid) {
          rejectPromise(new Error(
            `stale-completion restart probe failed (code=${code}, signal=${signal ?? 'none'})`,
          ));
          return;
        }
        resolvePromise(Object.freeze({
          processRestarted: true,
          childPid: evidence.pid,
          denied: true,
          rtoMs: Date.now() - startedAt,
        }));
      });
    });
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
  const promotedSourceSigning = generateKeyPairSync('ed25519');
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
    const initialRestartDenial = await proveStaleCompletionDeniedAfterRestart({
      databaseUrl: aUrl,
      guardPublicKey: composition.tsk.publicKeys.guard,
      headPublicKey: composition.tsk.publicKeys.credentialHead,
      activationLease: composition.tsk.credentialActivationLeaseGrant,
      proof: composition.tsk.targetCredentialProof,
      completion: {
        advisoryLockKey,
        agentId,
        clusterId,
        commandId: composition.commandId,
        pairId,
        sourceClientId,
        sourceEpoch,
        sourceSecretDigest,
        targetProof: composition.tsk.targetCredentialProof,
      },
    });

    // Exact Enterprise B -> A failback. The current B credential is accepted
    // as export authority only through its completed, persisted A -> B
    // reprovision lineage. The return bundle then carries the reviewed BPC and
    // TSK failback artifacts for one shared command and reprovisions a fresh A
    // credential from TSK's public signed return proof.
    const returnCommandId = composition.tsk.returnCommandId;
    assert.equal(composition.bpc.failback.commandId, returnCommandId,
      'BPC and TSK failback must attest one command');
    const returnSourceEpoch = composition.tsk.returnCredentialActivationLeaseGrant.leaseEpoch;
    const returnProtocolEvidence = {
      bpcPromotionAttestation: composition.bpc.failback.readinessAttestation,
      tskActivationLease: composition.tsk.returnActivationLeaseGrant,
      tskFinalizedReceipt: composition.tsk.returnFinalizedReceipt,
    };
    const returnSourceBundle = await exportIndependentState(b, {
      advisoryLockKey,
      clusterId,
      commandId: returnCommandId,
      protocolEvidence: returnProtocolEvidence,
      sourceEpoch: returnSourceEpoch,
      sourceKeyId: 'enterprise28-source-key-b-1',
      sourcePrivateKey: promotedSourceSigning.privateKey,
      sourceCredentialProofs: [{
        authorityCapability: authority,
        proofKind: 'promoted',
        expected: {
          agentId,
          pairId,
          sourceClientId,
          sourceSecretDigest,
        },
        proof: composition.tsk.targetCredentialProof,
        terminalRevocation: composition.tsk.targetCredentialRevocation,
      }],
    });
    const returnResolvers = Object.freeze({
      bpcResolver: composition.resolvers.bpcResolver,
      tskBResolver: composition.resolvers.tskReturnResolver,
      tskGuardResolver: composition.resolvers.tskGuardResolver,
    });
    const returnBundle = guardCountersignIndependentState(returnSourceBundle, {
      expectedCommandId: returnCommandId,
      guardKeyId: 'enterprise28-guard-key-1',
      guardPrivateKey: guardSigning.privateKey,
      sourcePublicKey: promotedSourceSigning.publicKey,
      ...returnResolvers,
    });
    const failbackStartedAt = Date.now();
    const returnImported = await importIndependentState(a, returnBundle, {
      advisoryLockKey,
      clusterId,
      commandId: returnCommandId,
      sourceEpoch: returnSourceEpoch,
      bpcPromotionDigest:
        composition.bpc.failback.readinessAttestation.attestationDigest,
      tskActivationDigest: composition.tsk.returnActivationLeaseGrant.grantDigest,
      tskFinalizedDigest: composition.tsk.returnFinalizedReceipt.receiptDigest,
      sourcePublicKey: promotedSourceSigning.publicKey,
      guardPublicKey: guardSigning.publicKey,
      ...returnResolvers,
    });
    assert.equal(returnImported.targetSystemId, bundle.manifest.sourceSystemId,
      'Enterprise failback did not return to the original A authority');
    const returnProof = await completeImportedPromotedTskCredential(
      a, composition.returnCredentialAuthority, {
        advisoryLockKey,
        agentId,
        clusterId,
        commandId: returnCommandId,
        pairId,
        sourceClientId: reprovisioned.targetClientId,
        sourceEpoch: returnSourceEpoch,
        sourceSecretDigest: composition.verifiedTargetCredential.secretDigest,
        targetProof: composition.tsk.returnCredentialProof,
      },
    );
    const returnReady = await assertIndependentStateReady(a, {
      clusterId,
      commandId: returnCommandId,
      manifestDigest: returnBundle.manifestDigest,
      sourceEpoch: returnSourceEpoch,
    });
    const returnRetry = await completeImportedPromotedTskCredential(
      a, composition.returnCredentialAuthority, {
        advisoryLockKey,
        agentId,
        clusterId,
        commandId: returnCommandId,
        pairId,
        sourceClientId: reprovisioned.targetClientId,
        sourceEpoch: returnSourceEpoch,
        sourceSecretDigest: composition.verifiedTargetCredential.secretDigest,
        targetProof: composition.tsk.returnCredentialProof,
      },
    );
    assert.equal(returnRetry.idempotent, true);
    assert.equal(returnRetry.receiptDigest, returnProof.receiptDigest);
    await assert.rejects(() => completeImportedPromotedTskCredential(
      b, composition.returnCredentialAuthority, {
        advisoryLockKey,
        agentId,
        clusterId,
        commandId: returnCommandId,
        pairId,
        sourceClientId: reprovisioned.targetClientId,
        sourceEpoch: returnSourceEpoch,
        sourceSecretDigest: composition.verifiedTargetCredential.secretDigest,
        targetProof: composition.tsk.returnCredentialProof,
      },
    ), /does not match the imported promotion|binding mismatch/);
    const failbackRestartDenial = await proveStaleCompletionDeniedAfterRestart({
      databaseUrl: bUrl,
      guardPublicKey: composition.tsk.publicKeys.guard,
      headPublicKey: composition.tsk.publicKeys.returnCredentialHead,
      activationLease: composition.tsk.returnCredentialActivationLeaseGrant,
      proof: composition.tsk.returnCredentialProof,
      completion: {
        advisoryLockKey,
        agentId,
        clusterId,
        commandId: returnCommandId,
        pairId,
        sourceClientId: reprovisioned.targetClientId,
        sourceEpoch: returnSourceEpoch,
        sourceSecretDigest: composition.verifiedTargetCredential.secretDigest,
        targetProof: composition.tsk.returnCredentialProof,
      },
    });

    const executeRepeatedEnterpriseHandoff = async ({
      sourcePool,
      targetPool,
      commandId: cycleCommandId,
      sourceEpoch: cycleSourceEpoch,
      bpcPromotionAttestation,
      tskActivationLease,
      tskFinalizedReceipt,
      tskReceiptResolver,
      sourcePrivateKey,
      sourcePublicKey,
      sourceKeyId,
      sourceCredentialAuthority,
      sourceCredentialProof,
      sourceCredentialRevocation,
      sourceCredential,
      sourceCredentialSecretDigest,
      sourceCredentialProvenance,
      sourceCredentialProvenanceSecretDigest,
      targetCredentialAuthority,
      targetCredentialLease,
      targetCredentialHeadPublicKey,
      targetCredentialProof,
      targetCredential,
      sourceDatabaseUrl,
    }) => {
      const startedAt = Date.now();
      const protocolEvidence = {
        bpcPromotionAttestation,
        tskActivationLease,
        tskFinalizedReceipt,
      };
      const sourceBundle = await exportIndependentState(sourcePool, {
        advisoryLockKey,
        clusterId,
        commandId: cycleCommandId,
        protocolEvidence,
        sourceEpoch: cycleSourceEpoch,
        sourceKeyId,
        sourcePrivateKey,
        sourceCredentialProofs: [{
          authorityCapability: sourceCredentialAuthority,
          proofKind: 'promoted',
          expected: {
            agentId,
            pairId,
            sourceClientId: sourceCredentialProvenance.clientId,
            sourceSecretDigest: sourceCredentialProvenanceSecretDigest,
          },
          proof: sourceCredentialProof,
          terminalRevocation: sourceCredentialRevocation,
        }],
      });
      const resolvers = Object.freeze({
        bpcResolver: composition.resolvers.bpcResolver,
        tskBResolver: tskReceiptResolver,
        tskGuardResolver: composition.resolvers.tskGuardResolver,
      });
      const bundle = guardCountersignIndependentState(sourceBundle, {
        expectedCommandId: cycleCommandId,
        guardKeyId: 'enterprise28-guard-key-1',
        guardPrivateKey: guardSigning.privateKey,
        sourcePublicKey,
        ...resolvers,
      });
      const imported = await importIndependentState(targetPool, bundle, {
        advisoryLockKey,
        clusterId,
        commandId: cycleCommandId,
        sourceEpoch: cycleSourceEpoch,
        bpcPromotionDigest: bpcPromotionAttestation.attestationDigest,
        tskActivationDigest: tskActivationLease.grantDigest,
        tskFinalizedDigest: tskFinalizedReceipt.receiptDigest,
        sourcePublicKey,
        guardPublicKey: guardSigning.publicKey,
        ...resolvers,
      });
      const completionInput = {
          advisoryLockKey,
          agentId,
          clusterId,
          commandId: cycleCommandId,
          pairId,
          sourceClientId: sourceCredential.clientId,
          sourceEpoch: cycleSourceEpoch,
          sourceSecretDigest: sourceCredentialSecretDigest,
          targetProof: targetCredentialProof,
      };
      const completed = await completeImportedPromotedTskCredential(
        targetPool, targetCredentialAuthority, completionInput,
      );
      const ready = await assertIndependentStateReady(targetPool, {
        clusterId,
        commandId: cycleCommandId,
        manifestDigest: bundle.manifestDigest,
        sourceEpoch: cycleSourceEpoch,
      });
      assert.equal(completed.targetClientId, targetCredential.clientId);
      assert.equal(imported.manifestDigest, bundle.manifestDigest);
      assert.equal(ready.manifestDigest, bundle.manifestDigest);
      const convergedBinding = (await targetPool.query(
        'SELECT tsk_client_id FROM ultra_identity_bindings WHERE pair_id=$1',
        [pairId],
      )).rows[0];
      assert.equal(convergedBinding?.tsk_client_id, targetCredential.clientId);
      const retry = await completeImportedPromotedTskCredential(
        targetPool, targetCredentialAuthority, {
          advisoryLockKey,
          agentId,
          clusterId,
          commandId: cycleCommandId,
          pairId,
          sourceClientId: sourceCredential.clientId,
          sourceEpoch: cycleSourceEpoch,
          sourceSecretDigest: sourceCredentialSecretDigest,
          targetProof: targetCredentialProof,
        },
      );
      assert.equal(retry.idempotent, true);
      let staleSourceCompletionDenied = false;
      try {
        await completeImportedPromotedTskCredential(
          sourcePool, targetCredentialAuthority, {
            advisoryLockKey,
            agentId,
            clusterId,
            commandId: cycleCommandId,
            pairId,
            sourceClientId: sourceCredential.clientId,
            sourceEpoch: cycleSourceEpoch,
            sourceSecretDigest: sourceCredentialSecretDigest,
            targetProof: targetCredentialProof,
          },
        );
      } catch (error) {
        if (!/does not match the imported promotion|binding mismatch/i.test(
          String(error?.message ?? error),
        )) throw error;
        staleSourceCompletionDenied = true;
      }
      assert.equal(staleSourceCompletionDenied, true);
      const restartDenial = await proveStaleCompletionDeniedAfterRestart({
        databaseUrl: sourceDatabaseUrl,
        guardPublicKey: composition.tsk.publicKeys.guard,
        headPublicKey: targetCredentialHeadPublicKey,
        activationLease: targetCredentialLease,
        proof: targetCredentialProof,
        completion: completionInput,
      });
      return Object.freeze({
        commandId: cycleCommandId,
        sourceEpoch: cycleSourceEpoch,
        manifestDigest: bundle.manifestDigest,
        sourceSystemId: bundle.manifest.sourceSystemId,
        targetSystemId: ready.targetSystemId,
        sourceClientId: sourceCredential.clientId,
        targetClientId: completed.targetClientId,
        receiptDigest: completed.receiptDigest,
        idempotentRetry: retry.idempotent,
        staleSourceCompletionDenied,
        restartDenial,
        importedSystemId: imported.targetSystemId,
        convergence: Object.freeze({
          sourceManifestDigest: bundle.manifestDigest,
          importedManifestDigest: imported.manifestDigest,
          readyManifestDigest: ready.manifestDigest,
          targetCredentialClientId: convergedBinding.tsk_client_id,
        }),
        rpo: 0,
        rtoMs: Date.now() - startedAt,
      });
    };

    const repeatForward = await executeRepeatedEnterpriseHandoff({
      sourcePool: a,
      targetPool: b,
      commandId: composition.tsk.repeatedCycle.forward.commandId,
      sourceEpoch: composition.tsk.repeatForwardCredential.leaseGrant.leaseEpoch,
      bpcPromotionAttestation:
        composition.bpc.repeatedCycle.forward.readinessAttestation,
      tskActivationLease: composition.tsk.repeatedCycle.forward.activationLease,
      tskFinalizedReceipt: composition.tsk.repeatedCycle.forward.finalizedReceipt,
      tskReceiptResolver: composition.resolvers.tskBResolver,
      sourcePrivateKey: sourceSigning.privateKey,
      sourcePublicKey: sourceSigning.publicKey,
      sourceKeyId: 'enterprise28-source-key-a-repeat-1',
      sourceCredentialAuthority: composition.returnCredentialAuthority,
      sourceCredentialProof: composition.tsk.returnCredentialProof,
      sourceCredentialRevocation: composition.tsk.returnCredentialRevocation,
      sourceCredential: composition.tsk.publicCredentialReturn,
      sourceCredentialSecretDigest: composition.verifiedReturnCredential.secretDigest,
      sourceCredentialProvenance: composition.tsk.publicCredentialTarget,
      sourceCredentialProvenanceSecretDigest:
        composition.verifiedTargetCredential.secretDigest,
      targetCredentialAuthority: composition.repeatForwardCredentialAuthority,
      targetCredentialLease: composition.tsk.repeatForwardCredential.leaseGrant,
      targetCredentialHeadPublicKey: composition.tsk.publicKeys.credentialHead,
      targetCredentialProof: composition.tsk.repeatForwardCredential.proof,
      targetCredential: composition.tsk.repeatForwardCredential.publicCredential,
      sourceDatabaseUrl: aUrl,
    });
    assert.equal(
      repeatForward.commandId,
      composition.bpc.repeatedCycle.forward.commandId,
      'BPC, TSK, and Enterprise repeat-forward commands diverged',
    );
    const repeatFailback = await executeRepeatedEnterpriseHandoff({
      sourcePool: b,
      targetPool: a,
      commandId: composition.tsk.repeatedCycle.failback.commandId,
      sourceEpoch: composition.tsk.repeatReturnCredential.leaseGrant.leaseEpoch,
      bpcPromotionAttestation:
        composition.bpc.repeatedCycle.failback.readinessAttestation,
      tskActivationLease: composition.tsk.repeatedCycle.failback.activationLease,
      tskFinalizedReceipt: composition.tsk.repeatedCycle.failback.finalizedReceipt,
      tskReceiptResolver: composition.resolvers.tskReturnResolver,
      sourcePrivateKey: promotedSourceSigning.privateKey,
      sourcePublicKey: promotedSourceSigning.publicKey,
      sourceKeyId: 'enterprise28-source-key-b-repeat-1',
      sourceCredentialAuthority: composition.repeatForwardCredentialAuthority,
      sourceCredentialProof: composition.tsk.repeatForwardCredential.proof,
      sourceCredentialRevocation: composition.tsk.repeatForwardCredentialRevocation,
      sourceCredential: composition.tsk.repeatForwardCredential.publicCredential,
      sourceCredentialSecretDigest:
        composition.verifiedRepeatForwardCredential.secretDigest,
      sourceCredentialProvenance: composition.tsk.publicCredentialReturn,
      sourceCredentialProvenanceSecretDigest:
        composition.verifiedReturnCredential.secretDigest,
      targetCredentialAuthority: composition.repeatReturnCredentialAuthority,
      targetCredentialLease: composition.tsk.repeatReturnCredential.leaseGrant,
      targetCredentialHeadPublicKey: composition.tsk.publicKeys.returnCredentialHead,
      targetCredentialProof: composition.tsk.repeatReturnCredential.proof,
      targetCredential: composition.tsk.repeatReturnCredential.publicCredential,
      sourceDatabaseUrl: bUrl,
    });
    assert.equal(
      repeatFailback.commandId,
      composition.bpc.repeatedCycle.failback.commandId,
      'BPC, TSK, and Enterprise repeat-failback commands diverged',
    );
    // Recover the exact stale B Enterprise database in place. No prior B
    // authority row survives this restore boundary; authority returns only
    // after the complete signed A export, exact BPC/TSK bindings, import,
    // readiness attestation, and credential completion converge.
    await resetUltra(b);
    const recoveredSite = await executeRepeatedEnterpriseHandoff({
      sourcePool: a,
      targetPool: b,
      commandId: composition.tsk.recoveredSite.handoff.commandId,
      sourceEpoch: composition.tsk.recoveredSite.credential.leaseGrant.leaseEpoch,
      bpcPromotionAttestation:
        composition.bpc.recoveredSite.readinessAttestation,
      tskActivationLease: composition.tsk.recoveredSite.handoff.activationLease,
      tskFinalizedReceipt: composition.tsk.recoveredSite.handoff.finalizedReceipt,
      tskReceiptResolver: composition.resolvers.tskBResolver,
      sourcePrivateKey: sourceSigning.privateKey,
      sourcePublicKey: sourceSigning.publicKey,
      sourceKeyId: 'enterprise28-source-key-a-recovered-1',
      sourceCredentialAuthority: composition.repeatReturnCredentialAuthority,
      sourceCredentialProof: composition.tsk.repeatReturnCredential.proof,
      sourceCredentialRevocation:
        composition.tsk.recoveredSite.sourceCredentialRevocation,
      sourceCredential: composition.tsk.repeatReturnCredential.publicCredential,
      sourceCredentialSecretDigest:
        composition.verifiedRepeatReturnCredential.secretDigest,
      sourceCredentialProvenance:
        composition.tsk.repeatForwardCredential.publicCredential,
      sourceCredentialProvenanceSecretDigest:
        composition.verifiedRepeatForwardCredential.secretDigest,
      targetCredentialAuthority: composition.recoveredCredentialAuthority,
      targetCredentialLease: composition.tsk.recoveredSite.credential.leaseGrant,
      targetCredentialHeadPublicKey: composition.tsk.publicKeys.credentialHead,
      targetCredentialProof: composition.tsk.recoveredSite.credential.proof,
      targetCredential: composition.tsk.recoveredSite.credential.publicCredential,
      sourceDatabaseUrl: aUrl,
    });
    assert.equal(
      recoveredSite.commandId,
      composition.bpc.recoveredSite.commandId,
      'BPC, TSK, and Enterprise recovered-site commands diverged',
    );
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
      failback: Object.freeze({
        commandId: returnCommandId,
        manifestDigest: returnBundle.manifestDigest,
        sourceEpoch: returnSourceEpoch,
        sourceSystemId: returnBundle.manifest.sourceSystemId,
        targetSystemId: returnReady.targetSystemId,
        sourceClientId: reprovisioned.targetClientId,
        targetClientId: returnProof.targetClientId,
        receiptDigest: returnProof.receiptDigest,
        idempotentRetry: returnRetry.idempotent,
        staleBCompletionDenied: true,
        staleBProtocolWriterDenied:
          composition.tsk.staleReturnedCredentialWriterDenied,
        rpo: 0,
        rtoMs: Date.now() - failbackStartedAt,
      }),
      repeatedCycle: Object.freeze({
        forward: repeatForward,
        failback: repeatFailback,
      }),
      recoveredSite,
      faults: Object.freeze({
        staleCompletionRestarts: Object.freeze({
          initial: initialRestartDenial,
          failback: failbackRestartDenial,
          repeatForward: repeatForward.restartDenial,
          repeatFailback: repeatFailback.restartDenial,
          recoveredSite: recoveredSite.restartDenial,
        }),
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
