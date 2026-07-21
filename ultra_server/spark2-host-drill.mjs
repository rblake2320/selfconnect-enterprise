import { writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  buildSpark2Evidence, validateSpark2Result, validateSpark2Topology,
} from './spark2-host-evidence.js';
import { assertCleanReviewedCheckout } from './final-ha-acceptance.mjs';
import { runTskLiveComposition } from './tsk-live-composition.mjs';

const SHA = /^[0-9a-f]{40}$/;

function required(env, name) {
  const value = env[name];
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new Error(`${name} is required`);
  }
  return value;
}

export async function runSpark2HostDrill(env = process.env) {
  const expectedEnterpriseCommit = required(env,
    'SPARK_HA_EXPECTED_ENTERPRISE_SHA').toLowerCase();
  if (!SHA.test(expectedEnterpriseCommit)) {
    throw new Error('SPARK_HA_EXPECTED_ENTERPRISE_SHA must be a full commit SHA');
  }
  const expectedTskCommit = required(env, 'SPARK_HA_EXPECTED_TSK_SHA').toLowerCase();
  if (!SHA.test(expectedTskCommit)) {
    throw new Error('SPARK_HA_EXPECTED_TSK_SHA must be a full commit SHA');
  }
  await assertCleanReviewedCheckout(fileURLToPath(new URL('..', import.meta.url)),
    expectedEnterpriseCommit);
  const commandId = required(env, 'SPARK_HA_COMMAND_ID');
  const urls = Object.freeze({
    source: required(env, 'SPARK_HA_SOURCE_PG_URL'),
    control: required(env, 'SPARK_HA_CONTROL_PG_URL'),
    target: required(env, 'SPARK_HA_TARGET_PG_URL'),
    redis: required(env, 'SPARK_HA_REDIS_URL'),
  });
  validateSpark2Topology(urls);
  const started = Date.now();
  const result = await runTskLiveComposition({
    tskRoot: required(env, 'SPARK_HA_TSK_ROOT'),
    expectedTskCommit,
    commandId,
    streamId: required(env, 'SPARK_HA_STREAM_ID'),
    aPostgresUrl: urls.source,
    bPostgresUrl: urls.target,
    controlPostgresUrl: urls.control,
    redis: Object.freeze({ kind: 'url', url: urls.redis }),
    preserveRedisAuthority: false,
    destructiveReset: true,
  });
  validateSpark2Result(result, required(env, 'SPARK2_EXPECTED_SYSTEM_ID'));
  const evidence = buildSpark2Evidence(result, {
    commandId,
    durationMs: Date.now() - started,
    enterpriseCommit: expectedEnterpriseCommit,
    tskCommit: expectedTskCommit,
  });
  await writeFile(required(env, 'SPARK_HA_EVIDENCE_FILE'),
    `${JSON.stringify(evidence, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  return evidence;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const evidence = await runSpark2HostDrill();
  process.stdout.write(`Spark-2 cross-host A->B->A: RPO=${evidence.outcome.dataLossRpo} ` +
    `RTO=${evidence.outcome.durationMs}ms target=${evidence.topology.targetHost}\n`);
}
