import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;
const SHA = /^[0-9a-f]{40}$/;

const REQUIRED_ENV = Object.freeze([
  'BPC_TEST_POSTGRES_URL', 'BPC_TEST_POSTGRES_B_URL', 'BPC_TEST_POSTGRES_CONTROL_URL',
  'BPC_TEST_REDIS_URLS', 'TSK_TEST_POSTGRES_URL_A', 'TSK_TEST_POSTGRES_URL_B',
  'TSK_TEST_SOURCE_PG_URL_A', 'TSK_TEST_RECEIVER_PG_URL_B',
  'TSK_TEST_CONTROL_PG_URL', 'TSK_TEST_REDIS_URL',
  'ULTRA_TEST_POSTGRES_URL_A', 'ULTRA_TEST_POSTGRES_URL_B',
]);

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

export const ACCEPTANCE_STEPS = Object.freeze([
  Object.freeze({
    id: 'bpc-authority-ha', component: 'bpc-protocol',
    args: ['run', 'test:ha:acceptance'],
    markers: [
      '# BPC #16 frozen HA acceptance', 'data-loss-RPO=0',
      'promotion: B writable at epoch=2 and originated N+1',
      'split-brain: signed equal-epoch competing quorum claim rejected',
    ],
  }),
  Object.freeze({
    id: 'tsk-credential-authority', component: 'tsk-protocol',
    args: ['run', 'test:credential-authority'],
    markers: ['"checks":48', '"duplicateEffects":0', '"staleWritesAdmitted":0', '"secretBearingReplicaRecords":0'],
  }),
  Object.freeze({
    id: 'tsk-process-sigkill', component: 'tsk-protocol',
    args: ['run', 'test:sigkill'],
    markers: ['RPO  : 0', 'PR2c SIGKILL-matrix checks passed'],
  }),
  Object.freeze({
    id: 'tsk-source-activation', component: 'tsk-protocol',
    args: ['run', 'test:b-activation'],
    markers: ['B originates N+1', 'B-source-activation checks passed'],
  }),
  Object.freeze({
    id: 'enterprise-independent-failover-failback', component: 'selfconnect-enterprise',
    cwd: HERE, args: ['run', 'test:independent-state'],
    markers: ['same-principal failback A -> B -> A completed', 'fail 0'],
  }),
  Object.freeze({
    id: 'enterprise-authenticated-outbox', component: 'selfconnect-enterprise',
    cwd: HERE, args: ['run', 'test:ultra-outbox'], markers: ['# fail 0'],
  }),
  Object.freeze({
    id: 'tsk-redis-sentinel-crash', component: 'tsk-protocol',
    args: ['run', 'test:sentinel'], markers: ['RPO  : 0', 'Sentinel-failover checks passed'],
  }),
  Object.freeze({
    id: 'tsk-live-redis-partition', component: 'tsk-protocol',
    args: ['run', 'test:partition'], markers: ['RPO  : 0', 'split-brain-partition checks passed'],
  }),
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function requiredPath(value, name) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new Error(`${name} is required`);
  }
  return resolve(value);
}

export function assertStepEvidence(step, output) {
  for (const marker of step.markers) {
    if (!output.includes(marker)) throw new Error(`${step.id} did not emit required evidence: ${marker}`);
  }
}

export function evidenceLines(step, output) {
  const lines = output.split(/\r?\n/).filter((line) =>
    step.markers.some((marker) => line.includes(marker)) || /\b(?:RPO|RTO)\b/.test(line),
  ).slice(0, 24).map((line) => line.trim().slice(0, 500));
  if (lines.some((line) => /(?:postgres(?:ql)?:\/\/|redis:\/\/|PRIVATE KEY|sharedSecret|password)/i.test(line))) {
    throw new Error(`${step.id} emitted secret-like material in an evidence line`);
  }
  return Object.freeze(lines);
}

export function validatePins(lock, roots) {
  for (const component of ['bpc-protocol', 'tsk-protocol']) {
    const expected = lock?.components?.[component]?.commit;
    if (!SHA.test(expected ?? '')) throw new Error(`${component} pin is invalid`);
    if (!roots[component]) throw new Error(`${component} root is required`);
  }
}

async function capture(command, args, { cwd, env, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, { cwd, env, shell: false, windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    let size = 0;
    let overflow = false;
    const collect = (chunk) => {
      size += chunk.length;
      if (size > MAX_OUTPUT_BYTES) { overflow = true; child.kill('SIGKILL'); return; }
      chunks.push(Buffer.from(chunk));
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.once('error', (error) => { clearTimeout(timer); rejectPromise(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      const output = Buffer.concat(chunks).toString('utf8');
      if (overflow) return rejectPromise(new Error(`command output exceeded ${MAX_OUTPUT_BYTES} bytes`));
      if (code !== 0) return rejectPromise(new Error(
        `command failed (code=${code}, signal=${signal ?? 'none'}): ${output.slice(-4000)}`,
      ));
      resolvePromise(output);
    });
  });
}

async function gitHead(root) {
  return (await capture('git', ['rev-parse', 'HEAD'], { cwd: root, env: process.env,
    timeoutMs: 30_000 })).trim();
}

export async function assertCleanReviewedCheckout(root, expected) {
  if (!SHA.test(expected ?? '')) throw new Error('ULTRA_FINAL_EXPECTED_ENTERPRISE_SHA must be a full commit SHA');
  const actual = await gitHead(root);
  if (actual !== expected) throw new Error(`Enterprise checkout mismatch: expected ${expected}, got ${actual}`);
  const status = await capture('git', ['status', '--porcelain'], {
    cwd: root, env: process.env, timeoutMs: 30_000,
  });
  if (status.trim() !== '') throw new Error('Enterprise checkout must be clean for final acceptance');
  return actual;
}

export async function runFinalAcceptance(options = {}) {
  for (const name of REQUIRED_ENV) {
    if (!process.env[name]) throw new Error(`${name} is required (final acceptance never skips)`);
  }
  const lock = JSON.parse(await readFile(resolve(REPO, 'portfolio-lock.json'), 'utf8'));
  const enterpriseCommit = await assertCleanReviewedCheckout(
    REPO, process.env.ULTRA_FINAL_EXPECTED_ENTERPRISE_SHA,
  );
  const roots = {
    'bpc-protocol': requiredPath(options.bpcRoot ?? process.env.BPC_PROTOCOL_ROOT, 'BPC_PROTOCOL_ROOT'),
    'tsk-protocol': requiredPath(options.tskRoot ?? process.env.TSK_PROTOCOL_ROOT, 'TSK_PROTOCOL_ROOT'),
    'selfconnect-enterprise': REPO,
  };
  validatePins(lock, roots);
  for (const component of ['bpc-protocol', 'tsk-protocol']) {
    const actual = await gitHead(roots[component]);
    const expected = lock.components[component].commit;
    if (actual !== expected) throw new Error(`${component} checkout mismatch: expected ${expected}, got ${actual}`);
  }

  const startedAt = new Date().toISOString();
  const results = [];
  for (const step of ACCEPTANCE_STEPS) {
    const start = Date.now();
    const output = await capture(npm, step.args, {
      cwd: step.cwd ?? roots[step.component], env: { ...process.env, NO_COLOR: '1' },
      timeoutMs: Number(process.env.ULTRA_FINAL_STEP_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS),
    });
    assertStepEvidence(step, output);
    results.push(Object.freeze({ id: step.id, durationMs: Date.now() - start,
      outputSha256: sha256(output), evidence: evidenceLines(step, output) }));
    process.stdout.write(`ok - ${step.id} (${results.at(-1).durationMs}ms)\n`);
  }
  const evidence = Object.freeze({
    schemaVersion: 1,
    claim: 'named controlled-deployment Ultra HA topology accepted',
    exclusions: Object.freeze([
      'government authorization', 'compliance certification', 'legal admissibility',
      'availability outside the recorded topology',
    ]),
    topology: Object.freeze({ bpcPostgresAuthorities: 3,
      tskAndUltraPostgresAuthorities: 3, postgresAuthoritiesTotal: 6,
      redisDataNodes: 3, redisSentinels: 3, ultraAuthorities: 2 }),
    commits: Object.freeze({
      enterprise: enterpriseCommit,
      bpc: lock.components['bpc-protocol'].commit,
      tsk: lock.components['tsk-protocol'].commit,
    }),
    startedAt, finishedAt: new Date().toISOString(), results: Object.freeze(results),
  });
  const evidencePath = requiredPath(
    options.evidenceFile ?? process.env.ULTRA_FINAL_EVIDENCE_FILE, 'ULTRA_FINAL_EVIDENCE_FILE',
  );
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`# final Ultra HA acceptance: ${results.length}/${ACCEPTANCE_STEPS.length} steps; evidence=${evidencePath}\n`);
  return evidence;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await runFinalAcceptance();
}
