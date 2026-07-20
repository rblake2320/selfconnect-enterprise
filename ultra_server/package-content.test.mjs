import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const expectedRuntimeFiles = [
  '.env.example',
  'README.md',
  'agent-auth.js',
  'ha-command.mjs',
  'ha-controller.js',
  'independent-state-command.mjs',
  'independent-state.js',
  'monitoring-security.js',
  'recovery-token.js',
  'runtime-stores.js',
  'security-boundary.js',
  'server.js',
  'ultra-state-outbox.js',
  'ultra-state-stream-command.mjs',
];

test('npm package uses an explicit runtime-only file allowlist', async () => {
  const packageJson = JSON.parse(
    await readFile(new URL('./package.json', import.meta.url), 'utf8'),
  );

  assert.equal(packageJson.private, true);
  assert.deepEqual([...packageJson.files].sort(), [...expectedRuntimeFiles].sort());
  assert.equal(packageJson.files.some((path) => path.includes('*')), false);
  assert.equal(
    packageJson.files.some((path) => /(?:\.log|\.jsonl?|\.pem|\.key)$/i.test(path)),
    false,
  );

  const executable = process.platform === 'win32' ? (process.env.ComSpec ?? 'cmd.exe') : 'npm';
  const args = process.platform === 'win32'
    ? ['/d', '/s', '/c', 'npm pack --dry-run --json']
    : ['pack', '--dry-run', '--json'];
  const pack = JSON.parse(execFileSync(executable, args, {
    cwd: new URL('.', import.meta.url),
    encoding: 'utf8',
  }));
  const packedPaths = pack[0].files.map(({ path }) => path).sort();
  assert.deepEqual(
    packedPaths,
    [...expectedRuntimeFiles, 'package.json'].sort(),
  );
});
