import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

function run(configPath, command = 'publish-once') {
  return () => execFileSync(process.execPath, [
    'ultra-state-stream-command.mjs', command, configPath,
  ], {
    cwd: new URL('.', import.meta.url),
    env: { ...process.env, DATABASE_URL: '' },
    encoding: 'utf8',
    stdio: 'pipe',
  });
}

test('stream command refuses remote plaintext and non-loopback listener before database access', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ultra-stream-config-'));
  try {
    const publisher = join(directory, 'publisher.json');
    const receiver = join(directory, 'receiver.json');
    await writeFile(publisher, JSON.stringify({ url: 'http://example.com/v1/ultra-state' }));
    await writeFile(receiver, JSON.stringify({ host: '0.0.0.0', port: 7781 }));
    assert.throws(run(publisher), /plaintext Ultra state transport is restricted to loopback/);
    assert.throws(run(receiver, 'receiver'), /built-in receiver binds loopback only/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
