import assert from 'node:assert/strict';
import test from 'node:test';

import { admitPostgresAuthorities } from './bpc-live-composition.mjs';

function fakePool(sequence) {
  let read = 0;
  let releases = 0;
  return {
    connect: async () => ({
      query: async () => ({ rows: [{
        system_identifier: sequence[Math.min(read++, sequence.length - 1)],
      }] }),
      release: () => { releases += 1; },
    }),
    get releases() { return releases; },
  };
}

function failingPool(error) {
  return { connect: async () => { throw error; } };
}

test('admits only stable distinct PostgreSQL authority identities', async () => {
  const pools = [fakePool(['11', '11']), fakePool(['22', '22']), fakePool(['33', '33'])];
  const result = await admitPostgresAuthorities(pools, { attempts: 2, delayMs: 0 });
  assert.deepEqual(result.identities.map((entry) => entry.systemIdentifier), ['11', '22', '33']);
  assert.equal(result.attempts, 2);
  assert.deepEqual(pools.map((pool) => pool.releases), [1, 1, 1]);
});

test('rejects a stable cloned authority and reports only role identities', async () => {
  const pools = [fakePool(['11', '11']), fakePool(['11', '11']), fakePool(['33', '33'])];
  await assert.rejects(
    () => admitPostgresAuthorities(pools, { attempts: 2, delayMs: 0 }),
    /source-a=11,promoted-b=11,control=33/,
  );
  assert.deepEqual(pools.map((pool) => pool.releases), [1, 1, 1]);
});

test('refuses unstable identity reads instead of admitting the last sample', async () => {
  const pools = [fakePool(['11', '12', '13']), fakePool(['21', '22', '23']),
    fakePool(['31', '32', '33'])];
  await assert.rejects(
    () => admitPostgresAuthorities(pools, { attempts: 3, delayMs: 0 }),
    /did not stabilize/,
  );
  assert.deepEqual(pools.map((pool) => pool.releases), [1, 1, 1]);
});

test('requires a second matching snapshot after a transient routing mismatch', async () => {
  const pools = [fakePool(['11', '11', '11']), fakePool(['11', '22', '22']),
    fakePool(['33', '33', '33'])];
  const result = await admitPostgresAuthorities(pools, { attempts: 3, delayMs: 0 });
  assert.deepEqual(result.identities.map((entry) => entry.systemIdentifier), ['11', '22', '33']);
  assert.equal(result.attempts, 3);
  assert.deepEqual(pools.map((pool) => pool.releases), [1, 1, 1]);
});

test('does not accept invalid identity or retry configuration', async () => {
  await assert.rejects(
    () => admitPostgresAuthorities([fakePool(['']), fakePool(['22']), fakePool(['33'])],
      { attempts: 2, delayMs: 0 }),
    /invalid system identifier/,
  );
  await assert.rejects(
    () => admitPostgresAuthorities([fakePool(['11']), fakePool(['22']), fakePool(['33'])],
      { attempts: 1, delayMs: 0 }),
    /retry configuration/,
  );
});

test('waits for peer connection settlement and releases successes on connect failure', async () => {
  const delayed = fakePool(['11']);
  let delayedSettled = false;
  const originalConnect = delayed.connect;
  delayed.connect = async () => {
    await new Promise((resolve) => setTimeout(resolve, 10));
    delayedSettled = true;
    return originalConnect();
  };
  const failure = new Error('connect refused');
  await assert.rejects(
    () => admitPostgresAuthorities([delayed, failingPool(failure), fakePool(['33'])],
      { attempts: 2, delayMs: 0 }),
    failure,
  );
  assert.equal(delayedSettled, true);
  assert.equal(delayed.releases, 1);
});

test('waits for all query results, releases every client, and preserves query failure', async () => {
  const failure = new Error('identity query failed');
  let delayedSettled = false;
  const delayed = fakePool(['33']);
  const originalConnect = delayed.connect;
  delayed.connect = async () => {
    const client = await originalConnect();
    const query = client.query;
    client.query = async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      delayedSettled = true;
      return query();
    };
    return client;
  };
  const broken = fakePool(['22']);
  const brokenConnect = broken.connect;
  broken.connect = async () => {
    const client = await brokenConnect();
    client.query = async () => { throw failure; };
    return client;
  };
  const first = fakePool(['11']);
  await assert.rejects(
    () => admitPostgresAuthorities([first, broken, delayed], { attempts: 2, delayMs: 0 }),
    failure,
  );
  assert.equal(delayedSettled, true);
  assert.deepEqual([first.releases, broken.releases, delayed.releases], [1, 1, 1]);
});

test('reports release failure only after successful identity admission', async () => {
  const releaseFailure = new Error('release failed');
  const brokenRelease = fakePool(['22', '22']);
  const originalConnect = brokenRelease.connect;
  brokenRelease.connect = async () => {
    const client = await originalConnect();
    const release = client.release;
    client.release = () => { release(); throw releaseFailure; };
    return client;
  };
  const first = fakePool(['11', '11']);
  const third = fakePool(['33', '33']);
  await assert.rejects(
    () => admitPostgresAuthorities([first, brokenRelease, third],
      { attempts: 2, delayMs: 0 }),
    releaseFailure,
  );
  assert.deepEqual([first.releases, brokenRelease.releases, third.releases], [1, 1, 1]);
});
