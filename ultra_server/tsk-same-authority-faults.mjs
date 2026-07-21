import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

import { Redis } from 'ioredis';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const now = () => Number(process.hrtime.bigint() / 1_000_000n);

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function digest(value) {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

function docker(...args) {
  return execFileSync('docker', args, { encoding: 'utf8', windowsHide: true }).trim();
}

function dockerSafe(...args) {
  try { return docker(...args); } catch (error) {
    return `${String(error?.stdout ?? '')}${String(error?.stderr ?? '')}${error?.message ?? ''}`;
  }
}

async function waitFor(label, operation, timeoutMs = 35_000, everyMs = 250) {
  const deadline = now() + timeoutMs;
  let last;
  while (now() < deadline) {
    try { return await operation(); } catch (error) { last = error; await sleep(everyMs); }
  }
  throw new Error(`${label} timed out: ${String(last?.message ?? last)}`);
}

function redisClient(redis) {
  return new Redis({ sentinels: redis.sentinels, name: redis.masterName, role: 'master',
    natMap: redis.natMap, maxRetriesPerRequest: 4, sentinelRetryStrategy: () => 200 });
}

function assertExactRecord(actual, expected) {
  assert.deepEqual(actual, expected, 'the exact TSK fencing tuple must survive the fault');
  return actual;
}

/**
 * Fault the same Sentinel authority that ratified the live TSK cutover. The
 * returned receipt contains no credentials and is bound to the exact command,
 * stream, PostgreSQL authorities, Redis key, and pre-fault tuple.
 */
export async function runSameTskRedisAuthorityFaults(options) {
  const { authority, commandId, redis, streamId, systemIds, topology } = options;
  assert.equal(authority.record.commandId, commandId);
  assert.equal(redis.kind, 'sentinel');
  const admin = new Redis({ host: redis.sentinels[0].host, port: redis.sentinels[0].port,
    maxRetriesPerRequest: 2 });
  admin.on('error', () => {});
  const masterAddress = async () => await admin.call(
    'SENTINEL', 'get-master-addr-by-name', redis.masterName,
  );
  const containerByAddress = new Map(Object.entries(topology.nodes).map(
    ([address, node]) => [address, node],
  ));
  let client = redisClient(redis);
  client.on('error', () => {});
  let disconnected;
  let stopped;
  try {
    await waitFor('same TSK authority readable', async () => {
      const raw = await client.get(authority.key);
      if (!raw) throw new Error('authority key missing');
      return assertExactRecord(JSON.parse(raw), authority.record);
    });

    const oldAddress = (await masterAddress()).join(':');
    const oldNode = containerByAddress.get(oldAddress);
    if (!oldNode) throw new Error(`unrecognized Sentinel master ${oldAddress}`);
    const partitionStart = now();
    docker('network', 'disconnect', topology.network, oldNode.container);
    disconnected = oldNode;
    await waitFor('isolated old master refuses writes', async () => {
      const output = dockerSafe('exec', oldNode.container, 'redis-cli', 'SET',
        'enterprise28:isolated-write-probe', 'forbidden');
      if (!/NOREPLICAS|not enough|good replica/i.test(output)) {
        throw new Error(`isolated master response: ${output}`);
      }
      return true;
    }, 30_000, 500);
    const promotedAddress = await waitFor('Sentinel promotion after partition', async () => {
      const value = (await masterAddress()).join(':');
      if (value === oldAddress) throw new Error('old master remains elected');
      return value;
    });
    client.disconnect();
    client = redisClient(redis);
    client.on('error', () => {});
    await waitFor('exact authority tuple on partition survivor', async () => {
      const raw = await client.get(authority.key);
      if (!raw) throw new Error('authority key missing after partition');
      return assertExactRecord(JSON.parse(raw), authority.record);
    });
    await waitFor('partition survivor durably writable', async () => {
      await client.set('enterprise28:survivor-probe', commandId);
      const acked = Number(await client.call('WAIT', '1', '3000'));
      if (acked < 1) throw new Error(`only ${acked} replica acknowledgements`);
      return true;
    });
    const partitionRtoMs = now() - partitionStart;

    docker('network', 'connect', '--ip', oldNode.ip, topology.network, oldNode.container);
    disconnected = undefined;
    await waitFor('old master demoted and reconciled', async () => {
      const role = docker('exec', oldNode.container, 'redis-cli', 'ROLE').split(/\r?\n/)[0];
      if (role.trim() !== 'slave') throw new Error(`role=${role}`);
      const raw = docker('exec', oldNode.container, 'redis-cli', 'GET', authority.key);
      if (!raw) throw new Error('authority absent on healed node');
      assertExactRecord(JSON.parse(raw), authority.record);
      return true;
    });

    const crashAddress = (await masterAddress()).join(':');
    const crashNode = containerByAddress.get(crashAddress);
    if (!crashNode) throw new Error(`unrecognized promoted master ${crashAddress}`);
    const crashStart = now();
    docker('kill', '-s', 'KILL', crashNode.container);
    stopped = crashNode;
    await waitFor('Sentinel promotion after master crash', async () => {
      const value = (await masterAddress()).join(':');
      if (value === crashAddress) throw new Error('crashed master remains elected');
      return value;
    });
    client.disconnect();
    client = redisClient(redis);
    client.on('error', () => {});
    await waitFor('exact authority tuple on crash survivor', async () => {
      const raw = await client.get(authority.key);
      if (!raw) throw new Error('authority key missing after crash');
      return assertExactRecord(JSON.parse(raw), authority.record);
    });
    await waitFor('crash survivor durably writable', async () => {
      await client.set('enterprise28:crash-survivor-probe', commandId);
      const acked = Number(await client.call('WAIT', '1', '3000'));
      if (acked < 1) throw new Error(`only ${acked} replica acknowledgements`);
      return true;
    });
    const crashRtoMs = now() - crashStart;

    return Object.freeze({ schemaVersion: 1, kind: 'tsk-same-redis-authority-faults',
      commandId, streamId, systemIds: Object.freeze({ ...systemIds }),
      redisAuthorityKeyDigest: digest(authority.key),
      redisAuthorityTupleDigest: digest(authority.record),
      fenceEpoch: authority.record.fenceEpoch,
      faults: Object.freeze({
        livePartition: Object.freeze({ rpo: 0, rtoMs: partitionRtoMs,
          oldMasterRefusedWrites: true, exactTuplePreserved: true,
          promotedMasterAddressDigest: digest(promotedAddress) }),
        masterSigkill: Object.freeze({ rpo: 0, rtoMs: crashRtoMs,
          exactTuplePreserved: true }),
      }) });
  } finally {
    try { client?.disconnect(); } catch { /* already disconnected */ }
    try { admin.disconnect(); } catch { /* already disconnected */ }
    if (disconnected) dockerSafe('network', 'connect', '--ip', disconnected.ip,
      topology.network, disconnected.container);
    if (stopped) dockerSafe('start', stopped.container);
  }
}
