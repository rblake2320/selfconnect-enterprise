import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createUltraRedisClient,
  loadUltraRedisAuthorityConfig,
} from './ultra-redis-authority.js';

test('Ultra HA Redis config requires a distinct three-Sentinel durable authority', () => {
  const config = loadUltraRedisAuthorityConfig({
    ULTRA_HA_REDIS_SENTINELS: '127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381',
    ULTRA_HA_REDIS_MASTER_NAME: 'ultramaster',
    ULTRA_HA_REDIS_NATMAP: '10.0.0.1:6379=127.0.0.1:6390',
    ULTRA_HA_REDIS_WAIT_REPLICAS: '2',
    ULTRA_HA_REDIS_WAIT_TIMEOUT_MS: '4000',
  }, { haEnabled: true });
  assert.equal(config.kind, 'sentinel');
  assert.equal(config.sentinels.length, 3);
  assert.deepEqual(config.durability, { waitReplicas: 2, waitTimeoutMs: 4000 });
  assert.deepEqual(config.natMap['10.0.0.1:6379'], { host: '127.0.0.1', port: 6390 });
  assert.throws(() => loadUltraRedisAuthorityConfig({
    ULTRA_HA_REDIS_SENTINELS: 'a:1,b:2', ULTRA_HA_REDIS_MASTER_NAME: 'm',
  }, { haEnabled: true }), /at least three/);
  assert.throws(() => loadUltraRedisAuthorityConfig({
    ULTRA_HA_REDIS_SENTINELS: 'a:1,a:1,a:1', ULTRA_HA_REDIS_MASTER_NAME: 'm',
  }, { haEnabled: true }), /distinct/);
  assert.throws(() => loadUltraRedisAuthorityConfig({
    ULTRA_HA_REDIS_SENTINELS: 'a:1,b:2,c:3', ULTRA_HA_REDIS_MASTER_NAME: 'm',
    ULTRA_HA_REDIS_WAIT_REPLICAS: '0',
  }, { haEnabled: true }), /WAIT_REPLICAS/);
});

test('Redis client construction binds Sentinel master discovery and disables offline queuing', () => {
  const calls = [];
  class FakeRedis {
    constructor(...args) { calls.push(args); }
  }
  const config = loadUltraRedisAuthorityConfig({
    ULTRA_HA_REDIS_SENTINELS: 's1:1,s2:2,s3:3',
    ULTRA_HA_REDIS_MASTER_NAME: 'ultramaster',
  }, { haEnabled: true });
  createUltraRedisClient(FakeRedis, config);
  const options = calls[0][0];
  assert.equal(options.name, 'ultramaster');
  assert.equal(options.role, 'master');
  assert.equal(options.enableOfflineQueue, false);
  assert.equal(options.maxRetriesPerRequest, 1);
});

test('non-HA compatibility mode remains URL-bound without a durability claim', () => {
  assert.deepEqual(loadUltraRedisAuthorityConfig({ REDIS_URL: 'redis://127.0.0.1:6379/0' }), {
    kind: 'url', url: 'redis://127.0.0.1:6379/0', durability: null,
  });
});
