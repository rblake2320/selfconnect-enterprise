const HOST = /^[A-Za-z0-9._-]{1,253}$/;
const MASTER = /^[A-Za-z0-9._-]{1,128}$/;

function positiveInteger(value, name, { min = 1, max = 60_000 } = {}) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer in [${min},${max}]`);
  }
  return parsed;
}

function endpoint(value, name) {
  if (typeof value !== 'string' || value.length > 512 || value.includes('\0')) {
    throw new Error(`${name} is invalid`);
  }
  const match = /^([^:]+):(\d{1,5})$/.exec(value.trim());
  if (!match || !HOST.test(match[1])) throw new Error(`${name} must be host:port`);
  return Object.freeze({ host: match[1], port: positiveInteger(match[2], `${name}.port`, { max: 65_535 }) });
}

function sentinelList(value) {
  if (typeof value !== 'string' || value.length > 4096) {
    throw new Error('ULTRA_HA_REDIS_SENTINELS is invalid');
  }
  const sentinels = value.split(',').map((item, index) => endpoint(
    item, `ULTRA_HA_REDIS_SENTINELS[${index}]`,
  ));
  if (sentinels.length < 3) throw new Error('Ultra HA requires at least three Redis Sentinels');
  const unique = new Set(sentinels.map(({ host, port }) => `${host}:${port}`));
  if (unique.size !== sentinels.length) throw new Error('Redis Sentinel endpoints must be distinct');
  return Object.freeze(sentinels);
}

function natMap(value) {
  if (value === undefined || value === '') return Object.freeze({});
  if (typeof value !== 'string' || value.length > 8192) throw new Error('ULTRA_HA_REDIS_NATMAP is invalid');
  const result = {};
  for (const [index, entry] of value.split(',').entries()) {
    const [internal, external, ...rest] = entry.split('=');
    if (rest.length !== 0) throw new Error(`ULTRA_HA_REDIS_NATMAP[${index}] is invalid`);
    const source = endpoint(internal, `ULTRA_HA_REDIS_NATMAP[${index}].source`);
    const target = endpoint(external, `ULTRA_HA_REDIS_NATMAP[${index}].target`);
    result[`${source.host}:${source.port}`] = target;
  }
  return Object.freeze(result);
}

export function loadUltraRedisAuthorityConfig(env, { haEnabled = false } = {}) {
  const sentinelValue = env.ULTRA_HA_REDIS_SENTINELS;
  if (sentinelValue) {
    if (!haEnabled) throw new Error('Redis Sentinel authority requires Ultra HA mode');
    const masterName = env.ULTRA_HA_REDIS_MASTER_NAME;
    if (typeof masterName !== 'string' || !MASTER.test(masterName)) {
      throw new Error('ULTRA_HA_REDIS_MASTER_NAME is invalid');
    }
    return Object.freeze({
      kind: 'sentinel',
      masterName,
      natMap: natMap(env.ULTRA_HA_REDIS_NATMAP),
      sentinels: sentinelList(sentinelValue),
      durability: Object.freeze({
        waitReplicas: positiveInteger(env.ULTRA_HA_REDIS_WAIT_REPLICAS ?? 1,
          'ULTRA_HA_REDIS_WAIT_REPLICAS', { max: 16 }),
        waitTimeoutMs: positiveInteger(env.ULTRA_HA_REDIS_WAIT_TIMEOUT_MS ?? 3_000,
          'ULTRA_HA_REDIS_WAIT_TIMEOUT_MS'),
      }),
    });
  }
  if (typeof env.REDIS_URL !== 'string' || env.REDIS_URL.length < 1 ||
      env.REDIS_URL.length > 8192 || env.REDIS_URL.includes('\0')) {
    throw new Error('REDIS_URL is required when Redis Sentinel is not configured');
  }
  return Object.freeze({ kind: 'url', url: env.REDIS_URL, durability: null });
}

export function createUltraRedisClient(Redis, config) {
  if (typeof Redis !== 'function') throw new Error('Redis constructor is required');
  const common = {
    lazyConnect: true,
    commandTimeout: 2_000,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
  };
  if (config.kind === 'sentinel') {
    return new Redis({
      ...common,
      sentinels: config.sentinels,
      name: config.masterName,
      role: 'master',
      natMap: config.natMap,
      sentinelRetryStrategy: () => 200,
    });
  }
  return new Redis(config.url, common);
}
