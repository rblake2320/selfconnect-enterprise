import { signGuardCommand } from '@tsk/server';

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error(`invalid argument near ${key ?? '<end>'}`);
    values.set(key.slice(2), value);
  }
  return values;
}

function required(values, key) {
  const value = values.get(key);
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

const args = parseArgs(process.argv.slice(2));
const guardSecret = process.env.ULTRA_HA_GUARD_SECRET;
const adminToken = process.env.ULTRA_ADMIN_TOKEN;
if (!guardSecret || Buffer.byteLength(guardSecret, 'utf8') < 32) {
  throw new Error('ULTRA_HA_GUARD_SECRET must contain at least 32 bytes');
}
if (!adminToken) throw new Error('ULTRA_ADMIN_TOKEN is required');

const url = new URL(required(args, 'url'));
if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
  throw new Error('--url must be an HTTP(S) URL without embedded credentials');
}
const command = required(args, 'command');
if (!['activate', 'promote', 'demote'].includes(command)) {
  throw new Error('--command must be activate, promote, or demote');
}
const fenceEpoch = Number(required(args, 'fence-epoch'));
if (!Number.isSafeInteger(fenceEpoch) || fenceEpoch < 1) {
  throw new Error('--fence-epoch must be a positive safe integer');
}
const leaseMs = Number(args.get('lease-ms') ?? '60000');
if (!Number.isSafeInteger(leaseMs) || leaseMs < 1) throw new Error('--lease-ms must be a positive safe integer');

const issuedAt = Date.now();
const signed = signGuardCommand({
  by: args.get('by') ?? 'ultra-operator',
  clusterId: required(args, 'cluster-id'),
  command,
  expiresAt: issuedAt + leaseMs,
  fenceEpoch,
  issuedAt,
  nodeId: required(args, 'node-id'),
  reason: args.get('reason') ?? 'operator-controlled transition',
}, guardSecret);

const response = await fetch(new URL('/ha/command', url), {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${adminToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify(signed),
});
const body = await response.json().catch(() => ({}));
console.log(JSON.stringify({ status: response.status, body }));
if (!response.ok) process.exitCode = 1;
