#!/usr/bin/env node
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';

import { NodePostgresTransactor, PgReplayNonceStore, assertSchemaReady } from '@bpc/server';
import { Pool } from 'pg';

import { createUltraStateHttpPublisher, createUltraStateHttpReceiver } from './ultra-state-outbox.js';

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

function usage() {
  throw new Error('usage: ultra-state-stream-command.mjs receiver|publish-once CONFIG_JSON');
}

function required(value, name) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function positiveInt(value, name, fallback) {
  value ??= fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

async function secretFile(path, name) {
  const secret = await readFile(required(path, name));
  if (secret.length < 32) throw new Error(`${name} must contain at least 32 bytes`);
  return Buffer.from(secret);
}

async function privateEd25519(path, name) {
  const key = createPrivateKey(await readFile(required(path, name)));
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${name} must contain a private Ed25519 key`);
  }
  return key;
}

async function publicKeyResolver(files, name) {
  if (!files || typeof files !== 'object' || Array.isArray(files) || Object.keys(files).length === 0) {
    throw new Error(`${name} must be a non-empty keyId-to-file map`);
  }
  const keys = new Map();
  for (const [keyId, path] of Object.entries(files)) {
    const encoded = await readFile(required(path, `${name}.${keyId}`));
    if (encoded.toString('ascii').includes('PRIVATE KEY')) {
      throw new Error(`${name}.${keyId} must not contain private key material`);
    }
    const key = createPublicKey(encoded);
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
      throw new Error(`${name}.${keyId} must contain a public Ed25519 key`);
    }
    keys.set(keyId, key);
  }
  return (keyId) => keys.get(keyId) ?? null;
}

function transportUrl(value) {
  const url = new URL(required(value, 'url'));
  if (url.username || url.password || url.hash) throw new Error('url credentials and fragments are forbidden');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    throw new Error('plaintext Ultra state transport is restricted to loopback');
  }
  return url.toString();
}

async function database(config) {
  const pool = new Pool({ connectionString: required(process.env.DATABASE_URL, 'DATABASE_URL') });
  try {
    await pool.query('SELECT 1');
    const db = new NodePostgresTransactor(pool, {
      statementTimeoutMs: positiveInt(config.statementTimeoutMs, 'statementTimeoutMs', 30_000),
      transactionTimeoutMs: positiveInt(config.transactionTimeoutMs, 'transactionTimeoutMs', 35_000),
    });
    const ready = await assertSchemaReady(db, config.schema ?? 'public');
    return { db, pool, ready };
  } catch (error) {
    await pool.end();
    throw error;
  }
}

async function receiver(config) {
  const host = config.host ?? '127.0.0.1';
  if (!LOOPBACK.has(host)) {
    throw new Error('the built-in receiver binds loopback only; expose it through an authenticated TLS proxy');
  }
  const port = positiveInt(config.port, 'port', 7781);
  if (port > 65_535) throw new Error('port must be at most 65535');
  const requestKeyId = required(config.requestKeyId, 'requestKeyId');
  const responseKeyId = required(config.responseKeyId, 'responseKeyId');
  const ackKeyId = required(config.ackKeyId, 'ackKeyId');
  const requestSecret = await secretFile(config.requestSecretFile, 'requestSecretFile');
  const responseSecret = await secretFile(config.responseSecretFile, 'responseSecretFile');
  const ackPrivateKey = await privateEd25519(config.ackPrivateKeyFile, 'ackPrivateKeyFile');
  const resolveAckPublicKey = await publicKeyResolver(config.ackPublicKeyFiles, 'ackPublicKeyFiles');
  const configuredAckPublicKey = resolveAckPublicKey(ackKeyId);
  if (!configuredAckPublicKey || !createPublicKey(ackPrivateKey).equals(configuredAckPublicKey)) {
    throw new Error('ackPrivateKeyFile does not match ackPublicKeyFiles[ackKeyId]');
  }
  const { db, pool, ready } = await database(config);
  let server;
  try {
    const nonceStore = await PgReplayNonceStore.open(db, config.schema ?? 'public');
    const runtime = createUltraStateHttpReceiver({
      db, ready, nonceStore,
      streamId: required(config.streamId, 'streamId'),
      expectedPath: required(config.expectedPath, 'expectedPath'),
      resolveRequestKey: (keyId) => keyId === requestKeyId ? requestSecret : null,
      responseKeyId, responseSecret,
      receiverId: required(config.receiverId, 'receiverId'),
      ackKeyId, ackPrivateKey, resolveAckPublicKey,
      freshnessMs: positiveInt(config.freshnessMs, 'freshnessMs', 30_000),
      nonceSafetyMs: positiveInt(config.nonceSafetyMs, 'nonceSafetyMs', 30_000),
      maxBodyBytes: positiveInt(config.maxBodyBytes, 'maxBodyBytes', 1_048_576),
      bodyReadMs: positiveInt(config.bodyReadMs, 'bodyReadMs', 10_000),
    });
    server = createServer(runtime.handler);
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, resolve);
    });
  } catch (error) {
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    await pool.end();
    throw error;
  }
  const close = async () => {
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
  };
  process.once('SIGINT', () => void close().then(() => process.exit(0)));
  process.once('SIGTERM', () => void close().then(() => process.exit(0)));
  process.stdout.write(`${JSON.stringify({ ok: true, mode: 'receiver', host, port })}\n`);
}

async function publishOnce(config) {
  const url = transportUrl(config.url);
  const requestKeyId = required(config.requestKeyId, 'requestKeyId');
  const responseKeyId = required(config.responseKeyId, 'responseKeyId');
  const { db, pool, ready } = await database(config);
  try {
    const requestSecret = await secretFile(config.requestSecretFile, 'requestSecretFile');
    const responseSecret = await secretFile(config.responseSecretFile, 'responseSecretFile');
    const resolveAckPublicKey = await publicKeyResolver(config.ackPublicKeyFiles, 'ackPublicKeyFiles');
    const runtime = createUltraStateHttpPublisher({
      db, ready, fetch: globalThis.fetch,
      streamId: required(config.streamId, 'streamId'),
      expectedReceiverId: required(config.expectedReceiverId, 'expectedReceiverId'),
      url,
      requestKeyId, requestSecret,
      resolveResponseKey: (keyId) => keyId === responseKeyId ? responseSecret : null,
      resolveAckPublicKey,
      timeoutMs: positiveInt(config.timeoutMs, 'timeoutMs', 15_000),
      maxRequestBytes: positiveInt(config.maxRequestBytes, 'maxRequestBytes', 1_048_576),
      maxResponseBytes: positiveInt(config.maxResponseBytes, 'maxResponseBytes', 262_144),
      leaseMs: positiveInt(config.leaseMs, 'leaseMs', 30_000),
    });
    const result = await runtime.publisher.drainOnce();
    process.stdout.write(`${JSON.stringify({ ok: true, mode: 'publish-once', ...result })}\n`);
  } finally {
    await pool.end();
  }
}

const [command, configPath] = process.argv.slice(2);
if (!command || !configPath) usage();
const config = JSON.parse(await readFile(configPath, 'utf8'));
if (command === 'receiver') await receiver(config);
else if (command === 'publish-once') await publishOnce(config);
else usage();
