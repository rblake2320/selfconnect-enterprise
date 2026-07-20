#!/usr/bin/env node
import { readFile, rename, writeFile } from 'node:fs/promises';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { Pool } from 'pg';

import {
  assertIndependentStateReady,
  exportIndependentState,
  guardCountersignIndependentState,
  importIndependentState,
} from './independent-state.js';

function usage() {
  throw new Error(
    'usage: independent-state-command.mjs export|countersign|import|ready INPUT_JSON [OUTPUT_JSON]',
  );
}

async function jsonFile(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function privateKey(path) {
  return createPrivateKey(await readFile(path));
}

async function publicKey(path) {
  const encoded = await readFile(path);
  if (encoded.toString('ascii').includes('PRIVATE KEY')) {
    throw new Error('verification key files must contain public keys only');
  }
  const key = createPublicKey(encoded);
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new Error('verification key files must contain public Ed25519 keys');
  }
  return key;
}

async function resolverFromFiles(files, name) {
  if (!files || typeof files !== 'object' || Array.isArray(files) || Object.keys(files).length === 0) {
    throw new Error(`${name} public-key file map is required`);
  }
  const keys = new Map();
  for (const [keyId, path] of Object.entries(files)) keys.set(keyId, await publicKey(path));
  return { resolve: (keyId) => keys.get(keyId) ?? null };
}

async function protocolResolvers(input) {
  return {
    bpcResolver: await resolverFromFiles(input.bpcPublicKeyFiles, 'BPC'),
    tskBResolver: await resolverFromFiles(input.tskBPublicKeyFiles, 'TSK B'),
    tskGuardResolver: await resolverFromFiles(input.tskGuardPublicKeyFiles, 'TSK guard'),
  };
}

async function atomicJson(path, value) {
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  await rename(temporary, path);
}

const [command, inputPath, outputPath] = process.argv.slice(2);
if (!command || !inputPath) usage();
const input = await jsonFile(inputPath);

if (command === 'countersign') {
  if (!outputPath) usage();
  const bundle = await jsonFile(input.sourceBundlePath);
  const result = guardCountersignIndependentState(bundle, {
    expectedCommandId: input.commandId,
    sourcePublicKey: await publicKey(input.sourcePublicKeyFile),
    guardKeyId: input.guardKeyId,
    guardPrivateKey: await privateKey(input.guardPrivateKeyFile),
    ...await protocolResolvers(input),
  });
  await atomicJson(outputPath, result);
  process.stdout.write(`${JSON.stringify({ ok: true, manifestDigest: result.manifestDigest })}\n`);
  process.exit(0);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const pool = new Pool({ connectionString: databaseUrl });
try {
  if (command === 'export') {
    if (!outputPath) usage();
    const result = await exportIndependentState(pool, {
      ...input,
      sourcePrivateKey: await privateKey(input.sourcePrivateKeyFile),
    });
    await atomicJson(outputPath, result);
    process.stdout.write(`${JSON.stringify({ ok: true, manifestDigest: result.manifestDigest })}\n`);
  } else if (command === 'import') {
    const bundle = await jsonFile(input.bundlePath);
    const result = await importIndependentState(pool, bundle, {
      ...input,
      sourcePublicKey: await publicKey(input.sourcePublicKeyFile),
      guardPublicKey: await publicKey(input.guardPublicKeyFile),
      ...await protocolResolvers(input),
    });
    process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
  } else if (command === 'ready') {
    const result = await assertIndependentStateReady(pool, input);
    process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
  } else {
    usage();
  }
} finally {
  await pool.end();
}
