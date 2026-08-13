import assert from 'node:assert/strict';
import test from 'node:test';

import {
  independentStateAllowsWrites,
  loadIndependentStateRuntimeConfig,
} from './independent-state.js';

const ha = { enabled: true, clusterId: 'cluster-1' };

test('independent-state runtime mode defaults to shared and requires production HA', () => {
  assert.deepEqual(loadIndependentStateRuntimeConfig({}, { enabled: false }, 'development'), {
    mode: 'shared', expected: null,
  });
  assert.throws(() => loadIndependentStateRuntimeConfig(
    { ULTRA_HA_STATE_MODE: 'independent' }, { enabled: false }, 'production',
  ), /requires production HA/);
  assert.throws(() => loadIndependentStateRuntimeConfig(
    { ULTRA_HA_STATE_MODE: 'independent' }, ha, 'development',
  ), /requires production HA/);
});

test('independent-state promotion pins are all-or-none and strictly validated', () => {
  assert.deepEqual(loadIndependentStateRuntimeConfig(
    { ULTRA_HA_STATE_MODE: 'independent' }, ha, 'production',
  ), { mode: 'independent', expected: null });
  assert.throws(() => loadIndependentStateRuntimeConfig({
    ULTRA_HA_STATE_MODE: 'independent', ULTRA_HA_REQUIRED_COMMAND_ID: 'command-1',
  }, ha, 'production'), /configured together/);
  const configured = loadIndependentStateRuntimeConfig({
    ULTRA_HA_STATE_MODE: 'independent',
    ULTRA_HA_REQUIRED_COMMAND_ID: 'command-1',
    ULTRA_HA_REQUIRED_SOURCE_EPOCH: '2',
    ULTRA_HA_REQUIRED_MANIFEST_DIGEST: 'a'.repeat(64),
  }, ha, 'production');
  assert.deepEqual(configured.expected, {
    clusterId: 'cluster-1', commandId: 'command-1', sourceEpoch: 2, manifestDigest: 'a'.repeat(64),
  });
  assert.throws(() => loadIndependentStateRuntimeConfig({
    ULTRA_HA_STATE_MODE: 'independent',
    ULTRA_HA_REQUIRED_COMMAND_ID: 'command-1',
    ULTRA_HA_REQUIRED_SOURCE_EPOCH: '0',
    ULTRA_HA_REQUIRED_MANIFEST_DIGEST: 'a'.repeat(64),
  }, ha, 'production'), /positive safe integer/);
});

test('every HA writer route fails closed until independent state is attested', () => {
  assert.equal(independentStateAllowsWrites('independent', null), false);
  assert.equal(independentStateAllowsWrites('independent', Object.freeze({ attested: true })), true);
  assert.equal(independentStateAllowsWrites('shared', null), true);
});
