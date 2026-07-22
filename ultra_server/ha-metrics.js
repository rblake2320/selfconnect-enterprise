// ultra_server/ha-metrics.js — Bounded-cardinality label helpers for the HA
// fault-signal metrics (docs/assurance/ha_test_coverage.json: monitoring-alerting).
//
// server.js owns the actual prom-client Counter/Gauge instances (as it already
// does for ultra_http_requests_total etc.); this module only decides what
// label value a raw internal reason/stage string collapses to, exactly like
// metricRouteLabel/metricAuthFailureLabel in monitoring-security.js. Keeping
// this pure (no prom-client import) means it can be unit-tested without
// touching the global metrics registry.

// Reasons ha-controller.js's applyCommand() can return in outcome.result.error
// (commandShapeError() plus the explicit denial branches). Anything outside
// this set collapses to '__other__' so a future new error string cannot
// silently create unbounded label cardinality on ultra_ha_promotion_denied_total.
const PROMOTION_DENIAL_REASONS = new Set([
  'invalid_body',
  'unexpected_command_field',
  'invalid_command',
  'invalid_command_id',
  'invalid_node_id',
  'invalid_cluster_id',
  'invalid_fence_epoch',
  'invalid_time',
  'invalid_actor',
  'invalid_reason',
  'invalid_signature',
  'signature_invalid',
  'wrong_cluster_or_node',
  'command_stale',
  'invalid_lease_window',
  'lease_window_too_short',
  'wrong_command_for_role',
  'lease_mismatch',
  'fence_release_failed',
  'fence_epoch_not_monotonic',
  'fencing_authority_unavailable',
]);

// Stages that can fail during HA recovery/reprovisioning/reload.
const RECOVERY_FAILURE_STAGES = new Set([
  'tsk_reprovision',
  'tsk_authority_reload',
  'sighup_reload',
]);

export function haPromotionDenialLabel(reason) {
  return typeof reason === 'string' && PROMOTION_DENIAL_REASONS.has(reason) ? reason : '__other__';
}

export function haRecoveryFailureStageLabel(stage) {
  return typeof stage === 'string' && RECOVERY_FAILURE_STAGES.has(stage) ? stage : '__other__';
}

export const HA_PROMOTION_DENIAL_LABEL_LIMIT = PROMOTION_DENIAL_REASONS.size + 1;
export const HA_RECOVERY_FAILURE_STAGE_LABEL_LIMIT = RECOVERY_FAILURE_STAGES.size + 1;

// fenceStore.applyCommand() only returns { status: 200 } on success, so any
// other outcome is a denial the caller must count.
export function isHaCommandDenied(outcomeStatus) {
  return typeof outcomeStatus === 'number' && outcomeStatus !== 200;
}
