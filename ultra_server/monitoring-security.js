import { createHash, timingSafeEqual } from 'node:crypto';

const ROUTE_LABELS = new Set([
  '/bind-identity',
  '/bpc/pairs',
  '/bpc/pairs/:pairId',
  '/confirm-recovery',
  '/health',
  '/metrics',
  '/provision-tsk',
  '/pubkeys/:pairId',
  '/register-pair',
  '/resume-identity',
  '/rotate-tsk/commit',
  '/rotate-tsk/prepare',
  '/status',
  '/tsk/keys',
  '/tsk/keys/:clientId',
  '/verify',
  '/verify-recovery-token',
]);

const METHOD_LABELS = new Set(['GET', 'POST', 'PATCH']);
const AUTH_FAILURE_LABELS = new Set(['bpc', 'tsk', 'identity', 'unknown', 'exception']);

function reject(res, status, error) {
  return res.status(status).json({ ok: false, error });
}

function tokenDigest(token) {
  return createHash('sha256').update(token, 'utf8').digest();
}

export function createMetricsAuthMiddleware(metricsTokens) {
  const configured = (Array.isArray(metricsTokens) ? metricsTokens : [metricsTokens])
    .filter((token) => typeof token === 'string' && token.length > 0)
    .map(tokenDigest);

  return function requireMetricsAuth(req, res, next) {
    if (configured.length === 0) {
      return reject(res, 503, 'METRICS_AUTH_UNCONFIGURED');
    }
    const header = req.get('Authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const actual = tokenDigest(token);
    let accepted = false;
    for (const expected of configured) {
      accepted = timingSafeEqual(expected, actual) || accepted;
    }
    if (!accepted) {
      return reject(res, 401, 'METRICS_AUTH_REQUIRED');
    }
    return next();
  };
}

export function validateMetricsTokenConfiguration({
  runtimeMode,
  current,
  previous = null,
  adminTokens = [],
}) {
  if (runtimeMode === 'production' && !current) {
    throw new Error('production mode missing required setting: ULTRA_METRICS_TOKEN');
  }
  if (runtimeMode === 'production' && Buffer.byteLength(current, 'utf8') < 32) {
    throw new Error('ULTRA_METRICS_TOKEN must contain at least 32 bytes in production');
  }
  if (
    runtimeMode === 'production' &&
    previous &&
    Buffer.byteLength(previous, 'utf8') < 32
  ) {
    throw new Error(
      'ULTRA_METRICS_TOKEN_PREVIOUS must contain at least 32 bytes when configured in production',
    );
  }
  if (previous && previous === current) {
    throw new Error('ULTRA_METRICS_TOKEN_PREVIOUS must differ from ULTRA_METRICS_TOKEN');
  }
  for (const [adminName, adminToken] of adminTokens) {
    if (!adminToken) continue;
    if (adminToken === current) {
      throw new Error(`ULTRA_METRICS_TOKEN must differ from ${adminName}`);
    }
    if (previous && adminToken === previous) {
      throw new Error(`ULTRA_METRICS_TOKEN_PREVIOUS must differ from ${adminName}`);
    }
  }
}

export function metricMethodLabel(method) {
  return METHOD_LABELS.has(method) ? method : 'OTHER';
}

export function metricRouteLabel(routePath) {
  return typeof routePath === 'string' && ROUTE_LABELS.has(routePath)
    ? routePath
    : '__unmatched__';
}

export function metricAuthFailureLabel(reason) {
  if (typeof reason !== 'string') return 'unknown';
  const normalized = reason.toLowerCase();
  if (AUTH_FAILURE_LABELS.has(normalized)) return normalized;
  if (normalized.startsWith('bpc:') || normalized.startsWith('bpc_')) return 'bpc';
  if (normalized.startsWith('tsk:') || normalized.startsWith('tsk_')) return 'tsk';
  if (normalized.startsWith('identity_')) return 'identity';
  return 'unknown';
}

export const METRIC_ROUTE_LABEL_LIMIT = ROUTE_LABELS.size + 1;
