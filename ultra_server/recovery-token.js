import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const TOKEN_VERSION = 1;
const AGENT_ID_PATTERN = /^SC-[0-9A-F]{8}$/;
const HEX_32_PATTERN = /^[0-9a-f]{64}$/i;

function deriveKey(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new TypeError('recovery signing secret must be a non-empty string');
  }
  return createHash('sha256').update(secret, 'utf8').digest();
}

function keyId(key) {
  return createHash('sha256')
    .update('selfconnect-ultra-recovery-kid-v1\0', 'utf8')
    .update(key)
    .digest('hex')
    .slice(0, 16);
}

export function createRecoveryKeyring(currentSecret, previousSecret = null) {
  const currentKey = deriveKey(currentSecret);
  const current = { kid: keyId(currentKey), key: currentKey };
  const verificationKeys = new Map([[current.kid, current.key]]);

  if (previousSecret) {
    const previousKey = deriveKey(previousSecret);
    const previousKid = keyId(previousKey);
    if (previousKid === current.kid) {
      throw new Error('current and previous recovery secrets must be different');
    }
    verificationKeys.set(previousKid, previousKey);
  }

  return Object.freeze({ current, verificationKeys });
}

function validateClaims(claims) {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new TypeError('recovery claims must be an object');
  }
  const { agentName, agentId, newPubHex, challengeHash } = claims;
  if (typeof agentName !== 'string' || agentName.length < 1 || agentName.length > 128) {
    throw new TypeError('invalid agentName');
  }
  if (typeof agentId !== 'string' || !AGENT_ID_PATTERN.test(agentId)) {
    throw new TypeError('invalid agentId');
  }
  if (typeof newPubHex !== 'string' || !HEX_32_PATTERN.test(newPubHex)) {
    throw new TypeError('invalid newPubHex');
  }
  if (typeof challengeHash !== 'string' || !HEX_32_PATTERN.test(challengeHash)) {
    throw new TypeError('invalid challengeHash');
  }
  return {
    agentName,
    agentId,
    newPubHex: newPubHex.toLowerCase(),
    challengeHash: challengeHash.toLowerCase(),
  };
}

function signingMaterial(token) {
  return Buffer.from(JSON.stringify([
    token.version,
    token.agentName,
    token.agentId,
    token.newPubHex,
    token.challengeHash,
    token.issuedAt,
    token.kid,
  ]), 'utf8');
}

export function issueRecoveryToken(claims, keyring, nowSec = Math.floor(Date.now() / 1000)) {
  const normalized = validateClaims(claims);
  if (!Number.isSafeInteger(nowSec) || nowSec <= 0) throw new TypeError('invalid issuance time');
  if (!keyring?.current?.kid || !Buffer.isBuffer(keyring.current.key)) {
    throw new TypeError('invalid recovery keyring');
  }
  const token = {
    version: TOKEN_VERSION,
    ...normalized,
    issuedAt: nowSec,
    kid: keyring.current.kid,
  };
  return {
    ...token,
    sig: createHmac('sha256', keyring.current.key).update(signingMaterial(token)).digest('hex'),
  };
}

export function verifyRecoveryToken(
  token,
  keyring,
  { nowSec = Math.floor(Date.now() / 1000), ttlSec = 60 } = {},
) {
  try {
    if (!token || typeof token !== 'object' || Array.isArray(token)) {
      return { valid: false, error: 'malformed token' };
    }
    if (token.version !== TOKEN_VERSION) return { valid: false, error: 'unsupported token version' };
    const claims = validateClaims(token);
    if (!Number.isSafeInteger(token.issuedAt) || token.issuedAt <= 0) {
      return { valid: false, error: 'invalid issuance time' };
    }
    if (typeof token.kid !== 'string' || !/^[0-9a-f]{16}$/.test(token.kid)) {
      return { valid: false, error: 'invalid key id' };
    }
    if (typeof token.sig !== 'string' || !/^[0-9a-f]{64}$/i.test(token.sig)) {
      return { valid: false, error: 'invalid signature encoding' };
    }
    if (!Number.isSafeInteger(nowSec) || !Number.isSafeInteger(ttlSec) || ttlSec < 1) {
      return { valid: false, error: 'invalid verifier configuration' };
    }
    const age = nowSec - token.issuedAt;
    if (age < 0 || age > ttlSec) return { valid: false, error: 'token expired' };

    const key = keyring?.verificationKeys?.get(token.kid);
    if (!key) return { valid: false, error: 'unknown key id' };
    const authenticated = {
      version: token.version,
      ...claims,
      issuedAt: token.issuedAt,
      kid: token.kid,
    };
    const expected = createHmac('sha256', key).update(signingMaterial(authenticated)).digest();
    const actual = Buffer.from(token.sig, 'hex');
    return timingSafeEqual(expected, actual)
      ? { valid: true, kid: token.kid }
      : { valid: false, error: 'invalid signature' };
  } catch {
    return { valid: false, error: 'malformed token' };
  }
}
