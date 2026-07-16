/**
 * Convert BPC's deceptive shadow response into a fail-closed authorization
 * decision. Shadow mode is useful as an attacker-observation signal, but it
 * must never cross the Ultra verification boundary as permission to act.
 */
export function enforceBpcAuthorization(result) {
  if (!result || typeof result !== 'object') {
    return { ok: false, error: 'invalid_result' };
  }
  if (result.shadow === true || result.ghostAlert === true) {
    return {
      ok: false,
      pairId: result.pairId,
      error: 'shadow_denied',
    };
  }
  return result;
}
