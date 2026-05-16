"""enterprise/birth_tag_v2.py — Signed Birth Tag Stamping (Tier 1)

Stamps a cryptographically signed property `SCID_SIG` alongside the existing
`SCID` property at agent startup.  The old `SCID` property continues to be
stamped by `registry.stamp_birth_tag()` — this module is purely additive.

What the signature covers:
    SCID        — agent identity string
    SCPID       — str(pid)
    SCCTIME     — OS process creation time (FILETIME epoch string)
    SCBORN      — float str — time.time() at spawn
    ts          — float seconds since epoch (anti-replay freshness anchor)

Signing key:
    Uses the agent's ed25519 signing key via enterprise.identity.AgentIdentity.
    The identity holds keys loaded from the Platform KSP (TPM-bound, non-
    exportable) when available, or DPAPI-wrapped Software KSP as fallback.
    Call AgentIdentity.load() once at startup to get the identity object.

Why Tier 1 (no flag, no verifier):
    The signer can land unconditionally — peers that don't understand `SCID_SIG`
    simply ignore the extra property (dict.get() access pattern is confirmed for
    all consumers).  The verifier (which enforces rejection) ships in Tier 2 as
    enterprise.version_gate, gated on SC_SUNSET_V1.

Anti-replay (Tier 2 enforcement):
    The `ts` field inside the signed payload allows Tier 2 verifiers to reject
    signatures older than 60 seconds.  The signer stamps a fresh `ts` every
    call, so a captured SCID_SIG blob cannot be replayed after 60s.

Usage:
    from enterprise.identity import AgentIdentity
    from enterprise.birth_tag_v2 import stamp_signed_birth_tag, verify_signed_birth_tag

    identity = AgentIdentity.load("agent-b-local")
    sig_hex = stamp_signed_birth_tag(hwnd, identity, agent_id, pid, ctime, born)

    # Tier 2 verifier (called from enterprise.version_gate):
    ok, reason = verify_signed_birth_tag(hwnd, identity.public_key_bytes)

Property written:
    SCID_SIG  — hex-encoded ed25519 signature over the canonical payload JSON
    SCID_STS  — float str — timestamp embedded in the payload (for freshness check)

Version: 1.0.0-enterprise  Tier 1 identity hardening
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

_log = logging.getLogger(__name__)

# New property keys stamped by this module (alongside existing SCID etc.)
PROP_SIG  = "SCID_SIG"   # hex ed25519 signature over SCID_PAYLOAD
PROP_STS  = "SCID_STS"   # float str — ts inside the signed payload (for Tier 2 freshness check)

# Fields covered by the signature — order is irrelevant (json.dumps sort_keys=True)
_SIG_FIELDS = ("scid", "scpid", "scctime", "scborn", "ts")


def _build_payload(
    agent_id: str,
    pid: int,
    ctime: str,
    born: float,
    ts: float,
) -> bytes:
    """Canonical UTF-8 JSON of the signed payload (sorted keys, no spaces)."""
    payload = {
        "scid":    agent_id,
        "scpid":   str(pid),
        "scctime": ctime,
        "scborn":  str(born),
        "ts":      str(ts),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def stamp_signed_birth_tag(
    hwnd: int,
    identity,               # enterprise.identity.AgentIdentity
    agent_id: str,
    pid: int,
    ctime: str,
    born: float,
    ts: Optional[float] = None,
) -> str:
    """Sign the birth tag fields and stamp SCID_SIG + SCID_STS on `hwnd`.

    Call this AFTER registry.stamp_birth_tag() so the unsigned properties are
    already present.  The signature covers the same values — any tampering of
    the unsigned properties is detectable when the Tier 2 verifier arrives.

    Args:
        hwnd:      Window handle to stamp the signed properties on.
        identity:  AgentIdentity that holds the signing key.
        agent_id:  Same value passed to stamp_birth_tag() (i.e. SCID value).
        pid:       Agent's process ID (os.getpid()).
        ctime:     OS process creation time string (SCCTIME value).
        born:      Spawn timestamp (time.time() at birth) (SCBORN value).
        ts:        Signing timestamp for anti-replay (defaults to time.time()).
                   Override only in tests.

    Returns:
        The hex-encoded signature string that was stamped as SCID_SIG.

    Raises:
        RuntimeError: If the signing key is unavailable or SetPropW fails.
    """
    from enterprise.registry import set_agent_prop

    if ts is None:
        ts = time.time()

    payload_bytes = _build_payload(agent_id, pid, ctime, born, ts)

    try:
        sig_bytes = identity.sign(payload_bytes)
    except Exception as exc:
        raise RuntimeError(f"birth_tag_v2: signing failed: {exc}") from exc

    sig_hex = sig_bytes.hex()

    ok_sig = set_agent_prop(hwnd, PROP_SIG, sig_hex)
    ok_sts = set_agent_prop(hwnd, PROP_STS, str(ts))

    if not ok_sig or not ok_sts:
        raise RuntimeError(
            f"birth_tag_v2: SetPropW failed for hwnd={hwnd:#010x} "
            f"(SCID_SIG ok={ok_sig}, SCID_STS ok={ok_sts})"
        )

    _log.debug(
        "birth_tag_v2: stamped SCID_SIG on hwnd=%#010x agent=%s ts=%.3f",
        hwnd, agent_id, ts,
    )
    return sig_hex


def verify_signed_birth_tag(
    hwnd: int,
    public_key_bytes: bytes,
    max_age_seconds: float = 60.0,
) -> tuple[bool, str]:
    """Verify the SCID_SIG property on `hwnd`.

    Reads SCID_SIG, SCID_STS, SCID, SCPID, SCCTIME, SCBORN from the window
    and verifies the signature.  Also checks that `ts` inside the signed
    payload is not older than `max_age_seconds` (anti-replay).

    This is called by the Tier 2 version_gate module.  It is provided here so
    that test harnesses can exercise the full sign→verify cycle without needing
    Tier 2 to be present.

    Args:
        hwnd:             Window handle to read properties from.
        public_key_bytes: Raw ed25519 public key bytes (32 bytes).
        max_age_seconds:  Maximum allowed age of the signed timestamp.
                          Tier 2 enforces 60s; tests may pass 0.0 to skip.

    Returns:
        (True, "ok") on success.
        (False, reason_string) on any failure.
    """
    from enterprise.registry import get_agent_prop
    from enterprise.identity import AgentIdentity

    sig_hex = get_agent_prop(hwnd, PROP_SIG)
    if not sig_hex:
        return False, "missing SCID_SIG property"

    sts_str = get_agent_prop(hwnd, PROP_STS)
    if not sts_str:
        return False, "missing SCID_STS property"

    try:
        ts = float(sts_str)
    except ValueError:
        return False, f"SCID_STS is not a float: {sts_str!r}"

    if max_age_seconds > 0:
        age = time.time() - ts
        if age > max_age_seconds:
            return False, f"SCID_SIG expired: age={age:.1f}s > {max_age_seconds}s"

    agent_id = get_agent_prop(hwnd, "SCID")
    pid_str  = get_agent_prop(hwnd, "SCPID")
    ctime    = get_agent_prop(hwnd, "SCCTIME")
    born_str = get_agent_prop(hwnd, "SCBORN")

    if not all([agent_id, pid_str, ctime, born_str]):
        return False, "one or more required birth-tag properties missing"

    try:
        born = float(born_str)
    except ValueError:
        return False, f"SCBORN is not a float: {born_str!r}"

    try:
        pid = int(pid_str)
    except ValueError:
        return False, f"SCPID is not an int: {pid_str!r}"

    payload_bytes = _build_payload(agent_id, pid, ctime, born, ts)

    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False, "SCID_SIG is not valid hex"

    if not AgentIdentity.verify(payload_bytes, sig_bytes, public_key_bytes):
        return False, "signature verification failed"

    return True, "ok"
