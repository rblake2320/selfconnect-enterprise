"""enterprise/handshake.py — Challenge-Response Handshake (Tier 2)

Upgrades peer trust from "read the birth tag" (v1) to "cryptographically prove key
possession" (v2).  Gated on SC_HANDSHAKE=v2 (default: off).

Protocol summary (Option B — nonce-bound attestation)
------------------------------------------------------
1.  Initiator calls discover_handshake_peers() which runs discover_mesh() then
    fires a HandshakeChallenge at each candidate's listener HWND concurrently
    (thread pool, max SC_HANDSHAKE_PARALLEL workers, default 8).

2.  Challenge JSON (dwData=DTYPE_CHALLENGE) sent via WM_COPYDATA to peer's HWND:
        {
          "type":           "challenge",
          "nonce":          "<32-hex-char random nonce>",
          "initiator_hwnd": <int>,
          "initiator_id":   "<agent_id string>"
        }

3.  Peer's HandshakeResponder signs TWO things and sends a response:
        {
          "type":              "response",
          "nonce":             "<same nonce>",
          "agent_id":          "<peer agent_id from CngIdentity>",
          "ed25519_pubkey":    "<64-hex ed25519 pubkey (32 bytes)>",
          "ed25519_sig":       "<128-hex ed25519 sig of (nonce:initiator_hwnd)>",
          "platform_ksp_pubkey": "<192-hex P-384 pubkey raw X||Y (96 bytes)>",  # if cng available
          "platform_ksp_sig":    "<192-hex ECDSA P-384 sig of (nonce || ed25519_pubkey)>"
        }

    The platform_ksp_sig signs BOTH the nonce (freshness) AND the ed25519_pubkey (binding).
    This is the cryptographic binding that closes Gap C: only the holder of both the P-384
    private key AND knowledge of the ed25519 pubkey can produce a valid platform_ksp_sig.

4.  Initiator verifies via verify_peer():
    a. nonce matches
    b. verify_peer() — three checks in sequence:
       1. agent_id derived from platform_ksp_pubkey via SHA-384 fingerprint
       2. platform_ksp_sig verifies (nonce || ed25519_pubkey) with P-384 key  ← Gap C closure
       3. ed25519_sig verifies (nonce:initiator_hwnd) with ed25519 key
    c. SCID_SIG birth-tag cross-check using the now-bound ed25519_pubkey

    If peer sends no platform_ksp_pubkey: steps b.1 and b.2 are skipped, Gap C warning logged.

Gap C status
------------
    Gap C (ed25519 ↔ CNG key independence) is closed at verify time for any peer that
    includes platform_ksp_sig in its response.  An attacker who extracts the DPAPI-wrapped
    ed25519 key cannot produce a valid platform_ksp_sig because the P-384 private key is
    bound to the Windows user profile in the Microsoft Software Key Storage Provider
    (NCrypt), which rejects operations from other user contexts.

    Provider used:  Microsoft Software Key Storage Provider (NCrypt, ECDSA P-384 / SHA-384)
    Provider NOT used in current build: Microsoft Platform Crypto Provider (TPM-backed)
    Gap C is closed against same-user extractors.  Moving to Platform Crypto Provider
    (TPM-backed) is a separate, scoped change in crypto.py:84 and lands as its own PR.

Flags
-----
    SC_HANDSHAKE=v2          — enable challenge-response (default: unset = v1)
    SC_HANDSHAKE_PARALLEL=8  — max concurrent handshakes (default: 8)
    SC_HANDSHAKE_TIMEOUT_MS  — per-candidate timeout (default: 500, from discovery_config)
    SC_HANDSHAKE_BACKOFF_SEC — failed-agent cooldown (default: 60, from discovery_config)

Backoff
-------
    A peer whose handshake fails is added to the backoff table keyed by agent_id.
    Subsequent discovery cycles skip that peer until backoff_sec has elapsed.
    Persistent failures (e.g., stale HWND) are not retried indefinitely.

Version: 2.0.0-enterprise  Tier 2  (Option B nonce-bound key binding)
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

# ── Env config ────────────────────────────────────────────────────────────────

_HANDSHAKE_ENABLED: bool = os.environ.get("SC_HANDSHAKE", "").lower() == "v2"
_HANDSHAKE_PARALLEL: int = int(os.environ.get("SC_HANDSHAKE_PARALLEL", "8"))

# Imported lazily so that tests can patch discovery_config before import
def _timeout_sec() -> float:
    from enterprise.discovery_config import HANDSHAKE_TIMEOUT_MS
    return HANDSHAKE_TIMEOUT_MS / 1000.0

def _backoff_sec() -> float:
    return float(os.environ.get("SC_HANDSHAKE_BACKOFF_SEC", "60"))


# ── WM_COPYDATA type tags ─────────────────────────────────────────────────────

DTYPE_CHALLENGE = 0x5343_4831   # "SCH1" — challenge frame
DTYPE_RESPONSE  = 0x5343_4832   # "SCH2" — response frame


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class HandshakePeer:
    """A peer that has successfully completed the v2 challenge-response."""
    agent_id:        str
    hwnd:            int
    public_key_hex:  str          # ed25519 pubkey hex (32 bytes = 64 hex chars)
    gap_c_closed:    bool = False  # True if platform_ksp_sig binding was verified
    verified_at:     float = field(default_factory=time.time)


@dataclass
class HandshakeResult:
    """Per-candidate outcome from a handshake attempt."""
    agent_id: str
    hwnd:     int
    ok:       bool
    reason:   str
    peer:     Optional[HandshakePeer] = None


# ── Backoff table ─────────────────────────────────────────────────────────────

class PeerBackoff:
    """Thread-safe per-agent_id failure backoff."""

    def __init__(self) -> None:
        self._lock:    threading.Lock = threading.Lock()
        self._fails:   dict[str, float] = {}   # agent_id → epoch of last failure

    def record_failure(self, agent_id: str) -> None:
        with self._lock:
            self._fails[agent_id] = time.time()

    def is_blocked(self, agent_id: str) -> bool:
        with self._lock:
            t = self._fails.get(agent_id)
            if t is None:
                return False
            return (time.time() - t) < _backoff_sec()

    def clear(self, agent_id: str) -> None:
        with self._lock:
            self._fails.pop(agent_id, None)

    def blocked_count(self) -> int:
        with self._lock:
            now = time.time()
            return sum(1 for t in self._fails.values() if (now - t) < _backoff_sec())


# Module-level shared backoff table (one per process)
_backoff = PeerBackoff()


# ── Exceptions ────────────────────────────────────────────────────────────────

class PeerVerificationError(Exception):
    """Raised by verify_peer() when any identity or binding check fails.

    Callers must catch this and treat the peer as unauthenticated.
    """


# ── Challenge builder ─────────────────────────────────────────────────────────

def _challenge_payload(nonce: str, initiator_hwnd: int, initiator_id: str) -> dict:
    return {
        "type":           "challenge",
        "nonce":          nonce,
        "initiator_hwnd": initiator_hwnd,
        "initiator_id":   initiator_id,
    }


def _signed_bytes(nonce: str, initiator_hwnd: int) -> bytes:
    """Canonical bytes that the responder signs and the initiator verifies."""
    return f"{nonce}:{initiator_hwnd}".encode()


def _cng_binding_bytes(nonce: str, ed25519_pubkey_bytes: bytes) -> bytes:
    """Canonical bytes the responder's P-384 key signs to bind it to the ed25519 key.

    The nonce is included so this signature is fresh and cannot be replayed across
    handshakes.  The ed25519_pubkey is included so the P-384 signature explicitly
    vouches for that specific key — this is the Gap C closure.
    """
    return nonce.encode("ascii") + ed25519_pubkey_bytes


def verify_peer(packet: dict, nonce: str, initiator_hwnd: int) -> bool:
    """Verify a peer's identity packet from a handshake response.

    Three-step verification in order:
        1. agent_id consistency — must equal SHA-384(platform_ksp_pubkey)[:8].upper()
        2. platform_ksp_sig — ECDSA P-384 / SHA-384 over (nonce || ed25519_pubkey):
           proves the holder of the P-384 private key explicitly vouches for this
           ed25519 pubkey in this session (Gap C closure)
        3. ed25519_sig — ed25519 signature over (nonce:initiator_hwnd):
           proves possession of the ed25519 private key

    If platform_ksp_pubkey is absent from packet, steps 1+2 are skipped and
    a WARNING is logged.  Step 3 always runs.

    Args:
        packet:        The decoded response dict from the peer.
        nonce:         The nonce sent in the challenge (hex string).
        initiator_hwnd: The HWND sent in the challenge.

    Returns:
        True on success.

    Raises:
        PeerVerificationError: on any check failure (caller treats peer as rejected).
    """
    from enterprise.identity import AgentIdentity
    from enterprise.crypto import cng_verify, cng_sha384

    ed25519_pub_hex = packet.get("ed25519_pubkey", "")
    ed25519_sig_hex = packet.get("ed25519_sig", "")
    p384_pub_hex    = packet.get("platform_ksp_pubkey", "")
    p384_sig_hex    = packet.get("platform_ksp_sig", "")
    agent_id        = packet.get("agent_id", "")

    if not ed25519_pub_hex or not ed25519_sig_hex:
        raise PeerVerificationError(
            "response missing ed25519_pubkey or ed25519_sig"
        )

    try:
        ed25519_pub_bytes = bytes.fromhex(ed25519_pub_hex)
        ed25519_sig_bytes = bytes.fromhex(ed25519_sig_hex)
    except ValueError as exc:
        raise PeerVerificationError(f"invalid ed25519 hex: {exc}") from exc

    # ── Steps 1 + 2: Platform KSP binding ────────────────────────────────────
    gap_c_closed = False
    if p384_pub_hex and p384_sig_hex:
        try:
            p384_pub_bytes = bytes.fromhex(p384_pub_hex)
            p384_sig_bytes = bytes.fromhex(p384_sig_hex)
        except ValueError as exc:
            raise PeerVerificationError(f"invalid platform_ksp hex: {exc}") from exc

        # Step 1: agent_id must be derived from platform_ksp_pubkey
        expected_id = "SC-" + cng_sha384(p384_pub_bytes).hex()[:8].upper()
        if expected_id != agent_id:
            raise PeerVerificationError(
                f"agent_id mismatch: response claims {agent_id!r} but "
                f"platform_ksp_pubkey fingerprint yields {expected_id!r} — "
                f"possible impersonation"
            )

        # Step 2: CNG binding signature — P-384 key signs (nonce || ed25519_pubkey)
        # This is the cryptographic closure of Gap C.
        binding_data = _cng_binding_bytes(nonce, ed25519_pub_bytes)
        if not cng_verify(binding_data, p384_sig_bytes, p384_pub_bytes):
            raise PeerVerificationError(
                "platform_ksp_sig verification failed — "
                "ed25519 pubkey is not bound to this P-384 identity"
            )

        gap_c_closed = True
        _log.debug(
            "verify_peer: P-384 binding verified for agent_id=%s (Gap C closed)",
            agent_id,
        )
    else:
        _log.warning(
            "verify_peer: no platform_ksp_pubkey in response "
            "agent_id=%s — Gap C not closed for this peer",
            agent_id,
        )

    # ── Step 3: ed25519 signature ─────────────────────────────────────────────
    ed25519_signed_data = _signed_bytes(nonce, initiator_hwnd)
    if not AgentIdentity.verify(ed25519_signed_data, ed25519_sig_bytes, ed25519_pub_bytes):
        raise PeerVerificationError("ed25519 signature verification failed")

    _log.debug(
        "verify_peer: ed25519 verified for agent_id=%s gap_c_closed=%s",
        agent_id, gap_c_closed,
    )
    return gap_c_closed   # True = Gap C closed, False = ed25519-only (no CNG binding)


# ── Responder ─────────────────────────────────────────────────────────────────

class HandshakeResponder:
    """Handles incoming challenge frames; signs and sends responses.

    Install as a CopyDataListener callback for DTYPE_CHALLENGE.

    Usage:
        from enterprise.transport import CopyDataListener
        from enterprise.handshake  import HandshakeResponder, DTYPE_CHALLENGE

        listener   = CopyDataListener()
        responder  = HandshakeResponder(my_hwnd=listener.hwnd, identity=my_identity)
        listener.register(DTYPE_CHALLENGE, responder.handle_challenge)
        listener.start()
    """

    def __init__(self, my_hwnd: int, identity, cng_identity=None) -> None:
        """
        Args:
            my_hwnd:      This agent's listener HWND (stamped in birth tag as SCLHWND).
            identity:     AgentIdentity (ed25519) — signs (nonce:initiator_hwnd).
            cng_identity: CngIdentity (P-384, Microsoft Software KSP) — optional.
                          When provided, signs (nonce || ed25519_pubkey) to bind the
                          two key systems at handshake time (closes Gap C).
        """
        self._hwnd     = my_hwnd
        self._identity = identity
        self._cng      = cng_identity

    def handle_challenge(self, sender_hwnd: int, payload: dict) -> None:
        """Callback invoked by CopyDataListener on DTYPE_CHALLENGE receipt.

        Produces an identity_packet response containing:
          - ed25519_sig: proves ed25519 key possession
          - platform_ksp_sig: binds P-384 key to ed25519 pubkey (Gap C closure)
            Only included when cng_identity was supplied at construction.

        Args:
            sender_hwnd: HWND that sent the WM_COPYDATA (OS-provided).
            payload:     Decoded JSON dict from the challenge frame.
        """
        nonce          = payload.get("nonce", "")
        initiator_hwnd = payload.get("initiator_hwnd", 0)

        if not nonce or not initiator_hwnd:
            _log.warning("handshake: malformed challenge from hwnd=%#x — dropped", sender_hwnd)
            return

        # ed25519: sign (nonce:initiator_hwnd) — proves key possession
        try:
            ed25519_sig_bytes = self._identity.sign(_signed_bytes(nonce, initiator_hwnd))
        except Exception as exc:
            _log.error("handshake: ed25519 sign failed: %s", exc)
            return

        ed25519_pub_bytes = self._identity.public_key_bytes

        response: dict = {
            "type":          "response",
            "nonce":         nonce,
            "agent_id":      getattr(self._identity, "agent_id", ""),
            "ed25519_pubkey": ed25519_pub_bytes.hex(),
            "ed25519_sig":    ed25519_sig_bytes.hex(),
        }

        # P-384: sign (nonce || ed25519_pubkey) — binds the two keys (Gap C closure)
        if self._cng is not None:
            try:
                binding_data    = _cng_binding_bytes(nonce, ed25519_pub_bytes)
                p384_sig_bytes  = self._cng.sign(binding_data)
                response["platform_ksp_pubkey"] = self._cng.public_key_bytes.hex()
                response["platform_ksp_sig"]    = p384_sig_bytes.hex()
                # agent_id from CngIdentity overrides ed25519 agent_id when binding present
                response["agent_id"] = getattr(self._cng, "agent_id", response["agent_id"])
            except Exception as exc:
                _log.warning(
                    "handshake: P-384 binding sign failed (non-fatal, Gap C not closed): %s", exc
                )

        try:
            from enterprise.registry import send_data
            ok = send_data(initiator_hwnd, response, data_type=DTYPE_RESPONSE)
            if not ok:
                _log.warning(
                    "handshake: send_data to initiator %#x failed", initiator_hwnd
                )
        except Exception as exc:
            _log.error("handshake: send_data raised: %s", exc)


# ── Initiator (per-candidate) ─────────────────────────────────────────────────

class HandshakeInitiator:
    """Sends a challenge to one peer and waits for a valid response.

    NOT reusable — create one instance per handshake attempt.
    """

    def __init__(
        self,
        my_hwnd:     int,
        my_agent_id: str,
    ) -> None:
        self._my_hwnd     = my_hwnd
        self._my_id       = my_agent_id
        self._event       = threading.Event()
        self._result:     Optional[dict] = None
        self._result_lock = threading.Lock()

    def handle_response(self, sender_hwnd: int, payload: dict) -> None:
        """Callback for CopyDataListener — called when a DTYPE_RESPONSE arrives."""
        with self._result_lock:
            if self._result is None:       # take only the first response
                self._result = payload
        self._event.set()

    def run(self, peer: "BirthTag", timeout_sec: float) -> HandshakeResult:  # type: ignore[name-defined]  # noqa: F821
        """Execute a full challenge-response cycle against one peer.

        Args:
            peer:        BirthTag candidate from discover_mesh().
            timeout_sec: Seconds to wait for a response before failing.

        Returns:
            HandshakeResult with ok=True if all verifications pass.
        """
        from enterprise.registry import send_data, get_agent_prop

        nonce = secrets.token_hex(16)   # 32 hex chars = 128 bits

        challenge = _challenge_payload(nonce, self._my_hwnd, self._my_id)
        sent = send_data(peer.hwnd, challenge, data_type=DTYPE_CHALLENGE)
        if not sent:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason="send_data(challenge) failed — peer HWND unreachable",
            )

        got_response = self._event.wait(timeout=timeout_sec)
        if not got_response:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason=f"timeout after {timeout_sec:.1f}s — no response",
            )

        with self._result_lock:
            resp = self._result

        # ── Step a: nonce match ───────────────────────────────────────────────
        if resp.get("nonce") != nonce:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason="nonce mismatch in response",
            )

        # ── Step b: verify_peer — binding + ed25519 verification ─────────────
        # verify_peer() performs:
        #   1. agent_id consistency against platform_ksp_pubkey fingerprint
        #   2. ECDSA P-384 binding sig verifies (nonce || ed25519_pubkey) ← Gap C
        #   3. ed25519 sig verifies (nonce:initiator_hwnd)
        try:
            gap_c_closed = verify_peer(resp, nonce, self._my_hwnd)
        except PeerVerificationError as exc:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason=str(exc),
            )

        # ── Step c: SCID_SIG birth-tag cross-check ────────────────────────────
        pub_hex   = resp.get("ed25519_pubkey", "")
        pub_bytes = bytes.fromhex(pub_hex) if pub_hex else b""

        btag_sig_hex = get_agent_prop(peer.hwnd, "SCID_SIG")
        if not btag_sig_hex:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason="birth-tag signature cross-check failed: missing SCID_SIG property",
            )
        if not pub_bytes:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason="birth-tag signature cross-check failed: missing peer public key",
            )

        from enterprise.birth_tag_v2 import verify_signed_birth_tag
        ok_btag, btag_reason = verify_signed_birth_tag(
            peer.hwnd, pub_bytes, max_age_seconds=60.0
        )
        if not ok_btag:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason=f"birth-tag signature cross-check failed: {btag_reason}",
            )

        _log.info(
            "handshake_succeeded agent=%s hwnd=%#x gap_c_closed=%s",
            peer.agent_id, peer.hwnd, gap_c_closed,
        )

        return HandshakeResult(
            agent_id=peer.agent_id,
            hwnd=peer.hwnd,
            ok=True,
            reason="ok",
            peer=HandshakePeer(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                public_key_hex=pub_hex,
                gap_c_closed=gap_c_closed,
            ),
        )


# ── orchestrator ──────────────────────────────────────────────────────────────

def discover_handshake_peers(
    my_hwnd:     int,
    my_agent_id: str,
    identity,                # AgentIdentity (ed25519) for signing challenge responses
    cng_identity=None,       # CngIdentity (P-384, Software KSP) for binding signature
    parallelism: int = _HANDSHAKE_PARALLEL,
    timeout_sec: Optional[float] = None,
    _candidates=None,        # override for tests (skip real discover_mesh())
) -> list[HandshakePeer]:
    """Discover mesh peers and handshake with each concurrently.

    Returns only peers that passed the full challenge-response sequence.

    The SC_HANDSHAKE env var is checked at call time (not import time) so that
    tests can set it after import without monkey-patching.

    Args:
        my_hwnd:      HWND of the caller's CopyDataListener window.
        my_agent_id:  Caller's agent ID string.
        identity:     AgentIdentity (ed25519) for signing challenge responses.
        cng_identity: CngIdentity (P-384, Microsoft Software KSP) for binding sig.
                      When provided, responder includes platform_ksp_sig that binds
                      the P-384 key to the ed25519 key per handshake (closes Gap C).
        parallelism:  Max concurrent handshakes (default: SC_HANDSHAKE_PARALLEL).
        timeout_sec:  Per-candidate timeout (default: SC_HANDSHAKE_TIMEOUT_MS/1000).
        _candidates:  Test-only override — list of BirthTag objects to use instead
                      of calling discover_mesh().

    Returns:
        List of HandshakePeer objects for peers that passed all checks.
        Empty list if SC_HANDSHAKE != "v2" (caller falls back to v1 trust-the-tag).
    """
    if os.environ.get("SC_HANDSHAKE", "").lower() != "v2":
        _log.debug("handshake: SC_HANDSHAKE != v2 — skipping (v1 mode)")
        return []

    if timeout_sec is None:
        timeout_sec = _timeout_sec()

    if _candidates is None:
        from enterprise.registry import discover_mesh
        candidates = discover_mesh()
    else:
        candidates = _candidates

    # Filter out our own HWND and any backoff-blocked peers
    candidates = [
        c for c in candidates
        if c.hwnd != my_hwnd and not _backoff.is_blocked(c.agent_id)
    ]

    if not candidates:
        _log.debug("handshake: no eligible candidates after backoff filter")
        return []

    from enterprise.transport import CopyDataListener

    # Shared listener for receiving all responses in this discovery cycle
    listener = CopyDataListener()

    verified: list[HandshakePeer] = []
    futures_map: dict = {}

    with ThreadPoolExecutor(max_workers=parallelism) as pool:
        for candidate in candidates:
            initiator = HandshakeInitiator(
                my_hwnd=listener.hwnd if hasattr(listener, "hwnd") else my_hwnd,
                my_agent_id=my_agent_id,
            )
            listener.register(DTYPE_RESPONSE, initiator.handle_response)
            fut = pool.submit(initiator.run, candidate, timeout_sec)
            futures_map[fut] = candidate

        try:
            for fut in as_completed(futures_map, timeout=timeout_sec * len(futures_map) + 1):
                candidate = futures_map[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    result = HandshakeResult(
                        agent_id=candidate.agent_id,
                        hwnd=candidate.hwnd,
                        ok=False,
                        reason=f"exception: {exc}",
                    )

                if result.ok and result.peer:
                    verified.append(result.peer)
                    _backoff.clear(result.peer.agent_id)
                    _log.info(
                        "handshake: peer %s VERIFIED (hwnd=%#x, gap_c_closed=%s)",
                        result.agent_id, result.hwnd, result.peer.gap_c_closed,
                    )
                else:
                    _backoff.record_failure(candidate.agent_id)
                    _log.warning(
                        "handshake_rejected agent=%s hwnd=%#x reason=%s",
                        result.agent_id, result.hwnd, result.reason[:80],
                    )
        except FuturesTimeout:
            _log.warning("handshake: as_completed timed out — partial results returned")

    if hasattr(listener, "stop"):
        try:
            listener.stop()
        except Exception:
            pass

    _log.info(
        "handshake: cycle complete — %d/%d peers verified, %d in backoff",
        len(verified), len(candidates), _backoff.blocked_count(),
    )
    return verified


# ── Convenience: is handshake v2 enabled? ────────────────────────────────────

def handshake_v2_enabled() -> bool:
    """Return True if SC_HANDSHAKE=v2 is active (checked at call time)."""
    return os.environ.get("SC_HANDSHAKE", "").lower() == "v2"
