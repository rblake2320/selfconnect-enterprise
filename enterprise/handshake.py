"""enterprise/handshake.py — Challenge-Response Handshake (Tier 2)

Upgrades peer trust from "read the birth tag" (v1) to "cryptographically prove key
possession" (v2).  Gated on SC_HANDSHAKE=v2 (default: off).

Protocol summary
----------------
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

3.  Peer's HandshakeResponder (running in a CopyDataListener callback) signs
    bytes(nonce + ":" + str(initiator_hwnd)) with its ed25519 AgentIdentity key,
    then sends a response back to the initiator's HWND:
        {
          "type":      "response",
          "nonce":     "<same nonce>",
          "signature": "<128-hex-char ed25519 signature>",
          "public_key":"<64-hex-char ed25519 pubkey>",
          "agent_id":  "<peer agent_id>"
        }

4.  Initiator verifies:
    a. nonce matches
    b. ed25519 signature of (nonce + ":" + str(initiator_hwnd)) with peer pubkey
    c. peer pubkey matches SCID_SIG property on peer's HWND (birth-tag cross-check)

5.  Attestation (Gap C bridge requirement):
    After successful ed25519 verification, initiator logs a `handshake_succeeded`
    event signed with CngIdentity (P-384 / Platform KSP) if one is available.
    This binds the Platform KSP identity to the ed25519 peer vouching chain —
    making the two key systems meet at verify time.  This is NOT a full key chain
    yet — that requires Tier 2 design item completion (see ROLLBACK.md Gap C) —
    but it creates the cryptographic paper trail required before SC_HANDSHAKE=v2
    can flip to default-on.

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

Version: 1.0.0-enterprise  Tier 2
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
    attested:        bool = False  # True if CngIdentity attestation log was written
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

    def __init__(self, my_hwnd: int, identity) -> None:
        """
        Args:
            my_hwnd:  This agent's listener HWND (stamped in birth tag as SCLHWND).
            identity: AgentIdentity (ed25519) — used to sign challenge responses.
        """
        self._hwnd     = my_hwnd
        self._identity = identity

    def handle_challenge(self, sender_hwnd: int, payload: dict) -> None:
        """Callback invoked by CopyDataListener on DTYPE_CHALLENGE receipt.

        Args:
            sender_hwnd: HWND that sent the WM_COPYDATA (OS-provided).
            payload:     Decoded JSON dict from the challenge frame.
        """
        import json

        nonce          = payload.get("nonce", "")
        initiator_hwnd = payload.get("initiator_hwnd", 0)
        initiator_id   = payload.get("initiator_id", "")

        if not nonce or not initiator_hwnd:
            _log.warning("handshake: malformed challenge from hwnd=%#x — dropped", sender_hwnd)
            return

        try:
            sig_bytes = self._identity.sign(_signed_bytes(nonce, initiator_hwnd))
        except Exception as exc:
            _log.error("handshake: sign failed: %s", exc)
            return

        response = {
            "type":       "response",
            "nonce":      nonce,
            "signature":  sig_bytes.hex(),
            "public_key": self._identity.public_key_bytes.hex(),
            "agent_id":   self._identity.agent_id
            if hasattr(self._identity, "agent_id")
            else "",
        }

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
        my_hwnd:    int,
        my_agent_id: str,
        cng_identity=None,   # CngIdentity — optional; used for attestation log
    ) -> None:
        self._my_hwnd    = my_hwnd
        self._my_id      = my_agent_id
        self._cng        = cng_identity
        self._event      = threading.Event()
        self._result:    Optional[dict] = None
        self._result_lock = threading.Lock()

    def handle_response(self, sender_hwnd: int, payload: dict) -> None:
        """Callback for CopyDataListener — called when a DTYPE_RESPONSE arrives."""
        with self._result_lock:
            if self._result is None:       # take only the first response
                self._result = payload
        self._event.set()

    def run(self, peer: "BirthTag", timeout_sec: float) -> HandshakeResult:  # type: ignore[name-defined]
        """Execute a full challenge-response cycle against one peer.

        Args:
            peer:        BirthTag candidate from discover_mesh().
            timeout_sec: Seconds to wait for a response before failing.

        Returns:
            HandshakeResult with ok=True if all verifications pass.
        """
        from enterprise.registry import send_data, get_agent_prop
        from enterprise.identity import AgentIdentity

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

        # ── Step b: ed25519 signature verification ────────────────────────────
        sig_hex = resp.get("signature", "")
        pub_hex = resp.get("public_key", "")
        if not sig_hex or not pub_hex:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason="response missing signature or public_key field",
            )

        try:
            sig_bytes = bytes.fromhex(sig_hex)
            pub_bytes = bytes.fromhex(pub_hex)
        except ValueError as exc:
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason=f"response contains invalid hex: {exc}",
            )

        signed_data = _signed_bytes(nonce, self._my_hwnd)
        if not AgentIdentity.verify(signed_data, sig_bytes, pub_bytes):
            return HandshakeResult(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                ok=False,
                reason="ed25519 signature verification failed",
            )

        # ── Step c: cross-check pubkey against birth-tag SCID_SIG ────────────
        btag_sig_hex = get_agent_prop(peer.hwnd, "SCID_SIG")
        if btag_sig_hex:
            # Peer has a signed birth tag — verify that the response pubkey
            # matches the pubkey that signed the birth tag.  We read SCID, SCPID,
            # SCCTIME, SCBORN, SCID_STS from the window to rebuild the payload,
            # then verify SCID_SIG against the claimed pubkey from the response.
            from enterprise.birth_tag_v2 import verify_signed_birth_tag
            ok_btag, btag_reason = verify_signed_birth_tag(
                peer.hwnd, pub_bytes, max_age_seconds=0.0  # age already checked at discovery
            )
            if not ok_btag:
                return HandshakeResult(
                    agent_id=peer.agent_id,
                    hwnd=peer.hwnd,
                    ok=False,
                    reason=f"birth-tag signature cross-check failed: {btag_reason}",
                )
        else:
            # Peer has no SCID_SIG — acceptable during SC_SUNSET_V1 grace period.
            _log.warning(
                "v1_peer_accepted_during_grace agent=%s hwnd=%#x",
                peer.agent_id, peer.hwnd,
            )

        # ── Step 5: attestation (Gap C bridge) ───────────────────────────────
        attested = False
        if self._cng is not None:
            try:
                cng_id = getattr(self._cng, "agent_id", "unknown")
                _log.info(
                    "handshake_succeeded agent=%s hwnd=%#x pubkey=%s... attested_by=%s",
                    peer.agent_id, peer.hwnd, pub_hex[:16], cng_id,
                )
                # Write attestation into CNG ledger if caller provides one
                if hasattr(self._cng, "_ledger") and self._cng._ledger is not None:
                    self._cng._ledger.log(
                        "handshake_succeeded",
                        result="ok",
                        metadata={
                            "peer_agent_id": peer.agent_id,
                            "peer_hwnd": peer.hwnd,
                            "peer_pubkey_prefix": pub_hex[:16],
                        },
                    )
                attested = True
            except Exception as exc:
                _log.warning("handshake: attestation log failed (non-fatal): %s", exc)

        return HandshakeResult(
            agent_id=peer.agent_id,
            hwnd=peer.hwnd,
            ok=True,
            reason="ok",
            peer=HandshakePeer(
                agent_id=peer.agent_id,
                hwnd=peer.hwnd,
                public_key_hex=pub_hex,
                attested=attested,
            ),
        )


# ── orchestrator ──────────────────────────────────────────────────────────────

def discover_handshake_peers(
    my_hwnd:    int,
    my_agent_id: str,
    identity,               # AgentIdentity (ed25519) for responding to challenges
    cng_identity=None,      # CngIdentity (P-384) for attestation logging; optional
    parallelism: int = _HANDSHAKE_PARALLEL,
    timeout_sec: Optional[float] = None,
    _candidates=None,       # override for tests (skip real discover_mesh())
) -> list[HandshakePeer]:
    """Discover mesh peers and handshake with each concurrently.

    Returns only peers that passed the full challenge-response sequence.

    The SC_HANDSHAKE env var is checked at call time (not import time) so that
    tests can set it after import without monkey-patching.

    Args:
        my_hwnd:      HWND of the caller's CopyDataListener window.
        my_agent_id:  Caller's agent ID string.
        identity:     AgentIdentity for signing challenge responses.
        cng_identity: Optional CngIdentity for attestation logging.
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
                cng_identity=cng_identity,
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
                        "handshake: peer %s VERIFIED (hwnd=%#x, attested=%s)",
                        result.agent_id, result.hwnd, result.peer.attested,
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
