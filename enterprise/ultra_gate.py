"""enterprise/ultra_gate.py — UltraGate: 7-layer BPC+TSK identity verification.

UltraGate is the main integration class that:
  1. At agent spawn: derives BPC P-256 keypair from DPAPI ed25519 root, registers
     with Ultra Server, provisions TSK client, binds identities.
  2. At each send_string() call: builds BPC+TSK request headers, verifies locally
     (fast path) or via Ultra Server (full 7-layer), and authorizes or denies.

The BPC layers 1-5 provide registered pair-key possession, pair registry, secret HMAC,
anti-replay, and behavioral anomaly. TSK layers 6-7 add a separately provisioned
shared secret, rotating segments, a checksum, and server-enforced HOTP state.
The server retains the complete tumbler record. The owning client receives the
secret and a reduced provisioning view containing segment types, lengths, and
order, so this module does not claim that the effective layout is hidden from
that client.

Ultra Server sidecar: Node.js process on 127.0.0.1:7777, imports @bpc/server and
@tsk/server packages directly. Python calls it via HTTP for provisioning and
full-server verification. Local fast-path verification runs in-process.

Version: 1.3.0  BPC+TSK integration
"""
from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError

from cryptography.hazmat.primitives.asymmetric import ec

from enterprise.bpc_crypto import (
    b64url,
    b64url_decode,
    body_hash,
    canonicalize,
    compute_fingerprint,
    constant_time_equal,
    derive_p256_from_ed25519,
    generate_nonce,
    hash_secret,
    hmac_derive,
    p256_public_key_to_jwk,
    sign_payload,
    verify_payload_with_jwk,
)
from enterprise.tsk_client import (
    CHECKSUM_LENGTH,
    TSKClientState,
    commit_hotp_counter,
    compute_checksum,
    generate_tsk_key,
    parse_provision_payload,
)

if TYPE_CHECKING:
    from enterprise.identity import AgentIdentity

_log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
BPC_VERSION = "1.0"
TSK_VERSION = "1"
DEFAULT_SERVER_URL = "http://127.0.0.1:7777"
NONCE_WINDOW_SEC = 120  # nonces older than this are rejected
DEFAULT_MESH_SECRET = "SelfConnect-Mesh-Dev-Secret-2026!"  # override via %APPDATA%\SelfConnect\mesh.key


class InjectionDeniedError(Exception):
    """Raised when UltraGate rejects an injection attempt."""
    def __init__(self, reason: str) -> None:
        super().__init__(f"InjectionDenied: {reason}")
        self.reason = reason


class UltraGateNotBootstrappedError(Exception):
    """Raised when gate methods are called before bootstrap()."""


class UltraGateServerUnavailableError(OSError):
    """Raised when a required Ultra Server decision cannot be obtained."""


@dataclass(frozen=True)
class _PeerBinding:
    """Locally trusted, complete BPC-to-TSK verification binding."""

    pub_jwk: dict[str, Any]
    fingerprint: str
    tsk_client_id: str
    tsk_state: TSKClientState


class UltraGate:
    """7-layer identity gate for SelfConnect send_string() calls.

    Usage:
        identity = AgentIdentity.load("agent-e-orchestrator")
        gate = UltraGate(identity, server_url="http://localhost:7777")
        gate.bootstrap()  # one-time at agent spawn

        # At each injection:
        gate.authorize_injection(target, text)  # raises InjectionDeniedError on failure
        # Then call send_string() normally.

    Attributes:
        identity: The AgentIdentity (ed25519+DPAPI) root of trust.
        server_url: URL of the Ultra Server sidecar.
        agent_id: Derived from identity (e.g. "SC-A7F3B2E1").
        pair_id: BPC pair ID assigned by Ultra Server.
        tsk_state: TSK client state (segments, shared secret, counters).
        _p256_private: ECDSA P-256 private key (derived from ed25519).
        _pub_jwk: P-256 public key JWK (for local verification).
        _secret_hash: HKDF-derived HMAC key for BPC Layer 3.
        _seen_nonces: Local nonce cache for anti-replay (Layer 4).
        _peer_bindings: Complete BPC public-key and TSK-state bindings by pair_id.
        _bootstrapped: True after bootstrap() has succeeded.
    """

    def __init__(
        self,
        identity: "AgentIdentity",
        mesh_secret: str | None = None,
        server_url: str = DEFAULT_SERVER_URL,
        admin_token: str | None = None,
    ) -> None:
        self.identity = identity
        self.agent_id: str = identity.agent_id
        self.server_url = server_url.rstrip("/")
        self._admin_token = admin_token or os.environ.get("ULTRA_ADMIN_TOKEN", "")
        self._mesh_secret = mesh_secret or self._load_mesh_secret()
        high_assurance = (
            os.environ.get("SC_IDENTITY_MODE", "").strip().lower() == "enforce"
            or os.environ.get("SC_REQUIRE_ULTRA_SERVER", "0").strip() == "1"
            or os.environ.get("ULTRA_RUNTIME_MODE", "").strip().lower() == "production"
        )
        if high_assurance and (
            self._mesh_secret == DEFAULT_MESH_SECRET
            or len(self._mesh_secret.encode("utf-8")) < 32
        ):
            raise ValueError(
                "high-assurance UltraGate requires an explicit mesh secret of at least 32 bytes"
            )
        self._p256_private = derive_p256_from_ed25519(identity._private_key, self.agent_id)
        self._pub_jwk = p256_public_key_to_jwk(self._p256_private)
        self._fingerprint = compute_fingerprint(self._pub_jwk)
        self._secret_hash = hash_secret(self._mesh_secret)
        self.pair_id: str = ""
        self.tsk_state: TSKClientState | None = None
        self._seen_nonces: dict[str, float] = {}  # nonce → timestamp
        self._peer_bindings: dict[str, _PeerBinding] = {}
        self._state_lock = threading.RLock()
        self._bootstrapped = False

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def bootstrap(self) -> None:
        """Register BPC pair, provision TSK, and bind identities with Ultra Server.

        Must be called once at agent spawn before any send_string() calls.
        Idempotent: re-calling after success is a no-op.
        """
        if self._bootstrapped:
            return
        try:
            pair_id = self._register_bpc_pair()
            self.pair_id = pair_id
            tsk_state = self._resume_tsk(pair_id)
            if tsk_state is None:
                tsk_state = self._provision_tsk()
                self._bind_identity(pair_id, tsk_state.client_id)
            self.tsk_state = tsk_state
            self._bootstrapped = True
            _log.info("UltraGate bootstrapped: agent=%s pair=%s tsk=%s",
                      self.agent_id, self.pair_id, self.tsk_state.client_id)
        except Exception as exc:
            _log.error("UltraGate bootstrap failed: %s", exc)
            raise

    # ── Lifecycle API auth (US-3 fix) ─────────────────────────────────────────

    def _lifecycle_auth_headers(self, payload_bytes: bytes) -> dict[str, str]:
        """
        Build the ``X-SC-Agent-Auth`` header block for lifecycle API calls.

        Closes US-3: the three lifecycle endpoints (/register-pair,
        /provision-tsk, /bind-identity) previously had no authentication guard.
        Any process that could reach localhost:7777 could register or revoke
        keys.

        The auth header contains:
          - agent_id: the permanent SC-XXXXXXXX identifier
          - pubkey_hex: raw Ed25519 public key (32 bytes, hex-encoded)
          - ts: Unix timestamp (float) — server should reject if > 30s old
          - nonce: UUID4 — server should reject if seen before (anti-replay)
          - sig: Ed25519 signature over SHA-256(payload_bytes + ts + nonce)
            encoded as base64 — proves the caller holds the private key

        The server-side guard (Ultra Server) must:
          1. Parse the header block from the JSON body or HTTP header.
          2. Verify the Ed25519 signature using the enrolled pubkey_hex.
          3. Check ts is within ±30 seconds of server time.
          4. Check nonce has not been seen before (store in Redis/memory).
          5. Verify agent_id matches the enrolled key fingerprint.

        This is a challenge-response-free scheme — the client proves possession
        of the enrolled key by signing a fresh (ts, nonce, payload_hash) tuple. It is stateless
        from the client's perspective and requires no pre-shared secret beyond
        the identity keypair that the agent already holds.
        """
        from enterprise.lifecycle_auth import lifecycle_auth_headers

        return lifecycle_auth_headers(self.identity, payload_bytes)

    def _register_bpc_pair(self) -> str:
        """POST /register-pair → returns pairId.

        Idempotency: includes X-Idempotency-Key so a crash-and-retry during
        bootstrap does not create a duplicate BPC pair on the server.
        The key is deterministic from agent_id + fingerprint, so retrying
        with the same identity is always safe.
        """
        import urllib.request
        idem_key = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"register-pair:{self.agent_id}:{self._fingerprint}",
        ))
        payload = json.dumps({
            "name": self.agent_id,
            "pubJwk": self._pub_jwk,
            "secretHash": self._secret_hash,
            "scope": "read-write",
            "fingerprint": self._fingerprint,
            "idempotencyKey": idem_key,
        }).encode("utf-8")
        auth_headers = self._lifecycle_auth_headers(payload)
        req = urllib.request.Request(
            f"{self.server_url}/register-pair",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Idempotency-Key": idem_key,
                **({"Authorization": f"Bearer {self._admin_token}"} if self._admin_token else {}),
                **auth_headers,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        pair_id = data.get("pairId")
        if not pair_id:
            raise RuntimeError(f"UltraGate: register-pair returned no pairId: {data}")
        _log.debug("UltraGate: registered BPC pair %s", pair_id)
        return pair_id

    def _provision_tsk(self) -> TSKClientState:
        """POST /provision-tsk → returns TSKClientState.

        Idempotency: includes X-Idempotency-Key so a crash-and-retry during
        bootstrap does not provision a second TSK client for the same agent.
        """
        import urllib.request
        idem_key = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"provision-tsk:{self.agent_id}",
        ))
        payload = json.dumps({
            "requestorId": self.agent_id,
            "idempotencyKey": idem_key,
        }).encode("utf-8")
        auth_headers = self._lifecycle_auth_headers(payload)
        req = urllib.request.Request(
            f"{self.server_url}/provision-tsk",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Idempotency-Key": idem_key,
                **auth_headers,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        client_id = data.get("clientId")
        shared_secret = data.get("sharedSecret")
        provision_payload = data.get("provisionPayload", {})
        if not client_id or not shared_secret:
            raise RuntimeError(f"UltraGate: provision-tsk returned incomplete data: {data}")
        state = parse_provision_payload(client_id, shared_secret, provision_payload)
        _log.debug("UltraGate: provisioned TSK client %s (%d segments)",
                   client_id, len(state.segments))
        return state

    def _resume_tsk(self, pair_id: str) -> TSKClientState | None:
        """Resume the server's currently bound TSK state after restart.

        The response is released only after the server verifies this agent's
        body-bound identity proof and, in production, operator authorization.
        A missing binding is the normal first-enrollment path and returns None.
        """
        import urllib.request

        payload = json.dumps({
            "pairId": pair_id,
            "agentId": self.agent_id,
        }, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.server_url}/resume-identity",
            data=payload,
            headers={
                "Content-Type": "application/json",
                **(
                    {"Authorization": f"Bearer {self._admin_token}"}
                    if self._admin_token else {}
                ),
                **self._lifecycle_auth_headers(payload),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        client_id = data.get("clientId")
        shared_secret = data.get("sharedSecret")
        if not client_id or not shared_secret:
            raise RuntimeError(f"UltraGate: resume-identity returned incomplete data: {data}")
        return parse_provision_payload(
            client_id,
            shared_secret,
            data.get("provisionPayload", {}),
        )

    def rotate_tsk(self) -> TSKClientState:
        """Rotate the active TSK with a retry-safe two-phase server ceremony."""
        import urllib.request

        if not self._bootstrapped or not self.pair_id or self.tsk_state is None:
            raise UltraGateNotBootstrappedError("Call UltraGate.bootstrap() first")
        old_client_id = self.tsk_state.client_id
        idempotency_key = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"rotate-tsk:{self.pair_id}:{old_client_id}",
        ))
        prepare_body = {
            "pairId": self.pair_id,
            "oldClientId": old_client_id,
            "agentId": self.agent_id,
            "idempotencyKey": idempotency_key,
        }
        prepare_payload = json.dumps(
            prepare_body, separators=(",", ":")
        ).encode("utf-8")
        prepare_request = urllib.request.Request(
            f"{self.server_url}/rotate-tsk/prepare",
            data=prepare_payload,
            headers={
                "Content-Type": "application/json",
                "X-Idempotency-Key": idempotency_key,
                **(
                    {"Authorization": f"Bearer {self._admin_token}"}
                    if self._admin_token else {}
                ),
                **self._lifecycle_auth_headers(prepare_payload),
            },
            method="POST",
        )
        with urllib.request.urlopen(prepare_request, timeout=10) as response:
            prepared = json.loads(response.read().decode("utf-8"))
        new_client_id = prepared.get("clientId")
        shared_secret = prepared.get("sharedSecret")
        if not new_client_id or not shared_secret:
            raise RuntimeError(f"UltraGate: rotation prepare was incomplete: {prepared}")
        new_state = parse_provision_payload(
            new_client_id,
            shared_secret,
            prepared.get("provisionPayload", {}),
        )

        commit_payload = json.dumps({
            "pairId": self.pair_id,
            "oldClientId": old_client_id,
            "newClientId": new_client_id,
            "agentId": self.agent_id,
        }, separators=(",", ":")).encode("utf-8")
        commit_request = urllib.request.Request(
            f"{self.server_url}/rotate-tsk/commit",
            data=commit_payload,
            headers={
                "Content-Type": "application/json",
                **(
                    {"Authorization": f"Bearer {self._admin_token}"}
                    if self._admin_token else {}
                ),
                **self._lifecycle_auth_headers(commit_payload),
            },
            method="POST",
        )
        with urllib.request.urlopen(commit_request, timeout=10) as response:
            committed = json.loads(response.read().decode("utf-8"))
        if not committed.get("ok") or committed.get("newClientId") != new_client_id:
            raise RuntimeError(f"UltraGate: rotation commit failed: {committed}")
        self.tsk_state = new_state
        _log.info(
            "UltraGate TSK rotated: agent=%s pair=%s old=%s new=%s",
            self.agent_id,
            self.pair_id,
            old_client_id,
            new_client_id,
        )
        return new_state

    def _bind_identity(self, pair_id: str, tsk_client_id: str) -> None:
        """POST /bind-identity — links BPC pair to TSK client on server.

        Idempotency: includes X-Idempotency-Key so a crash-and-retry does not
        create a duplicate binding.  The key is deterministic from pair_id +
        tsk_client_id, so retrying with the same inputs is always safe.
        """
        import urllib.request
        idem_key = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"bind-identity:{pair_id}:{tsk_client_id}",
        ))
        payload = json.dumps({
            "pairId": pair_id,
            "tskClientId": tsk_client_id,
            "agentId": self.agent_id,
            "idempotencyKey": idem_key,
        }).encode("utf-8")
        auth_headers = self._lifecycle_auth_headers(payload)
        req = urllib.request.Request(
            f"{self.server_url}/bind-identity",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Idempotency-Key": idem_key,
                **auth_headers,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()  # consume response

    # ── Request building ───────────────────────────────────────────────────────

    def build_injection_request(
        self,
        target_hwnd: int,
        text: str,
    ) -> dict[str, str]:
        """Build BPC+TSK headers for a send_string() call.

        Args:
            target_hwnd: HWND of the target terminal (integer).
            text: Text to be injected.

        Returns:
            Dict of X-BPC-* and X-TSK-* headers.

        Raises:
            UltraGateNotBootstrappedError: If bootstrap() hasn't been called.
        """
        if not self._bootstrapped:
            raise UltraGateNotBootstrappedError("Call UltraGate.bootstrap() first")
        assert self.tsk_state is not None

        now_ms = int(time.time() * 1000)
        nonce = generate_nonce()
        path = f"/terminal/{target_hwnd:#010x}"
        bh = body_hash(text)

        canonical = {
            "body_hash": bh,
            "method": "POST",  # INJECT is not in BPC ALLOWED_METHODS; POST is the correct wire method
            "nonce": nonce,
            "pair_id": self.pair_id,
            "path": path,
            "secret_hmac": hmac_derive(self._secret_hash, nonce + str(now_ms)),
            "timestamp": now_ms,
            "version": BPC_VERSION,
        }
        signature = sign_payload(self._p256_private, canonical)
        tsk_key = generate_tsk_key(self.tsk_state, now_ms=now_ms)

        return {
            "X-BPC-Pair-ID": self.pair_id,
            "X-BPC-Signed-Data": b64url(canonicalize(canonical).encode("utf-8")),
            "X-BPC-Signature": signature,
            "X-BPC-Version": BPC_VERSION,
            "X-TSK-Client-ID": self.tsk_state.client_id,
            "X-TSK-Key": tsk_key,
            "X-TSK-Version": TSK_VERSION,
            # X-Target-Path must match the path in the signed canonical payload.
            # The Ultra Server extracts this header and passes it as req.path to
            # verifyBPCRequest, which then checks payload['path'] == req.path.
            "X-Target-Path": path,
        }

    # ── Local fast-path verification ──────────────────────────────────────────

    def verify_local(
        self,
        headers: dict[str, str],
        text: str,
        peer_pair_id: str,
    ) -> tuple[bool, str]:
        """Verify BPC+TSK headers locally without contacting Ultra Server.

        Covers: nonce freshness, timestamp window, ECDSA signature, body hash,
        TSK checksum. Does NOT run Layer 5 (anomaly) or full TSK segment
        verification — use verify_server() for those.

        Args:
            headers: The X-BPC-* / X-TSK-* header dict.
            text: The text that was injected (for body hash verification).
            peer_pair_id: The registered pair_id of the sending agent.

        Returns:
            (ok, reason) — reason is "" on success, error description on failure.
        """
        try:
            # 1. Extract fields
            signed_data_b64 = headers.get("X-BPC-Signed-Data", "")
            signature = headers.get("X-BPC-Signature", "")
            pair_id = headers.get("X-BPC-Pair-ID", "")
            tsk_key = headers.get("X-TSK-Key", "")
            tsk_client_id = headers.get("X-TSK-Client-ID", "")

            if not all([signed_data_b64, signature, pair_id, tsk_key, tsk_client_id]):
                return False, "missing required headers"

            # 2. Pair ID must match registered peer
            if pair_id != peer_pair_id:
                return False, f"pair_id mismatch: got {pair_id!r}"

            # Local verification is permitted only for explicitly registered
            # peers and the exact TSK state held by this gate.  Missing state or
            # an unknown client ID must never degrade into signature/checksum
            # bypasses.
            with self._state_lock:
                binding = self._peer_bindings.get(peer_pair_id)
            if binding is None:
                return False, f"no complete cached binding for peer {peer_pair_id!r}"
            if binding.tsk_state is None:
                return False, "peer TSK state unavailable"
            if tsk_client_id != binding.tsk_client_id:
                return False, f"TSK client_id mismatch: got {tsk_client_id!r}"

            expected_tsk_length = (
                sum(segment.seg_len for segment in binding.tsk_state.segments)
                + CHECKSUM_LENGTH
            )
            if len(tsk_key) != expected_tsk_length:
                return False, (
                    "TSK key length mismatch: "
                    f"got {len(tsk_key)}, expected {expected_tsk_length}"
                )

            # 3. Decode canonical payload
            payload_json = b64url_decode(signed_data_b64).decode("utf-8")
            payload = json.loads(payload_json)
            if payload.get("pair_id") != pair_id:
                return False, "signed pair_id mismatch"

            # 4. Timestamp window (±60 seconds)
            ts = payload.get("timestamp", 0)
            now_ms = int(time.time() * 1000)
            if abs(now_ms - ts) > 60_000:
                return False, f"timestamp out of window: {abs(now_ms - ts)}ms"

            # 5. Body hash
            expected_bh = body_hash(text)
            if not constant_time_equal(payload.get("body_hash", ""), expected_bh):
                return False, "body_hash mismatch"

            # 6. ECDSA P-256 signature from the explicitly registered peer.
            if not verify_payload_with_jwk(binding.pub_jwk, payload, signature):
                return False, "ECDSA signature invalid"

            # 7. TSK checksum. The exact length check above prevents a truncated
            # body from being reinterpreted as a shorter valid key.
            expected_cksum = compute_checksum(
                binding.tsk_state.shared_secret,
                tsk_key[:-CHECKSUM_LENGTH],
            )
            if not constant_time_equal(tsk_key[-CHECKSUM_LENGTH:], expected_cksum):
                return False, "TSK checksum mismatch"

            # 8. Commit nonce only after all cryptographic checks pass. Recording
            # it earlier lets a forged request race the valid request and poison
            # the local replay cache.
            nonce = payload.get("nonce", "")
            if not isinstance(nonce, str) or not nonce:
                return False, "missing signed nonce"
            if not self._consume_nonce(nonce, now_ms / 1000):
                return False, "nonce replay detected"

            return True, ""

        except Exception as exc:
            return False, f"verification error: {exc}"

    def verify_server(
        self,
        headers: dict[str, str],
        text: str,
    ) -> tuple[bool, str]:
        """Full 7-layer verification via Ultra Server.

        Runs the complete BPC 12-step pipeline + TSK segment verification + identity
        binding check. Use this for high-security contexts or when anomaly detection
        (Layer 5) is important.

        Args:
            headers: The X-BPC-* / X-TSK-* header dict.
            text: The injected text (for body hash computation).

        Returns:
            (ok, reason) — reason is "" on success, error description on failure.
        """
        import urllib.request
        try:
            body = json.dumps({
                "headers": headers,
                "bodyHash": body_hash(text),
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.server_url}/verify",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                # RFC 4226 commit-after-success: advance HOTP counters only when
                # the server has confirmed the key was valid. This keeps the Python
                # client's counter in sync with the server's stored counter, preventing
                # counter drift that causes INVALID_KEY after N sequential requests.
                if self.tsk_state:
                    for seg in self.tsk_state.segments:
                        if seg.type == "hotp":
                            commit_hotp_counter(self.tsk_state, seg.segment_id)
                return True, ""
            return False, data.get("error", "server verification failed")
        except HTTPError as exc:
            try:
                data = json.loads(exc.read().decode("utf-8"))
                reason = data.get("error") or data.get("message") or str(exc)
            except Exception:
                reason = str(exc)
            return False, f"server rejected verification: {reason}"
        except (URLError, TimeoutError, ConnectionError, OSError) as exc:
            return False, f"server unavailable: {exc}"
        except Exception as exc:
            return False, f"server verification error: {exc}"

    # ── Injection authorization ───────────────────────────────────────────────

    def authorize_injection(self, target_hwnd: int, text: str) -> None:
        """Authorize a send_string() call. Called from the identity gate.

        This method is the hot-path gate. It builds the request and requires a
        live Ultra Server decision. On failure, it raises before the caller can
        reach the Win32 transport.

        Args:
            target_hwnd: HWND integer of the target terminal.
            text: Text to be injected.

        Raises:
            InjectionDeniedError: If verification fails.
            UltraGateNotBootstrappedError: If bootstrap() hasn't been called.
        """
        if not self._bootstrapped:
            raise UltraGateNotBootstrappedError("Call UltraGate.bootstrap() first")

        headers = self.build_injection_request(target_hwnd, text)
        ok, reason = self.verify_server(headers, text)
        if not ok:
            _log.error("UltraGate: server verification failed for hwnd=%#x: %s", target_hwnd, reason)
            if reason.startswith("server unavailable:"):
                raise UltraGateServerUnavailableError(reason)
            raise InjectionDeniedError(reason)
        _log.debug("UltraGate: authorized injection → hwnd=%#x (%d chars)", target_hwnd, len(text))

    def _self_verify(self, headers: dict[str, str], text: str) -> tuple[bool, str]:
        """Verify the request we just built (smoke-tests the crypto pipeline)."""
        try:
            signed_data_b64 = headers.get("X-BPC-Signed-Data", "")
            signature = headers.get("X-BPC-Signature", "")
            tsk_key = headers.get("X-TSK-Key", "")
            payload_json = b64url_decode(signed_data_b64).decode("utf-8")
            payload = json.loads(payload_json)

            # Verify own signature
            if not verify_payload_with_jwk(self._pub_jwk, payload, signature):
                return False, "own ECDSA signature failed self-check"

            # Verify body hash
            expected_bh = body_hash(text)
            if not constant_time_equal(payload.get("body_hash", ""), expected_bh):
                return False, "body_hash self-check failed"

            # Verify TSK checksum (CHECKSUM_LENGTH=12 per protocol-constants.ts)
            if self.tsk_state and len(tsk_key) > CHECKSUM_LENGTH:
                expected_cksum = compute_checksum(
                    self.tsk_state.shared_secret, tsk_key[:-CHECKSUM_LENGTH]
                )
                if not constant_time_equal(tsk_key[-CHECKSUM_LENGTH:], expected_cksum):
                    return False, "TSK checksum self-check failed"

            return True, ""
        except Exception as exc:
            return False, f"self-verify exception: {exc}"

    # ── Peer registry ─────────────────────────────────────────────────────────

    def register_peer_binding(
        self,
        pair_id: str,
        pub_jwk: dict[str, Any],
        expected_tsk_client_id: str,
        tsk_state: TSKClientState,
    ) -> None:
        """Register a complete peer binding for local fast-path verification.

        The caller must obtain every value from the same authenticated binding
        transaction. Partial registration is unsupported by design.
        """
        if not isinstance(pair_id, str) or not pair_id.strip():
            raise ValueError("peer pair_id must be a non-empty string")
        if not isinstance(expected_tsk_client_id, str) or not expected_tsk_client_id.strip():
            raise ValueError("expected TSK client_id must be a non-empty string")
        if not isinstance(tsk_state, TSKClientState):
            raise TypeError("peer TSK state must be TSKClientState")
        if tsk_state.client_id != expected_tsk_client_id:
            raise ValueError("peer TSK state client_id does not match expected binding")
        if not tsk_state.segments:
            raise ValueError("peer TSK state must contain at least one segment")

        segment_ids: set[str] = set()
        for segment in tsk_state.segments:
            if (
                not segment.segment_id
                or segment.segment_id in segment_ids
                or segment.type not in {"static", "totp", "hotp"}
                or not isinstance(segment.seg_len, int)
                or segment.seg_len < 1
            ):
                raise ValueError("peer TSK state contains an invalid or duplicate segment")
            segment_ids.add(segment.segment_id)

        if (
            not isinstance(pub_jwk, dict)
            or pub_jwk.get("kty") != "EC"
            or pub_jwk.get("crv") != "P-256"
        ):
            raise ValueError("peer public key must be an EC P-256 JWK")
        try:
            x_bytes = b64url_decode(str(pub_jwk["x"]))
            y_bytes = b64url_decode(str(pub_jwk["y"]))
            if len(x_bytes) != 32 or len(y_bytes) != 32:
                raise ValueError("invalid coordinate length")
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, "big"),
                int.from_bytes(y_bytes, "big"),
                ec.SECP256R1(),
            ).public_key()
        except Exception as exc:
            raise ValueError("peer public key is not a valid P-256 point") from exc

        normalized_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": str(pub_jwk["x"]),
            "y": str(pub_jwk["y"]),
        }
        fingerprint = compute_fingerprint(normalized_jwk)
        with self._state_lock:
            existing = self._peer_bindings.get(pair_id)
            if existing is not None and (
                existing.fingerprint != fingerprint
                or existing.tsk_client_id != expected_tsk_client_id
                or not constant_time_equal(
                    existing.tsk_state.shared_secret,
                    tsk_state.shared_secret,
                )
                or existing.tsk_state.segments != tsk_state.segments
            ):
                raise ValueError("peer binding conflict; use an authenticated rotation ceremony")

            self._peer_bindings[pair_id] = _PeerBinding(
                pub_jwk=normalized_jwk,
                fingerprint=fingerprint,
                tsk_client_id=expected_tsk_client_id,
                tsk_state=copy.deepcopy(tsk_state),
            )
        _log.debug(
            "UltraGate: registered complete peer binding pair=%s tsk=%s",
            pair_id,
            expected_tsk_client_id,
        )

    # ── Nonce management ──────────────────────────────────────────────────────

    def _expire_nonces(self) -> None:
        """Remove nonces older than NONCE_WINDOW_SEC from the local cache."""
        with self._state_lock:
            cutoff = time.time() - NONCE_WINDOW_SEC
            expired = [k for k, ts in self._seen_nonces.items() if ts < cutoff]
            for k in expired:
                del self._seen_nonces[k]

    def _consume_nonce(self, nonce: str, verified_at: float) -> bool:
        """Atomically expire, check, and record one locally verified nonce."""
        with self._state_lock:
            cutoff = time.time() - NONCE_WINDOW_SEC
            expired = [k for k, ts in self._seen_nonces.items() if ts < cutoff]
            for key in expired:
                del self._seen_nonces[key]
            if nonce in self._seen_nonces:
                return False
            self._seen_nonces[nonce] = verified_at
            return True

    # ── Mesh secret ───────────────────────────────────────────────────────────

    @staticmethod
    def _load_mesh_secret() -> str:
        """Load mesh secret from %APPDATA%\\SelfConnect\\mesh.key (if present).

        Falls back to DEFAULT_MESH_SECRET for development environments.
        The mesh.key file should be DPAPI-encrypted in production — this loader
        reads the plaintext version only (bootstrap_mesh.py handles encryption).
        """
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            key_file = os.path.join(appdata, "SelfConnect", "mesh.key")
            if os.path.exists(key_file):
                try:
                    return open(key_file, encoding="utf-8").read().strip()
                except Exception:
                    pass
        return DEFAULT_MESH_SECRET

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Return gate status dict (for diagnostics)."""
        return {
            "bootstrapped": self._bootstrapped,
            "agent_id": self.agent_id,
            "pair_id": self.pair_id,
            "tsk_client_id": self.tsk_state.client_id if self.tsk_state else None,
            "fingerprint": self._fingerprint,
            "peer_count": self._binding_count(),
            "nonce_cache_size": self._nonce_count(),
            "server_url": self.server_url,
        }

    def _binding_count(self) -> int:
        with self._state_lock:
            return len(self._peer_bindings)

    def _nonce_count(self) -> int:
        with self._state_lock:
            return len(self._seen_nonces)
