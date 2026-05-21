"""enterprise/ultra_gate.py — UltraGate: BPC + TSK 7-Layer Identity Gate

Main gate module.  Wraps every send_string() call with a 7-layer identity
verification pipeline combining BPC (Layers 1-5) and TSK (Layers 6-7).

Layers:
  L1  ECDSA P-256 device-bound signature (BPC)
  L2  Pair registry check (BPC — server-side, fast-path skipped locally)
  L3  User secret HMAC derivation (BPC)
  L4  Anti-replay nonce + timestamp window (BPC)
  L5  Anomaly engine (BPC — server-side)
  L6  TSK tumbler key assembly + checksum (TSK)
  L7  Structural secrecy — server verifies segment positions (TSK)

Bootstrap (once per agent spawn, ~200-500ms):
  1. Derive BPC P-256 keypair from ed25519 AgentIdentity via HKDF
  2. Register BPC pair with Ultra Server (POST /register-pair)
  3. Provision TSK client (POST /provision-tsk)
  4. Bind identities (POST /bind-identity)
  5. Cache: pairId, tskClientId, sharedSecret, provisionPayload

Per-injection (local fast-path ~2-5ms, server path ~20-50ms):
  1. Build BPC canonical payload + ECDSA signature
  2. Assemble TSK key
  3. Verify locally (nonce, timestamp, body hash, ECDSA)
  4. If SC_IDENTITY_MODE=enforce: server verify (optional, configurable)
  5. Pass → inject.  Fail → InjectionDeniedError + ledger entry.

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

import requests

from enterprise.bpc_crypto import (
    BPCHeaders,
    P256KeyPair,
    body_hash,
    derive_p256_private_key,
    p256_public_key_from_jwk,
    sign_bpc_request,
    verify_bpc_request_local,
)
from enterprise.tsk_client import TSKClient, TSKHeaders, tsk_client_from_server_response

_log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

ULTRA_SERVER_URL: str = os.environ.get("SC_ULTRA_SERVER_URL", "http://localhost:7777")
ULTRA_SERVER_TIMEOUT_MS: int = int(os.environ.get("SC_ULTRA_SERVER_TIMEOUT_MS", "5000"))
ULTRA_VERIFY_SERVER: bool = os.environ.get("SC_ULTRA_VERIFY_SERVER", "0") == "1"
ULTRA_SIG_WINDOW_MS: int = int(os.environ.get("SC_ULTRA_SIG_WINDOW_MS", "60000"))


# ── Exceptions ────────────────────────────────────────────────────────────────

class InjectionDeniedError(Exception):
    """Raised when the UltraGate rejects an injection request."""
    def __init__(self, reason: str, layer: int = 0) -> None:
        self.reason = reason
        self.layer = layer
        super().__init__(f"Injection denied (L{layer}): {reason}")


class UltraGateBootstrapError(Exception):
    """Raised when UltraGate bootstrap fails and cannot degrade."""
    pass


# ── Gate result ───────────────────────────────────────────────────────────────

@dataclass
class GateResult:
    ok: bool
    layer: int = 0          # Layer at which verification passed or failed
    reason: str = "ok"
    degraded: bool = False  # True if running in degraded mode
    degraded_level: int = 0


# ── UltraGate ─────────────────────────────────────────────────────────────────

class UltraGate:
    """Per-agent BPC + TSK identity gate.

    Lifecycle:
      gate = UltraGate(identity)
      gate.bootstrap()          # once at spawn
      gate.verify_injection(target_hwnd, text, method, path)  # per send_string
    """

    def __init__(self, identity: Any) -> None:
        """
        Args:
            identity: enterprise.identity.AgentIdentity instance.
        """
        self._identity = identity
        self._agent_id: str = identity.agent_name
        self._keypair: Optional[P256KeyPair] = None
        self._pair_id: Optional[str] = None
        self._secret: Optional[str] = None
        self._tsk_client: Optional[TSKClient] = None
        self._seen_nonces: Set[str] = set()
        self._bootstrapped: bool = False
        self._degraded_level: int = 0  # 0 = full 7-layer, 1-5 = degraded

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def bootstrap(self) -> None:
        """Perform birth registration: derive keys, register with Ultra Server.

        On failure, sets degraded level per the graceful degradation cascade.
        Raises UltraGateBootstrapError only if degradation is not possible.
        """
        try:
            self._derive_keypair()
            self._register_bpc_pair()
            self._provision_tsk()
            self._bind_identity()
            self._bootstrapped = True
            self._degraded_level = 0
            _log.info("UltraGate bootstrap complete for agent=%s pair=%s tsk=%s",
                      self._agent_id, self._pair_id,
                      self._tsk_client.client_id if self._tsk_client else None)
        except _TSKProvisionError:
            # Level 1: BPC-only (TSK service issue)
            self._degraded_level = 1
            self._bootstrapped = True
            _log.warning("UltraGate degraded to Level 1 (BPC-only): TSK provision failed for agent=%s",
                         self._agent_id)
        except _BPCRegisterError:
            # Level 2: Enterprise-only (Node.js bridge down)
            self._degraded_level = 2
            self._bootstrapped = True
            _log.warning("UltraGate degraded to Level 2 (enterprise-only): BPC register failed for agent=%s",
                         self._agent_id)
        except Exception as exc:
            # Level 2 fallback for any unexpected bootstrap error
            self._degraded_level = 2
            self._bootstrapped = True
            _log.warning("UltraGate degraded to Level 2 (unexpected bootstrap error): agent=%s error=%s",
                         self._agent_id, exc)

    def _derive_keypair(self) -> None:
        """Derive BPC P-256 keypair from ed25519 AgentIdentity via HKDF."""
        # AgentIdentity exposes _private_key_bytes (raw 32-byte ed25519 seed)
        # or private_key_bytes property depending on implementation.
        priv_bytes = self._get_ed25519_private_bytes()
        p256_priv = derive_p256_private_key(priv_bytes, self._agent_id)
        self._keypair = P256KeyPair.from_private_key(p256_priv)
        _log.debug("UltraGate: derived P-256 keypair for agent=%s fingerprint=%s",
                   self._agent_id, self._keypair.public_key_fingerprint())

    def _get_ed25519_private_bytes(self) -> bytes:
        """Extract raw ed25519 private key bytes from AgentIdentity."""
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        # AgentIdentity stores ed25519 private key; extract raw 32-byte seed.
        priv = self._identity._private_key
        raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return raw  # 32 bytes

    def _register_bpc_pair(self) -> None:
        """POST /register-pair to Ultra Server."""
        if not self._keypair:
            raise _BPCRegisterError("No keypair derived")
        payload = {
            "agentId": self._agent_id,
            "publicKeyJwk": self._keypair.public_key_jwk(),
            "fingerprint": self._keypair.public_key_fingerprint(),
        }
        try:
            resp = requests.post(
                f"{ULTRA_SERVER_URL}/register-pair",
                json=payload,
                timeout=ULTRA_SERVER_TIMEOUT_MS / 1000,
            )
            resp.raise_for_status()
            data = resp.json()
            self._pair_id = data["pairId"]
            self._secret = data["secret"]
            _log.debug("UltraGate: registered BPC pair=%s for agent=%s", self._pair_id, self._agent_id)
        except Exception as exc:
            raise _BPCRegisterError(str(exc)) from exc

    def _provision_tsk(self) -> None:
        """POST /provision-tsk to Ultra Server."""
        if not self._pair_id:
            raise _TSKProvisionError("No pair_id — BPC not registered")
        payload = {"agentId": self._agent_id, "pairId": self._pair_id}
        try:
            resp = requests.post(
                f"{ULTRA_SERVER_URL}/provision-tsk",
                json=payload,
                timeout=ULTRA_SERVER_TIMEOUT_MS / 1000,
            )
            resp.raise_for_status()
            self._tsk_client = tsk_client_from_server_response(resp.json())
            _log.debug("UltraGate: provisioned TSK client=%s for agent=%s",
                       self._tsk_client.client_id, self._agent_id)
        except Exception as exc:
            raise _TSKProvisionError(str(exc)) from exc

    def _bind_identity(self) -> None:
        """POST /bind-identity to Ultra Server."""
        payload = {
            "agentId": self._agent_id,
            "pairId": self._pair_id,
            "tskClientId": self._tsk_client.client_id if self._tsk_client else None,
        }
        try:
            resp = requests.post(
                f"{ULTRA_SERVER_URL}/bind-identity",
                json=payload,
                timeout=ULTRA_SERVER_TIMEOUT_MS / 1000,
            )
            resp.raise_for_status()
            _log.debug("UltraGate: bound identity for agent=%s", self._agent_id)
        except Exception as exc:
            # Bind failure is non-fatal — degrade to Level 1
            _log.warning("UltraGate: bind-identity failed (non-fatal): agent=%s error=%s",
                         self._agent_id, exc)

    # ── Per-injection request building ────────────────────────────────────────

    def build_injection_request(
        self,
        target_hwnd: int,
        text: str,
        method: str = "INJECT",
        path: str = "/inject",
    ) -> Dict[str, Any]:
        """Build a signed injection request dict with BPC headers and TSK headers.

        Returns a dict with:
          bpc_payload: BPCCanonicalPayload
          bpc_headers: BPCHeaders
          tsk_headers: TSKHeaders (or None if TSK unavailable)
          body: bytes
          method: str
          path: str
        """
        body = json.dumps({
            "target_hwnd": target_hwnd,
            "text": text,
            "agent_id": self._agent_id,
            "ts": int(time.time() * 1000),
        }, separators=(",", ":"), sort_keys=True).encode()

        if self._keypair and self._pair_id and self._secret:
            bpc_payload, bpc_headers = sign_bpc_request(
                keypair=self._keypair,
                pair_id=self._pair_id,
                secret=self._secret,
                method=method,
                path=path,
                body=body,
            )
        else:
            bpc_payload = None
            bpc_headers = None

        tsk_headers = self._tsk_client.build_headers() if self._tsk_client else None

        return {
            "bpc_payload": bpc_payload,
            "bpc_headers": bpc_headers,
            "tsk_headers": tsk_headers,
            "body": body,
            "method": method,
            "path": path,
        }

    # ── Local fast-path verification ──────────────────────────────────────────

    def verify_local(
        self,
        request: Dict[str, Any],
    ) -> GateResult:
        """Local fast-path verification (~2-5ms).

        Runs all verifiable layers without a server round-trip:
          L1: ECDSA P-256 signature
          L4: Nonce freshness + timestamp window
          L6: TSK checksum

        L2 (pair registry), L3 (server-side secret HMAC), L5 (anomaly),
        L7 (structural secrecy positions) require the server.
        """
        bpc_headers: Optional[BPCHeaders] = request.get("bpc_headers")
        tsk_headers: Optional[TSKHeaders] = request.get("tsk_headers")
        body: bytes = request.get("body", b"")
        method: str = request.get("method", "INJECT")
        path: str = request.get("path", "/inject")

        # ── L1 + L4: BPC local verify ─────────────────────────────────────────
        if bpc_headers and self._keypair:
            ok, reason = verify_bpc_request_local(
                public_key=self._keypair.public_key,
                headers=bpc_headers,
                method=method,
                path=path,
                body=body,
                sig_window_ms=ULTRA_SIG_WINDOW_MS,
                seen_nonces=self._seen_nonces,
            )
            if not ok:
                layer = 4 if reason in ("timestamp_expired", "replay_detected") else 1
                return GateResult(ok=False, layer=layer, reason=reason,
                                  degraded=self._degraded_level > 0,
                                  degraded_level=self._degraded_level)
        elif self._degraded_level >= 3:
            # Level 3+: skip BPC entirely
            pass
        else:
            return GateResult(ok=False, layer=1, reason="bpc_not_bootstrapped",
                              degraded=self._degraded_level > 0,
                              degraded_level=self._degraded_level)

        # ── L6: TSK checksum ──────────────────────────────────────────────────
        if tsk_headers and self._tsk_client:
            if not self._tsk_client.verify_checksum(tsk_headers.key):
                return GateResult(ok=False, layer=6, reason="tsk_checksum_invalid",
                                  degraded=self._degraded_level > 0,
                                  degraded_level=self._degraded_level)
        elif self._degraded_level >= 1:
            # Level 1+: TSK unavailable, skip
            pass
        else:
            return GateResult(ok=False, layer=6, reason="tsk_not_provisioned",
                              degraded=self._degraded_level > 0,
                              degraded_level=self._degraded_level)

        return GateResult(ok=True, layer=7, reason="ok",
                          degraded=self._degraded_level > 0,
                          degraded_level=self._degraded_level)

    # ── Server verification ───────────────────────────────────────────────────

    def verify_server(
        self,
        request: Dict[str, Any],
    ) -> GateResult:
        """Full 7-layer server verification (~20-50ms).

        Sends the BPC headers and TSK headers to Ultra Server for L2, L3, L5, L7.
        Falls back to local result if server is unreachable.
        """
        bpc_headers: Optional[BPCHeaders] = request.get("bpc_headers")
        tsk_headers: Optional[TSKHeaders] = request.get("tsk_headers")
        body: bytes = request.get("body", b"")
        method: str = request.get("method", "INJECT")
        path: str = request.get("path", "/inject")

        headers_dict = {}
        if bpc_headers:
            headers_dict.update(bpc_headers.as_dict())
        if tsk_headers:
            headers_dict.update(tsk_headers.as_dict())

        try:
            resp = requests.post(
                f"{ULTRA_SERVER_URL}/verify",
                headers=headers_dict,
                data=body,
                params={"method": method, "path": path},
                timeout=ULTRA_SERVER_TIMEOUT_MS / 1000,
            )
            if resp.status_code == 200:
                return GateResult(ok=True, layer=7, reason="ok",
                                  degraded=self._degraded_level > 0,
                                  degraded_level=self._degraded_level)
            else:
                data = resp.json() if resp.content else {}
                reason = data.get("error", f"server_rejected_{resp.status_code}")
                layer = data.get("layer", 2)
                return GateResult(ok=False, layer=layer, reason=reason,
                                  degraded=self._degraded_level > 0,
                                  degraded_level=self._degraded_level)
        except requests.exceptions.ConnectionError:
            # Server unreachable — degrade to Level 2 (enterprise-only)
            _log.warning("UltraGate: Ultra Server unreachable, degrading to Level 2 for agent=%s",
                         self._agent_id)
            self._degraded_level = max(self._degraded_level, 2)
            # Fall back to local verification result
            return self.verify_local(request)
        except Exception as exc:
            _log.warning("UltraGate: server verify error for agent=%s: %s", self._agent_id, exc)
            self._degraded_level = max(self._degraded_level, 2)
            return self.verify_local(request)

    # ── Combined verify (mode-aware) ──────────────────────────────────────────

    def verify_injection(
        self,
        target_hwnd: int,
        text: str,
        method: str = "INJECT",
        path: str = "/inject",
    ) -> GateResult:
        """Build and verify an injection request.  Returns GateResult.

        Uses ULTRA_VERIFY_SERVER to decide local vs server verification.
        """
        request = self.build_injection_request(target_hwnd, text, method, path)
        if ULTRA_VERIFY_SERVER and self._degraded_level < 2:
            return self.verify_server(request)
        return self.verify_local(request)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def bootstrapped(self) -> bool:
        return self._bootstrapped

    @property
    def degraded_level(self) -> int:
        return self._degraded_level

    @property
    def pair_id(self) -> Optional[str]:
        return self._pair_id

    @property
    def tsk_client_id(self) -> Optional[str]:
        return self._tsk_client.client_id if self._tsk_client else None


# ── Internal exceptions ───────────────────────────────────────────────────────

class _BPCRegisterError(Exception):
    pass


class _TSKProvisionError(Exception):
    pass
