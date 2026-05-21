"""enterprise/key_recovery.py — Key recovery protocol for SelfConnect Enterprise.

Solves the chicken-and-egg problem: if a terminal's DPAPI identity key gets
corrupted, it can't communicate to re-register because communication requires
identity. This module breaks that deadlock via an out-of-band filesystem path.

Recovery flow:
  1. AgentIdentity.load() fails → RecoveryManager detects corruption.
  2. RecoveryManager generates a new keypair via AgentIdentity.init(overwrite=True).
  3. Writes the new public key to %APPDATA%\SelfConnect\{name}\recovery.pub.
  4. POSTs /confirm-recovery to the Ultra Server, signed with the new private key
     and counter-signed by the server. Receives a server confirmation token.
     (Gap 2 fix: server confirmation prevents an attacker with session access from
     writing their own recovery.pub and hijacking the agent's identity.)
  5. Writes the server confirmation token to recovery.token alongside recovery.pub.
  6. Stamps SCRECOVERY=1 on the agent's listener HWND.
  7. Peers running discover_mesh() detect SCRECOVERY=1, read recovery.pub AND
     recovery.token, verify the server token, update their local peer registry,
     and accept the new key.
  8. Next handshake uses the new key. Ledger records key_rotation_recovery.

Security properties:
  - Recovery only works on the same machine + same user (DPAPI scope, shared %APPDATA%).
  - Recovery window: 60 seconds (configurable). Stale files are ignored.
  - Recovery downgrades to enterprise-only verification (Level 2) during the window.
  - Recovery is logged to the ledger with old/new fingerprints.
  - New agent_id is different from old (derived from new pubkey). Policy bundle
    must include the new agent_id or have a wildcard recovery entry.
  - Gap 2 fix: Peers require a server-signed confirmation token alongside
    recovery.pub. An attacker who writes a rogue recovery.pub cannot forge the
    server token without the Ultra Server's HMAC key.

Version: 1.1.0  BPC+TSK integration — Gap 2 server-confirmation hardening
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
RECOVERY_WINDOW_SEC: int = int(os.environ.get("SC_RECOVERY_WINDOW_SEC", "60"))
PROP_RECOVERY = "SCRECOVERY"  # Set to "1" on HWND during recovery window
DEFAULT_SERVER_URL = "http://localhost:7777"

# ── Gap 2: Server confirmation token verification ─────────────────────────────
# The Ultra Server signs recovery confirmations with an HMAC-SHA256 key that
# is only known to the server process. Peers verify the token before accepting
# a new recovery key. An attacker who writes a rogue recovery.pub cannot forge
# this token without compromising the Ultra Server itself.
#
# Token format (JSON):
#   { "agent_name": str, "new_pub_hex": str, "issued_at": int, "sig": str }
# where sig = HMAC-SHA256(server_key, f"{agent_name}:{new_pub_hex}:{issued_at}")
# encoded as hex.
#
# The server key is generated at Ultra Server startup and never written to disk.
# It is rotated on every server restart. Tokens are only valid for RECOVERY_WINDOW_SEC.


def _appdata_dir() -> Path:
    """Return %APPDATA%\SelfConnect, creating it if needed."""
    base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
    d = Path(base) / "SelfConnect"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _recovery_pub_path(agent_name: str) -> Path:
    """Path to recovery.pub file for a given agent."""
    p = _appdata_dir() / agent_name
    p.mkdir(parents=True, exist_ok=True)
    return p / "recovery.pub"


def _recovery_token_path(agent_name: str) -> Path:
    """Path to recovery.token file for a given agent (Gap 2 fix)."""
    p = _appdata_dir() / agent_name
    p.mkdir(parents=True, exist_ok=True)
    return p / "recovery.token"


class RecoveryManager:
    """Manages the key recovery lifecycle for a single agent.

    Usage:
        try:
            identity = AgentIdentity.load("agent-e-orchestrator")
        except (OSError, ValueError):
            mgr = RecoveryManager("agent-e-orchestrator", server_url="http://localhost:7777")
            identity = mgr.recover()
            mgr.notify_peers(listener_hwnd=my_hwnd)
    """

    def __init__(self, agent_name: str, server_url: str = DEFAULT_SERVER_URL) -> None:
        self.agent_name = agent_name
        self.server_url = server_url.rstrip("/")
        self._recovery_start: float = 0.0
        self._new_pub_hex: str = ""

    def recover(self) -> Any:
        """Generate a new identity, write recovery.pub, and get server confirmation.

        Gap 2 fix: After writing recovery.pub, POSTs /confirm-recovery to the
        Ultra Server with the new public key. The server returns a signed
        confirmation token that peers must verify before accepting the new key.

        Returns the new AgentIdentity. The new agent_id will differ from the
        old one (it's derived from the new public key).

        Raises:
            RuntimeError: If recovery itself fails (e.g. DPAPI unavailable or
                          Ultra Server unreachable during recovery).
        """
        from enterprise.identity import AgentIdentity
        _log.critical(
            "RecoveryManager: identity key for '%s' is corrupted. "
            "Generating new keypair. New agent_id will differ.",
            self.agent_name,
        )
        identity = AgentIdentity.init(self.agent_name, overwrite=True)
        self._new_pub_hex = identity.public_key_bytes.hex()
        self._recovery_start = time.time()

        # Write recovery.pub (new public key in hex, one line)
        pub_path = _recovery_pub_path(self.agent_name)
        pub_path.write_text(self._new_pub_hex + "\n", encoding="utf-8")
        _log.info(
            "RecoveryManager: wrote recovery.pub for '%s' at %s (new agent_id: %s)",
            self.agent_name, pub_path, identity.agent_id,
        )

        # Gap 2 fix: Request server confirmation token
        try:
            token = self._request_server_confirmation(identity)
            token_path = _recovery_token_path(self.agent_name)
            token_path.write_text(json.dumps(token) + "\n", encoding="utf-8")
            _log.info(
                "RecoveryManager: server confirmation token written for '%s'",
                self.agent_name,
            )
        except Exception as exc:
            # If the server is unreachable, recovery.pub is written but peers
            # will reject the key because no valid token exists. This is the
            # correct fail-safe behavior — an offline attacker cannot recover.
            _log.error(
                "RecoveryManager: failed to get server confirmation for '%s': %s. "
                "Peers will reject the new key until the server confirms it.",
                self.agent_name, exc,
            )
            # Remove recovery.pub so peers don't see a partial recovery state
            try:
                pub_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise RuntimeError(
                f"RecoveryManager: Ultra Server unreachable — cannot complete recovery "
                f"for '{self.agent_name}': {exc}"
            ) from exc

        return identity

    def _request_server_confirmation(self, identity: Any) -> dict:
        """POST /confirm-recovery to the Ultra Server.

        The server verifies the new public key is signed by the new private key
        (proof of possession) and returns a signed confirmation token.

        Returns the token dict: { agent_name, new_pub_hex, issued_at, sig }
        """
        from enterprise.bpc_crypto import sign_payload, b64url
        import hashlib

        # Proof of possession: sign a challenge with the new private key
        challenge = f"recovery:{self.agent_name}:{self._new_pub_hex}:{int(time.time())}"
        challenge_hash = hashlib.sha256(challenge.encode()).hexdigest()
        signature = sign_payload(identity._private_key, {"challenge_hash": challenge_hash})

        payload = json.dumps({
            "agentName": self.agent_name,
            "newPubHex": self._new_pub_hex,
            "challengeHash": challenge_hash,
            "signature": signature,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.server_url}/confirm-recovery",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if not data.get("token"):
            raise RuntimeError(
                f"confirm-recovery returned no token: {data}"
            )
        return data["token"]

    def notify_peers(self, listener_hwnd: int) -> None:
        """Stamp SCRECOVERY=1 on the agent's listener HWND so peers detect it.

        Peers calling discover_mesh() will see SCRECOVERY=1, read recovery.pub
        AND recovery.token, verify the server token, and update their local
        peer registry within the recovery window.
        """
        try:
            import ctypes
            user32 = ctypes.windll.user32
            user32.SetPropW(listener_hwnd, PROP_RECOVERY, ctypes.c_char_p(b"1"))
            _log.info("RecoveryManager: stamped SCRECOVERY=1 on hwnd=%#x", listener_hwnd)
        except Exception as exc:
            _log.error("RecoveryManager: failed to stamp SCRECOVERY on hwnd=%#x: %s",
                       listener_hwnd, exc)

    def clear_recovery_flag(self, listener_hwnd: int) -> None:
        """Remove SCRECOVERY property from HWND after recovery window expires."""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            user32.RemovePropW(listener_hwnd, PROP_RECOVERY)
            _log.info("RecoveryManager: cleared SCRECOVERY from hwnd=%#x", listener_hwnd)
        except Exception as exc:
            _log.warning("RecoveryManager: failed to clear SCRECOVERY: %s", exc)

    def is_window_active(self) -> bool:
        """True if we're within the recovery window."""
        return (
            self._recovery_start > 0
            and time.time() - self._recovery_start < RECOVERY_WINDOW_SEC
        )


# ── Peer-side: detect recovering agents ──────────────────────────────────────

def check_peer_recovery(
    hwnd: int,
    agent_name: str,
    server_url: str = DEFAULT_SERVER_URL,
) -> Optional[bytes]:
    """Check if a peer is in recovery mode. If so, return their new public key bytes.

    Called from discover_mesh() when SCRECOVERY=1 is detected on a peer's HWND.

    Gap 2 fix: Also verifies the server-signed confirmation token in recovery.token.
    If the token is missing or invalid, the new key is rejected even if recovery.pub
    exists and is fresh. This prevents an attacker from writing a rogue recovery.pub.

    Args:
        hwnd: The HWND of the peer.
        agent_name: The peer's registered agent name (from SCID property).
        server_url: URL of the Ultra Server for token verification.

    Returns:
        New public key bytes if the recovery file is fresh AND the server token
        is valid. None otherwise.
    """
    pub_path = _recovery_pub_path(agent_name)
    if not pub_path.exists():
        _log.debug("check_peer_recovery: no recovery.pub for agent '%s'", agent_name)
        return None

    mtime = pub_path.stat().st_mtime
    age = time.time() - mtime
    if age > RECOVERY_WINDOW_SEC:
        _log.warning(
            "check_peer_recovery: recovery.pub for '%s' is %.0fs old (window=%ds) — ignoring",
            agent_name, age, RECOVERY_WINDOW_SEC,
        )
        return None

    try:
        hex_key = pub_path.read_text(encoding="utf-8").strip()
        pub_bytes = bytes.fromhex(hex_key)
    except Exception as exc:
        _log.error("check_peer_recovery: failed to read recovery.pub for '%s': %s", agent_name, exc)
        return None

    # Gap 2 fix: Verify the server-signed confirmation token
    token_path = _recovery_token_path(agent_name)
    if not token_path.exists():
        _log.warning(
            "check_peer_recovery: recovery.pub for '%s' exists but no recovery.token found — "
            "REJECTING new key (Gap 2: server confirmation required)",
            agent_name,
        )
        return None

    try:
        token = json.loads(token_path.read_text(encoding="utf-8").strip())
    except Exception as exc:
        _log.error("check_peer_recovery: failed to read recovery.token for '%s': %s", agent_name, exc)
        return None

    if not _verify_server_token(token, agent_name, hex_key, server_url):
        _log.warning(
            "check_peer_recovery: recovery.token for '%s' is INVALID — "
            "REJECTING new key (Gap 2: server token verification failed)",
            agent_name,
        )
        return None

    _log.info(
        "check_peer_recovery: agent '%s' is in recovery (file age=%.0fs, server token valid). "
        "New pubkey: %s...",
        agent_name, age, hex_key[:16],
    )
    return pub_bytes


def _verify_server_token(
    token: dict,
    agent_name: str,
    new_pub_hex: str,
    server_url: str,
) -> bool:
    """Verify a server-signed recovery confirmation token.

    Calls GET /verify-recovery-token on the Ultra Server to validate the token.
    The server checks the HMAC signature and that the token is not expired.

    Returns True if the token is valid, False otherwise.
    """
    try:
        # Verify token fields match what we expect
        if token.get("agentName") != agent_name:
            _log.warning("_verify_server_token: agentName mismatch for '%s'", agent_name)
            return False
        if token.get("newPubHex") != new_pub_hex:
            _log.warning("_verify_server_token: newPubHex mismatch for '%s'", agent_name)
            return False

        # Check token age locally first (fast path)
        issued_at = token.get("issuedAt", 0)
        age = int(time.time()) - issued_at
        if age > RECOVERY_WINDOW_SEC:
            _log.warning(
                "_verify_server_token: token for '%s' is %ds old (window=%ds) — expired",
                agent_name, age, RECOVERY_WINDOW_SEC,
            )
            return False

        # Ask the server to verify the HMAC signature
        payload = json.dumps({
            "token": token,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{server_url}/verify-recovery-token",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return bool(data.get("valid"))
    except Exception as exc:
        _log.error("_verify_server_token: server verification failed for '%s': %s", agent_name, exc)
        return False


def update_peer_registry_from_recovery(
    hwnd: int,
    agent_name: str,
    ledger: Any,
    old_pub_hex: str = "",
    server_url: str = DEFAULT_SERVER_URL,
) -> Optional[bytes]:
    """Full recovery handling: check, update peer registry, log to ledger.

    Combines check_peer_recovery() with ledger logging.

    Args:
        hwnd: The recovering peer's HWND.
        agent_name: The peer's agent name.
        ledger: AgentLedger to record the key rotation event.
        old_pub_hex: Previous public key hex (for ledger record). Can be empty.
        server_url: URL of the Ultra Server for token verification.

    Returns:
        New public key bytes if recovery was processed, None otherwise.
    """
    new_pub = check_peer_recovery(hwnd, agent_name, server_url=server_url)
    if new_pub is None:
        return None

    new_pub_hex = new_pub.hex()
    try:
        ledger.log(
            f"peer_key_rotation_recovery agent={agent_name} hwnd={hwnd:#x}",
            result=f"old={old_pub_hex[:16] or 'unknown'} new={new_pub_hex[:16]}",
        )
    except Exception:
        pass

    _log.info(
        "update_peer_registry_from_recovery: accepted new key for '%s' (hwnd=%#x)",
        agent_name, hwnd,
    )
    return new_pub
