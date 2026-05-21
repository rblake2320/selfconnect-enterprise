"""enterprise/key_recovery.py — Key Recovery Protocol

Handles the chicken-and-egg problem when an agent's DPAPI key file is
corrupted or lost: the agent cannot authenticate to re-register because
its identity key is gone.

Recovery protocol (from integration plan):
  1. Affected terminal generates new keypair via AgentIdentity.init(name, overwrite=True)
  2. Writes new pubkey to {APPDATA}/SelfConnect/{name}/recovery.pub
  3. Stamps SCRECOVERY=1 on HWND
  4. Peers detect recovery tag, read pubkey from filesystem, update local peer registry
  5. 60-second recovery window — stale recovery files ignored

Usage:
    from enterprise.key_recovery import KeyRecovery
    recovery = KeyRecovery(identity, hwnd)
    recovery.initiate()          # start recovery (generates new keypair, stamps HWND)
    recovery.is_in_recovery()    # check if this agent is in recovery mode
    recovery.complete()          # finalize recovery (clear SCRECOVERY stamp)

Peer-side:
    from enterprise.key_recovery import PeerRecoveryDetector
    detector = PeerRecoveryDetector()
    if detector.check_peer(peer_hwnd):
        new_pubkey = detector.read_recovery_pubkey(peer_hwnd, peer_agent_id)

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import logging
import os
import platform
import tempfile
import time
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# Recovery window in seconds — stale recovery files are ignored after this.
RECOVERY_WINDOW_SEC: int = int(os.environ.get("SC_RECOVERY_WINDOW_SEC", "60"))

# HWND property name for recovery flag (Windows-specific; cross-platform stub elsewhere)
PROP_RECOVERY = "SCRECOVERY"


# ── Path helpers ──────────────────────────────────────────────────────────────

def _sc_appdata_dir() -> Path:
    """Return the SelfConnect AppData directory."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", tempfile.gettempdir()))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "SelfConnect"


def recovery_pub_path(agent_name: str) -> Path:
    """Return path to the recovery public key file for an agent."""
    return _sc_appdata_dir() / agent_name / "recovery.pub"


def recovery_timestamp_path(agent_name: str) -> Path:
    """Return path to the recovery timestamp file for an agent."""
    return _sc_appdata_dir() / agent_name / "recovery.ts"


# ── KeyRecovery ───────────────────────────────────────────────────────────────

class KeyRecovery:
    """Manages the recovery lifecycle for a single agent identity."""

    def __init__(self, identity: object, hwnd: int = 0) -> None:
        """
        Args:
            identity: enterprise.identity.AgentIdentity instance.
            hwnd:     Window handle of the agent's terminal (0 on non-Windows).
        """
        self._identity = identity
        self._hwnd = hwnd
        self._agent_name: str = getattr(identity, "agent_name", getattr(identity, "name", "unknown"))

    def initiate(self) -> bytes:
        """Start recovery: generate new keypair, write recovery.pub, stamp HWND.

        Returns the new public key bytes (raw ed25519 public key, 32 bytes).
        """
        _log.warning("KeyRecovery: initiating recovery for agent=%s hwnd=%#010x",
                     self._agent_name, self._hwnd)

        # Step 1: Generate new keypair via AgentIdentity.init(overwrite=True)
        # AgentIdentity.init() generates a new ed25519 keypair and persists it.
        try:
            self._identity.init(self._agent_name, overwrite=True)
        except TypeError:
            # Some implementations use positional args only
            self._identity.init(overwrite=True)

        # Step 2: Write new pubkey to recovery.pub
        pub_path = recovery_pub_path(self._agent_name)
        pub_path.parent.mkdir(parents=True, exist_ok=True)

        pub_bytes = self._get_public_key_bytes()
        pub_path.write_bytes(pub_bytes)

        # Write recovery timestamp
        ts_path = recovery_timestamp_path(self._agent_name)
        ts_path.write_text(str(time.time()))

        # Step 3: Stamp SCRECOVERY=1 on HWND (Windows only)
        self._stamp_recovery_hwnd()

        _log.info("KeyRecovery: recovery initiated for agent=%s pub=%s",
                  self._agent_name, pub_path)
        return pub_bytes

    def _get_public_key_bytes(self) -> bytes:
        """Extract raw ed25519 public key bytes from AgentIdentity."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pub = self._identity._private_key.public_key()
        return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def _stamp_recovery_hwnd(self) -> None:
        """Stamp SCRECOVERY=1 on the agent's HWND (Windows only)."""
        if self._hwnd == 0:
            return
        try:
            from enterprise.registry import set_agent_prop
            set_agent_prop(self._hwnd, PROP_RECOVERY, "1")
            _log.debug("KeyRecovery: stamped SCRECOVERY=1 on hwnd=%#010x", self._hwnd)
        except Exception as exc:
            _log.warning("KeyRecovery: could not stamp SCRECOVERY on hwnd=%#010x: %s",
                         self._hwnd, exc)

    def is_in_recovery(self) -> bool:
        """Check if this agent is currently in recovery mode."""
        ts_path = recovery_timestamp_path(self._agent_name)
        if not ts_path.exists():
            return False
        try:
            ts = float(ts_path.read_text().strip())
            return (time.time() - ts) < RECOVERY_WINDOW_SEC
        except Exception:
            return False

    def complete(self) -> None:
        """Finalize recovery: clear SCRECOVERY stamp and remove recovery files."""
        # Clear HWND stamp
        if self._hwnd != 0:
            try:
                from enterprise.registry import set_agent_prop
                set_agent_prop(self._hwnd, PROP_RECOVERY, "0")
            except Exception:
                pass

        # Remove recovery files
        for path in [recovery_pub_path(self._agent_name),
                     recovery_timestamp_path(self._agent_name)]:
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass

        _log.info("KeyRecovery: recovery completed for agent=%s", self._agent_name)

    def read_recovery_pubkey(self) -> Optional[bytes]:
        """Read the recovery public key if within the recovery window."""
        if not self.is_in_recovery():
            return None
        pub_path = recovery_pub_path(self._agent_name)
        if not pub_path.exists():
            return None
        try:
            return pub_path.read_bytes()
        except Exception as exc:
            _log.warning("KeyRecovery: could not read recovery.pub for agent=%s: %s",
                         self._agent_name, exc)
            return None


# ── PeerRecoveryDetector ──────────────────────────────────────────────────────

class PeerRecoveryDetector:
    """Peer-side: detects recovery mode on remote agents and reads their new pubkey.

    Used by the mesh to update local peer registry when a peer re-keys.
    """

    def check_peer(self, peer_hwnd: int) -> bool:
        """Return True if the peer HWND has SCRECOVERY=1 stamped."""
        if peer_hwnd == 0:
            return False
        try:
            from enterprise.registry import get_agent_prop
            val = get_agent_prop(peer_hwnd, PROP_RECOVERY)
            return val == "1"
        except Exception:
            return False

    def read_recovery_pubkey(self, peer_hwnd: int, peer_agent_id: str) -> Optional[bytes]:
        """Read the recovery public key from the peer's filesystem.

        Validates that the recovery timestamp is within RECOVERY_WINDOW_SEC.
        Returns None if stale or missing.
        """
        ts_path = recovery_timestamp_path(peer_agent_id)
        if not ts_path.exists():
            return None
        try:
            ts = float(ts_path.read_text().strip())
            if (time.time() - ts) >= RECOVERY_WINDOW_SEC:
                _log.debug("PeerRecoveryDetector: stale recovery file for agent=%s", peer_agent_id)
                return None
        except Exception:
            return None

        pub_path = recovery_pub_path(peer_agent_id)
        if not pub_path.exists():
            return None
        try:
            pub_bytes = pub_path.read_bytes()
            _log.info("PeerRecoveryDetector: read recovery pubkey for agent=%s (%d bytes)",
                      peer_agent_id, len(pub_bytes))
            return pub_bytes
        except Exception as exc:
            _log.warning("PeerRecoveryDetector: could not read recovery.pub for agent=%s: %s",
                         peer_agent_id, exc)
            return None

    def update_peer_registry(
        self,
        peer_agent_id: str,
        new_pubkey_bytes: bytes,
        local_registry: dict,
    ) -> None:
        """Update the local peer registry with the peer's new public key.

        Args:
            peer_agent_id:   Agent ID of the recovering peer.
            new_pubkey_bytes: Raw ed25519 public key bytes (32 bytes).
            local_registry:  Dict mapping agent_id → public key bytes.
        """
        local_registry[peer_agent_id] = new_pubkey_bytes
        _log.info("PeerRecoveryDetector: updated local registry for agent=%s", peer_agent_id)
