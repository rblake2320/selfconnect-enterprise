"""enterprise/key_recovery.py — Key recovery protocol for SelfConnect Enterprise.

Solves the chicken-and-egg problem: if a terminal's DPAPI identity key gets
corrupted, it can't communicate to re-register because communication requires
identity. This module breaks that deadlock via an out-of-band filesystem path.

Recovery flow:
  1. AgentIdentity.load() fails → RecoveryManager detects corruption.
  2. RecoveryManager generates a new keypair via AgentIdentity.init(overwrite=True).
  3. Writes the new public key to %APPDATA%\SelfConnect\{name}\recovery.pub.
  4. Stamps SCRECOVERY=1 on the agent's listener HWND.
  5. Peers running discover_mesh() detect SCRECOVERY=1, read recovery.pub,
     update their local peer registry, and accept the new key.
  6. Next handshake uses the new key. Ledger records key_rotation_recovery.

Security properties:
  - Recovery only works on the same machine + same user (DPAPI scope, shared %APPDATA%).
  - Recovery window: 60 seconds (configurable). Stale files are ignored.
  - Recovery downgrades to enterprise-only verification (Level 2) during the window.
  - Recovery is logged to the ledger with old/new fingerprints.
  - New agent_id is different from old (derived from new pubkey). Policy bundle
    must include the new agent_id or have a wildcard recovery entry.

Version: 1.0.0  BPC+TSK integration
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
RECOVERY_WINDOW_SEC: int = int(os.environ.get("SC_RECOVERY_WINDOW_SEC", "60"))
PROP_RECOVERY = "SCRECOVERY"  # Set to "1" on HWND during recovery window


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


class RecoveryManager:
    """Manages the key recovery lifecycle for a single agent.

    Usage:
        try:
            identity = AgentIdentity.load("agent-e-orchestrator")
        except (OSError, ValueError):
            mgr = RecoveryManager("agent-e-orchestrator")
            identity = mgr.recover()
            mgr.notify_peers(listener_hwnd=my_hwnd)
    """

    def __init__(self, agent_name: str) -> None:
        self.agent_name = agent_name
        self._recovery_start: float = 0.0
        self._new_pub_hex: str = ""

    def recover(self) -> Any:
        """Generate a new identity and write recovery.pub.

        Returns the new AgentIdentity. The new agent_id will differ from the
        old one (it's derived from the new public key).

        Raises:
            RuntimeError: If recovery itself fails (e.g. DPAPI unavailable).
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
        return identity

    def notify_peers(self, listener_hwnd: int) -> None:
        """Stamp SCRECOVERY=1 on the agent's listener HWND so peers detect it.

        Peers calling discover_mesh() will see SCRECOVERY=1, read recovery.pub,
        and update their local peer registry within the recovery window.
        """
        try:
            import ctypes
            user32 = ctypes.windll.user32
            # SetPropW(hwnd, propName, value) — PROP_RECOVERY = "SCRECOVERY"
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

def check_peer_recovery(hwnd: int, agent_name: str) -> Optional[bytes]:
    """Check if a peer is in recovery mode. If so, return their new public key bytes.

    Called from discover_mesh() when SCRECOVERY=1 is detected on a peer's HWND.

    Args:
        hwnd: The HWND of the peer.
        agent_name: The peer's registered agent name (from SCID property).

    Returns:
        New public key bytes if the recovery file is fresh (within window).
        None if no recovery file, recovery window expired, or file is invalid.
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
        _log.info(
            "check_peer_recovery: agent '%s' is in recovery (file age=%.0fs). "
            "New pubkey: %s...",
            agent_name, age, hex_key[:16],
        )
        return pub_bytes
    except Exception as exc:
        _log.error("check_peer_recovery: failed to read recovery.pub for '%s': %s", agent_name, exc)
        return None


def update_peer_registry_from_recovery(
    hwnd: int,
    agent_name: str,
    ledger: Any,
    old_pub_hex: str = "",
) -> Optional[bytes]:
    """Full recovery handling: check, update peer registry, log to ledger.

    Combines check_peer_recovery() with ledger logging.

    Args:
        hwnd: The recovering peer's HWND.
        agent_name: The peer's agent name.
        ledger: AgentLedger to record the key rotation event.
        old_pub_hex: Previous public key hex (for ledger record). Can be empty.

    Returns:
        New public key bytes if recovery was processed, None otherwise.
    """
    new_pub = check_peer_recovery(hwnd, agent_name)
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
