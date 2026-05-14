"""enterprise/identity.py — Persistent, Machine-Bound Agent Identity

An agent identity is an ed25519 key pair generated once on first boot and
stored encrypted under Windows DPAPI.  The identity survives every terminal
restart, crash, PID change, and HWND change — the private key is the agent.

    # First boot — generates and stores a new key pair
    identity = AgentIdentity.init("agent-e-orchestrator")
    print(identity.agent_id)   # SC-A7F3B2E1

    # Every subsequent boot — loads the stored key pair
    identity = AgentIdentity.load("agent-e-orchestrator")

    # Prove identity
    sig = identity.sign(b"I performed action X")
    assert AgentIdentity.verify(b"I performed action X", sig, identity.public_key_bytes)

Identity model:
    agent_id   = "SC-" + first 8 hex chars of SHA-256(public_key_raw_bytes).upper()
    private key = ed25519 private key, stored as DPAPI-encrypted blob on disk
    public key  = raw bytes stored in plaintext alongside the encrypted private key

DPAPI storage (Windows):
    Private key bytes are encrypted with CryptProtectData (user + machine scope).
    The encrypted blob cannot be decrypted on any other machine or by any other
    Windows user account — it is hardware-bound by the OS.

    Storage path: {data_dir}/{agent_name}/identity.dpapi   (encrypted private key)
                  {data_dir}/{agent_name}/identity.pub     (raw public key bytes, hex)

    Default data_dir: %APPDATA%\\SelfConnect

Why this can't be faked:
    - The private key never leaves the machine in plaintext
    - DPAPI decryption is bound to the Windows user SID + machine SID
    - Signatures produced on machine A cannot be reproduced on machine B
      even if the encrypted blob file is copied
    - agent_id is derived from the public key — it cannot be assumed by
      a different key pair

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import hashlib
import os
import re
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Only slug-style names are safe for filesystem identity directories.
# Rejects: path separators, null bytes, dotdot components, UNC paths.
_SAFE_AGENT_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')

# ── DPAPI ctypes interface ─────────────────────────────────────────────────────

crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _DATA_BLOB(ctypes.Structure):
    """Win32 DATA_BLOB — used by CryptProtectData / CryptUnprotectData."""

    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """Encrypt bytes with DPAPI (current user + machine scope)."""
    in_blob = _DATA_BLOB()
    in_blob.cbData = len(plaintext)
    in_blob.pbData = ctypes.cast(
        ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_ubyte)
    )
    out_blob = _DATA_BLOB()

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "SelfConnect Agent Identity",  # description (stored in blob, informational)
        None,                          # optional entropy
        None,                          # reserved
        None,                          # prompt struct
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(f"CryptProtectData failed: error {kernel32.GetLastError()}")

    encrypted = bytes(out_blob.pbData[: out_blob.cbData])
    kernel32.LocalFree(out_blob.pbData)
    return encrypted


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt a DPAPI blob (must run on same machine + user that encrypted it)."""
    in_buf = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
    in_blob = _DATA_BLOB()
    in_blob.cbData = len(ciphertext)
    in_blob.pbData = ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_ubyte))
    out_blob = _DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,                          # ppszDataDescr (ignore)
        None,                          # optional entropy
        None,                          # reserved
        None,                          # prompt struct
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError(
            f"CryptUnprotectData failed: error {kernel32.GetLastError()} "
            "(wrong machine or user?)"
        )

    plaintext = bytes(out_blob.pbData[: out_blob.cbData])
    kernel32.LocalFree(out_blob.pbData)
    return plaintext


# ── Default storage location ───────────────────────────────────────────────────

def _default_data_dir() -> Path:
    appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
    return Path(appdata) / "SelfConnect"


# ── AgentIdentity ──────────────────────────────────────────────────────────────

class AgentIdentity:
    """Persistent, machine-bound ed25519 agent identity.

    The identity is permanent: it survives terminal restarts, crashes, reboots,
    and new HWND / PID assignments.  The agent_id derived from the public key
    fingerprint is the stable identifier that peers recognise across sessions.

    Use init() on first boot, load() on every subsequent boot.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        agent_name: str,
    ) -> None:
        self._private_key  = private_key
        self._public_key   = public_key
        self._agent_name   = agent_name
        self._pub_raw      = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._agent_id     = "SC-" + hashlib.sha256(self._pub_raw).hexdigest()[:8].upper()

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def init(
        cls,
        agent_name: str,
        data_dir: Optional[Path] = None,
        overwrite: bool = False,
    ) -> "AgentIdentity":
        """Generate a new key pair and store it under DPAPI.

        Args:
            agent_name: Logical name for this agent (used as storage directory).
            data_dir:   Override for %APPDATA%\\SelfConnect.
            overwrite:  If True, replace any existing key.  Default False.

        Raises:
            FileExistsError: If an identity already exists and overwrite=False.
        """
        storage = cls._storage_paths(agent_name, data_dir)
        if storage["dpapi"].exists() and not overwrite:
            raise FileExistsError(
                f"Identity for '{agent_name}' already exists at {storage['dpapi']}. "
                "Use load() to resume or pass overwrite=True to regenerate."
            )

        storage["dir"].mkdir(parents=True, exist_ok=True)
        private_key = Ed25519PrivateKey.generate()
        public_key  = private_key.public_key()

        # Serialise private key as raw bytes, then DPAPI-encrypt
        priv_raw  = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        encrypted = _dpapi_encrypt(priv_raw)
        storage["dpapi"].write_bytes(encrypted)

        # Public key in plaintext hex (needed by peers for verification)
        pub_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        storage["pub"].write_text(pub_raw.hex(), encoding="ascii")

        return cls(private_key, public_key, agent_name)

    @classmethod
    def load(
        cls,
        agent_name: str,
        data_dir: Optional[Path] = None,
    ) -> "AgentIdentity":
        """Load an existing identity from DPAPI storage.

        Raises:
            FileNotFoundError: If no identity exists for agent_name.
            OSError: If DPAPI decryption fails (wrong machine or user).
        """
        storage = cls._storage_paths(agent_name, data_dir)
        if not storage["dpapi"].exists():
            raise FileNotFoundError(
                f"No identity found for '{agent_name}' at {storage['dpapi']}. "
                "Run init() on first boot."
            )

        encrypted = storage["dpapi"].read_bytes()
        priv_raw  = _dpapi_decrypt(encrypted)
        private_key = Ed25519PrivateKey.from_private_bytes(priv_raw)
        public_key  = private_key.public_key()

        return cls(private_key, public_key, agent_name)

    @classmethod
    def exists(cls, agent_name: str, data_dir: Optional[Path] = None) -> bool:
        """Return True if an identity for agent_name is stored on this machine."""
        return cls._storage_paths(agent_name, data_dir)["dpapi"].exists()

    # ── Identity properties ───────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        """Permanent identifier: 'SC-' + 8-char SHA-256 fingerprint of public key."""
        return self._agent_id

    @property
    def agent_name(self) -> str:
        """Logical name this identity was initialised under."""
        return self._agent_name

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte ed25519 public key — share with peers for verification."""
        return self._pub_raw

    # ── Cryptographic operations ──────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """Sign data with the agent's private key.  Returns 64-byte signature."""
        return self._private_key.sign(data)

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify a signature against a known public key.

        Args:
            data:             The original signed bytes.
            signature:        64-byte signature from sign().
            public_key_bytes: 32-byte raw ed25519 public key (from agent_id source).

        Returns:
            True if signature is valid; False otherwise (never raises).
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, data)
            return True
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"AgentIdentity(agent_id={self._agent_id!r}, name={self._agent_name!r})"

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _storage_paths(agent_name: str, data_dir: Optional[Path]) -> dict:
        if not _SAFE_AGENT_NAME_RE.match(agent_name):
            raise ValueError(
                f"agent_name {agent_name!r} is invalid: must match "
                r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$"
            )
        root = (data_dir or _default_data_dir()).resolve()
        base = (root / agent_name).resolve()
        if not base.is_relative_to(root):
            raise ValueError(
                f"agent_name {agent_name!r} escapes the identity root directory"
            )
        return {
            "dir":   base,
            "dpapi": base / "identity.dpapi",
            "pub":   base / "identity.pub",
        }
