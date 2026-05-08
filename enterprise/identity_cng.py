"""enterprise/identity_cng.py — CNSA 2.0-Compliant Agent Identity via Windows CNG

Drop-in replacement for AgentIdentity backed by Windows NCrypt software KSP
instead of DPAPI + Python ed25519.

    # v0.3.0 path (DPAPI, ed25519)   — unchanged, still available
    from enterprise.identity import AgentIdentity

    # v0.4.0 path (NCrypt, ECDSA P-384, FIPS 140-2 certified)
    from enterprise.identity_cng import CngIdentity, CngLedger

    # Interface is identical:
    identity = CngIdentity.init("agent-e-orchestrator")   # first boot
    identity = CngIdentity.load("agent-e-orchestrator")   # every subsequent boot
    sig = identity.sign(b"action data")                   # 96-byte P1363 signature
    ok  = CngIdentity.verify(b"action data", sig, identity.public_key_bytes)

Key differences from AgentIdentity:
    Private key    — stored in NCrypt software KSP (not DPAPI blob file)
    Public key     — written to {data_dir}/{agent_name}/identity_cng.pub (96-byte hex)
    Signature      — ECDSA P-384, 96 bytes IEEE P1363 (not ed25519, 64 bytes)
    Hash function  — SHA-384 everywhere (not SHA-256)
    agent_id       — "SC-" + SHA-384(pub_key)[:8].upper() (8-char fingerprint)

Storage:
    NCrypt key name:    "SelfConnect.{agent_name}"  (per-user, machine-bound)
    Public key file:    {data_dir}/{agent_name}/identity_cng.pub   (raw X||Y hex)
    Default data_dir:   %APPDATA%\\SelfConnect  (same as AgentIdentity)

CngLedger:
    Subcomponent with the same API as AgentLedger but uses SHA-384 for the hash
    chain.  Use with CngIdentity for a fully CNSA 2.0 compliant audit trail.

Version: 1.0.0-enterprise  Session 16
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from enterprise.crypto import (
    ALGO_ID,
    CngSigner,
    cng_key_exists,
    cng_sha384,
    cng_verify,
)
from enterprise.identity import _default_data_dir
from enterprise.labels import LabelEnvelope

# Genesis hash for CngLedger chains.
# SHA-384 digest is 96 hex chars — distinct from AgentLedger's 64-char SHA-256 genesis,
# so mixing the two chain types fails loudly rather than silently.
GENESIS_HASH_CNG = "0" * 96


# ── CngIdentity ────────────────────────────────────────────────────────────────

class CngIdentity:
    """Persistent, machine-bound ECDSA P-384 agent identity via Windows NCrypt.

    Identical interface to AgentIdentity — callers can swap the import without
    changing any other code.  The cryptographic backend is entirely different:

        AgentIdentity   — ed25519 private key, DPAPI-encrypted file, SHA-256 agent_id
        CngIdentity     — ECDSA P-384 via NCrypt KSP, no plaintext key file, SHA-384 agent_id

    The NCrypt software KSP stores the private key under the current Windows user
    profile.  It cannot be decrypted by any other user or moved to another machine
    without re-enrollment.  Binding is enforced by the OS, not by application code.

    Use init() on first boot, load() on every subsequent boot.
    """

    def __init__(
        self,
        signer: CngSigner,
        agent_name: str,
    ) -> None:
        self._signer     = signer
        self._agent_name = agent_name
        pub              = signer.public_key_bytes
        # SHA-384 fingerprint — distinct namespace from AgentIdentity (SHA-256)
        self._agent_id   = "SC-" + cng_sha384(pub).hex()[:8].upper()

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def init(
        cls,
        agent_name: str,
        data_dir: Optional[Path] = None,
        overwrite: bool = False,
    ) -> "CngIdentity":
        """Generate a new ECDSA P-384 key and persist it in NCrypt software KSP.

        Also writes the public key bytes to {data_dir}/{agent_name}/identity_cng.pub
        so that peers can verify signatures without opening the KSP.

        Args:
            agent_name: Logical name for this agent.
            data_dir:   Override for %APPDATA%\\SelfConnect.
            overwrite:  If True, replace any existing key. Default False.

        Raises:
            FileExistsError: If an identity already exists and overwrite=False.
        """
        storage = cls._storage_paths(agent_name, data_dir)
        if storage["pub"].exists() and not overwrite:
            raise FileExistsError(
                f"CngIdentity for '{agent_name}' already exists at {storage['pub']}. "
                "Use load() to resume or pass overwrite=True to regenerate."
            )

        key_name = cls._ncrypt_key_name(agent_name)
        signer   = CngSigner.create(key_name, overwrite=overwrite)

        storage["dir"].mkdir(parents=True, exist_ok=True)
        storage["pub"].write_text(signer.public_key_bytes.hex(), encoding="ascii")
        # Store algorithm ID alongside public key for crypto-agility
        storage["algo"].write_text(ALGO_ID, encoding="ascii")

        return cls(signer, agent_name)

    @classmethod
    def load(
        cls,
        agent_name: str,
        data_dir: Optional[Path] = None,
    ) -> "CngIdentity":
        """Load an existing identity from NCrypt software KSP.

        Raises:
            FileNotFoundError: If no identity exists for agent_name.
            OSError: If NCrypt cannot open the key (wrong machine or user).
        """
        storage = cls._storage_paths(agent_name, data_dir)
        if not storage["pub"].exists():
            raise FileNotFoundError(
                f"No CngIdentity found for '{agent_name}' at {storage['pub']}. "
                "Run init() on first boot."
            )

        key_name = cls._ncrypt_key_name(agent_name)
        signer   = CngSigner.load(key_name)
        return cls(signer, agent_name)

    @classmethod
    def exists(cls, agent_name: str, data_dir: Optional[Path] = None) -> bool:
        """Return True if a CngIdentity for agent_name is stored on this machine."""
        storage = cls._storage_paths(agent_name, data_dir)
        return storage["pub"].exists() and cng_key_exists(cls._ncrypt_key_name(agent_name))

    # ── Identity properties ───────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        """Permanent identifier: 'SC-' + 8-char SHA-384 fingerprint of public key."""
        return self._agent_id

    @property
    def agent_name(self) -> str:
        """Logical name this identity was initialised under."""
        return self._agent_name

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 96-byte ECDSA P-384 public key (X || Y) — share with peers."""
        return self._signer.public_key_bytes

    @property
    def algo_id(self) -> str:
        """Algorithm identifier — embed in any identity record for crypto-agility."""
        return self._signer.algo_id

    # ── Cryptographic operations ──────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """Sign data with ECDSA P-384 / SHA-384. Returns 96-byte P1363 signature."""
        return self._signer.sign(data)

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify a P-384/SHA-384 signature against a known public key.

        Returns True if valid; False otherwise (never raises).
        """
        return cng_verify(data, signature, public_key_bytes)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Release NCrypt handles held by the underlying CngSigner."""
        self._signer.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "CngIdentity":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"CngIdentity(agent_id={self._agent_id!r}, name={self._agent_name!r})"

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _storage_paths(agent_name: str, data_dir: Optional[Path]) -> dict:
        base = (data_dir or _default_data_dir()) / agent_name
        return {
            "dir":  base,
            "pub":  base / "identity_cng.pub",
            "algo": base / "identity_cng.algo",
        }

    @staticmethod
    def _ncrypt_key_name(agent_name: str) -> str:
        """NCrypt key store name — scoped to SelfConnect to avoid collisions."""
        return f"SelfConnect.{agent_name}"


# ── CngLedger ──────────────────────────────────────────────────────────────────

class CngLedger:
    """Append-only, signed, SHA-384 hash-chained action log for CngIdentity agents.

    Identical interface to AgentLedger but uses SHA-384 for the hash chain
    (CNSA 2.0 compliant) and is intended for use with CngIdentity.  The two
    ledger types produce incompatible chains and must not be mixed for the same
    log file.

    Log format is identical to AgentLedger with one addition:
        "algo": "ECDSA_P384_SHA384"   # always present in every entry
    """

    def __init__(
        self,
        identity: CngIdentity,
        log_path: Optional[Path] = None,
    ) -> None:
        self._identity  = identity
        self._log_path  = log_path or self._default_path(identity.agent_name)
        self._seq       = self._load_last_seq()
        self._prev_hash = self._load_last_hash()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def agent_id(self) -> str:
        return self._identity.agent_id

    def log(
        self,
        action: str,
        result: str = "",
        metadata: Optional[dict] = None,
        label: Optional[LabelEnvelope] = None,
    ) -> dict:
        """Append a signed, SHA-384 chained entry to the ledger.

        Args:
            label: Optional LabelEnvelope.  When provided, its to_dict() is
                   merged after metadata so the label is authoritative for
                   classification and caveat fields.

        Returns the full entry dict as written (including sig and algo fields).
        """
        self._seq += 1

        entry: dict = {
            "seq":       self._seq,
            "agent_id":  self._identity.agent_id,
            "algo":      ALGO_ID,
            "action":    action,
            "result":    result,
            "ts":        time.time(),
            "prev_hash": self._prev_hash,
        }
        if metadata:
            entry.update(metadata)
        if label is not None:
            entry.update(label.to_dict())

        entry_bytes     = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        sig_bytes       = self._identity.sign(entry_bytes)
        entry["sig"]    = sig_bytes.hex()
        self._prev_hash = cng_sha384(entry_bytes).hex()

        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

        return entry

    def verify(self) -> tuple[bool, int, str]:
        """Verify all signatures and SHA-384 hash chain integrity.

        Returns:
            (valid, entry_count, message)
        """
        if not self._log_path.exists():
            return True, 0, "ledger is empty"

        prev_hash = GENESIS_HASH_CNG
        count     = 0

        with self._log_path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, count, f"line {lineno}: JSON parse error: {exc}"

                sig_hex = entry.pop("sig", None)
                if sig_hex is None:
                    return False, count, f"line {lineno}: missing 'sig' field"

                stored_prev = entry.get("prev_hash", "")
                if stored_prev != prev_hash:
                    return (
                        False,
                        count,
                        f"line {lineno}: chain broken "
                        f"(expected {prev_hash[:12]}..., got {stored_prev[:12]}...)",
                    )

                entry_bytes = json.dumps(
                    entry, sort_keys=True, separators=(",", ":")
                ).encode()

                try:
                    sig_bytes = bytes.fromhex(sig_hex)
                except ValueError:
                    return False, count, f"line {lineno}: invalid sig hex"

                if not CngIdentity.verify(entry_bytes, sig_bytes, self._identity.public_key_bytes):
                    return False, count, f"line {lineno}: signature invalid"

                prev_hash = cng_sha384(entry_bytes).hex()
                count += 1

        return True, count, f"{count} entries, all signatures valid, chain intact"

    def tail(self, n: int = 10) -> list[dict]:
        """Return the last n entries from the ledger (most recent last)."""
        if not self._log_path.exists():
            return []
        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        recent = [ln for ln in lines if ln.strip()][-n:]
        result = []
        for line in recent:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result

    def entry_count(self) -> int:
        """Return the number of entries currently in the ledger."""
        if not self._log_path.exists():
            return 0
        return sum(1 for ln in self._log_path.read_text(encoding="utf-8").splitlines() if ln.strip())

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_last_seq(self) -> int:
        if not self._log_path.exists():
            return 0
        last = self._last_entry()
        return last.get("seq", 0) if last else 0

    def _load_last_hash(self) -> str:
        if not self._log_path.exists():
            return GENESIS_HASH_CNG
        last = self._last_entry()
        if not last:
            return GENESIS_HASH_CNG
        last.pop("sig", None)
        entry_bytes = json.dumps(last, sort_keys=True, separators=(",", ":")).encode()
        return cng_sha384(entry_bytes).hex()

    def _last_entry(self) -> Optional[dict]:
        if not self._log_path.exists():
            return None
        lines = [ln for ln in self._log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        for line in reversed(lines):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _default_path(agent_name: str) -> Path:
        return _default_data_dir() / agent_name / "ledger_cng.jsonl"
