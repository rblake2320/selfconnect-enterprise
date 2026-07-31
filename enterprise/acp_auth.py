"""Owner-key enrollment for ACP terminal authentication setup.

ACP terminal authentication is an out-of-band Preview flow: a capable client
launches the same agent program with ``--setup``, waits for success, then
reconnects.  This module performs a local proof-of-possession ceremony and
stores only the enrolled public trust root.
"""
from __future__ import annotations

import math
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable

from enterprise.delegation import canonical_bytes, public_key_fingerprint
from enterprise.identity import AgentIdentity

ED25519 = "ed25519"
ECDSA_P384_SHA384 = "ecdsa-p384-sha384"


class ACPTrustStore:
    """Durable owner trust roots established through key possession proof."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS acp_owner_trust_root (
                fingerprint TEXT PRIMARY KEY NOT NULL,
                principal TEXT NOT NULL,
                algorithm TEXT NOT NULL CHECK (algorithm IN ('ed25519', 'ecdsa-p384-sha384')),
                public_key BLOB NOT NULL,
                enrolled_at REAL NOT NULL,
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                UNIQUE (principal, fingerprint)
            ) STRICT
            """
        )

    def enroll_with_signer(
        self,
        *,
        principal: str,
        signer: Any,
        now: float,
        confirm: Callable[[str], bool],
    ) -> str:
        """Prove private-key possession and persist the corresponding public key."""
        _bounded_principal(principal)
        if not isinstance(now, (int, float)) or not math.isfinite(float(now)):
            raise ValueError("enrollment time must be finite")
        public_key = bytes(signer.public_key_bytes)
        algorithm = _algorithm_for_key(public_key)
        fingerprint = public_key_fingerprint(public_key)
        prompt = f"ENROLL {principal} {fingerprint[:16]}"
        if not confirm(prompt):
            raise PermissionError("owner trust-root enrollment was not confirmed")
        challenge = canonical_bytes(
            {
                "schema": "selfconnect.acp.owner-enrollment.v1",
                "principal": principal,
                "publicKeyFingerprint": fingerprint,
                "nonce": secrets.token_hex(32),
                "issuedAt": float(now),
            }
        )
        signature = bytes(signer.sign(challenge))
        if not _verify(algorithm, public_key, challenge, signature):
            raise PermissionError("owner key possession proof failed")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT principal, public_key FROM acp_owner_trust_root WHERE fingerprint = ?",
                    (fingerprint,),
                ).fetchone()
                if existing is not None and (existing[0] != principal or bytes(existing[1]) != public_key):
                    raise ValueError("owner fingerprint is already bound to different enrollment data")
                self._connection.execute(
                    """
                    INSERT INTO acp_owner_trust_root
                        (fingerprint, principal, algorithm, public_key, enrolled_at, active)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(fingerprint) DO UPDATE SET active = 1
                    """,
                    (fingerprint, principal, algorithm, public_key, float(now)),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return fingerprint

    def resolve_key(self, fingerprint: str) -> bytes | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT public_key FROM acp_owner_trust_root WHERE fingerprint = ? AND active = 1",
                (fingerprint,),
            ).fetchone()
        return bytes(row[0]) if row is not None else None

    def has_active_root(self) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM acp_owner_trust_root WHERE active = 1 LIMIT 1"
            ).fetchone()
        return row is not None

    def deactivate(self, fingerprint: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE acp_owner_trust_root SET active = 0 WHERE fingerprint = ? AND active = 1",
                (fingerprint,),
            )
        return cursor.rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _bounded_principal(principal: str) -> None:
    if (
        not isinstance(principal, str)
        or not principal
        or len(principal) > 256
        or any(ord(ch) < 32 for ch in principal)
    ):
        raise ValueError("principal must be a bounded non-control string")


def _algorithm_for_key(public_key: bytes) -> str:
    if len(public_key) == 32:
        return ED25519
    if len(public_key) == 96:
        return ECDSA_P384_SHA384
    raise ValueError("unsupported owner public key format")


def _verify(algorithm: str, public_key: bytes, payload: bytes, signature: bytes) -> bool:
    if algorithm == ED25519:
        return AgentIdentity.verify(payload, signature, public_key)
    if algorithm == ECDSA_P384_SHA384:
        from enterprise.crypto import cng_verify

        return cng_verify(payload, signature, public_key)
    return False


__all__ = ["ACPTrustStore", "ECDSA_P384_SHA384", "ED25519"]
