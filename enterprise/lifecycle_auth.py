"""Signed Ultra lifecycle request authentication shared by Python clients."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Protocol


LIFECYCLE_AUTH_DOMAIN = b"selfconnect/ultra/agent-lifecycle-auth/v1\x00"
LIFECYCLE_AUTH_AUDIENCE = "selfconnect-ultra-lifecycle-v1"


class SigningIdentity(Protocol):
    agent_id: str
    public_key_bytes: bytes

    def sign(self, data: bytes) -> bytes: ...


def lifecycle_auth_headers(
    identity: SigningIdentity,
    payload: bytes,
    *,
    method: str,
    path: str,
    audience: str = LIFECYCLE_AUTH_AUDIENCE,
) -> dict[str, str]:
    """Return an endpoint- and protocol-bound Ed25519 Ultra lifecycle proof."""
    if method != "POST":
        raise ValueError("Ultra lifecycle proofs require the exact POST method")
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("Ultra lifecycle proof path must be an exact absolute path")
    if audience != LIFECYCLE_AUTH_AUDIENCE:
        raise ValueError("Ultra lifecycle proof audience is not supported")
    timestamp = str(time.time())
    nonce = str(uuid.uuid4())
    material = b"".join(
        (
            LIFECYCLE_AUTH_DOMAIN,
            method.encode("ascii"),
            b"\x00",
            path.encode("ascii"),
            b"\x00",
            audience.encode("ascii"),
            b"\x00",
            hashlib.sha256(payload).digest(),
            timestamp.encode("ascii"),
            b"\x00",
            nonce.encode("ascii"),
        )
    )
    signature = identity.sign(material)
    return {
        "X-SC-Agent-Auth": json.dumps(
            {
                "agent_id": identity.agent_id,
                "pubkey_hex": identity.public_key_bytes.hex(),
                "ts": timestamp,
                "nonce": nonce,
                "method": method,
                "path": path,
                "aud": audience,
                "sig": base64.b64encode(signature).decode("ascii"),
            },
            separators=(",", ":"),
        )
    }
