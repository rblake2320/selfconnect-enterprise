"""Signed Ultra lifecycle request authentication shared by Python clients."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Protocol


class SigningIdentity(Protocol):
    agent_id: str
    public_key_bytes: bytes

    def sign(self, data: bytes) -> bytes: ...


def lifecycle_auth_headers(identity: SigningIdentity, payload: bytes) -> dict[str, str]:
    """Return the exact Ed25519 proof expected by Ultra Server."""
    timestamp = str(time.time())
    nonce = str(uuid.uuid4())
    material = hashlib.sha256(payload).digest() + timestamp.encode() + nonce.encode()
    signature = identity.sign(material)
    return {
        "X-SC-Agent-Auth": json.dumps(
            {
                "agent_id": identity.agent_id,
                "pubkey_hex": identity.public_key_bytes.hex(),
                "ts": timestamp,
                "nonce": nonce,
                "sig": base64.b64encode(signature).decode("ascii"),
            },
            separators=(",", ":"),
        )
    }
