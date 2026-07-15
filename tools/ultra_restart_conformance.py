"""Live restart-durability conformance probe for Ultra Server production mode."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from enterprise.ultra_gate import UltraGate


class ConformanceIdentity:
    """Ephemeral real Ed25519 principal used only by the live conformance run."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self.public_key_bytes = private_key.public_key().public_bytes_raw()
        digest = hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()
        self.agent_id = f"SC-{digest}"

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


def _private_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _verify_gate(gate: UltraGate) -> None:
    payload = "ultra-production-restart-conformance"
    headers = gate.build_injection_request(0xA11CE, payload)
    ok, reason = gate.verify_server(headers, payload)
    if not ok:
        raise RuntimeError(f"live Ultra verification failed: {reason}")


def seed(state_path: Path, server_url: str) -> None:
    for _attempt in range(20):
        identity = ConformanceIdentity(Ed25519PrivateKey.generate())
        mesh_secret = secrets.token_urlsafe(32)
        gate = UltraGate(identity, mesh_secret=mesh_secret, server_url=server_url)
        gate.bootstrap()
        if gate.tsk_state and any(segment.type == "hotp" for segment in gate.tsk_state.segments):
            break
    else:
        raise RuntimeError("could not provision a HOTP-bearing map after 20 live attempts")
    _verify_gate(gate)
    original_tsk_client_id = gate.tsk_state.client_id
    for _attempt in range(20):
        gate.rotate_tsk()
        if gate.tsk_state and any(
            segment.type == "hotp" for segment in gate.tsk_state.segments
        ):
            break
    else:
        raise RuntimeError("could not rotate to a HOTP-bearing map after 20 attempts")
    if gate.tsk_state.client_id == original_tsk_client_id:
        raise RuntimeError("TSK rotation did not change the client identifier")
    _verify_gate(gate)
    state = {
        "private_key": base64.b64encode(_private_bytes(identity._private_key)).decode("ascii"),
        "mesh_secret": mesh_secret,
        "agent_id": identity.agent_id,
        "pair_id": gate.pair_id,
        "tsk_client_id": gate.tsk_state.client_id if gate.tsk_state else "",
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    try:
        os.chmod(state_path, 0o600)
    except OSError:
        pass
    print(json.dumps({
        "ok": True,
        "phase": "seed-after-rotation",
        "original_tsk_client_id": original_tsk_client_id,
        **{k: v for k, v in state.items() if k not in {"private_key", "mesh_secret"}},
    }))


def verify(state_path: Path, server_url: str) -> None:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(state["private_key"]))
    identity = ConformanceIdentity(private_key)
    gate = UltraGate(identity, mesh_secret=state["mesh_secret"], server_url=server_url)
    gate.bootstrap()
    if gate.pair_id != state["pair_id"]:
        raise RuntimeError("BPC pair changed across restart")
    if not gate.tsk_state or gate.tsk_state.client_id != state["tsk_client_id"]:
        raise RuntimeError("TSK client changed across restart")
    _verify_gate(gate)
    print(json.dumps({
        "ok": True,
        "phase": "verify-after-restart",
        "agent_id": identity.agent_id,
        "pair_id": gate.pair_id,
        "tsk_client_id": gate.tsk_state.client_id,
    }))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("seed", "verify"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--server-url", default="http://127.0.0.1:7777")
    args = parser.parse_args()
    if args.phase == "seed":
        seed(args.state, args.server_url)
    else:
        verify(args.state, args.server_url)


if __name__ == "__main__":
    main()
