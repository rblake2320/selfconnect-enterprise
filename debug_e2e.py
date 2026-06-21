"""Debug script to inspect the signed payload and server response."""
import sys
sys.path.insert(0, "/home/ubuntu/selfconnect-enterprise")

# Patch windll before importing enterprise
import ctypes
if not hasattr(ctypes, "windll"):
    from unittest.mock import MagicMock
    ctypes.windll = MagicMock()

import json
import urllib.request
import base64
import tempfile
import pathlib

from enterprise.identity import AgentIdentity
from enterprise.ultra_gate import UltraGate

with tempfile.TemporaryDirectory() as d:
    data_dir = pathlib.Path(d)
    identity = AgentIdentity.init("test-debug", data_dir=data_dir)
    gate = UltraGate(identity, server_url="http://localhost:7777")
    gate.bootstrap()
    print(f"Bootstrapped: pair_id={gate.pair_id}")

    text = "hello world"
    headers = gate.build_injection_request(0x1234, text)
    print("Headers built:")
    for k, v in headers.items():
        print(f"  {k}: {v[:60]}")

    # Decode signed data to see what method is in it
    signed_data = headers["X-BPC-Signed-Data"]
    padded = signed_data + "=" * (-len(signed_data) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    print("\nSigned payload:")
    for k, v in payload.items():
        print(f"  {k}: {str(v)[:60]}")

    # Now call verify_server
    ok, reason = gate.verify_server(headers, text)
    print(f"\nverify_server: ok={ok}, reason={reason!r}")

    # Also call the /verify endpoint directly with verbose output
    body = json.dumps({
        "headers": headers,
        "bodyHash": __import__("enterprise.tsk_client", fromlist=["body_hash"]).body_hash(text) if False else None,
    }).encode("utf-8")
    from enterprise.ultra_gate import body_hash
    body = json.dumps({"headers": headers, "bodyHash": body_hash(text)}).encode("utf-8")
    req = urllib.request.Request(
        "http://localhost:7777/verify",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    print(f"\nDirect /verify response: {json.dumps(result, indent=2)}")
