"""
enroll_terminal.py — Terminal Birth Certificate via BPC Enrollment

Generates or rotates a terminal identity through the proper BPC enrollment
path (AgentIdentity DPAPI ed25519), signs a birth certificate, and appends
the event to the immutable wire-dispatch provenance ledger.

Run at PowerShell startup via the profile, or standalone:
    python enroll_terminal.py [--rotate] [--agent-name cc-windows-terminal]

Outputs to stdout for the profile to display.
Exit code 0 = enrolled/loaded OK, 1 = failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── path setup ────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from enterprise.identity import AgentIdentity, _default_data_dir  # noqa: E402
from enterprise.ledger import AgentLedger  # noqa: E402

# ── constants ─────────────────────────────────────────────────────────────────
AGENT_NAME   = "cc-windows-terminal"
LEDGER_PATH  = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming")) \
               / "SelfConnect" / "wire-ledger" / "wire-dispatch.jsonl"
CERT_PATH    = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming")) \
               / "SelfConnect" / "terminal-birth-cert.json"


def _load_prev_cert_hash() -> str:
    """Return SHA-256 of the previous cert file, or all-zeros if none."""
    if CERT_PATH.exists():
        return hashlib.sha256(CERT_PATH.read_bytes()).hexdigest()
    return "0" * 64


def enroll(agent_name: str = AGENT_NAME, rotate: bool = False) -> dict:
    """Create or load the terminal identity and return the birth cert dict."""
    data_dir = _default_data_dir()
    agent_dir = data_dir / agent_name
    identity_exists = (agent_dir / "identity.dpapi").exists()
    certificate_exists = CERT_PATH.exists()

    prev_cert_hash = _load_prev_cert_hash()
    if rotate:
        reason = "explicit key rotation"
    elif identity_exists and certificate_exists:
        reason = "certificate refresh for existing identity"
    elif identity_exists:
        reason = "certificate recovery for existing identity"
    else:
        reason = "new enrollment"

    if rotate and agent_dir.exists():
        identity = AgentIdentity.init(agent_name, overwrite=True)
    elif (agent_dir / "identity.dpapi").exists():
        identity = AgentIdentity.load(agent_name)
    else:
        identity = AgentIdentity.init(agent_name)

    pub_hex   = identity.public_key_bytes.hex()
    fingerprint = "SC-" + hashlib.sha256(identity.public_key_bytes).hexdigest()[:8].upper()
    assert fingerprint == identity.agent_id, "agent_id mismatch"

    ts = time.time()
    cert = {
        "terminal_id":          identity.canonical_id,
        "process_instance_id":  socket.gethostname().lower() + "-" + str(os.getpid()),
        "agent_id":             identity.agent_id,
        "parent_id":            "cc-windows-orchestrator",
        "bpc_public_key_fp":    fingerprint,
        "bpc_public_key_hex":   pub_hex,
        "bpc_algo":             "ed25519-dpapi",
        "tsk_channel_id":       "tsk-channel-cc-windows",
        "tsk_session_id":       "tsk-session-" + hashlib.sha256(pub_hex.encode()).hexdigest()[:12],
        "created_at":           datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        "hostname":             socket.gethostname(),
        "username":             os.environ.get("USERNAME", "unknown"),
        "process_id":           os.getpid(),
        "policy_profile":       "terminal.default.v1",
        "prev_cert_hash":       prev_cert_hash,
        "reason":               reason,
    }

    # Sign the cert payload
    payload = json.dumps(cert, sort_keys=True, separators=(",", ":")).encode()
    sig_bytes = identity.sign(payload)
    cert["sig"] = sig_bytes.hex()

    return cert, identity, ts


def write_cert(cert: dict) -> None:
    CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CERT_PATH.write_text(json.dumps(cert, indent=2))


def append_ledger(cert: dict, identity, ts: float) -> str:
    """Append birth cert event to the wire-dispatch provenance ledger."""
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)

    ledger = AgentLedger(identity, LEDGER_PATH)
    entry = ledger.log(
        action="terminal_birth:enrollment",
        result="allow",
        metadata={
            "terminal_id":    cert["terminal_id"],
            "bpc_fp":         cert["bpc_public_key_fp"],
            "tsk_channel":    cert["tsk_channel_id"],
            "tsk_session":    cert["tsk_session_id"],
            "reason":         cert["reason"],
            "cert_path":      str(CERT_PATH),
        },
    )
    # log() returns the entry dict
    return str(entry.get("seq", "?")) if isinstance(entry, dict) else "?"


def main():
    ap = argparse.ArgumentParser(description="BPC terminal enrollment")
    ap.add_argument("--rotate",     action="store_true", help="Force key rotation")
    ap.add_argument("--agent-name", default=AGENT_NAME,  help="Agent name slug")
    ap.add_argument("--quiet",      action="store_true", help="Minimal output (for profile)")
    args = ap.parse_args()

    try:
        cert, identity, ts = enroll(args.agent_name, rotate=args.rotate)
        write_cert(cert)
        ledger_seq = append_ledger(cert, identity, ts)

        if args.quiet:
            # Single-line profile output
            print(
                f"\n  >> BPC  {cert['bpc_public_key_fp']}"
                f"  tsk:{cert['tsk_session_id']}"
                f"  ledger:#{ledger_seq}"
                f"  {cert['reason']}\n"
            )
        else:
            print("\n=== Terminal Birth Certificate ===")
            print("  BPC identity restored/rotated : YES")
            print(f"  BPC public key fingerprint    : {cert['bpc_public_key_fp']}")
            print(f"  BPC algo                      : {cert['bpc_algo']}")
            print(f"  Terminal birth cert path      : {CERT_PATH}")
            print(f"  TSK channel binding           : {cert['tsk_channel_id']}")
            print(f"  TSK session ID                : {cert['tsk_session_id']}")
            print(f"  Ledger entry                  : #{ledger_seq}")
            print(f"  Reason                        : {cert['reason']}")
            print(f"  Cert signature                : {cert['sig'][:32]}...")
            print("  BPC tests                     : run `pytest tests/` to verify")
            print("  TSK tests                     : run `cd ../tsk-protocol && npm test`")
            print("=================================\n")

        sys.exit(0)

    except Exception as exc:
        print(f"\n[BPC ENROLL ERROR] {exc}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
