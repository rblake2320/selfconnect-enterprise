"""bootstrap_mesh.py — One-time mesh setup CLI for BPC+TSK identity gate.

Run once before starting the SelfConnect mesh:
  python bootstrap_mesh.py

Steps:
  1. Prompts for a mesh secret (used for BPC Layer 3 HMAC derivation).
  2. Saves the secret to %APPDATA%\SelfConnect\mesh.key (plaintext for now;
     DPAPI encryption is optional — see --encrypt flag).
  3. Starts the Ultra Server sidecar (Node.js on localhost:7777).
  4. Verifies sidecar health.

Usage:
  python bootstrap_mesh.py                  # interactive
  python bootstrap_mesh.py --secret "..."   # non-interactive
  python bootstrap_mesh.py --encrypt        # DPAPI-encrypt mesh.key
  python bootstrap_mesh.py --stop           # kill the ultra_server sidecar
  python bootstrap_mesh.py --status         # check if sidecar is running

The sidecar runs as a subprocess. Use --stop to kill it cleanly, or just
kill the process via Task Manager. It has no persistent state between runs
(in-memory stores) — pairs and TSK clients re-register automatically on next
mesh start.

Version: 1.0.0  BPC+TSK integration
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


SIDECAR_DIR = Path(__file__).parent / "ultra_server"
SIDECAR_SCRIPT = SIDECAR_DIR / "server.js"
SERVER_URL = os.environ.get("ULTRA_SERVER_URL", "http://127.0.0.1:7777")
PID_FILE = Path(os.environ.get("APPDATA", str(Path.home()))) / "SelfConnect" / "ultra_server.pid"


def _appdata_sc() -> Path:
    base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
    p = Path(base) / "SelfConnect"
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_mesh_secret(secret: str, encrypt: bool = False) -> Path:
    """Save mesh secret to %APPDATA%\SelfConnect\mesh.key."""
    key_file = _appdata_sc() / "mesh.key"
    key_file.write_text(secret, encoding="utf-8")
    key_file.chmod(0o600)
    print(f"[bootstrap] Mesh secret saved to {key_file}")
    if encrypt:
        _dpapi_encrypt(key_file)
    return key_file


def _dpapi_encrypt(key_file: Path) -> None:
    """Optionally encrypt mesh.key with DPAPI via PowerShell."""
    try:
        ps_cmd = (
            f"$data = [System.IO.File]::ReadAllBytes('{key_file}');"
            f"$enc = [System.Security.Cryptography.ProtectedData]::Protect("
            f"  $data, $null, 'CurrentUser');"
            f"[System.IO.File]::WriteAllBytes('{key_file}.dpapi', $enc);"
            f"Remove-Item '{key_file}'"
        )
        subprocess.run(["powershell", "-Command", ps_cmd], check=True, capture_output=True)
        print(f"[bootstrap] Encrypted to {key_file}.dpapi (DPAPI / CurrentUser scope)")
    except Exception as exc:
        print(f"[bootstrap] DPAPI encryption failed (continuing with plaintext): {exc}")


def start_sidecar() -> subprocess.Popen:
    """Start the Node.js Ultra Server sidecar."""
    node_path = "node"  # assumes node is in PATH
    if not SIDECAR_SCRIPT.exists():
        raise FileNotFoundError(f"Ultra Server not found at {SIDECAR_SCRIPT}")

    print(f"[bootstrap] Starting Ultra Server sidecar at {SERVER_URL}...")
    proc = subprocess.Popen(
        [node_path, str(SIDECAR_SCRIPT)],
        cwd=str(SIDECAR_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Save PID for --stop
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(proc.pid), encoding="utf-8")

    # Wait for sidecar to be ready (up to 10 seconds)
    for i in range(20):
        time.sleep(0.5)
        try:
            resp = urllib.request.urlopen(f"{SERVER_URL}/status", timeout=1)
            data = json.loads(resp.read())
            if data.get("ok"):
                print(f"[bootstrap] Ultra Server ready (pid={proc.pid})")
                return proc
        except Exception:
            pass
        # Check if process died
        if proc.poll() is not None:
            out, _ = proc.communicate()
            raise RuntimeError(f"Ultra Server crashed on startup:\n{out}")

    raise RuntimeError("Ultra Server did not become ready within 10 seconds")


def stop_sidecar() -> None:
    """Kill the running Ultra Server sidecar."""
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text().strip())
        try:
            import signal
            os.kill(pid, signal.SIGTERM)
            print(f"[bootstrap] Sent SIGTERM to Ultra Server (pid={pid})")
            PID_FILE.unlink(missing_ok=True)
        except ProcessLookupError:
            print(f"[bootstrap] Ultra Server (pid={pid}) not running")
            PID_FILE.unlink(missing_ok=True)
    else:
        print("[bootstrap] No PID file found. Is the sidecar running?")


def check_status() -> None:
    """Check Ultra Server health."""
    try:
        resp = urllib.request.urlopen(f"{SERVER_URL}/status", timeout=2)
        data = json.loads(resp.read())
        print(f"[bootstrap] Ultra Server: {data}")
    except Exception as exc:
        print(f"[bootstrap] Ultra Server unreachable: {exc}")
        print("  Start with: python bootstrap_mesh.py")


def main() -> None:
    parser = argparse.ArgumentParser(description="SelfConnect BPC+TSK mesh bootstrap")
    parser.add_argument("--secret", help="Mesh secret (omit to be prompted)")
    parser.add_argument("--encrypt", action="store_true", help="DPAPI-encrypt mesh.key")
    parser.add_argument("--stop", action="store_true", help="Stop the Ultra Server sidecar")
    parser.add_argument("--status", action="store_true", help="Check sidecar status")
    parser.add_argument("--no-start", action="store_true", help="Set secret only, don't start sidecar")
    args = parser.parse_args()

    if args.stop:
        stop_sidecar()
        return

    if args.status:
        check_status()
        return

    # Mesh secret setup
    key_file = _appdata_sc() / "mesh.key"
    dpapi_file = _appdata_sc() / "mesh.key.dpapi"

    if key_file.exists() or dpapi_file.exists():
        print(f"[bootstrap] Existing mesh.key found at {key_file.parent}/")
        use_existing = input("Use existing secret? [Y/n] ").strip().lower()
        if use_existing not in ("n", "no"):
            secret = None  # UltraGate will load it automatically
        else:
            secret = args.secret or getpass.getpass("New mesh secret (min 16 chars, upper+lower+digit+2 special): ")
            save_mesh_secret(secret, encrypt=args.encrypt)
    else:
        secret = args.secret or getpass.getpass("Mesh secret (min 16 chars, upper+lower+digit+2 special): ")
        if len(secret) < 16:
            print("[bootstrap] ERROR: Secret must be at least 16 characters.")
            sys.exit(1)
        save_mesh_secret(secret, encrypt=args.encrypt)

    if args.no_start:
        print("[bootstrap] --no-start: secret saved, sidecar NOT started.")
        return

    # Start sidecar
    try:
        proc = start_sidecar()
        print()
        print("[bootstrap] Mesh ready.")
        print("  Set SC_IDENTITY_MODE=audit  — to test (logs, no blocking)")
        print("  Set SC_IDENTITY_MODE=enforce — to enforce (blocks on failure)")
        print("  Set SC_IDENTITY_MODE=bypass  — to revert (default, no gates)")
        print()
        print("  Emergency bypass: python -c \"from enterprise.identity_gate import emergency_bypass; emergency_bypass()\"")
        print()
        print(f"  Ultra Server PID: {proc.pid}")
        print("  Status: python bootstrap_mesh.py --status")
        print("  Stop:   python bootstrap_mesh.py --stop")
    except Exception as exc:
        print(f"[bootstrap] ERROR: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
