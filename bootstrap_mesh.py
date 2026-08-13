"""bootstrap_mesh.py — One-time mesh setup CLI for BPC+TSK identity gate.

Run once before starting the SelfConnect mesh:
  python bootstrap_mesh.py

Steps:
  1. Prompts for a mesh secret (used for BPC Layer 3 HMAC derivation).
  2. Stores the secret in Windows Credential Manager.
  3. Starts the Ultra Server sidecar (Node.js on localhost:7777).
  4. Verifies sidecar health.

Usage:
  python bootstrap_mesh.py                  # interactive
  printf "..." | python bootstrap_mesh.py --secret-stdin
  python bootstrap_mesh.py --migrate        # migrate and remove verified legacy files
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
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from enterprise.identity import _dpapi_decrypt
from enterprise.windows_credentials import MESH_SECRET_TARGET, read_credential, write_credential


SIDECAR_DIR = Path(__file__).parent / "ultra_server"
SIDECAR_SCRIPT = SIDECAR_DIR / "server.js"
SERVER_URL = os.environ.get("ULTRA_SERVER_URL", "http://127.0.0.1:7777")
PID_FILE = Path(os.environ.get("APPDATA", str(Path.home()))) / "SelfConnect" / "ultra_server.pid"


def _appdata_sc() -> Path:
    base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
    p = Path(base) / "SelfConnect"
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_mesh_secret(secret: str) -> str:
    """Store and read-back verify a strong mesh secret in Credential Manager."""
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("mesh secret must contain at least 32 UTF-8 bytes")
    write_credential(MESH_SECRET_TARGET, secret)
    verified = read_credential(MESH_SECRET_TARGET)
    if verified is None or not hmac.compare_digest(verified, secret):
        raise RuntimeError("Credential Manager read-back verification failed")
    print(f"[bootstrap] Mesh secret stored in Credential Manager as {MESH_SECRET_TARGET}")
    return MESH_SECRET_TARGET


def migrate_legacy_mesh_secret() -> dict[str, object]:
    """Migrate plaintext/DPAPI files, deleting only after credential read-back."""
    key_file = _appdata_sc() / "mesh.key"
    dpapi_file = _appdata_sc() / "mesh.key.dpapi"
    found: list[tuple[Path, str]] = []
    if key_file.exists():
        found.append((key_file, key_file.read_text(encoding="utf-8").strip()))
    if dpapi_file.exists():
        found.append((dpapi_file, _dpapi_decrypt(dpapi_file.read_bytes()).decode("utf-8").strip()))
    if not found:
        return {"migrated": False, "removed": []}
    secret = found[0][1]
    if any(not hmac.compare_digest(secret, value) for _, value in found[1:]):
        raise RuntimeError("legacy mesh-secret files disagree; refusing migration")
    existing = read_credential(MESH_SECRET_TARGET)
    if existing is None:
        save_mesh_secret(secret)
    elif not hmac.compare_digest(existing, secret):
        raise RuntimeError(
            "legacy mesh secret conflicts with the rotated Credential Manager value; "
            "refusing migration"
        )
    removed: list[str] = []
    for path, _ in found:
        path.unlink()
        removed.append(str(path))
    return {"migrated": True, "removed": removed}


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
    try:
        print(f"[bootstrap] Credential present: {read_credential(MESH_SECRET_TARGET) is not None}")
    except OSError as exc:
        print(f"[bootstrap] Credential Manager unavailable: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SelfConnect BPC+TSK mesh bootstrap")
    parser.add_argument("--secret-stdin", action="store_true", help="read the secret from stdin")
    parser.add_argument("--encrypt", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--migrate", action="store_true", help="migrate verified legacy mesh.key files")
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

    if args.migrate or (_appdata_sc() / "mesh.key").exists() or (_appdata_sc() / "mesh.key.dpapi").exists():
        migration = migrate_legacy_mesh_secret()
        print(f"[bootstrap] Legacy migration: {migration}")
    existing = read_credential(MESH_SECRET_TARGET)
    if args.secret_stdin:
        save_mesh_secret(sys.stdin.readline().rstrip("\r\n"))
    elif existing is None:
        secret = getpass.getpass("Mesh secret (at least 32 UTF-8 bytes): ")
        save_mesh_secret(secret)
    else:
        print(f"[bootstrap] Using existing Credential Manager entry {MESH_SECRET_TARGET}")

    if args.no_start:
        print("[bootstrap] --no-start: credential ready, sidecar NOT started.")
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
