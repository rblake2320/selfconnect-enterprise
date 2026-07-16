"""Installed-service acceptance helper for the provenance service boundary.

This helper is executed under disposable, distinct Windows user tokens by
``provenance_service_acceptance.ps1``. It never prints private key material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if (REPO_ROOT / "enterprise").is_dir() and str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_VERIFY_WHEEL_ONLY = len(sys.argv) > 1 and sys.argv[1] == "verify-wheel"
if not _VERIFY_WHEEL_ONLY:
    import pywintypes
    import win32con
    import win32file
    import win32pipe
    import win32security
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from enterprise.identity import AgentIdentity
    from enterprise.provenance import SessionEventType
    from enterprise.provenance_ipc import (
        MAX_FRAME_BYTES,
        PROTOCOL_VERSION,
        build_record_request,
        decode_frame,
    )
    from enterprise.provenance_pipe import (
        FILE_FLAG_FIRST_PIPE_INSTANCE,
        FILE_READ_DATA,
        FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA,
        PIPE_REJECT_REMOTE_CLIENTS,
        SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
        SYNCHRONIZE,
        ProvenancePipeClient,
        ProvenancePipeError,
    )

    _PIPE_ACCESS = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE


class EphemeralIdentity:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        self.agent_id = "SC-" + hashlib.sha256(self.public_key_bytes).hexdigest()[:8].upper()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("acceptance configuration must be an object")
    return value


def _identity(config: dict[str, Any]) -> AgentIdentity:
    return AgentIdentity.load(
        str(config["identity_name"]),
        data_dir=Path(config["identity_dir"]),
    )


def verify_wheel(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    source_root = repo_root / "enterprise"
    source_files = sorted(
        path.relative_to(repo_root).as_posix()
        for path in source_root.rglob("*.py")
        if path.is_file()
    )
    mismatches: list[str] = []
    digest = hashlib.sha256()
    with zipfile.ZipFile(args.wheel) as archive:
        wheel_files = sorted(
            name
            for name in archive.namelist()
            if name.startswith("enterprise/") and name.endswith(".py")
        )
        if wheel_files != source_files:
            missing = sorted(set(source_files) - set(wheel_files))
            extra = sorted(set(wheel_files) - set(source_files))
            mismatches.extend(f"missing:{name}" for name in missing)
            mismatches.extend(f"extra:{name}" for name in extra)
        for name in sorted(set(source_files) & set(wheel_files)):
            source_bytes = (repo_root / Path(name)).read_bytes()
            wheel_bytes = archive.read(name)
            if source_bytes != wheel_bytes:
                mismatches.append(f"content:{name}")
            digest.update(name.encode("utf-8") + b"\0" + wheel_bytes)
    result = {
        "file_count": len(source_files),
        "mismatches": mismatches,
        "ok": not mismatches,
        "runtime_tree_sha256": digest.hexdigest(),
        "wheel_sha256": hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
    }
    _write_json(args.output, result)
    return 0 if result["ok"] else 1


def _resolve_pipe_name(config: dict[str, Any]) -> str:
    endpoint = json.loads(Path(config["endpoint_file"]).read_text(encoding="utf-8"))
    if not isinstance(endpoint, dict) or endpoint.get("version") != (
        "selfconnect.provenance.endpoint.v1"
    ):
        raise ValueError("invalid provenance endpoint")
    if endpoint.get("service_sid") != config["service_sid"]:
        raise ValueError("provenance endpoint SID mismatch")
    if endpoint.get("service_agent_id") != config["service_agent_id"]:
        raise ValueError("provenance endpoint identity mismatch")
    pipe_name = str(endpoint.get("pipe_name", ""))
    if not pipe_name.startswith(r"\\.\pipe\SelfConnectProvenance.v1."):
        raise ValueError("invalid provenance endpoint pipe")
    return pipe_name


def _client(config: dict[str, Any]) -> ProvenancePipeClient:
    return ProvenancePipeClient(
        expected_service_sid=str(config["service_sid"]),
        service_agent_id=str(config["service_agent_id"]),
        service_algorithm=str(config["service_algorithm"]),
        service_public_key=bytes.fromhex(str(config["service_public_key_hex"])),
        pipe_name=_resolve_pipe_name(config),
        timeout_ms=int(config.get("timeout_ms", 5_000)),
    )


def _raw_exchange(pipe_name: str, payload: bytes) -> dict[str, Any]:
    win32pipe.WaitNamedPipe(pipe_name, 5_000)
    handle = win32file.CreateFile(
        pipe_name,
        _PIPE_ACCESS,
        0,
        None,
        win32con.OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        None,
    )
    try:
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, payload)
        _hr, data = win32file.ReadFile(handle, MAX_FRAME_BYTES + 1)
        return decode_frame(bytes(data))
    finally:
        win32file.CloseHandle(handle)


def _denial(response: dict[str, Any], expected: str) -> bool:
    return response.get("ok") is False and response.get("error") == expected


def _filesystem_denials(config: dict[str, Any]) -> dict[str, bool]:
    sentinel = Path(config["sentinel_path"])
    ledger = Path(config["ledger_dir"])
    renamed = sentinel.with_name(sentinel.name + ".renamed")
    results: dict[str, bool] = {}

    def denied(name: str, operation) -> None:
        try:
            operation()
        except (OSError, pywintypes.error):
            results[name] = True
        else:
            results[name] = False

    def append() -> None:
        with sentinel.open("ab") as handle:
            handle.write(b"x")

    def truncate() -> None:
        with sentinel.open("wb") as handle:
            handle.write(b"x")

    denied("create", lambda: (ledger / "client-created.jsonl").write_text("x", encoding="ascii"))
    denied("append", append)
    denied("truncate", truncate)
    denied("delete", sentinel.unlink)
    denied("rename", lambda: sentinel.rename(renamed))

    def rewrite_dacl() -> None:
        descriptor = win32security.GetFileSecurity(
            str(sentinel),
            win32security.DACL_SECURITY_INFORMATION,
        )
        win32security.SetFileSecurity(
            str(sentinel),
            win32security.DACL_SECURITY_INFORMATION,
            descriptor,
        )

    denied("change_dacl", rewrite_dacl)
    return results


def bootstrap(args: argparse.Namespace) -> int:
    identity = AgentIdentity.init(args.name, data_dir=args.identity_dir)
    _write_json(
        args.output,
        {
            "agent_id": identity.agent_id,
            "algorithm": "ed25519",
            "identity_dir": str(args.identity_dir),
            "identity_name": args.name,
            "public_key_hex": identity.public_key_bytes.hex(),
        },
    )
    return 0


def exercise(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    identity = _identity(config)
    client = _client(config)
    session_id = str(uuid.uuid4())
    nonce = uuid.uuid4().hex
    valid = build_record_request(
        identity,
        session_id=session_id,
        nonce=nonce,
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "installed-service-proof", "result": "bounded"},
    )
    committed = client.submit(valid)
    replay = client.submit(valid)
    nonce_replay = build_record_request(
        identity,
        session_id=session_id,
        request_id=str(uuid.uuid4()),
        nonce=nonce,
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "nonce-replay"},
    )
    stale = build_record_request(
        identity,
        session_id=str(uuid.uuid4()),
        issued_at_ms=int(time.time() * 1000) - 120_000,
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "stale"},
    )
    bad_signature = build_record_request(
        identity,
        session_id=str(uuid.uuid4()),
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "bad-signature"},
    )
    bad_signature["request_signature"] = "00" * 64
    wrong_agent = build_record_request(
        EphemeralIdentity(),
        session_id=str(uuid.uuid4()),
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "wrong-agent"},
    )
    unsupported = build_record_request(
        identity,
        session_id=str(uuid.uuid4()),
        event_type=SessionEventType.TOOL_CALL,
        payload={"action": "unsupported-version"},
    )
    unsupported["version"] = "selfconnect.provenance.ipc.v999"

    wrong_sid_denied = False
    try:
        ProvenancePipeClient(
            expected_service_sid="S-1-5-18",
            service_agent_id=str(config["service_agent_id"]),
            service_algorithm=str(config["service_algorithm"]),
            service_public_key=bytes.fromhex(str(config["service_public_key_hex"])),
            pipe_name=_resolve_pipe_name(config),
        ).submit(build_record_request(identity, event_type=SessionEventType.TOOL_CALL))
    except ProvenancePipeError:
        wrong_sid_denied = True

    wrong_key_denied = False
    try:
        ProvenancePipeClient(
            expected_service_sid=str(config["service_sid"]),
            service_agent_id=str(config["service_agent_id"]),
            service_algorithm="ed25519",
            service_public_key=b"\0" * 32,
            pipe_name=_resolve_pipe_name(config),
        ).submit(build_record_request(identity, event_type=SessionEventType.TOOL_CALL))
    except ProvenancePipeError:
        wrong_key_denied = True

    checks = {
        "committed": committed.get("status") == "committed",
        "idempotent_replay": replay.get("status") == "already_committed",
        "nonce_replay_denied": _denial(client.submit(nonce_replay), "replayed_nonce"),
        "stale_denied": _denial(client.submit(stale), "stale_request"),
        "bad_signature_denied": _denial(client.submit(bad_signature), "invalid_request_signature"),
        "wrong_agent_denied": _denial(client.submit(wrong_agent), "unknown_agent"),
        "unsupported_version_denied": _denial(client.submit(unsupported), "unsupported_protocol"),
        "malformed_denied": _denial(
            _raw_exchange(_resolve_pipe_name(config), b"{not-json"),
            "invalid_json",
        ),
        "oversized_denied": _denial(
            _raw_exchange(_resolve_pipe_name(config), b"x" * (MAX_FRAME_BYTES + 1)),
            "frame_too_large",
        ),
        "wrong_server_sid_denied": wrong_sid_denied,
        "wrong_service_key_denied": wrong_key_denied,
    }
    checks.update({f"filesystem_{name}_denied": value for name, value in _filesystem_denials(config).items()})
    result = {
        "checks": checks,
        "ok": all(checks.values()),
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id,
        "valid_request_id": valid["request_id"],
    }
    _write_json(args.output, result)
    return 0 if result["ok"] else 1


def probe_connect(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    denied = False
    code = None
    try:
        pipe_name = _resolve_pipe_name(config)
        win32pipe.WaitNamedPipe(pipe_name, 2_000)
        handle = win32file.CreateFile(
            pipe_name,
            _PIPE_ACCESS,
            0,
            None,
            win32con.OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        )
    except (OSError, ValueError, json.JSONDecodeError, pywintypes.error) as exc:
        denied = True
        winerror_value = getattr(exc, "winerror", None)
        code = int(winerror_value) if winerror_value is not None else None
    else:
        win32file.CloseHandle(handle)
    _write_json(args.output, {"access_denied": denied, "winerror": code})
    return 0 if denied else 1


def hold_pipe(args: argparse.Namespace) -> int:
    handle = win32pipe.CreateNamedPipe(
        str(args.pipe_name),
        win32pipe.PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        win32pipe.PIPE_TYPE_MESSAGE
        | win32pipe.PIPE_READMODE_MESSAGE
        | win32pipe.PIPE_WAIT
        | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        MAX_FRAME_BYTES,
        MAX_FRAME_BYTES,
        0,
        None,
    )
    try:
        args.ready.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + args.timeout
        while not args.stop.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        return 0 if args.stop.exists() else 1
    finally:
        win32file.CloseHandle(handle)


def burst(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    identity = _identity(config)
    requests = [
        build_record_request(
            identity,
            session_id=str(uuid.uuid4()),
            event_type=SessionEventType.TOOL_CALL,
            payload={"action": "restart-burst", "ordinal": index},
        )
        for index in range(args.count)
    ]

    def submit(request):
        while not args.go.exists():
            time.sleep(0.02)
        last_error = ""
        error_count = 0
        for attempt in range(1, args.retries + 1):
            try:
                response = _client(config).submit(request)
                if response.get("ok") is True and response.get("status") in {
                    "committed",
                    "already_committed",
                }:
                    return {
                        "attempts": attempt,
                        "recovered_after_error": error_count > 0,
                        "request_id": request["request_id"],
                        "status": response["status"],
                    }
                last_error = str(response.get("error", "denied"))
                error_count += 1
            except Exception as exc:  # bounded retry against an intentional service kill
                last_error = type(exc).__name__
                error_count += 1
            time.sleep(args.retry_delay)
        return {
            "attempts": args.retries,
            "error": last_error,
            "recovered_after_error": error_count > 0,
            "request_id": request["request_id"],
        }

    results = []
    with ThreadPoolExecutor(max_workers=min(args.workers, args.count)) as executor:
        futures = [executor.submit(submit, request) for request in requests]
        args.ready.write_text("ready\n", encoding="ascii")
        for future in as_completed(futures):
            results.append(future.result())
    recovered = sum(bool(item.get("recovered_after_error")) for item in results)
    ok = (
        len(results) == args.count
        and all("status" in item for item in results)
        and recovered > 0
    )
    _write_json(
        args.output,
        {
            "count": args.count,
            "ok": ok,
            "recovered_after_error_count": recovered,
            "results": results,
        },
    )
    return 0 if ok else 1


def verify_dacl(args: argparse.Namespace) -> int:
    from enterprise.provenance_service import verify_service_path_acl

    try:
        verify_service_path_acl(
            args.path,
            service_sid=args.service_sid,
            client_sids=frozenset({args.client_sid}),
            service_requires_write=True,
        )
    except Exception as exc:
        result = {
            "blocked": True,
            "error_type": type(exc).__name__,
            "message": str(exc),
        }
    else:
        result = {"blocked": False, "error_type": None, "message": ""}
    _write_json(args.output, result)
    return 0


def verify_ledger(args: argparse.Namespace) -> int:
    from enterprise.provenance import canonical_hash, verify_log

    public_key = bytes.fromhex(args.public_key_hex)
    result = verify_log(
        args.path,
        args.session_id,
        recorder_public_key=public_key,
        require_recorder_signatures=True,
    )
    records = [
        json.loads(line)
        for line in args.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    chain = [item for item in records if isinstance(item.get("seq"), int)]
    payload = {
        "agent_attestations_verified": result.agent_attestations_verified,
        "count": result.count,
        "head_hash": canonical_hash(chain[-1]) if chain else None,
        "high_water_seq": result.high_water_seq,
        "message": result.message,
        "ok": result.ok,
        "path": str(args.path),
        "session_id": args.session_id,
        "signatures_verified": result.signatures_verified,
    }
    _write_json(args.output, payload)
    return 0 if result.ok else 1


def verify_index(args: argparse.Namespace) -> int:
    from enterprise.session_index import verify_index_file

    ok, message, count = verify_index_file(
        args.path,
        public_key=bytes.fromhex(args.public_key_hex),
        expected_agent_id=args.agent_id,
        require_signatures=True,
    )
    _write_json(
        args.output,
        {"count": count, "message": message, "ok": ok, "path": str(args.path)},
    )
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    wheel_parser = commands.add_parser("verify-wheel")
    wheel_parser.add_argument("--wheel", type=Path, required=True)
    wheel_parser.add_argument("--repo-root", type=Path, required=True)
    wheel_parser.add_argument("--output", type=Path, required=True)
    wheel_parser.set_defaults(func=verify_wheel)

    bootstrap_parser = commands.add_parser("bootstrap")
    bootstrap_parser.add_argument("--identity-dir", type=Path, required=True)
    bootstrap_parser.add_argument("--name", default="provenance-acceptance-agent")
    bootstrap_parser.add_argument("--output", type=Path, required=True)
    bootstrap_parser.set_defaults(func=bootstrap)

    exercise_parser = commands.add_parser("exercise")
    exercise_parser.add_argument("--config", type=Path, required=True)
    exercise_parser.add_argument("--output", type=Path, required=True)
    exercise_parser.set_defaults(func=exercise)

    probe_parser = commands.add_parser("probe-connect")
    probe_parser.add_argument("--config", type=Path, required=True)
    probe_parser.add_argument("--output", type=Path, required=True)
    probe_parser.set_defaults(func=probe_connect)

    hold_parser = commands.add_parser("hold-pipe")
    hold_parser.add_argument("--config", type=Path, required=True)
    hold_parser.add_argument("--pipe-name", required=True)
    hold_parser.add_argument("--ready", type=Path, required=True)
    hold_parser.add_argument("--stop", type=Path, required=True)
    hold_parser.add_argument("--timeout", type=float, default=30.0)
    hold_parser.set_defaults(func=hold_pipe)

    burst_parser = commands.add_parser("burst")
    burst_parser.add_argument("--config", type=Path, required=True)
    burst_parser.add_argument("--output", type=Path, required=True)
    burst_parser.add_argument("--count", type=int, default=40)
    burst_parser.add_argument("--workers", type=int, default=8)
    burst_parser.add_argument("--retries", type=int, default=30)
    burst_parser.add_argument("--retry-delay", type=float, default=0.5)
    burst_parser.add_argument("--ready", type=Path, required=True)
    burst_parser.add_argument("--go", type=Path, required=True)
    burst_parser.set_defaults(func=burst)

    dacl_parser = commands.add_parser("verify-dacl")
    dacl_parser.add_argument("--path", type=Path, required=True)
    dacl_parser.add_argument("--service-sid", required=True)
    dacl_parser.add_argument("--client-sid", required=True)
    dacl_parser.add_argument("--output", type=Path, required=True)
    dacl_parser.set_defaults(func=verify_dacl)

    ledger_parser = commands.add_parser("verify-ledger")
    ledger_parser.add_argument("--path", type=Path, required=True)
    ledger_parser.add_argument("--session-id", required=True)
    ledger_parser.add_argument("--public-key-hex", required=True)
    ledger_parser.add_argument("--output", type=Path, required=True)
    ledger_parser.set_defaults(func=verify_ledger)

    index_parser = commands.add_parser("verify-index")
    index_parser.add_argument("--path", type=Path, required=True)
    index_parser.add_argument("--public-key-hex", required=True)
    index_parser.add_argument("--agent-id", required=True)
    index_parser.add_argument("--output", type=Path, required=True)
    index_parser.set_defaults(func=verify_index)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
