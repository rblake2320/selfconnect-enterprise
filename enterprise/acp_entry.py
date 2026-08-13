"""Command entry point for the SelfConnect governed ACP shim."""
from __future__ import annotations

import argparse
import importlib
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

from enterprise.acp_auth import ACPTrustStore
from enterprise.acp_shim import ACPShim, serve_stdio
from enterprise.identity import AgentIdentity

_FACTORY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")


def run_setup(
    *,
    trust_store_path: str | Path,
    identity_name: str,
    identity_dir: str | Path | None,
    principal: str,
    confirm: Callable[[str], bool],
    now: float,
) -> str:
    """Load the owner identity and complete proof-of-possession enrollment."""
    identity = AgentIdentity.load(
        identity_name,
        data_dir=Path(identity_dir) if identity_dir is not None else None,
    )
    store = ACPTrustStore(trust_store_path)
    try:
        return store.enroll_with_signer(
            principal=principal,
            signer=identity,
            now=now,
            confirm=confirm,
        )
    finally:
        store.close()


def load_shim_factory(reference: str) -> ACPShim:
    """Load a deployment-owned ``module:function`` returning an ACPShim."""
    if not _FACTORY.fullmatch(reference):
        raise ValueError("factory must be a dotted module:function reference")
    module_name, function_name = reference.split(":", 1)
    module = importlib.import_module(module_name)
    factory = getattr(module, function_name)
    shim = factory()
    if type(shim) is not ACPShim:
        raise TypeError("ACP factory must return the exact ACPShim type")
    return shim


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scent-acp")
    parser.add_argument("--setup", action="store_true", help="Enroll an owner key interactively")
    parser.add_argument("--trust-store", default=os.environ.get("SELFCONNECT_ACP_TRUST_STORE"))
    parser.add_argument("--identity-name", default=os.environ.get("SELFCONNECT_ACP_IDENTITY_NAME"))
    parser.add_argument("--identity-dir", default=os.environ.get("SELFCONNECT_ACP_IDENTITY_DIR"))
    parser.add_argument("--principal", default=os.environ.get("SELFCONNECT_ACP_OWNER_PRINCIPAL"))
    parser.add_argument("--factory", default=os.environ.get("SELFCONNECT_ACP_FACTORY"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.setup:
        missing = [
            name
            for name, value in (
                ("--trust-store", args.trust_store),
                ("--identity-name", args.identity_name),
                ("--principal", args.principal),
            )
            if not value
        ]
        if missing:
            print(f"setup requires {', '.join(missing)}", file=sys.stderr)
            return 2

        def confirm(expected: str) -> bool:
            print(f"Type exactly to confirm owner-key enrollment:\n{expected}", file=sys.stderr)
            return input().strip() == expected

        try:
            fingerprint = run_setup(
                trust_store_path=args.trust_store,
                identity_name=args.identity_name,
                identity_dir=args.identity_dir,
                principal=args.principal,
                confirm=confirm,
                now=time.time(),
            )
        except Exception as exc:  # noqa: BLE001 - terminal boundary prints bounded type only
            print(f"setup failed: {type(exc).__name__}", file=sys.stderr)
            return 1
        print(f"Owner key enrolled: {fingerprint}", file=sys.stderr)
        return 0

    if not args.factory:
        print("serve mode requires --factory or SELFCONNECT_ACP_FACTORY", file=sys.stderr)
        return 2
    try:
        shim = load_shim_factory(args.factory)
    except Exception as exc:  # noqa: BLE001 - terminal boundary prints bounded type only
        print(f"factory load failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    serve_stdio(shim)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
