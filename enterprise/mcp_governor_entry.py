"""Command entry point for selfconnect-mcp-governor."""
from __future__ import annotations

import argparse
import importlib
import os
import re
import sys
from collections.abc import Sequence

from enterprise.governed_runtime import GovernedRuntime
from enterprise.mcp_governor import MCPGovernor, serve_stdio

_FACTORY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")


def load_runtime_factory(reference: str) -> GovernedRuntime:
    if not _FACTORY.fullmatch(reference):
        raise ValueError("factory must be a dotted module:function reference")
    module_name, function_name = reference.split(":", 1)
    runtime = getattr(importlib.import_module(module_name), function_name)()
    if type(runtime) is not GovernedRuntime:
        raise TypeError("factory must return the exact GovernedRuntime type")
    return runtime


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="selfconnect-mcp-governor")
    parser.add_argument("--factory", default=os.environ.get("SELFCONNECT_MCP_GOVERNOR_FACTORY"))
    args = parser.parse_args(argv)
    if not args.factory:
        print(
            "serve mode requires --factory or SELFCONNECT_MCP_GOVERNOR_FACTORY",
            file=sys.stderr,
        )
        return 2
    try:
        runtime = load_runtime_factory(args.factory)
    except Exception as exc:  # noqa: BLE001 - bounded terminal error
        print(f"factory load failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    try:
        serve_stdio(MCPGovernor(runtime.dispatcher), input_stream=sys.stdin, output_stream=sys.stdout)
    finally:
        runtime.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
