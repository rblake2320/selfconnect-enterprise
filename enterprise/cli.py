"""enterprise/cli.py — `scent` CLI: SelfConnect Enterprise command-line interface."""
from __future__ import annotations

import argparse
import sys
import time

from enterprise import __version__ as _VERSION
from enterprise.watcher import (
    MAX_RECENT_EVENTS,
    WatcherState,
    make_audit_table,
    make_lease_table,
    make_status_table,
)

# ── CLI input bounds ───────────────────────────────────────────────────────────
_MIN_HZ: int = 1
_MAX_HZ: int = 60    # above 60 Hz is meaningless and burns CPU
_MIN_LAST: int = 1
_MAX_LAST: int = MAX_RECENT_EVENTS


def _bounded_int(min_val: int, max_val: int, name: str):
    """Return an argparse type-converter that validates an integer is in [min, max]."""
    def _convert(value: str) -> int:
        try:
            v = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be an integer, got {value!r}")
        if v < min_val or v > max_val:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {min_val} and {max_val}, got {v}"
            )
        return v
    _convert.__name__ = name
    return _convert


def _get_console():
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None


def cmd_status(args: argparse.Namespace) -> int:
    state = WatcherState()
    state.refresh()
    console = _get_console()
    if console is None:
        print(f"Channel health: {state.channel_health()}")
        print(f"Active leases: {len(state.active_leases())}")
        if state.error:
            print(f"Warning: {state.error}")
        return 0
    table = make_status_table(state)
    if table:
        console.print(table)
    lease_table = make_lease_table(state)
    if lease_table:
        console.print(lease_table)
    if state.error:
        console.print(f"[yellow]Warning:[/yellow] {state.error}")
    return 0


def cmd_leases(args: argparse.Namespace) -> int:
    state = WatcherState()
    state.refresh()
    console = _get_console()
    leases = state.active_leases()
    if console is None:
        for lease in leases:
            print(f"{lease.lease_id}  {lease.agent_id}  HWND={lease.hwnd}  role={lease.role}  ttl={lease.ttl_seconds:.0f}s")
        return 0
    table = make_lease_table(state)
    if table:
        console.print(table)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    state = WatcherState()
    state.refresh()
    console = _get_console()
    n = getattr(args, "last", 20)
    if console is None:
        for evt in state.recent_events(n):
            print(f"{evt.timestamp:.0f}  {evt.event_type}  {evt.agent_id}  {evt.details}")
        return 0
    table = make_audit_table(state, n)
    if table:
        console.print(table)
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    try:
        from rich.live import Live
        from rich.console import Console
    except ImportError:
        print("rich is required for watch mode. Install: pip install rich")
        return 1
    state = WatcherState()
    console = Console()
    refresh_hz = getattr(args, "hz", 2)
    console.print("[bold]SelfConnect Enterprise — Live Watch[/bold] (Ctrl+C to exit)")
    try:
        with Live(console=console, refresh_per_second=refresh_hz) as live:
            while True:
                state.refresh()
                from rich.columns import Columns
                tables = [t for t in [make_status_table(state), make_lease_table(state), make_audit_table(state, 10)] if t]
                if tables:
                    live.update(Columns(tables, equal=False, expand=False))
                time.sleep(1.0 / max(refresh_hz, 1))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(f"scent {_VERSION}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scent",
        description="SelfConnect Enterprise — governed OS-native AI peer mesh CLI",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("status", help="One-shot status report")
    sub.add_parser("leases", help="List active channel leases")
    audit_p = sub.add_parser("audit", help="Show recent audit events")
    audit_p.add_argument(
        "--last",
        type=_bounded_int(_MIN_LAST, _MAX_LAST, "--last"),
        default=20,
        metavar="N",
        help=f"Number of events to show (1–{_MAX_LAST}, default 20)",
    )
    watch_p = sub.add_parser("watch", help="Live-updating dashboard (Ctrl+C to exit)")
    watch_p.add_argument(
        "--hz",
        type=_bounded_int(_MIN_HZ, _MAX_HZ, "--hz"),
        default=2,
        metavar="HZ",
        help=f"Refresh rate in Hz ({_MIN_HZ}–{_MAX_HZ}, default 2)",
    )
    sub.add_parser("version", help="Print version and exit")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "status": cmd_status,
        "leases": cmd_leases,
        "audit": cmd_audit,
        "watch": cmd_watch,
        "version": cmd_version,
        None: lambda a: (parser.print_help(), 0)[1],
    }
    return dispatch.get(args.command, lambda a: (parser.print_help(), 1)[1])(args)


if __name__ == "__main__":
    sys.exit(main())
