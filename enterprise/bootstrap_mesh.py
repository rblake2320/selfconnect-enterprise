"""enterprise/bootstrap_mesh.py — Bootstrap Mesh CLI

Command-line utility for bootstrapping the Ultra identity mesh across all
registered agents in a SelfConnect Enterprise deployment.

Usage:
    python -m enterprise.bootstrap_mesh [OPTIONS]

    Options:
      --mode {bypass,audit,enforce}   Set SC_IDENTITY_MODE for all agents (default: audit)
      --agent AGENT_ID                Bootstrap a specific agent only
      --all                           Bootstrap all agents in the registry
      --status                        Show current mesh status
      --recover AGENT_ID              Initiate key recovery for a specific agent
      --server-url URL                Ultra Server URL (default: http://localhost:7777)
      --timeout MS                    Server timeout in milliseconds (default: 5000)
      --verbose                       Enable debug logging

Exit codes:
    0  All agents bootstrapped successfully
    1  One or more agents failed to bootstrap
    2  Ultra Server unreachable
    3  Invalid arguments

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional

import requests

_log = logging.getLogger("bootstrap_mesh")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_server(server_url: str, timeout_ms: int) -> bool:
    """Return True if Ultra Server is reachable."""
    try:
        resp = requests.get(f"{server_url}/health", timeout=timeout_ms / 1000)
        return resp.status_code == 200
    except Exception:
        return False


def _load_agent_registry() -> List[Dict]:
    """Load agent registry from enterprise registry module."""
    try:
        from enterprise.registry import list_agents
        return list_agents()
    except Exception as exc:
        _log.warning("Could not load agent registry: %s", exc)
        return []


def _bootstrap_agent(agent_id: str, server_url: str, timeout_ms: int) -> Dict:
    """Bootstrap a single agent: derive keypair, register BPC, provision TSK, bind."""
    result = {"agent_id": agent_id, "ok": False, "error": None, "pair_id": None,
              "tsk_client_id": None, "degraded_level": 0}

    try:
        from enterprise.identity import AgentIdentity
        from enterprise.ultra_gate import UltraGate

        # Load or create identity
        identity = AgentIdentity(agent_id)

        # Set server URL for this bootstrap
        os.environ["SC_ULTRA_SERVER_URL"] = server_url
        os.environ["SC_ULTRA_SERVER_TIMEOUT_MS"] = str(timeout_ms)

        gate = UltraGate(identity)
        gate.bootstrap()

        result["ok"] = gate.bootstrapped
        result["pair_id"] = gate.pair_id
        result["tsk_client_id"] = gate.tsk_client_id
        result["degraded_level"] = gate.degraded_level

        if gate.degraded_level > 0:
            from enterprise.identity_gate import DEGRADATION_DESCRIPTIONS
            result["degraded_reason"] = DEGRADATION_DESCRIPTIONS.get(gate.degraded_level, "unknown")

    except Exception as exc:
        result["error"] = str(exc)
        _log.error("Bootstrap failed for agent=%s: %s", agent_id, exc)

    return result


def _show_status(server_url: str, timeout_ms: int) -> None:
    """Display current mesh status."""
    print("\n=== SelfConnect Ultra Mesh Status ===\n")

    # Server status
    server_ok = _check_server(server_url, timeout_ms)
    print(f"Ultra Server ({server_url}): {'✓ reachable' if server_ok else '✗ unreachable'}")

    if server_ok:
        try:
            resp = requests.get(f"{server_url}/health", timeout=timeout_ms / 1000)
            data = resp.json()
            print(f"  Registered pairs:    {data.get('pairs', 0)}")
            print(f"  TSK clients:         {data.get('tskClients', 0)}")
            print(f"  Identity bindings:   {data.get('bindings', 0)}")
            print(f"  Server uptime:       {data.get('uptime', 0):.1f}s")
        except Exception:
            pass

    # Identity mode
    mode = os.environ.get("SC_IDENTITY_MODE", "bypass")
    print(f"\nSC_IDENTITY_MODE: {mode}")

    # Emergency bypass
    from enterprise.identity_gate import _is_bypass_active, _bypass_mutex_path
    bypass = _is_bypass_active()
    print(f"Emergency bypass:  {'ACTIVE (' + str(_bypass_mutex_path()) + ')' if bypass else 'inactive'}")

    # Agent registry
    agents = _load_agent_registry()
    print(f"\nRegistered agents: {len(agents)}")
    for agent in agents[:20]:  # Show first 20
        agent_id = agent.get("id") or agent.get("name") or str(agent)
        print(f"  - {agent_id}")
    if len(agents) > 20:
        print(f"  ... and {len(agents) - 20} more")

    print()


def _initiate_recovery(agent_id: str) -> None:
    """Initiate key recovery for a specific agent."""
    print(f"\nInitiating key recovery for agent: {agent_id}")
    try:
        from enterprise.identity import AgentIdentity
        from enterprise.key_recovery import KeyRecovery

        identity = AgentIdentity(agent_id)
        recovery = KeyRecovery(identity)
        pub_bytes = recovery.initiate()
        print(f"  ✓ New keypair generated")
        print(f"  ✓ Recovery public key written ({len(pub_bytes)} bytes)")
        print(f"  ✓ Recovery window: 60 seconds")
        print(f"  → Run bootstrap_mesh --agent {agent_id} to re-register with Ultra Server")
    except Exception as exc:
        print(f"  ✗ Recovery failed: {exc}")
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap the SelfConnect Ultra identity mesh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--mode", choices=["bypass", "audit", "enforce"],
                        help="Set SC_IDENTITY_MODE (default: audit)")
    parser.add_argument("--agent", metavar="AGENT_ID",
                        help="Bootstrap a specific agent only")
    parser.add_argument("--all", action="store_true",
                        help="Bootstrap all agents in the registry")
    parser.add_argument("--status", action="store_true",
                        help="Show current mesh status")
    parser.add_argument("--recover", metavar="AGENT_ID",
                        help="Initiate key recovery for a specific agent")
    parser.add_argument("--server-url", default=os.environ.get("SC_ULTRA_SERVER_URL", "http://localhost:7777"),
                        help="Ultra Server URL (default: http://localhost:7777)")
    parser.add_argument("--timeout", type=int, default=5000,
                        help="Server timeout in milliseconds (default: 5000)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")

    args = parser.parse_args(argv)

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    # Set mode
    if args.mode:
        os.environ["SC_IDENTITY_MODE"] = args.mode
        _log.info("SC_IDENTITY_MODE set to: %s", args.mode)

    # Status
    if args.status:
        _show_status(args.server_url, args.timeout)
        return 0

    # Recovery
    if args.recover:
        _initiate_recovery(args.recover)
        return 0

    # Check server reachability
    if not _check_server(args.server_url, args.timeout):
        print(f"✗ Ultra Server unreachable at {args.server_url}", file=sys.stderr)
        print("  Start it with: node enterprise/ultra_server.js", file=sys.stderr)
        return 2

    # Determine agents to bootstrap
    agents_to_bootstrap: List[str] = []
    if args.agent:
        agents_to_bootstrap = [args.agent]
    elif args.all:
        registry = _load_agent_registry()
        agents_to_bootstrap = [a.get("id") or a.get("name") or str(a) for a in registry]
        if not agents_to_bootstrap:
            print("No agents found in registry. Use --agent AGENT_ID to bootstrap a specific agent.")
            return 0
    else:
        parser.print_help()
        return 3

    # Bootstrap
    results = []
    failed = 0
    print(f"\nBootstrapping {len(agents_to_bootstrap)} agent(s) against {args.server_url}...\n")

    for agent_id in agents_to_bootstrap:
        t0 = time.time()
        result = _bootstrap_agent(agent_id, args.server_url, args.timeout)
        elapsed_ms = (time.time() - t0) * 1000
        result["elapsed_ms"] = round(elapsed_ms, 1)
        results.append(result)

        if result["ok"]:
            degraded = result.get("degraded_level", 0)
            if degraded == 0:
                status = "✓ OK (7-layer)"
            else:
                status = f"⚠ OK (degraded L{degraded}: {result.get('degraded_reason', '')})"
            print(f"  {status:<50} {agent_id}  [{elapsed_ms:.0f}ms]")
            if result["pair_id"]:
                print(f"    pair_id={result['pair_id']}  tsk_client_id={result['tsk_client_id']}")
        else:
            failed += 1
            print(f"  ✗ FAILED  {agent_id}  [{elapsed_ms:.0f}ms]")
            print(f"    error: {result['error']}")

    print(f"\n{'='*60}")
    print(f"Bootstrapped: {len(results) - failed}/{len(results)} agents")
    if failed:
        print(f"Failed:       {failed} agent(s)")
    print()

    if args.json:
        print(json.dumps(results, indent=2))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
