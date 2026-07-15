"""Run a live, no-mock governed-execution conformance probe on Windows.

This is evidence collection, not an IRS authorization determination. It uses a
real target HWND, a real externally pinned signed policy, the persistent DPAPI
identity, the real Win32 target guard/router, and the signed action ledger.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from enterprise.governed_runtime import GovernedRuntime
from enterprise.uia_output import read_terminal_text


def _load_public_key(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    try:
        text = raw.decode("ascii").strip()
        if len(text) in (64, 192):
            return bytes.fromhex(text)
    except (UnicodeDecodeError, ValueError):
        pass
    if len(raw) not in (32, 96):
        raise ValueError("trust-root file must contain a 32/96-byte key or its hex encoding")
    return raw


def _status(name: str, status: str, detail: str = "") -> dict[str, str]:
    return {"check": name, "status": status, "detail": detail}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trust-root-file", type=Path, required=True)
    parser.add_argument("--agent-name", required=True)
    parser.add_argument("--identity-dir", type=Path)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--hwnd", type=lambda value: int(value, 0), required=True)
    parser.add_argument(
        "--classification",
        choices=("UNCLASSIFIED", "CUI", "SECRET", "TOP_SECRET"),
        required=True,
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--text", default="SC-IRS-CONFORMANCE-PROBE")
    parser.add_argument(
        "--expect-output",
        help=(
            "Output token that must newly appear after execution. It must not be present "
            "in --text, so command echo cannot satisfy the effect check."
        ),
    )
    parser.add_argument("--effect-timeout-ms", type=int, default=5000)
    parser.add_argument("--operator-id")
    parser.add_argument("--approve-interactively", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checks: list[dict[str, str]] = []
    try:
        if args.expect_output and args.expect_output in args.text:
            raise ValueError("--expect-output must not occur verbatim in --text")
        if not 100 <= args.effect_timeout_ms <= 30000:
            raise ValueError("--effect-timeout-ms must be between 100 and 30000")
        runtime = GovernedRuntime.from_signed_policy(
            policy_path=args.policy,
            trust_root_pub=_load_public_key(args.trust_root_file),
            agent_name=args.agent_name,
            identity_data_dir=args.identity_dir,
            ledger_path=args.ledger,
        )
        checks.append(_status("externally_pinned_signed_policy", "PASS", "policy loaded"))
        checks.append(_status("persistent_cryptographic_identity", "PASS", runtime.identity.agent_id))

        lease = runtime.dispatcher.call_tool(
            "sc_request_lease",
            {
                "hwnd": args.hwnd,
                "role": "sender",
                "agent_id": runtime.identity.agent_id,
                "ttl_seconds": 300,
            },
        )
        if not lease["ok"]:
            raise RuntimeError(lease["error"])
        checks.append(
            _status(
                "live_hwnd_pid_exe_class_binding",
                "PASS",
                (
                    f"pid={lease['result']['target_pid']} "
                    f"exe_path={lease['result']['target_exe_path']}"
                ),
            )
        )

        policy = runtime.dispatcher.call_tool(
            "sc_policy_check",
            {
                "action_type": "inject",
                "agent_id": runtime.identity.agent_id,
                "target_hwnd": args.hwnd,
                "classification": args.classification,
            },
        )
        if not policy["ok"] or not policy["result"]["allowed"]:
            reason = policy.get("error") or policy.get("result", {}).get("rule", "denied")
            raise RuntimeError(f"policy gate denied live probe: {reason}")
        checks.append(_status("mandatory_runtime_policy_gate", "PASS", policy["result"]["policy_id"]))

        approval_id = None
        if policy["result"].get("requires_approval"):
            if not args.execute:
                checks.append(_status("human_approval", "NOT_RUN", "execution not requested"))
            elif not args.approve_interactively or not args.operator_id:
                raise RuntimeError(
                    "policy requires approval; use --approve-interactively and --operator-id"
                )
            else:
                approval_id = runtime.operator_queue.submit(
                    runtime.identity.agent_id,
                    "sc_inject_text",
                    runtime.dispatcher.approval_context_for(
                        lease["result"]["lease_id"],
                        {
                            "hwnd": args.hwnd,
                            "text": args.text,
                            "classification": args.classification,
                        },
                        action="sc_inject_text",
                    ),
                )
                phrase = f"APPROVE {approval_id[:8]}"
                entered = input(f"Type {phrase!r} to authorize the bounded probe: ").strip()
                if entered != phrase:
                    runtime.operator_queue.deny(approval_id, args.operator_id)
                    raise RuntimeError("operator did not approve the probe")
                runtime.operator_queue.approve(approval_id, args.operator_id)
                checks.append(_status("human_approval", "PASS", args.operator_id))
        else:
            checks.append(_status("human_approval", "NOT_REQUIRED", "policy did not require it"))

        if args.execute:
            effect_before = ""
            effect_before_count = 0
            if args.expect_output:
                effect_before = read_terminal_text(args.hwnd)
                effect_before_count = effect_before.count(args.expect_output)
            request = {
                "lease_id": lease["result"]["lease_id"],
                "hwnd": args.hwnd,
                "text": args.text,
                "classification": args.classification,
            }
            if approval_id:
                request["approval_id"] = approval_id
            execution = runtime.dispatcher.call_tool("sc_inject_text", request)
            if not execution["ok"] or not execution["result"].get("success"):
                raise RuntimeError(execution.get("error") or "target did not confirm execution")
            checks.append(
                _status(
                    "live_governed_delivery",
                    "PASS",
                    execution["result"]["receipt_id"],
                )
            )
            if args.expect_output:
                deadline = time.monotonic() + (args.effect_timeout_ms / 1000.0)
                while True:
                    effect_after = read_terminal_text(args.hwnd)
                    if effect_after.count(args.expect_output) > effect_before_count:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "execution effect unconfirmed: expected output did not newly appear"
                        )
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                checks.append(
                    _status(
                        "live_governed_execution_effect",
                        "PASS",
                        "expected output newly observed by UIA",
                    )
                )
            else:
                checks.append(
                    _status(
                        "live_governed_execution_effect",
                        "NOT_RUN",
                        "use --expect-output with a token absent from --text",
                    )
                )
        else:
            checks.append(_status("live_governed_delivery", "NOT_RUN", "use --execute"))
            checks.append(
                _status("live_governed_execution_effect", "NOT_RUN", "use --execute")
            )

        verified, count, message = runtime.verify_audit()
        if not verified:
            raise RuntimeError(f"signed ledger verification failed: {message}")
        checks.append(_status("signed_hash_chained_action_ledger", "PASS", f"{count} entries"))
        checks.append(
            _status(
                "off_host_worm_and_irs_deployment_controls",
                "NOT_ASSESSED",
                "requires deployment-specific sink, retention, inventory, privacy, and authorization evidence",
            )
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(_status("conformance_run", "FAIL", str(exc)))
        print(json.dumps({"overall": "FAIL", "checks": checks}, indent=2))
        return 1

    overall = "PASS" if args.execute and args.expect_output else "PARTIAL"
    print(json.dumps({"overall": overall, "checks": checks}, indent=2))
    return 0 if overall == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
