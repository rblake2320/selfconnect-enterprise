"""tools/wfp_policy.py — Windows Filtering Platform (WFP) policy generator.

Produces a PowerShell deployment script that installs WFP rules to block all
outbound network traffic from a target process EXCEPT to explicitly allowlisted
hosts and ports.

This is a DEPLOYMENT HELPER, not runtime code. It generates a .ps1 file that
an operator runs with administrator privileges to harden the network boundary
for a SelfConnect agent process. It does not modify the SelfConnect runtime.

Usage:
    python tools/wfp_policy.py --process python.exe \
        --allow 10.0.0.1:443 --allow 192.168.1.0/24 --out wfp-selfconnect.ps1
    python tools/wfp_policy.py --config tools/wfp_profiles/mode_c.json --out wfp-mode-c.ps1
    python tools/wfp_policy.py --list-profiles

Design:
    The generated script uses netsh advfirewall (Windows Firewall API) which
    wraps WFP at the application layer. For full WFP sublayer control, the
    operator can use the --wfp-native flag to emit BFE (Base Filtering Engine)
    netsh commands instead of the advfirewall surface.

    The deny-by-default approach: one BLOCK rule at low priority for all
    outbound from the target process, then per-allowlist ALLOW rules at high
    priority for each permitted destination. WFP processes rules by weight;
    higher-weight rules are evaluated first.

Remediation target: G-2 (Network-Layer Egress Not Enforced) in gap-analysis.md.
Controls addressed: SC-7, SC-8, AC-4.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import NamedTuple

# ── Input sanitization ────────────────────────────────────────────────────────

_CONTROL_CHARS = {"\n", "\r", "\t", "\x00", "\x0b", "\x0c"}


def _sanitize_ps_string(value: str, field_name: str = "value") -> str:
    """Sanitize a value for safe embedding in a PowerShell single-quoted string.

    Two-step hardening (FINDING-1 + GPT-review follow-up):

    Step 1 — Reject control characters (\n, \r, \t, \x00, etc.).
             These break script line structure even inside single-quoted strings.

    Step 2 — Escape single quotes ('' is the PowerShell single-quote escape).
             Values are embedded in PS single-quoted literals (no $-expansion,
             no backtick-expansion), so the only character that needs escaping
             is the single quote itself.

    Using single-quoted PS literals instead of double-quoted eliminates the
    entire $(...)/$(cmd)/`n/variable-expansion injection class structurally
    rather than via a deny-list.

    Raises:
        ValueError: if value contains any character from _CONTROL_CHARS.
    Returns:
        Value with single quotes doubled, safe for embedding as 'value' in PS.
    """
    for ch in _CONTROL_CHARS:
        if ch in value:
            raise ValueError(
                f"Invalid control character {ch!r} in {field_name!r}: "
                f"control characters are not permitted in PowerShell script fields"
            )
    # Escape single quotes for single-quoted PS context: ' → ''
    return value.replace("'", "''")


# ── Data model ────────────────────────────────────────────────────────────────

class AllowEntry(NamedTuple):
    host: str           # IP, CIDR, or hostname
    port: int | None    # None = any port
    protocol: str       # tcp | udp | any

    @classmethod
    def parse(cls, spec: str) -> "AllowEntry":
        """Parse 'host', 'host:port', 'host:port/proto', 'cidr', 'cidr:port'.

        IPv6 addresses must be bracket-quoted if a port is also specified:
          ::1           → loopback, no port
          [::1]:443     → loopback, port 443
        Bare IPv6 without brackets (e.g. ::1) is treated as host-only.
        """
        protocol = "tcp"
        port: int | None = None

        # Strip protocol suffix
        if spec.endswith("/udp"):
            protocol = "udp"
            spec = spec[:-4]
        elif spec.endswith("/any"):
            protocol = "any"
            spec = spec[:-4]
        elif spec.endswith("/tcp"):
            spec = spec[:-4]

        # Bracketed IPv6 with optional port: [::1]:443
        if spec.startswith("["):
            bracket_end = spec.find("]")
            if bracket_end == -1:
                raise ValueError(f"Unclosed bracket in: {spec!r}")
            host = spec[1:bracket_end]
            remainder = spec[bracket_end + 1:]
            if remainder.startswith(":") and remainder[1:].isdigit():
                port = int(remainder[1:])
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port {port} in '{spec}'")
        else:
            # Try to parse as bare IPv6 first (contains colons but no port ambiguity)
            try:
                ipaddress.ip_address(spec)
                host = spec  # bare IPv6 address — no port
            except ValueError:
                # Not a bare IP — try host:port split
                if ":" in spec:
                    parts = spec.rsplit(":", 1)
                    if parts[1].isdigit():
                        host = parts[0]
                        port = int(parts[1])
                        if port < 1 or port > 65535:
                            raise ValueError(f"Invalid port {port} in '{spec}'")
                    else:
                        host = spec
                else:
                    host = spec

        # Validate: IP, CIDR, or hostname
        _validate_host(host)
        return cls(host=host, port=port, protocol=protocol)


def _validate_host(host: str) -> None:
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    try:
        ipaddress.ip_network(host, strict=False)
        return
    except ValueError:
        pass
    # Hostname — basic length/character check (not DNS resolution)
    if not host or len(host) > 253 or ".." in host:
        raise ValueError(f"Invalid host specification: {host!r}")
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_*")
    if not all(c in allowed_chars for c in host):
        raise ValueError(f"Invalid characters in host: {host!r}")


@dataclass
class WfpProfile:
    name: str
    process: str                            # e.g. "python.exe" or full path
    allow: list[AllowEntry] = field(default_factory=list)
    description: str = ""
    wfp_native: bool = False                # True = BFE commands; False = advfirewall

    def __post_init__(self) -> None:
        """Sanitize all string fields on construction (FINDING-1 fix)."""
        self.name    = _sanitize_ps_string(self.name,    "name")
        self.process = _sanitize_ps_string(self.process, "process")

    @classmethod
    def from_dict(cls, d: dict) -> "WfpProfile":
        allow = [AllowEntry.parse(s) for s in d.get("allow", [])]
        return cls(
            name=d["name"],
            process=d["process"],
            allow=allow,
            description=d.get("description", ""),
            wfp_native=d.get("wfp_native", False),
        )

    @classmethod
    def from_json(cls, path: Path) -> "WfpProfile":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)


# ── Built-in profiles ─────────────────────────────────────────────────────────

BUILTIN_PROFILES: dict[str, dict] = {
    "mode_a": {
        "name": "mode_a",
        "process": "python.exe",
        "description": (
            "Mode A (Simulation) — no classified data, no egress restriction required. "
            "Permissive profile for development and testing."
        ),
        "allow": ["0.0.0.0/0"],          # All outbound permitted
    },
    "mode_b": {
        "name": "mode_b",
        "process": "python.exe",
        "description": (
            "Mode B (CUI) — controlled unclassified information. "
            "Allowlists common SaaS/API egress. Tighten per-deployment."
        ),
        "allow": [
            "api.anthropic.com:443",
            "api.openai.com:443",
            "storage.googleapis.com:443",
            "s3.amazonaws.com:443",
            "127.0.0.1:8100",            # MemoryWeb local
            "127.0.0.1:8300",            # UltraRAG local
        ],
    },
    "mode_c": {
        "name": "mode_c",
        "process": "python.exe",
        "description": (
            "Mode C (SECRET / Classified) — deny-all egress except localhost "
            "and explicitly provisioned internal hosts. No cloud API access. "
            "Operator must add internal host allowlist entries post-deploy."
        ),
        "allow": [
            "127.0.0.1",                 # Loopback only — all ports
            "::1",                       # IPv6 loopback
        ],
    },
    "mode_c_strict": {
        "name": "mode_c_strict",
        "process": "python.exe",
        "description": (
            "Mode C Strict — loopback only, TCP only, specific ports. "
            "Maximum network isolation for classified deployments."
        ),
        "allow": [
            "127.0.0.1:8100/tcp",        # MemoryWeb
            "127.0.0.1:8300/tcp",        # UltraRAG
            "127.0.0.1:5432/tcp",        # PostgreSQL local
        ],
    },
}


# ── PowerShell script generator ───────────────────────────────────────────────

_RULE_PREFIX = "SelfConnect-WFP"

_PS_HEADER = """\
#Requires -RunAsAdministrator
# ===========================================================================
# SelfConnect Enterprise — WFP Egress Policy
# Profile:     {name}
# Process:     {process}
# Generated:   {date}
# Controls:    SC-7, SC-8, AC-4
# Gap:         G-2 remediation (gap-analysis.md)
# ===========================================================================
# {description}
#
# INSTALLATION:
#   Run this script as Administrator ONCE per host.
#   To remove: Run with -Remove flag.
#   To verify: Run with -Verify flag.
#
# REQUIRES: Windows Firewall service running (MpsSvc)
#           netsh advfirewall (ships with Windows Vista+)
# ===========================================================================

param(
    [switch]$Remove,
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RulePrefix = '{rule_prefix}'
$ProcessName = '{process}'
"""

_PS_REMOVE = """
# ── Remove mode ──────────────────────────────────────────────────────────────
if ($Remove) {
    Write-Host "Removing SelfConnect WFP rules..." -ForegroundColor Yellow
    $rules = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Remove-NetFirewallRule
        Write-Host "Removed $($rules.Count) rules." -ForegroundColor Green
    } else {
        Write-Host "No rules found with prefix '$RulePrefix'." -ForegroundColor Yellow
    }
    exit 0
}
"""

_PS_VERIFY = """
# ── Verify mode ──────────────────────────────────────────────────────────────
if ($Verify) {
    Write-Host "Verifying SelfConnect WFP rules..." -ForegroundColor Cyan
    $rules = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "ERROR: No SelfConnect WFP rules found. Run install first." -ForegroundColor Red
        exit 1
    }
    $blockRule = $rules | Where-Object { $_.DisplayName -like "*BLOCK*" }
    if (-not $blockRule) {
        Write-Host "ERROR: Block-all rule missing." -ForegroundColor Red
        exit 1
    }
    $allowCount = ($rules | Where-Object {$_.Action -eq 'Allow'}).Count
    Write-Host "OK — $($rules.Count) rules installed ($allowCount allow, 1 block)." -ForegroundColor Green
    $rules | Format-Table DisplayName, Action, Enabled -AutoSize
    exit 0
}
"""

_PS_INSTALL_HEADER = """
# ── Install mode ─────────────────────────────────────────────────────────────
Write-Host "Installing SelfConnect WFP egress policy for '$ProcessName'..." -ForegroundColor Cyan

# Remove any existing SelfConnect rules first (idempotent install)
$existing = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing $($existing.Count) existing SelfConnect rules (reinstall)..." -ForegroundColor Yellow
    $existing | Remove-NetFirewallRule
}
"""

_PS_BLOCK_RULE = """
# ── Block-all-outbound rule (lowest priority, deny-by-default) ────────────────
New-NetFirewallRule `
    -DisplayName "{rule_prefix}-BLOCK-ALL-OUTBOUND" `
    -Direction Outbound `
    -Action Block `
    -Protocol Any `
    -Program '{process_path}' `
    -Profile Any `
    -Enabled True `
    | Out-Null
Write-Host "  [BLOCK] All outbound from $ProcessName" -ForegroundColor Red
"""

_PS_ALLOW_RULE_IP = """
New-NetFirewallRule `
    -DisplayName "{rule_prefix}-ALLOW-{idx:04d}-{label}" `
    -Direction Outbound `
    -Action Allow `
    -Protocol {proto} `
    -RemoteAddress '{remote}' `
    {port_line}`
    -Program '{process_path}' `
    -Profile Any `
    -Enabled True `
    | Out-Null
Write-Host "  [ALLOW] {label}" -ForegroundColor Green
"""

_PS_FOOTER = """
Write-Host ""
Write-Host "SelfConnect WFP policy installed." -ForegroundColor Green
Write-Host "  Profile: {name}" -ForegroundColor Cyan
Write-Host "  Block:   All outbound from $ProcessName (deny-by-default)" -ForegroundColor Red
Write-Host "  Allow:   {allow_count} explicit allowlist entries" -ForegroundColor Green
Write-Host ""
Write-Host "Verify with: .\\{out_name} -Verify" -ForegroundColor Cyan
Write-Host "Remove with: .\\{out_name} -Remove" -ForegroundColor Cyan
"""


def _proto_str(proto: str) -> str:
    return {"tcp": "TCP", "udp": "UDP", "any": "Any"}.get(proto, "TCP")


def _process_path_ps(process: str) -> str:
    """Return PowerShell-safe process path string for New-NetFirewallRule -Program."""
    # If it looks like a bare exe name (no slashes/backslashes), the rule applies
    # to that exe regardless of path — use %SystemRoot% convention.
    if "\\" not in process and "/" not in process:
        return f"%SystemRoot%\\*\\{process}"
    # Absolute path — use as-is but escape backslashes for PS heredoc
    return process.replace("\\", "\\\\")


def generate_powershell(profile: WfpProfile, out_name: str) -> str:
    """Generate the complete PowerShell deployment script for a WfpProfile."""
    lines: list[str] = []

    # Header
    lines.append(_PS_HEADER.format(
        name=profile.name,
        process=profile.process,
        date=date.today().isoformat(),
        description=textwrap.fill(profile.description or "No description.", width=72),
        rule_prefix=_RULE_PREFIX,
    ))

    # Remove + Verify modes
    lines.append(_PS_REMOVE)
    lines.append(_PS_VERIFY)
    lines.append(_PS_INSTALL_HEADER)

    process_path = _process_path_ps(profile.process)

    # Block-all rule
    lines.append(_PS_BLOCK_RULE.format(
        rule_prefix=_RULE_PREFIX,
        process_path=process_path,
    ))

    # Per-entry allow rules
    for idx, entry in enumerate(profile.allow, start=1):
        label = entry.host
        if entry.port:
            label = f"{entry.host}:{entry.port}"
        label = label.replace("/", "-").replace(".", "-").replace(":", "-")[:40]

        port_line = ""
        if entry.port:
            port_line = f"-RemotePort {entry.port} `\n    "

        proto = _proto_str(entry.protocol)

        lines.append(_PS_ALLOW_RULE_IP.format(
            rule_prefix=_RULE_PREFIX,
            idx=idx,
            label=label,
            proto=proto,
            remote=entry.host,
            port_line=port_line,
            process_path=process_path,
        ))

    # Footer
    lines.append(_PS_FOOTER.format(
        name=profile.name,
        allow_count=len(profile.allow),
        out_name=out_name,
    ))

    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wfp_policy.py",
        description="Generate WFP egress policy PowerShell scripts for SelfConnect agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Mode C profile (classified, loopback-only):
              python tools/wfp_policy.py --profile mode_c --out wfp-mode-c.ps1

              # Custom: block all except one internal host and local API:
              python tools/wfp_policy.py \\
                --process python.exe \\
                --allow 10.10.0.50:8443/tcp \\
                --allow 127.0.0.1:8100/tcp \\
                --name sc-custom \\
                --out wfp-custom.ps1

              # From a JSON config file:
              python tools/wfp_policy.py --config tools/wfp_profiles/mode_c.json --out wfp-mode-c.ps1

              # List built-in profiles:
              python tools/wfp_policy.py --list-profiles
        """),
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--profile", choices=list(BUILTIN_PROFILES), help="Use a built-in profile")
    src.add_argument("--config", type=Path, help="JSON config file (see --list-profiles for format)")

    p.add_argument("--process", default="python.exe", help="Process executable to constrain (default: python.exe)")
    p.add_argument("--allow", action="append", default=[], metavar="HOST[:PORT][/PROTO]",
                   help="Add an allowlist entry. Repeatable. Format: host, host:port, host:port/tcp|udp|any")
    p.add_argument("--name", default="sc-custom", help="Profile name (used in rule labels)")
    p.add_argument("--description", default="", help="Human-readable policy description")
    p.add_argument("--out", type=Path, required=False, help="Output .ps1 file path (default: stdout)")
    p.add_argument("--list-profiles", action="store_true", help="List built-in profiles and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_profiles:
        print("Built-in WFP profiles:")
        print()
        for name, data in BUILTIN_PROFILES.items():
            print(f"  {name}")
            print(f"    Process: {data['process']}")
            desc = textwrap.fill(data.get("description", ""), width=68, initial_indent="    ", subsequent_indent="    ")
            print(desc)
            allow = data.get("allow", [])
            print(f"    Allowlist ({len(allow)} entries):")
            for entry in allow:
                print(f"      {entry}")
            print()
        return 0

    # Build profile
    if args.profile:
        profile = WfpProfile.from_dict(BUILTIN_PROFILES[args.profile])
    elif args.config:
        if not args.config.exists():
            print(f"ERROR: Config file not found: {args.config}", file=sys.stderr)
            return 1
        profile = WfpProfile.from_json(args.config)
    else:
        # Custom from CLI args
        if not args.allow:
            print("ERROR: Specify --profile, --config, or at least one --allow entry.", file=sys.stderr)
            return 1
        try:
            entries = [AllowEntry.parse(s) for s in args.allow]
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        profile = WfpProfile(
            name=args.name,
            process=args.process,
            allow=entries,
            description=args.description,
        )

    out_name = args.out.name if args.out else "wfp-policy.ps1"
    script = generate_powershell(profile, out_name)

    if args.out:
        args.out.write_text(script, encoding="utf-8")
        sha256 = hashlib.sha256(script.encode("utf-8")).hexdigest()
        print(f"Written: {args.out}  ({args.out.stat().st_size} bytes)")
        print(f"Profile: {profile.name}")
        print(f"Process: {profile.process}")
        print(f"Allow entries: {len(profile.allow)}")
        print(f"SHA-256: {sha256}")
        print()
        print("VERIFY before running (compare hash above):")
        print(f'  powershell -Command "(Get-FileHash -Algorithm SHA256 \'{args.out}\').Hash"')
        print()
        print(f"Install (as Admin): powershell -ExecutionPolicy Bypass -File {args.out}")
        print(f"Verify:             powershell -ExecutionPolicy Bypass -File {args.out} -Verify")
        print(f"Remove:             powershell -ExecutionPolicy Bypass -File {args.out} -Remove")
    else:
        sys.stdout.write(script)

    return 0


if __name__ == "__main__":
    sys.exit(main())
