"""Run all Win32 capability probes and print a summary table.

Usage:  python experiments/win32_probe/run_all.py
Each probe is self-contained and parks cleanly (it creates/deletes its own
resources). Nothing here is imported by the shipping `enterprise` package.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
PROBES = [
    ("TPM hardware identity", "tpm_identity.py"),
    ("Named-pipe OS identity", "named_pipe_identity.py"),
    ("UIA structured read", "uia_read.py"),
]


def main() -> int:
    results = []
    for label, script in PROBES:
        print(f"\n===== {label} ({script}) =====")
        proc = subprocess.run(
            [sys.executable, str(HERE / script)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        sys.stdout.write(proc.stdout)
        if proc.stderr.strip():
            sys.stdout.write(proc.stderr)
        results.append((label, proc.returncode))

    print("\n===== SUMMARY =====")
    code_map = {0: "PASS", 1: "PARTIAL/SW", 2: "N/A", 3: "FAIL"}
    for label, rc in results:
        print(f"  {code_map.get(rc, f'rc={rc}'):<11} {label}")
    return 0 if all(rc in (0,) for _, rc in results) else 1


if __name__ == "__main__":
    sys.exit(main())
