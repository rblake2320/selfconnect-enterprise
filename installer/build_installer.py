#!/usr/bin/env python3
"""
installer/build_installer.py
Build the SelfConnect Enterprise MSI installer.

Usage:
    python installer/build_installer.py
    python installer/build_installer.py --wix-path "C:/Program Files/WiX Toolset v4/bin"
    python installer/build_installer.py --output-dir releases/

Requires:
    - Python 3.10+ with `build` package: pip install build
    - WiX v4 toolset (wix.exe) on PATH or specified via --wix-path
"""
from __future__ import annotations

import argparse
import ast
import re
import shutil
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALLER_DIR = REPO_ROOT / "installer"
INSTALLER_DIST = INSTALLER_DIR / "dist"
REPO_DIST = REPO_ROOT / "dist"
WXS_SOURCE = INSTALLER_DIR / "selfconnect-enterprise.wxs"
INIT_FILE = REPO_ROOT / "enterprise" / "__init__.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_version() -> str:
    """Extract __version__ from enterprise/__init__.py via AST (no import needed)."""
    source = INIT_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(INIT_FILE))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    if isinstance(node.value, ast.Constant):
                        return str(node.value.value)
    # Fallback: regex search
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', source, re.MULTILINE)
    if m:
        return m.group(1)
    raise RuntimeError(f"Could not find __version__ in {INIT_FILE}")


def find_wix(wix_path: str | None) -> Path:
    """Locate wix.exe.  Search order: --wix-path arg, PATH, common install dirs."""
    candidates: list[Path] = []

    if wix_path:
        candidates.append(Path(wix_path) / "wix.exe")
        candidates.append(Path(wix_path) / "heat.exe")  # v3 toolset check

    # Scan PATH
    wix_on_path = shutil.which("wix")
    if wix_on_path:
        candidates.insert(0, Path(wix_on_path))

    # Common installation directories
    common = [
        Path(r"C:\Program Files\WiX Toolset v4\bin\wix.exe"),
        Path(r"C:\Program Files (x86)\WiX Toolset v4\bin\wix.exe"),
        Path(r"C:\tools\wixtoolset\wix.exe"),
    ]
    candidates.extend(common)

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "WiX toolset (wix.exe) not found.\n"
        "Install WiX v4: https://wixtoolset.org/releases/\n"
        "Or pass --wix-path to specify its location."
    )


def build_wheel() -> Path:
    """Run 'python -m build --wheel' and return the path to the produced .whl."""
    print("[1/5] Building Python wheel...")
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(REPO_DIST)],
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        raise RuntimeError("python -m build failed — see output above.")

    # Locate the newest wheel
    wheels = sorted(REPO_DIST.glob("selfconnect_enterprise-*.whl"), key=lambda p: p.stat().st_mtime)
    if not wheels:
        raise FileNotFoundError(f"No selfconnect_enterprise-*.whl found in {REPO_DIST}")
    wheel = wheels[-1]
    print(f"    Wheel: {wheel.name}")
    return wheel


def stage_wheel(wheel: Path) -> Path:
    """Copy the wheel to installer/dist/ under a fixed name for the WXS source."""
    INSTALLER_DIST.mkdir(parents=True, exist_ok=True)
    dest = INSTALLER_DIST / "selfconnect_enterprise.whl"
    shutil.copy2(wheel, dest)
    print(f"[2/5] Staged wheel -> {dest}")
    return dest


def create_service_sentinel() -> None:
    """Create the sentinel file referenced by the ServiceComponent in the WXS."""
    assets_dir = INSTALLER_DIR / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    sentinel = assets_dir / ".service_installed"
    sentinel.write_text("# Service installation sentinel — do not delete\n", encoding="utf-8")
    print(f"[3/5] Service sentinel: {sentinel}")


def build_msi(wix_exe: Path, version: str, output_dir: Path) -> Path:
    """Run wix build and return path to the produced .msi."""
    output_dir.mkdir(parents=True, exist_ok=True)
    msi_name = f"selfconnect-enterprise-{version}.msi"
    msi_path = output_dir / msi_name

    print(f"[4/5] Running: {wix_exe} build {WXS_SOURCE.name} -> {msi_name}")
    cmd = [
        str(wix_exe),
        "build",
        str(WXS_SOURCE),
        "-out",
        str(msi_path),
        "-ext",
        "WixToolset.Util.wixext",
        "-ext",
        "WixToolset.UI.wixext",
    ]

    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        raise RuntimeError(f"wix build failed with exit code {result.returncode}")

    if not msi_path.exists():
        raise FileNotFoundError(f"wix build succeeded but {msi_path} was not created.")

    size_kb = msi_path.stat().st_size // 1024
    print(f"[4/5] MSI created: {msi_path}  ({size_kb} KB)")
    return msi_path


def print_usage(msi_path: Path) -> None:
    """Print install/uninstall commands for the operator."""
    name = msi_path.name
    print()
    print("=" * 60)
    print("INSTALL / UNINSTALL COMMANDS")
    print("=" * 60)
    print()
    print("Standard install (GUI):")
    print(f"    msiexec /i \"{name}\"")
    print()
    print("Silent install (enterprise IT):")
    print(f"    msiexec /i \"{name}\" /quiet /norestart SCENT_AUDIT_MODE=enterprise")
    print()
    print("Verify service:")
    print("    sc query SelfConnectEnterprise")
    print()
    print("Verify CLI:")
    print("    scent version")
    print()
    print("Uninstall (GUI):")
    print(f"    msiexec /x \"{name}\"")
    print()
    print("Silent uninstall:")
    print(f"    msiexec /x \"{name}\" /quiet /norestart")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the SelfConnect Enterprise MSI installer."
    )
    parser.add_argument(
        "--wix-path",
        metavar="DIR",
        default=None,
        help="Directory containing wix.exe (e.g. C:/Program Files/WiX Toolset v4/bin)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default=str(REPO_ROOT / "dist"),
        help="Directory to write the .msi into (default: dist/)",
    )
    parser.add_argument(
        "--skip-wheel",
        action="store_true",
        help="Skip running python -m build; use existing wheel in installer/dist/",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()

    try:
        version = read_version()
        print(f"Version: {version}")
    except Exception as exc:
        print(f"ERROR: Could not read version — {exc}", file=sys.stderr)
        return 1

    # Locate WiX first so we fail early if it's missing
    try:
        wix_exe = find_wix(args.wix_path)
        print(f"WiX: {wix_exe}")
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        if args.skip_wheel:
            # Expect the wheel to already be staged
            staged = INSTALLER_DIST / "selfconnect_enterprise.whl"
            if not staged.exists():
                raise FileNotFoundError(
                    f"--skip-wheel specified but no wheel at {staged}"
                )
            print(f"[1/5] Skipping wheel build — using {staged}")
            print("[2/5] Wheel already staged")
        else:
            wheel = build_wheel()
            stage_wheel(wheel)

        create_service_sentinel()
        msi_path = build_msi(wix_exe, version, output_dir)
        print("[5/5] Done.")
        print_usage(msi_path)
        return 0

    except (RuntimeError, FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
