"""
TPM/NCrypt ECDSA P-384 signing benchmark for SelfConnect Enterprise.

Tests BOTH storage providers explicitly and reports results separately:
  - Microsoft Platform Crypto Provider (TPM-oriented provider target)
  - Microsoft Software Key Storage Provider (software fallback — NOT the target)

These are DIFFERENT provider boundaries. A successful Platform-KSP operation
must still be paired with the exact key's hardware-property evidence before a
hardware-custody claim is made. Software KSP is a software-backed boundary.

Usage:
    python bench/tpm_sign_bench.py [--iterations 200]

Run elevated (Administrator) to get accurate TPM query results.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
import ctypes

# Provider name constants — do NOT mix these up
MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"   # Hardware TPM target
MS_SOFTWARE_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider"  # Software fallback

NCRYPT_SILENT_FLAG = 0x00000040
NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080


def _ncrypt_bench(provider_name: str, key_name: str, iterations: int) -> tuple[list[float], str | None]:
    """
    Benchmark NCrypt ECDSA P-384 signing against a specific named provider.
    Returns (samples_ms, error_string).
    error_string is None on success, describes failure on error.
    """
    ncrypt = ctypes.WinDLL("ncrypt.dll")

    h_provider = ctypes.c_void_p()
    status = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(h_provider),
        ctypes.c_wchar_p(provider_name),
        0
    )
    if status & 0xFFFFFFFF != 0:
        error_map = {
            0x80090030: "NTE_DEVICE_NOT_READY — TPM unprovisioned (run tpm.msc as admin)",
            0x80090029: "NTE_NOT_SUPPORTED — TPM disabled in firmware or not present",
            0x80090020: "NTE_FAIL — provider general failure",
            0x80090016: "NTE_BAD_KEYSET — key context error",
            0x80070005: "ERROR_ACCESS_DENIED — need elevation",
        }
        code = status & 0xFFFFFFFF
        msg = error_map.get(code, f"Unknown error 0x{code:08x}")
        return [], msg

    h_key = ctypes.c_void_p()
    # Try to open existing bench key first
    status = ncrypt.NCryptOpenKey(
        h_provider,
        ctypes.byref(h_key),
        ctypes.c_wchar_p(key_name),
        0,
        NCRYPT_SILENT_FLAG
    )
    if status & 0xFFFFFFFF != 0:
        # Key doesn't exist — create it
        status = ncrypt.NCryptCreatePersistedKey(
            h_provider,
            ctypes.byref(h_key),
            ctypes.c_wchar_p("ECDSA_P384"),
            ctypes.c_wchar_p(key_name),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG
        )
        if status & 0xFFFFFFFF != 0:
            ncrypt.NCryptFreeObject(h_provider)
            code = status & 0xFFFFFFFF
            return [], f"Key creation failed: 0x{code:08x}"

        status = ncrypt.NCryptFinalizeKey(h_key, 0)
        if status & 0xFFFFFFFF != 0:
            ncrypt.NCryptFreeObject(h_key)
            ncrypt.NCryptFreeObject(h_provider)
            return [], f"Key finalization failed: 0x{status & 0xFFFFFFFF:08x}"

    # SHA-384 digest is 48 bytes
    hash_data = (ctypes.c_byte * 48)(*([0xAB] * 48))
    sig_buf = (ctypes.c_byte * 256)()
    sig_len = ctypes.c_ulong(0)

    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        status = ncrypt.NCryptSignHash(
            h_key,
            None,
            hash_data,
            48,
            sig_buf,
            256,
            ctypes.byref(sig_len),
            0
        )
        elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
        if status & 0xFFFFFFFF == 0:
            samples.append(elapsed_ms)

    ncrypt.NCryptFreeObject(h_key)
    ncrypt.NCryptFreeObject(h_provider)

    if not samples:
        return [], "All sign iterations failed"
    return samples, None


def _software_ecdsa_bench(iterations: int) -> list[float]:
    """Pure Python software ECDSA P-384 — for comparison only."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    key = ec.generate_private_key(ec.SECP384R1())
    data = b"x" * 32
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        key.sign(data, ec.ECDSA(hashes.SHA384()))
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return samples


def _check_tpm() -> dict:
    """Non-elevated TPM state check via registry."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\TPM\Parameters", 0,
                             winreg.KEY_READ)
        winreg.CloseKey(key)
        tpm_service = "TPM service key found"
    except Exception:
        tpm_service = "TPM service key not found"

    # Check if tpm.sys driver is present
    import os
    tpm_driver = os.path.exists(r"C:\Windows\System32\drivers\tpm.sys")

    return {
        "tpm_driver": tpm_driver,
        "tpm_service": tpm_service,
        "note": "Run 'Get-Tpm' in elevated PowerShell for definitive TPM state"
    }


def print_report(label: str, provider: str, samples: list[float],
                 error: str | None, iterations: int) -> None:
    print(f"\n{'='*65}")
    print(f"  {label}")
    print(f"  Provider: {provider}")
    print(f"{'='*65}")

    if error:
        print("  STATUS: FAILED")
        print(f"  REASON: {error}")
        print("  SECURITY NOTE: This provider is NOT available for signing.")
        print(f"{'='*65}")
        return

    sorted_s = sorted(samples)
    p50 = statistics.median(samples)
    p95 = sorted_s[int(0.95 * len(sorted_s))]
    p99 = sorted_s[int(0.99 * len(sorted_s))]
    mean = statistics.mean(samples)
    mx = max(samples)

    print(f"  STATUS: OK ({len(samples)}/{iterations} iterations succeeded)")
    print(f"  Mean : {mean:.2f} ms")
    print(f"  p50  : {p50:.2f} ms")
    print(f"  p95  : {p95:.2f} ms")
    print(f"  p99  : {p99:.2f} ms")
    print(f"  Max  : {mx:.2f} ms")
    print("")
    print(f"  Recommended heartbeat re-sign : every {max(1, int(p95 * 2 / 1000))}s  (2x p95)")
    print(f"  Handshake timeout per agent   : {p95 * 10:.0f} ms  (10x p95)")
    print(f"{'='*65}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()

    print("\nSelfConnect Identity Hardening — NCrypt Signing Benchmark")
    print(f"Platform: {sys.platform} | Python: {sys.version.split()[0]}")
    print(f"Iterations: {args.iterations}")
    print("\nIMPORTANT: Platform KSP and Software KSP have different security properties.")
    print("Platform KSP is the TPM-oriented target; verify the exact key's hardware property separately.")

    tpm_state = _check_tpm()
    print(f"\nTPM Driver present: {tpm_state['tpm_driver']}")
    print(f"TPM Service: {tpm_state['tpm_service']}")
    print(f"NOTE: {tpm_state['note']}")

    # --- Test 1: Platform Crypto Provider (THE TARGET) ---
    print("\n[1/3] Testing Microsoft Platform Crypto Provider (HARDWARE TPM TARGET)...")
    platform_samples, platform_err = _ncrypt_bench(
        MS_PLATFORM_CRYPTO_PROVIDER,
        "sc_bench_platform_p384",
        args.iterations
    )
    print_report(
        "Microsoft Platform Crypto Provider (Hardware TPM)",
        MS_PLATFORM_CRYPTO_PROVIDER,
        platform_samples, platform_err, args.iterations
    )

    # --- Test 2: Software KSP (fallback only, NOT the security target) ---
    print("\n[2/3] Testing Microsoft Software Key Storage Provider (SOFTWARE FALLBACK)...")
    sw_ksp_samples, sw_ksp_err = _ncrypt_bench(
        MS_SOFTWARE_KEY_STORAGE_PROVIDER,
        "sc_bench_software_p384",
        args.iterations
    )
    print_report(
        "Microsoft Software Key Storage Provider (SOFTWARE — NOT TPM-backed)",
        MS_SOFTWARE_KEY_STORAGE_PROVIDER,
        sw_ksp_samples, sw_ksp_err, args.iterations
    )

    # --- Test 3: Pure Python software (baseline comparison) ---
    print("\n[3/3] Testing pure Python ECDSA P-384 (baseline comparison)...")
    try:
        py_samples = _software_ecdsa_bench(args.iterations)
        print_report(
            "Python cryptography library ECDSA P-384 (pure software, no NCrypt)",
            "cryptography.hazmat",
            py_samples, None, args.iterations
        )
    except ImportError:
        print("  cryptography library not installed — skipping")

    # --- Decision ---
    print(f"\n{'='*65}")
    print("  DECISION")
    print(f"{'='*65}")
    if platform_err:
        print(f"  Platform KSP: UNAVAILABLE ({platform_err})")
        print("")
        print("  Branch B options (pick one explicitly):")
        print("  B1 — Ship Software KSP, document reduced guarantee in SECURITY.md")
        print("       Risk: 'TPM-backed' claims would be inaccurate for regulated deployment")
        print("  B2 — Find dev machine with provisioned TPM 2.0 for all signing work")
        print("       Best for federal trajectory")
        print("  B3 — Software KSP in dev/CI, Platform KSP enforced at deploy via startup check")
        print("       Best long-term if dev hardware varies")
    else:
        p95 = sorted(platform_samples)[int(0.95 * len(platform_samples))]
        print(f"  Platform KSP: AVAILABLE (p95={p95:.1f}ms)")
        if p95 < 30:
            print("  Heartbeat: sub-second re-sign feasible")
        elif p95 < 100:
            print(f"  Heartbeat: re-sign every {int(p95*2/1000) or 1}s recommended")
        else:
            print("  Heartbeat: sign on-demand only (p95 too high for periodic re-sign)")
        print("  Proceed: Tier 1 unblocked. Platform KSP confirmed as signing primitive.")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    main()
