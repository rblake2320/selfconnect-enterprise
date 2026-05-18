"""conftest.py — pytest configuration for SelfConnect Enterprise tests.

Installs the Linux ctypes.windll shim before any test collection so that
Windows-only modules (enterprise.crypto, enterprise.identity, etc.) can be
imported and tested on Linux using real cryptographic operations via the
Python `cryptography` library (OpenSSL backend).
"""
import sys
import ctypes

# Install the windll shim on non-Windows platforms BEFORE any test collection
if sys.platform != "win32":
    sys.path.insert(0, '.')
    from tests.conftest_linux_shim import install_windll_shim
    install_windll_shim()
