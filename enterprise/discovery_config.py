"""enterprise/discovery_config.py — Discovery safety caps for SelfConnect Enterprise.

Centralizes the tunable limits for discover_mesh() so they can be overridden via
environment variables without touching registry.py logic.

Defaults:
    SC_DISCOVERY_CAP = 32   — max candidates processed per discovery cycle
    SC_HANDSHAKE_TIMEOUT_MS = 500  — per-candidate handshake timeout (Tier 2, unused until v2)

Topology note: 8 parallel handshakes at p95=22ms Platform KSP sign = ~220ms wall-clock
when 8 responders are distinct. If 8 challengers converge on one responder, TPM serializes
signs and wall-clock approaches 8×22ms = 176ms. Both well under 500ms. Cap of 32 means
worst case 4 batches × 500ms = 2s discovery (with 8-parallel Tier 2 handshake).

Rationale for cap=32:
    - Legitimate meshes are nowhere near 32 agents on a single machine
    - SetPropW is one syscall — an attacker can stamp thousands of fake SCID
      properties; without a cap, discovery becomes a free DoS vector
    - Cap raises with an audit event so legitimate growth is tracked, not silently ignored

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import os

# Maximum SCID-stamped windows processed per discover_mesh() call.
# Raise via SC_DISCOVERY_CAP env var; change emits discovery_candidate_capped audit event.
MAX_CANDIDATES_PER_CYCLE: int = int(os.environ.get("SC_DISCOVERY_CAP", "32"))

# Per-candidate handshake timeout in milliseconds (used by Tier 2 challenge-response).
# Based on Platform KSP p95=22ms × 10 = 220ms round-trip + 280ms margin = 500ms.
HANDSHAKE_TIMEOUT_MS: int = int(os.environ.get("SC_HANDSHAKE_TIMEOUT_MS", "500"))

# Max SCID property stamps from a single PID before that PID is flagged as suspicious.
MAX_STAMPS_PER_PID: int = int(os.environ.get("SC_MAX_STAMPS_PER_PID", "4"))

# Seconds a failed handshake result is cached (Tier 2 backoff).
HANDSHAKE_BACKOFF_SEC: int = int(os.environ.get("SC_HANDSHAKE_BACKOFF_SEC", "60"))

# ── BPC+TSK identity gate constants (Tier 3 — ultra-gate) ────────────────────
# SC_IDENTITY_MODE: "audit" (default) | "enforce" | explicitly confirmed
# "bypass".  The runtime identity gate performs the confirmation check; this
# shared configuration surface must still reject misspellings instead of
# silently exposing an unsafe string to downstream callers.
_identity_mode = os.environ.get("SC_IDENTITY_MODE", "audit").strip().lower()
if _identity_mode not in {"audit", "enforce", "bypass"}:
    raise RuntimeError(
        f"SC_IDENTITY_MODE={_identity_mode!r} is not a recognised mode "
        "(expected 'audit', 'enforce', or explicitly confirmed 'bypass')"
    )
IDENTITY_MODE_DEFAULT: str = _identity_mode

# Maximum time to wait for Ultra Server to respond (milliseconds).
IDENTITY_BRIDGE_TIMEOUT_MS: int = int(os.environ.get("SC_IDENTITY_BRIDGE_TIMEOUT_MS", "500"))

# Minimum degradation level in enforce mode.
# Level 2 = enterprise-only (ed25519 + birth tag). Never go below in enforce.
ENFORCE_MIN_DEGRADATION_LEVEL: int = int(os.environ.get("SC_ENFORCE_MIN_LEVEL", "2"))

# Key recovery window in seconds. Recovery.pub files older than this are ignored.
RECOVERY_WINDOW_SEC: int = int(os.environ.get("SC_RECOVERY_WINDOW_SEC", "60"))

# URL of the Ultra Server sidecar.
ULTRA_SERVER_URL: str = os.environ.get("ULTRA_SERVER_URL", "http://127.0.0.1:7777")
