"""enterprise/tsk_client.py — Python TSK client (segment value derivation + key assembly).

Implements the client-side operations matching @tsk/core's segment.ts:
  - deriveSegmentValue() for static, TOTP, HOTP segment types.
  - Key assembly: concatenate segments in client-visible order + checksum.
  - HMAC-SHA-256 with hex-encoded 256-bit shared secret (matches TSK crypto.ts).

The shared secret is a 64-hex-char string provided by the Ultra Server at
provisioning time. It is NEVER stored on disk — held in memory only for the
lifetime of the UltraGate instance.

TSK segment types:
  - static: HMAC(secret, "static:<segmentId>")  — never changes
  - totp:   HMAC(secret, "totp:<segmentId>:<T>")  — T = floor(nowMs/1000/windowSec)
  - hotp:   HMAC(secret, "hotp:<segmentId>:<counter>")  — counter per use

SECURITY NOTE: The positional map (which positions in the key string map to
which segments) is a SERVER-ONLY SECRET (Structural Secrecy, Layer 7). The
client only knows the segment IDs, types, and lengths — not where they land
in the final key string. This Python client assembles segments in the order
the server specifies in the provision payload's `clientSegments` list.

Version: 1.0.0  BPC+TSK integration
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import re
import time
from dataclasses import dataclass, field
from typing import Any

# ── Base64url helpers ─────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hmac_raw(secret_bytes: bytes, data: str) -> str:
    """HMAC-SHA-256 over data string, returns base64url output.

    Matches hmacRaw() in TSK crypto.ts — same byte-level operations.
    """
    return _b64url(_hmac.new(secret_bytes, data.encode("utf-8"), hashlib.sha256).digest())


# ── Secret validation (matches validateHexSecret in TSK crypto.ts) ───────────

_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

def validate_hex_secret(secret: str) -> None:
    """Validate 256-bit hex shared secret. Raises ValueError on invalid input.

    Prevents silent key collapse when non-hex chars are passed to bytes.fromhex().
    Matches validateHexSecret() in TSK crypto.ts.
    """
    if not isinstance(secret, str):
        raise TypeError("TSK: sharedSecret must be a string")
    if len(secret) != 64:
        raise ValueError(f"TSK: sharedSecret must be 64 hex chars (256 bits), got {len(secret)}")
    if not _HEX_RE.match(secret):
        raise ValueError("TSK: sharedSecret contains non-hex characters")


# ── Segment config ────────────────────────────────────────────────────────────

@dataclass
class SegmentConfig:
    """TSK segment configuration (from provision payload clientSegments list)."""
    segment_id: str
    type: str           # "static" | "totp" | "hotp"
    seg_len: int        # length of this segment's contribution in the key string
    window_sec: int = 60        # TOTP: window size in seconds
    counter: int = 0            # HOTP: current counter value


# ── TSK client state ──────────────────────────────────────────────────────────

@dataclass
class TSKClientState:
    """Holds all TSK client state for one provisioned client.

    Attributes:
        client_id: TSK client ID assigned by Ultra Server (e.g. "tsk_abc123").
        shared_secret: 64-char hex-encoded 256-bit shared secret.
        segments: Ordered list of segment configs from provision payload.
        hotp_counters: Per-segment HOTP counters (commit-after-success pattern).
        _secret_bytes: Pre-decoded secret bytes for hot-path HMAC operations.
    """
    client_id: str
    shared_secret: str
    segments: list[SegmentConfig]
    hotp_counters: dict[str, int] = field(default_factory=dict)
    _secret_bytes: bytes = field(default=b"", init=False)

    def __post_init__(self) -> None:
        validate_hex_secret(self.shared_secret)
        self._secret_bytes = bytes.fromhex(self.shared_secret)
        # Ensure HOTP counters are initialized for each segment
        for seg in self.segments:
            if seg.type == "hotp" and seg.segment_id not in self.hotp_counters:
                self.hotp_counters[seg.segment_id] = seg.counter


# ── Segment value derivation ──────────────────────────────────────────────────

def derive_segment_value(
    secret_bytes: bytes,
    seg: SegmentConfig,
    now_ms: int | None = None,
    hotp_counter: int | None = None,
) -> str:
    """Derive the current value for a single segment.

    Matches deriveSegmentValue() in segment.ts. Uses _hmac_raw() which produces
    base64url output identical to hmacRaw() in TSK crypto.ts.

    Args:
        secret_bytes: Pre-decoded 32-byte secret (from validate_hex_secret).
        seg: Segment configuration.
        now_ms: Current time in milliseconds (for TOTP). Defaults to time.time()*1000.
        hotp_counter: Counter override (for HOTP). Defaults to seg.counter.
    """
    if seg.type == "static":
        derivation_input = f"static:{seg.segment_id}"
    elif seg.type == "totp":
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        window_sec = seg.window_sec if seg.window_sec > 0 else 60
        T = int(now_ms / 1000 / window_sec)
        derivation_input = f"totp:{seg.segment_id}:{T}"
    else:  # hotp
        counter = hotp_counter if hotp_counter is not None else seg.counter
        derivation_input = f"hotp:{seg.segment_id}:{counter}"

    full = _hmac_raw(secret_bytes, derivation_input)
    return _pad_or_truncate(secret_bytes, full, seg.seg_len)


def _pad_or_truncate(secret_bytes: bytes, s: str, length: int) -> str:
    """Pad or truncate HMAC output to exactly `length` base64url characters.

    Matches padOrTruncate() in segment.ts (SECURITY FIX applied: uses original
    secret bytes for all rounds, not HMAC output as key).
    """
    if len(s) >= length:
        return s[:length]
    result = s
    round_num = 0
    while len(result) < length:
        result += _hmac_raw(secret_bytes, f"pad:{round_num}:{result}")
        round_num += 1
    return result[:length]


# ── Key assembly ──────────────────────────────────────────────────────────────

def generate_tsk_key(state: TSKClientState, now_ms: int | None = None) -> str:
    """Assemble the full TSK key from all segments + checksum.

    The key is the concatenation of all segment values in the order specified
    by state.segments, followed by a 10-char checksum derived from the key body.

    Args:
        state: TSKClientState with provisioned segments.
        now_ms: Current time in milliseconds (defaults to now).

    Returns:
        TSK key string (base64url chars only).
    """
    if now_ms is None:
        now_ms = int(time.time() * 1000)

    parts: list[str] = []
    for seg in state.segments:
        counter = state.hotp_counters.get(seg.segment_id, seg.counter)
        val = derive_segment_value(state._secret_bytes, seg, now_ms=now_ms, hotp_counter=counter)
        parts.append(val)

    key_body = "".join(parts)
    checksum = compute_checksum(state.shared_secret, key_body)
    return key_body + checksum


# TSK Protocol Constants (must match protocol-constants.ts)
# CHECKSUM_LENGTH: Python originally used 10 — TypeScript uses 12 (IL4 hardening).
# CHECKSUM_PREFIX: Python originally used "cksum:" — TypeScript uses "checksum:".
# Both mismatches were documented in protocol-constants.ts and caused KEY_LENGTH_MISMATCH
# and CHECKSUM_INVALID errors when the Python client talked to the TypeScript server.
CHECKSUM_LENGTH = 12
CHECKSUM_DERIVATION_PREFIX = "checksum"


def compute_checksum(shared_secret: str, key_body: str) -> str:
    """Compute 12-char checksum over the key body using the shared secret.

    PROTOCOL FIX: Changed from 10-char / \"cksum:\" to 12-char / \"checksum:\" to
    match the TypeScript server (protocol-constants.ts CHECKSUM_LENGTH=12,
    CHECKSUM_DERIVATION_PREFIX=\"checksum\"). The old values caused KEY_LENGTH_MISMATCH
    and CHECKSUM_INVALID on every cross-language verification.

    Used by server to reject malformed keys quickly (99.99% of forgeries caught
    with one HMAC operation before running full TSK segment verification).
    """
    validate_hex_secret(shared_secret)
    secret_bytes = bytes.fromhex(shared_secret)
    return _pad_or_truncate(
        secret_bytes,
        _hmac_raw(secret_bytes, f"{CHECKSUM_DERIVATION_PREFIX}:{key_body}"),
        CHECKSUM_LENGTH,
    )


def commit_hotp_counter(state: TSKClientState, segment_id: str) -> None:
    """Advance HOTP counter for a segment after successful verification.

    Implements the commit-after-success pattern: counter only increments when
    the server has confirmed acceptance, preventing counter drift on failures.
    """
    if segment_id in state.hotp_counters:
        state.hotp_counters[segment_id] += 1


# ── Provision payload parsing ─────────────────────────────────────────────────

def parse_provision_payload(
    client_id: str,
    shared_secret: str,
    provision_payload: dict[str, Any],
) -> TSKClientState:
    """Build TSKClientState from the server's provision response.

    Args:
        client_id: TSK client ID from server.
        shared_secret: 64-char hex secret from server.
        provision_payload: The provisionPayload dict from /provision-tsk response.
            Expected shape: { clientSegments: [{segmentId, type, length, windowSec?, counter?}] }

    Returns:
        Ready-to-use TSKClientState.
    """
    segments: list[SegmentConfig] = []
    for raw in provision_payload.get("clientSegments", []):
        # The server uses 'segmentLength' in provisionPayload.clientSegments
        # (not 'length') — this matches the TypeScript protocol-constants.ts spec.
        seg_len = raw.get("segmentLength") or raw.get("length")
        if seg_len is None:
            raise ValueError(
                f"parse_provision_payload: segment {raw.get('segmentId', '?')} "
                f"has no segmentLength or length field"
            )
        seg = SegmentConfig(
            segment_id=raw["segmentId"],
            type=raw["type"],
            seg_len=int(seg_len),
            window_sec=raw.get("windowSec", 60),
            counter=raw.get("initialCounter", raw.get("counter", 0)),
        )
        segments.append(seg)
    return TSKClientState(
        client_id=client_id,
        shared_secret=shared_secret,
        segments=segments,
    )
