"""enterprise/tsk_client.py — TSK Client (Python port)

Python port of the TSK (Tumbler-Style Rotating Segment Keys) client-side
operations for the latency-sensitive per-injection path.

Implements:
  - Segment value derivation (static, totp, hotp) via HMAC-SHA-256
  - Key assembly from provision payload + tumbler map
  - Checksum computation and verification
  - TSK request headers construction

The provision payload received from the Ultra Server contains:
  clientId, segmentIds, segmentTypes, windowSecs, keyLength
  (positions and lengths are NOT in the payload — structural secrecy property)

The server holds the full TumblerMap including positions.  The client sends
assembled segment values in segmentId order; the server places them at the
correct positions using its stored map.

TSK Spec §3.2 segment types:
  static  — HMAC(secret, "static:<segmentId>")
  totp    — HMAC(secret, "totp:<segmentId>:<T>")  T = floor(unixMs/1000 / windowSec)
  hotp    — HMAC(secret, "hotp:<segmentId>:<counter>")

TSK Spec §3.3 checksum:
  HMAC(sharedSecret, "checksum:" + key[0..keyLength-8])[0..7]

Version: 1.0.0  Tier 1
"""
from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as _CryptoHMAC


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    h = _CryptoHMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


def _hmac_sha256_b64url(key: bytes, message: bytes) -> str:
    return _b64url_encode(_hmac_sha256(key, message))


def _fill_to_length(key: bytes, secret: bytes, segment_id: str, target_len: int) -> str:
    """Fill segment value to target_len chars via repeated HMAC rounds if needed.

    Base value is HMAC output (43 base64url chars).  If target_len > 43,
    additional rounds are appended.  Output is truncated to target_len.
    """
    value = _hmac_sha256_b64url(secret, segment_id.encode())
    while len(value) < target_len:
        value += _hmac_sha256_b64url(secret, (segment_id + ":" + str(len(value))).encode())
    return value[:target_len]


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class SegmentConfig:
    """Client-side segment configuration (no position — structural secrecy)."""
    segment_id: str
    segment_type: str       # "static" | "totp" | "hotp"
    window_sec: int = 30    # TOTP window in seconds (ignored for static/hotp)
    length: int = 8         # Segment character length (received from server at provision)


@dataclass
class TSKProvisionPayload:
    """Provision payload received from Ultra Server.

    Contains what the client needs to generate keys.
    Does NOT contain positions (structural secrecy property).
    """
    client_id: str
    shared_secret: str          # 256-bit hex string
    key_length: int             # Total key length in characters
    segments: List[SegmentConfig]
    checksum_length: int = 8    # Last N chars are checksum


@dataclass
class TSKHeaders:
    """TSK HTTP headers (TSK Spec §7)."""
    client_id: str      # X-TSK-Client-ID
    key: str            # X-TSK-Key
    version: str = "1"  # X-TSK-Version

    def as_dict(self) -> dict:
        return {
            "X-TSK-Client-ID": self.client_id,
            "X-TSK-Key":       self.key,
            "X-TSK-Version":   self.version,
        }


# ── TSK Client ────────────────────────────────────────────────────────────────

class TSKClient:
    """Stateful TSK client for a single provisioned identity.

    Thread-safe: HOTP counter increments are protected by a lock.
    """

    def __init__(self, provision: TSKProvisionPayload) -> None:
        self._provision = provision
        self._secret = bytes.fromhex(provision.shared_secret)
        self._hotp_counters: Dict[str, int] = {
            seg.segment_id: 0
            for seg in provision.segments
            if seg.segment_type == "hotp"
        }
        self._lock = Lock()

    @property
    def client_id(self) -> str:
        return self._provision.client_id

    # ── Segment derivation ────────────────────────────────────────────────────

    def _derive_static(self, seg: SegmentConfig) -> str:
        """TSK Spec §3.2: HMAC(secret, "static:<segmentId>")"""
        msg = f"static:{seg.segment_id}"
        return _fill_to_length(self._secret, self._secret, msg, seg.length)

    def _derive_totp(self, seg: SegmentConfig, t_override: Optional[int] = None) -> str:
        """TSK Spec §3.2: HMAC(secret, "totp:<segmentId>:<T>")"""
        t = t_override if t_override is not None else int(time.time() / seg.window_sec)
        msg = f"totp:{seg.segment_id}:{t}"
        return _fill_to_length(self._secret, self._secret, msg, seg.length)

    def _derive_hotp(self, seg: SegmentConfig) -> str:
        """TSK Spec §3.2: HMAC(secret, "hotp:<segmentId>:<counter>")"""
        with self._lock:
            counter = self._hotp_counters[seg.segment_id]
            self._hotp_counters[seg.segment_id] = counter + 1
        msg = f"hotp:{seg.segment_id}:{counter}"
        return _fill_to_length(self._secret, self._secret, msg, seg.length)

    def _derive_segment(self, seg: SegmentConfig) -> str:
        if seg.segment_type == "static":
            return self._derive_static(seg)
        elif seg.segment_type == "totp":
            return self._derive_totp(seg)
        elif seg.segment_type == "hotp":
            return self._derive_hotp(seg)
        else:
            raise ValueError(f"Unknown segment type: {seg.segment_type!r}")

    # ── Key assembly ──────────────────────────────────────────────────────────

    def _compute_checksum(self, key_without_checksum: str) -> str:
        """TSK Spec §3.3: HMAC(sharedSecret, "checksum:" + key[0..keyLength-8])[0..7]"""
        msg = f"checksum:{key_without_checksum}"
        raw = _hmac_sha256(self._secret, msg.encode())
        return _b64url_encode(raw)[:self._provision.checksum_length]

    def assemble_key(self) -> str:
        """Assemble the full TSK key string.

        TSK Spec §5: concatenate segment values in segmentId order, then append checksum.
        The server uses its stored TumblerMap to place segments at the correct positions.
        The client sends values in segmentId order — the server handles positioning.
        """
        segments_in_order = sorted(self._provision.segments, key=lambda s: s.segment_id)
        values = [self._derive_segment(seg) for seg in segments_in_order]
        key_without_checksum = "".join(values)
        checksum = self._compute_checksum(key_without_checksum)
        return key_without_checksum + checksum

    def build_headers(self) -> TSKHeaders:
        """Build TSK headers for a request."""
        return TSKHeaders(
            client_id=self.client_id,
            key=self.assemble_key(),
        )

    # ── Local checksum verification ───────────────────────────────────────────

    def verify_checksum(self, key: str) -> bool:
        """Verify the checksum of an assembled key (fast tamper detection)."""
        cs_len = self._provision.checksum_length
        key_body = key[:-cs_len]
        expected_cs = self._compute_checksum(key_body)
        actual_cs = key[-cs_len:]
        # Constant-time comparison
        import hmac as _hmac_std
        return _hmac_std.compare_digest(expected_cs.encode(), actual_cs.encode())

    # ── TOTP window verification (for local fast-path) ────────────────────────

    def verify_totp_segment(
        self,
        seg: SegmentConfig,
        received_value: str,
        tolerance: int = 1,
    ) -> bool:
        """Verify a TOTP segment allowing ±tolerance windows (clock drift tolerance)."""
        t_now = int(time.time() / seg.window_sec)
        for t in range(t_now - tolerance, t_now + tolerance + 1):
            expected = self._derive_totp(seg, t_override=t)
            import hmac as _hmac_std
            if _hmac_std.compare_digest(expected.encode(), received_value.encode()):
                return True
        return False


# ── Factory ───────────────────────────────────────────────────────────────────

def tsk_client_from_server_response(response: dict) -> TSKClient:
    """Build a TSKClient from the Ultra Server's /provision-tsk response dict.

    Expected response shape:
    {
      "clientId": "...",
      "sharedSecret": "<64-char hex>",
      "keyLength": 52,
      "segments": [
        {"segmentId": "s0", "type": "static", "windowSec": 0, "length": 8},
        {"segmentId": "s1", "type": "totp",   "windowSec": 30, "length": 8},
        ...
      ],
      "checksumLength": 8
    }
    """
    segments = [
        SegmentConfig(
            segment_id=s["segmentId"],
            segment_type=s["type"],
            window_sec=s.get("windowSec", 30),
            length=s.get("length", 8),
        )
        for s in response["segments"]
    ]
    provision = TSKProvisionPayload(
        client_id=response["clientId"],
        shared_secret=response["sharedSecret"],
        key_length=response["keyLength"],
        segments=segments,
        checksum_length=response.get("checksumLength", 8),
    )
    return TSKClient(provision)
