"""enterprise/audit_config.py — Runtime audit / WORM replication configuration.

Reads from environment variables so service, CLI, and test all share the same config path.
"""
from __future__ import annotations

import logging
import os
import re
from enum import Enum

logger = logging.getLogger(__name__)

# S3/R2 bucket names: 3–63 chars, lowercase alphanumeric, hyphens, dots.
# Dots are allowed by S3 spec but discouraged (virtual-hosted-style SSL issues).
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]$")

# Prefix: printable ASCII only; no leading slash; no path-traversal components.
_PREFIX_RE = re.compile(r"^[\x20-\x7E]*$")


def _validate_bucket_name(raw: str, env_var: str) -> str:
    """Validate an S3/R2 bucket name from an env var.

    Raises ValueError with a descriptive message if the name is invalid.
    Returns the name unchanged if valid or empty (empty means not configured).
    """
    if not raw:
        return raw
    # Reject control characters and whitespace (newline injection / SSRF header
    # injection when bucket name is interpolated into an HTTP request).
    if not _BUCKET_NAME_RE.match(raw):
        raise ValueError(
            f"{env_var}={raw!r} is not a valid bucket name. "
            "Expected 3-63 lowercase alphanumeric/hyphen/dot characters, "
            "starting and ending with alphanumeric."
        )
    # Reject IP-address-style names (e.g. 192.168.1.1) — these bypass
    # virtual-hosted-style routing and may reach unintended endpoints.
    _parts = raw.split(".")
    if all(p.isdigit() for p in _parts) and len(_parts) == 4:
        raise ValueError(
            f"{env_var}={raw!r} looks like an IP address and is not a valid bucket name."
        )
    return raw


def _validate_prefix(raw: str, env_var: str) -> str:
    """Validate a WORM key prefix.

    Rejects path-traversal (``..``), non-printable characters, and leading
    slashes (which would create double-slash keys like ``//audit/``).
    Returns the value unchanged if valid.
    """
    if not raw:
        return raw
    if not _PREFIX_RE.match(raw):
        raise ValueError(
            f"{env_var}={raw!r} contains non-printable or non-ASCII characters."
        )
    if raw.startswith("/"):
        raise ValueError(
            f"{env_var}={raw!r} must not start with '/'. Use a relative prefix."
        )
    if ".." in raw.split("/"):
        raise ValueError(
            f"{env_var}={raw!r} contains '..' path traversal component."
        )
    return raw


class AuditMode(str, Enum):
    CONSUMER = "consumer"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"


class WormSinkType(str, Enum):
    NONE = "none"
    MEMORY = "memory"
    FILE = "file"
    S3 = "s3"
    R2 = "r2"


def load_audit_config() -> "AuditConfig":
    return AuditConfig.from_env()


class AuditConfig:
    def __init__(
        self,
        audit_mode: AuditMode = AuditMode.CONSUMER,
        worm_sink: WormSinkType = WormSinkType.MEMORY,
        worm_bucket: str = "",
        worm_prefix: str = "scent/audit/",
        worm_region: str = "us-east-1",
        worm_endpoint: str = "",
        worm_file_dir: str = "",
        worm_min_retention_days: int = 365,
        r2_account_id: str = "",
        r2_api_token: str = "",
        r2_jurisdiction: str = "default",
    ) -> None:
        self.audit_mode = audit_mode
        self.worm_sink = worm_sink
        self.worm_bucket = worm_bucket
        self.worm_prefix = worm_prefix
        self.worm_region = worm_region
        self.worm_endpoint = worm_endpoint
        self.worm_file_dir = worm_file_dir
        self.worm_min_retention_days = worm_min_retention_days
        self.r2_account_id = r2_account_id
        self.r2_api_token = r2_api_token
        self.r2_jurisdiction = r2_jurisdiction

    @classmethod
    def from_env(cls) -> "AuditConfig":
        raw_mode = os.environ.get("SCENT_AUDIT_MODE", "consumer").lower()
        try:
            audit_mode = AuditMode(raw_mode)
        except ValueError:
            audit_mode = AuditMode.CONSUMER
        raw_sink = os.environ.get("SCENT_WORM_SINK", "memory").lower()
        try:
            worm_sink = WormSinkType(raw_sink)
        except ValueError:
            worm_sink = WormSinkType.MEMORY
        # Validate bucket name — reject path traversal / injection attempts.
        raw_bucket = os.environ.get("SCENT_WORM_BUCKET", "")
        try:
            worm_bucket = _validate_bucket_name(raw_bucket, "SCENT_WORM_BUCKET")
        except ValueError as exc:
            logger.error("SCENT_WORM_BUCKET rejected: %s; treating as unset.", exc)
            worm_bucket = ""

        # Validate prefix — reject traversal and non-printable characters.
        raw_prefix = os.environ.get("SCENT_WORM_PREFIX", "scent/audit/")
        try:
            worm_prefix = _validate_prefix(raw_prefix, "SCENT_WORM_PREFIX")
        except ValueError as exc:
            logger.error(
                "SCENT_WORM_PREFIX rejected: %s; falling back to default 'scent/audit/'.", exc
            )
            worm_prefix = "scent/audit/"

        raw_retention = os.environ.get("SCENT_WORM_MIN_RETENTION_DAYS", "365")
        try:
            minimum_retention_days = int(raw_retention)
            if not 1 <= minimum_retention_days <= 36_500:
                raise ValueError
        except ValueError:
            logger.error(
                "SCENT_WORM_MIN_RETENTION_DAYS=%r rejected; using 365.",
                raw_retention,
            )
            minimum_retention_days = 365

        jurisdiction = os.environ.get("SCENT_R2_JURISDICTION", "default").lower()
        if jurisdiction not in {"default", "eu", "fedramp"}:
            logger.error(
                "SCENT_R2_JURISDICTION=%r rejected; using default.",
                jurisdiction,
            )
            jurisdiction = "default"

        return cls(
            audit_mode=audit_mode,
            worm_sink=worm_sink,
            worm_bucket=worm_bucket,
            worm_prefix=worm_prefix,
            worm_region=os.environ.get("SCENT_WORM_REGION", "us-east-1"),
            worm_endpoint=os.environ.get("SCENT_WORM_ENDPOINT", ""),
            worm_file_dir=os.environ.get("SCENT_WORM_FILE_DIR", ""),
            worm_min_retention_days=minimum_retention_days,
            r2_account_id=os.environ.get("SCENT_R2_ACCOUNT_ID", ""),
            r2_api_token=os.environ.get("SCENT_R2_API_TOKEN", ""),
            r2_jurisdiction=jurisdiction,
        )

    def requires_worm(self) -> bool:
        return self.audit_mode in (AuditMode.ENTERPRISE, AuditMode.GOVERNMENT)

    def fail_closed_without_worm(self) -> bool:
        return self.audit_mode == AuditMode.GOVERNMENT

    def describe(self) -> str:
        parts = [f"mode={self.audit_mode.value}", f"sink={self.worm_sink.value}"]
        if self.worm_bucket:
            parts.append(f"bucket={self.worm_bucket}")
        if self.worm_file_dir:
            parts.append(f"dir={self.worm_file_dir}")
        parts.append(f"minimum_retention_days={self.worm_min_retention_days}")
        return " ".join(parts)
