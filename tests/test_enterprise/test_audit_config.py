"""tests/test_enterprise/test_audit_config.py — Unit tests for enterprise.audit_config."""
from __future__ import annotations

import pytest

from enterprise.audit_config import (
    AuditConfig,
    AuditMode,
    WormSinkType,
    _validate_bucket_name,
    _validate_prefix,
    load_audit_config,
)


# ---------------------------------------------------------------------------
# Enum value tests
# ---------------------------------------------------------------------------

class TestAuditModeEnum:
    def test_consumer_value(self):
        assert AuditMode.CONSUMER.value == "consumer"

    def test_enterprise_value(self):
        assert AuditMode.ENTERPRISE.value == "enterprise"

    def test_government_value(self):
        assert AuditMode.GOVERNMENT.value == "government"

    def test_is_str_subclass(self):
        assert isinstance(AuditMode.CONSUMER, str)


class TestWormSinkTypeEnum:
    def test_none_value(self):
        assert WormSinkType.NONE.value == "none"

    def test_memory_value(self):
        assert WormSinkType.MEMORY.value == "memory"

    def test_file_value(self):
        assert WormSinkType.FILE.value == "file"

    def test_s3_value(self):
        assert WormSinkType.S3.value == "s3"

    def test_r2_value(self):
        assert WormSinkType.R2.value == "r2"

    def test_is_str_subclass(self):
        assert isinstance(WormSinkType.MEMORY, str)


# ---------------------------------------------------------------------------
# AuditConfig defaults
# ---------------------------------------------------------------------------

class TestAuditConfigDefaults:
    def test_default_audit_mode(self):
        cfg = AuditConfig()
        assert cfg.audit_mode == AuditMode.CONSUMER

    def test_default_worm_sink(self):
        cfg = AuditConfig()
        assert cfg.worm_sink == WormSinkType.MEMORY

    def test_default_worm_prefix(self):
        cfg = AuditConfig()
        assert cfg.worm_prefix == "scent/audit/"

    def test_default_worm_region(self):
        cfg = AuditConfig()
        assert cfg.worm_region == "us-east-1"

    def test_default_worm_bucket_empty(self):
        cfg = AuditConfig()
        assert cfg.worm_bucket == ""

    def test_default_worm_file_dir_empty(self):
        cfg = AuditConfig()
        assert cfg.worm_file_dir == ""


# ---------------------------------------------------------------------------
# from_env() tests
# ---------------------------------------------------------------------------

class TestAuditConfigFromEnv:
    def test_reads_audit_mode_consumer(self, monkeypatch):
        monkeypatch.setenv("SCENT_AUDIT_MODE", "consumer")
        cfg = AuditConfig.from_env()
        assert cfg.audit_mode == AuditMode.CONSUMER

    def test_reads_audit_mode_enterprise(self, monkeypatch):
        monkeypatch.setenv("SCENT_AUDIT_MODE", "enterprise")
        cfg = AuditConfig.from_env()
        assert cfg.audit_mode == AuditMode.ENTERPRISE

    def test_reads_audit_mode_government(self, monkeypatch):
        monkeypatch.setenv("SCENT_AUDIT_MODE", "government")
        cfg = AuditConfig.from_env()
        assert cfg.audit_mode == AuditMode.GOVERNMENT

    def test_invalid_audit_mode_falls_back_to_consumer(self, monkeypatch):
        monkeypatch.setenv("SCENT_AUDIT_MODE", "supersecret")
        cfg = AuditConfig.from_env()
        assert cfg.audit_mode == AuditMode.CONSUMER

    def test_reads_worm_sink_none(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_SINK", "none")
        cfg = AuditConfig.from_env()
        assert cfg.worm_sink == WormSinkType.NONE

    def test_reads_worm_sink_file(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_SINK", "file")
        cfg = AuditConfig.from_env()
        assert cfg.worm_sink == WormSinkType.FILE

    def test_reads_worm_sink_s3(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_SINK", "s3")
        cfg = AuditConfig.from_env()
        assert cfg.worm_sink == WormSinkType.S3

    def test_reads_worm_sink_r2(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_SINK", "r2")
        cfg = AuditConfig.from_env()
        assert cfg.worm_sink == WormSinkType.R2

    def test_invalid_worm_sink_falls_back_to_memory(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_SINK", "floppy")
        cfg = AuditConfig.from_env()
        assert cfg.worm_sink == WormSinkType.MEMORY

    def test_reads_worm_bucket(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_BUCKET", "my-audit-bucket")
        cfg = AuditConfig.from_env()
        assert cfg.worm_bucket == "my-audit-bucket"

    def test_reads_worm_prefix(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_PREFIX", "custom/prefix/")
        cfg = AuditConfig.from_env()
        assert cfg.worm_prefix == "custom/prefix/"

    def test_reads_worm_region(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_REGION", "eu-west-1")
        cfg = AuditConfig.from_env()
        assert cfg.worm_region == "eu-west-1"

    def test_reads_worm_endpoint(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_ENDPOINT", "https://s3.example.com")
        cfg = AuditConfig.from_env()
        assert cfg.worm_endpoint == "https://s3.example.com"

    def test_reads_worm_file_dir(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_FILE_DIR", "/tmp/audit")
        cfg = AuditConfig.from_env()
        assert cfg.worm_file_dir == "/tmp/audit"

    def test_env_mode_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("SCENT_AUDIT_MODE", "ENTERPRISE")
        cfg = AuditConfig.from_env()
        assert cfg.audit_mode == AuditMode.ENTERPRISE

    def test_env_sink_is_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_SINK", "S3")
        cfg = AuditConfig.from_env()
        assert cfg.worm_sink == WormSinkType.S3

    def test_default_prefix_when_not_set(self, monkeypatch):
        monkeypatch.delenv("SCENT_WORM_PREFIX", raising=False)
        cfg = AuditConfig.from_env()
        assert cfg.worm_prefix == "scent/audit/"

    def test_default_region_when_not_set(self, monkeypatch):
        monkeypatch.delenv("SCENT_WORM_REGION", raising=False)
        cfg = AuditConfig.from_env()
        assert cfg.worm_region == "us-east-1"


# ---------------------------------------------------------------------------
# requires_worm() / fail_closed_without_worm()
# ---------------------------------------------------------------------------

class TestRequiresWorm:
    def test_consumer_does_not_require_worm(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER)
        assert cfg.requires_worm() is False

    def test_enterprise_requires_worm(self):
        cfg = AuditConfig(audit_mode=AuditMode.ENTERPRISE)
        assert cfg.requires_worm() is True

    def test_government_requires_worm(self):
        cfg = AuditConfig(audit_mode=AuditMode.GOVERNMENT)
        assert cfg.requires_worm() is True


class TestFailClosedWithoutWorm:
    def test_consumer_does_not_fail_closed(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER)
        assert cfg.fail_closed_without_worm() is False

    def test_enterprise_does_not_fail_closed(self):
        cfg = AuditConfig(audit_mode=AuditMode.ENTERPRISE)
        assert cfg.fail_closed_without_worm() is False

    def test_government_fails_closed(self):
        cfg = AuditConfig(audit_mode=AuditMode.GOVERNMENT)
        assert cfg.fail_closed_without_worm() is True


# ---------------------------------------------------------------------------
# describe()
# ---------------------------------------------------------------------------

class TestDescribe:
    def test_describe_includes_mode_and_sink(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.MEMORY)
        desc = cfg.describe()
        assert "mode=consumer" in desc
        assert "sink=memory" in desc

    def test_describe_includes_bucket_when_set(self):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.S3,
            worm_bucket="my-bucket",
        )
        desc = cfg.describe()
        assert "bucket=my-bucket" in desc

    def test_describe_excludes_bucket_when_empty(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.NONE)
        desc = cfg.describe()
        assert "bucket=" not in desc

    def test_describe_includes_dir_when_set(self):
        cfg = AuditConfig(
            audit_mode=AuditMode.ENTERPRISE,
            worm_sink=WormSinkType.FILE,
            worm_file_dir="/var/audit",
        )
        desc = cfg.describe()
        assert "dir=/var/audit" in desc

    def test_describe_excludes_dir_when_empty(self):
        cfg = AuditConfig(audit_mode=AuditMode.CONSUMER, worm_sink=WormSinkType.NONE)
        desc = cfg.describe()
        assert "dir=" not in desc

    def test_describe_returns_string(self):
        cfg = AuditConfig()
        assert isinstance(cfg.describe(), str)


# ---------------------------------------------------------------------------
# load_audit_config() convenience function
# ---------------------------------------------------------------------------

class TestLoadAuditConfig:
    def test_returns_audit_config_instance(self, monkeypatch):
        monkeypatch.delenv("SCENT_AUDIT_MODE", raising=False)
        cfg = load_audit_config()
        assert isinstance(cfg, AuditConfig)

    def test_reflects_env(self, monkeypatch):
        monkeypatch.setenv("SCENT_AUDIT_MODE", "government")
        monkeypatch.setenv("SCENT_WORM_SINK", "file")
        cfg = load_audit_config()
        assert cfg.audit_mode == AuditMode.GOVERNMENT
        assert cfg.worm_sink == WormSinkType.FILE


# ---------------------------------------------------------------------------
# WRAITH security regression tests — bucket name / prefix injection (HIGH)
# ---------------------------------------------------------------------------

class TestValidateBucketName:
    """Regression tests for SCENT_WORM_BUCKET injection prevention."""

    def test_valid_bucket_accepted(self):
        assert _validate_bucket_name("my-audit-bucket", "SCENT_WORM_BUCKET") == "my-audit-bucket"

    def test_empty_bucket_accepted(self):
        assert _validate_bucket_name("", "SCENT_WORM_BUCKET") == ""

    def test_bucket_with_dots_accepted(self):
        assert _validate_bucket_name("my.audit.bucket", "SCENT_WORM_BUCKET") == "my.audit.bucket"

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError, match="SCENT_WORM_BUCKET"):
            _validate_bucket_name("../../../etc/passwd", "SCENT_WORM_BUCKET")

    def test_newline_injection_rejected(self):
        with pytest.raises(ValueError, match="SCENT_WORM_BUCKET"):
            _validate_bucket_name("bucket\nHost: attacker.com", "SCENT_WORM_BUCKET")

    def test_uppercase_rejected(self):
        # S3 bucket names must be lowercase; uppercase would allow reaching a
        # differently-named bucket on case-insensitive file systems.
        with pytest.raises(ValueError, match="SCENT_WORM_BUCKET"):
            _validate_bucket_name("MY-BUCKET", "SCENT_WORM_BUCKET")

    def test_ip_address_style_rejected(self):
        with pytest.raises(ValueError, match="IP address"):
            _validate_bucket_name("192.168.1.1", "SCENT_WORM_BUCKET")

    def test_too_short_rejected(self):
        with pytest.raises(ValueError, match="SCENT_WORM_BUCKET"):
            _validate_bucket_name("ab", "SCENT_WORM_BUCKET")

    def test_too_long_rejected(self):
        with pytest.raises(ValueError, match="SCENT_WORM_BUCKET"):
            _validate_bucket_name("a" * 64, "SCENT_WORM_BUCKET")

    def test_invalid_bucket_from_env_falls_back_to_empty(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_BUCKET", "../../../evil")
        cfg = AuditConfig.from_env()
        assert cfg.worm_bucket == ""

    def test_valid_bucket_from_env_is_accepted(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_BUCKET", "valid-bucket-99")
        cfg = AuditConfig.from_env()
        assert cfg.worm_bucket == "valid-bucket-99"


class TestValidatePrefix:
    """Regression tests for SCENT_WORM_PREFIX injection prevention."""

    def test_valid_prefix_accepted(self):
        assert _validate_prefix("scent/audit/", "SCENT_WORM_PREFIX") == "scent/audit/"

    def test_empty_prefix_accepted(self):
        assert _validate_prefix("", "SCENT_WORM_PREFIX") == ""

    def test_leading_slash_rejected(self):
        with pytest.raises(ValueError, match="must not start with"):
            _validate_prefix("/absolute/path/", "SCENT_WORM_PREFIX")

    def test_traversal_segment_rejected(self):
        with pytest.raises(ValueError, match="path traversal"):
            _validate_prefix("audit/../../../etc/", "SCENT_WORM_PREFIX")

    def test_non_printable_rejected(self):
        with pytest.raises(ValueError, match="non-printable"):
            _validate_prefix("audit/\x00evil/", "SCENT_WORM_PREFIX")

    def test_invalid_prefix_from_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_PREFIX", "/absolute/path/")
        cfg = AuditConfig.from_env()
        assert cfg.worm_prefix == "scent/audit/"

    def test_valid_prefix_from_env_is_accepted(self, monkeypatch):
        monkeypatch.setenv("SCENT_WORM_PREFIX", "custom/prefix/")
        cfg = AuditConfig.from_env()
        assert cfg.worm_prefix == "custom/prefix/"
