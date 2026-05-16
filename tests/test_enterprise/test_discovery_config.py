"""Tests for enterprise/discovery_config.py — Tier 1 identity hardening."""
import os
import importlib


def test_defaults():
    """Default values match the spec: cap=32, timeout=500ms."""
    import enterprise.discovery_config as dc
    assert dc.MAX_CANDIDATES_PER_CYCLE == int(os.environ.get("SC_DISCOVERY_CAP", "32"))
    assert dc.HANDSHAKE_TIMEOUT_MS == int(os.environ.get("SC_HANDSHAKE_TIMEOUT_MS", "500"))
    assert dc.MAX_STAMPS_PER_PID == int(os.environ.get("SC_MAX_STAMPS_PER_PID", "4"))
    assert dc.HANDSHAKE_BACKOFF_SEC == int(os.environ.get("SC_HANDSHAKE_BACKOFF_SEC", "60"))


def test_env_override(monkeypatch):
    """SC_DISCOVERY_CAP env var overrides the cap."""
    monkeypatch.setenv("SC_DISCOVERY_CAP", "16")
    import enterprise.discovery_config as dc
    importlib.reload(dc)
    assert dc.MAX_CANDIDATES_PER_CYCLE == 16
    # restore
    importlib.reload(dc)


def test_default_cap_is_32(monkeypatch):
    """Without env override, cap is exactly 32 — not unlimited."""
    monkeypatch.delenv("SC_DISCOVERY_CAP", raising=False)
    import enterprise.discovery_config as dc
    importlib.reload(dc)
    assert dc.MAX_CANDIDATES_PER_CYCLE == 32
    importlib.reload(dc)
