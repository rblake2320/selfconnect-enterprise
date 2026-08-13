"""CLI contract tests for the scent-acp entry point."""
from __future__ import annotations

import sys
import types
from unittest.mock import patch

import pytest

from enterprise.acp_auth import ACPTrustStore
from enterprise.acp_entry import load_shim_factory, main, run_setup
from enterprise.acp_shim import ACPShim
from enterprise.identity import AgentIdentity


def _identity(tmp_path, name: str) -> AgentIdentity:
    with (
        patch("enterprise.identity._dpapi_encrypt", side_effect=lambda value: b"ENC:" + value),
        patch("enterprise.identity._dpapi_decrypt", side_effect=lambda value: value[4:]),
    ):
        return AgentIdentity.init(name, data_dir=tmp_path)


def test_run_setup_enrolls_loaded_owner_identity(tmp_path):
    owner = _identity(tmp_path, "entry-owner")
    trust_path = tmp_path / "entry-trust.sqlite3"
    with patch("enterprise.acp_entry.AgentIdentity.load", return_value=owner):
        fingerprint = run_setup(
            trust_store_path=trust_path,
            identity_name="entry-owner",
            identity_dir=tmp_path,
            principal="OWNER:RON",
            confirm=lambda _prompt: True,
            now=1_000.0,
        )
    store = ACPTrustStore(trust_path)
    assert store.resolve_key(fingerprint) == owner.public_key_bytes
    store.close()


def test_main_setup_requires_explicit_configuration(capsys):
    assert main(["--setup"]) == 2
    assert "--trust-store" in capsys.readouterr().err


def test_main_serve_requires_deployment_factory(capsys):
    assert main([]) == 2
    assert "requires --factory" in capsys.readouterr().err


def test_factory_reference_rejects_code_like_input():
    with pytest.raises(ValueError, match="dotted module:function"):
        load_shim_factory("os:system('whoami')")


def test_factory_must_return_exact_shim_type():
    module = types.ModuleType("test_acp_bad_factory")
    module.build = lambda: object()
    sys.modules[module.__name__] = module
    try:
        with pytest.raises(TypeError, match="exact ACPShim"):
            load_shim_factory("test_acp_bad_factory:build")
    finally:
        sys.modules.pop(module.__name__, None)


def test_factory_accepts_exact_shim_type_without_calling_transport():
    module = types.ModuleType("test_acp_good_factory")
    shim = object.__new__(ACPShim)
    module.build = lambda: shim
    sys.modules[module.__name__] = module
    try:
        assert load_shim_factory("test_acp_good_factory:build") is shim
    finally:
        sys.modules.pop(module.__name__, None)
