from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from enterprise.ultra_gate import UltraGate


def _bootstrap_module():
    path = Path(__file__).parents[1] / "bootstrap_mesh.py"
    spec = importlib.util.spec_from_file_location("selfconnect_bootstrap_mesh", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_plaintext_migration_verifies_before_delete(tmp_path, monkeypatch):
    module = _bootstrap_module()
    secret = "a-strong-mesh-secret-with-at-least-32-bytes"
    legacy = tmp_path / "mesh.key"
    legacy.write_text(secret, encoding="utf-8")
    store = {}
    monkeypatch.setattr(module, "_appdata_sc", lambda: tmp_path)
    monkeypatch.setattr(module, "write_credential", lambda target, value: store.__setitem__(target, value))
    monkeypatch.setattr(module, "read_credential", lambda target: store.get(target))
    result = module.migrate_legacy_mesh_secret()
    assert result["migrated"] is True
    assert not legacy.exists()
    assert store[module.MESH_SECRET_TARGET] == secret


def test_failed_credential_readback_preserves_plaintext(tmp_path, monkeypatch):
    module = _bootstrap_module()
    legacy = tmp_path / "mesh.key"
    legacy.write_text("a-strong-mesh-secret-with-at-least-32-bytes", encoding="utf-8")
    monkeypatch.setattr(module, "_appdata_sc", lambda: tmp_path)
    monkeypatch.setattr(module, "write_credential", lambda _target, _value: None)
    monkeypatch.setattr(module, "read_credential", lambda _target: None)
    try:
        module.migrate_legacy_mesh_secret()
    except RuntimeError:
        pass
    else:
        raise AssertionError("migration must fail closed")
    assert legacy.exists()


def test_stale_legacy_secret_cannot_overwrite_rotated_credential(tmp_path, monkeypatch):
    module = _bootstrap_module()
    legacy_secret = "legacy-mesh-secret-with-at-least-32-bytes"
    rotated_secret = "rotated-mesh-secret-with-at-least-32-bytes"
    legacy = tmp_path / "mesh.key"
    legacy.write_text(legacy_secret, encoding="utf-8")
    store = {module.MESH_SECRET_TARGET: rotated_secret}
    writes = []
    monkeypatch.setattr(module, "_appdata_sc", lambda: tmp_path)
    monkeypatch.setattr(module, "write_credential", lambda target, value: writes.append((target, value)))
    monkeypatch.setattr(module, "read_credential", lambda target: store.get(target))

    with pytest.raises(RuntimeError, match="conflicts with the rotated"):
        module.migrate_legacy_mesh_secret()

    assert legacy.exists()
    assert writes == []
    assert store[module.MESH_SECRET_TARGET] == rotated_secret


def test_matching_vault_value_allows_legacy_cleanup_without_rewrite(tmp_path, monkeypatch):
    module = _bootstrap_module()
    secret = "matching-mesh-secret-with-at-least-32-bytes"
    legacy = tmp_path / "mesh.key"
    legacy.write_text(secret, encoding="utf-8")
    monkeypatch.setattr(module, "_appdata_sc", lambda: tmp_path)
    monkeypatch.setattr(module, "read_credential", lambda _target: secret)
    monkeypatch.setattr(
        module,
        "write_credential",
        lambda _target, _value: (_ for _ in ()).throw(AssertionError("must not rewrite vault")),
    )

    result = module.migrate_legacy_mesh_secret()

    assert result["migrated"] is True
    assert not legacy.exists()


def test_credential_unavailable_does_not_resurrect_default(monkeypatch):
    monkeypatch.delenv("SELFCONNECT_ALLOW_INSECURE_DEV_SECRET", raising=False)
    monkeypatch.setattr(
        "enterprise.windows_credentials.read_credential",
        lambda _target: None,
    )
    with pytest.raises(RuntimeError, match="not provisioned"):
        UltraGate._load_mesh_secret()


def test_malformed_legacy_dpapi_is_preserved(tmp_path, monkeypatch):
    module = _bootstrap_module()
    legacy = tmp_path / "mesh.key.dpapi"
    legacy.write_bytes(b"malformed")
    monkeypatch.setattr(module, "_appdata_sc", lambda: tmp_path)
    monkeypatch.setattr(module, "_dpapi_decrypt", lambda _value: (_ for _ in ()).throw(OSError("bad blob")))
    with pytest.raises(OSError, match="bad blob"):
        module.migrate_legacy_mesh_secret()
    assert legacy.exists()
