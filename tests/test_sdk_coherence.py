from __future__ import annotations

import json
from pathlib import Path

from tools.sdk_coherence import LEGACY_SDK_SHA, check


SHA = "a" * 40


def _root(tmp_path: Path, *, pin: str = SHA, gitlink: str = SHA, ci_extra: str = "") -> Path:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\ndependencies=["selfconnect @ git+https://github.com/rblake2320/selfconnect.git@{pin}"]\n', encoding="utf-8"
    )
    (tmp_path / "portfolio-lock.json").write_text(json.dumps({"components": {"selfconnect": {"commit": pin}}}), encoding="utf-8")
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "git submodule update --init --recursive\npython -m tools.sdk_coherence\n" + ci_extra, encoding="utf-8"
    )
    # A temporary repository gives the verifier a real gitlink to inspect.
    import subprocess
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "coherence@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Coherence"], cwd=tmp_path, check=True)
    subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"160000,{gitlink},sdk"], cwd=tmp_path, check=True)
    return tmp_path


def test_matching_selectors_pass_when_reviewed_sha_is_supplied(tmp_path: Path) -> None:
    report = check(root=_root(tmp_path), required_core_sha=SHA)
    assert report["overall"] == "PASS"


def test_legacy_or_divergent_sdk_is_a_release_hold(tmp_path: Path) -> None:
    report = check(root=_root(tmp_path, gitlink=LEGACY_SDK_SHA), required_core_sha=SHA)
    assert report["overall"] == "HOLD"
    assert any("selectors disagree" in error for error in report["errors"])


def test_missing_ci_submodule_initialization_is_a_release_hold(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / ".github" / "workflows" / "ci.yml").write_text("python -m tools.sdk_coherence\n", encoding="utf-8")
    report = check(root=root, required_core_sha=SHA)
    assert report["overall"] == "HOLD"
    assert any("initialize" in error for error in report["errors"])
