"""Tests for the fail-closed ACP registry readiness gate."""
from __future__ import annotations

import json

from tools.acp_registry_readiness import main, readiness_issues


def _metadata():
    return {
        "id": "selfconnect-governed",
        "name": "SelfConnect Governed ACP",
        "version": "1.2.3",
        "description": "Governed ACP action adapter",
        "distribution": {"uvx": {"package": "selfconnect-enterprise==1.2.3"}},
    }


def test_readiness_requires_published_distribution_and_acceptance(tmp_path):
    issues = readiness_issues(
        {key: value for key, value in _metadata().items() if key != "distribution"},
        icon_path=tmp_path / "missing.svg",
        terminal_auth_verified=False,
    )
    assert "missing published distribution" in issues
    assert "missing local icon.svg" in issues
    assert "terminal authentication has no recorded client acceptance" in issues


def test_readiness_accepts_complete_candidate_inputs(tmp_path):
    icon = tmp_path / "icon.svg"
    icon.write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    assert readiness_issues(_metadata(), icon_path=icon, terminal_auth_verified=True) == []


def test_cli_reports_hold_without_claiming_publication(tmp_path, capsys):
    metadata = tmp_path / "agent.json"
    metadata.write_text(json.dumps({"id": "selfconnect-governed"}), encoding="utf-8")
    assert main([str(metadata)]) == 1
    output = capsys.readouterr().out
    assert output.startswith("HOLD:")
    assert "missing published distribution" in output
