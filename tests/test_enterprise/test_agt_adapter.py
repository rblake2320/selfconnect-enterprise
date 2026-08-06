from __future__ import annotations

from dataclasses import dataclass

import pytest

from enterprise.agt_adapter import AGTCedarAdapter, AGTConfigurationError


@dataclass
class _Result:
    value: object


class FakeAgentControl:
    def __init__(self, *, decision: str = "allow", transform: dict | None = None) -> None:
        self.decision = decision
        self.transform = transform
        self.calls = []

    async def run_tool(self, tool_name, args, execute, **kwargs):
        self.calls.append((tool_name, args, kwargs))
        if self.decision == "deny":
            raise RuntimeError("cedar denied pre_tool_call")
        effective = self.transform if self.transform is not None else args
        return _Result(execute(effective))


def test_adapter_delegates_enforcement_and_execution_to_agent_control():
    control = FakeAgentControl(transform={"value": "redacted"})
    adapter = AGTCedarAdapter(control)
    executed = []

    result = adapter.run_tool_sync(
        "sc_example",
        {"value": "secret"},
        lambda args: executed.append(args) or {"seen": args["value"]},
        snapshot={"agent_id": "SC-ONE"},
    )

    assert result.value == {"seen": "redacted"}
    assert result.effective_arguments == {"value": "redacted"}
    assert executed == [{"value": "redacted"}]
    assert control.calls == [
        (
            "sc_example",
            {"value": "secret"},
            {"tool_call_id": None, "snapshot": {"agent_id": "SC-ONE"}, "mode": "enforce"},
        )
    ]


def test_adapter_does_not_execute_when_agent_control_denies():
    adapter = AGTCedarAdapter(FakeAgentControl(decision="deny"))
    executed = []

    with pytest.raises(RuntimeError, match="cedar denied"):
        adapter.run_tool_sync("sc_example", {}, lambda args: executed.append(args) or {})

    assert executed == []


def test_adapter_rejects_non_object_tool_result():
    adapter = AGTCedarAdapter(FakeAgentControl())
    with pytest.raises(RuntimeError, match="non-object"):
        adapter.run_tool_sync("sc_example", {}, lambda _args: "text")


def test_adapter_requires_agent_control_contract():
    with pytest.raises(AGTConfigurationError, match="run_tool"):
        AGTCedarAdapter(object())


def test_missing_manifest_fails_before_optional_import(tmp_path):
    with pytest.raises(AGTConfigurationError, match="manifest not found"):
        AGTCedarAdapter.from_manifest(tmp_path / "missing.yaml")
