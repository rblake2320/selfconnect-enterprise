"""Microsoft Agent Governance Toolkit (AGT) policy adapter.

Policy semantics stay in AGT's Agent Control Specification runtime.  This
module only maps a synchronous SelfConnect tool dispatch into AGT's async
``run_tool`` enforcement wrapper; it does not parse or reimplement Cedar.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class AGTConfigurationError(RuntimeError):
    """AGT cannot be loaded with the requested fail-closed posture."""


class AgentControlProtocol(Protocol):
    async def run_tool(
        self,
        tool_name: str,
        args: Any,
        execute: Callable[[Any], Any | Awaitable[Any]],
        *,
        tool_call_id: str | None = None,
        snapshot: Mapping[str, Any] | None = None,
        mode: str = "enforce",
    ) -> Any: ...


@dataclass(frozen=True)
class AGTToolOutcome:
    """The AGT-protected value and arguments that actually reached the tool."""

    value: dict[str, Any]
    effective_arguments: dict[str, Any]


class AGTCedarAdapter:
    """Delegate tool policy enforcement to AGT/ACS in ``enforce`` mode."""

    def __init__(self, control: AgentControlProtocol) -> None:
        if not callable(getattr(control, "run_tool", None)):
            raise AGTConfigurationError("AGT control must provide run_tool()")
        self._control = control

    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> "AGTCedarAdapter":
        """Load an ACS manifest using the optional official AGT SDK."""
        path = Path(manifest_path).expanduser().resolve()
        if not path.is_file():
            raise AGTConfigurationError(f"AGT manifest not found: {path}")
        try:
            from agent_control_specification import AgentControl
        except (ImportError, OSError) as exc:
            raise AGTConfigurationError(
                "AGT policy support requires Python 3.11+ and the "
                "'agent-control-specification' package"
            ) from exc
        try:
            return cls(AgentControl.from_path(str(path)))
        except Exception as exc:  # noqa: BLE001 - invalid policy must fail closed
            raise AGTConfigurationError(f"AGT manifest failed to load: {exc}") from exc

    async def run_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        execute: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        tool_call_id: str | None = None,
        snapshot: Mapping[str, Any] | None = None,
    ) -> AGTToolOutcome:
        """Run a validated tool through AGT pre/post Cedar enforcement."""
        executed_arguments: dict[str, Any] | None = None

        def governed_execute(effective: Any) -> dict[str, Any]:
            nonlocal executed_arguments
            if not isinstance(effective, dict):
                raise RuntimeError("AGT produced non-object SelfConnect tool arguments")
            executed_arguments = dict(effective)
            return execute(executed_arguments)

        result = await self._control.run_tool(
            tool_name,
            dict(arguments),
            governed_execute,
            tool_call_id=tool_call_id,
            snapshot=dict(snapshot or {}),
            mode="enforce",
        )
        value = getattr(result, "value", result)
        if not isinstance(value, dict):
            raise RuntimeError("AGT returned a non-object SelfConnect tool result")
        if executed_arguments is None:
            raise RuntimeError("AGT returned without executing the protected tool")
        return AGTToolOutcome(value=value, effective_arguments=executed_arguments)

    def run_tool_sync(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        execute: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        tool_call_id: str | None = None,
        snapshot: Mapping[str, Any] | None = None,
    ) -> AGTToolOutcome:
        """Synchronous bridge for ``MCPDispatcher``.

        Refuse nested event-loop use instead of offloading enforcement to an
        ungoverned background thread. Async hosts should call ``run_tool``.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.run_tool(
                    tool_name,
                    arguments,
                    execute,
                    tool_call_id=tool_call_id,
                    snapshot=snapshot,
                )
            )
        raise RuntimeError("synchronous AGT dispatch cannot run inside an active event loop")


__all__ = ["AGTCedarAdapter", "AGTConfigurationError", "AGTToolOutcome", "AgentControlProtocol"]
