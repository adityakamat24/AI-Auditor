"""Telemetry decorators (PRD §9.1) - the gating decorator + an AG2 binder.

``@instrumented_tool`` tags an async tool function with a :class:`ToolMeta` (its catalog name and an
optional declared purpose) without changing its behavior. :class:`GatedToolset` runs a tagged tool
*through* the Telemetry SDK's inline gate: a DENY raises :class:`~harness.telemetry.sdk.GateDeniedError`
out of ``call``; an ALLOW/CONFIRM runs the body. ``as_autogen_callable`` adapts a tagged tool into a
plain ``async def`` (with the tool's name/docstring) suitable for AG2 tool registration.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar
from uuid import UUID

AsyncTool = Callable[..., Awaitable[Any]]
F = TypeVar("F", bound=AsyncTool)


def _summarize_result(result: Any) -> str | None:
    """Compact string summary of a tool's return value for the ToolCallEnd event (truncated)."""
    if result is None:
        return None
    text = result if isinstance(result, str) else repr(result)
    return text[:4000]


@dataclass(frozen=True)
class ToolMeta:
    """Metadata attached to an instrumented tool: its catalog name + optional declared purpose."""

    name: str
    declared_purpose: str | None = None


def instrumented_tool(name: str, *, declared_purpose: str | None = None) -> Callable[[F], F]:
    """Tag an async tool with :class:`ToolMeta` (``fn.tool_meta``) and return it unchanged."""

    def decorator(func: F) -> F:
        func.tool_meta = ToolMeta(name, declared_purpose)  # type: ignore[attr-defined]
        return func

    return decorator


class GatedToolset:
    """Executes instrumented tools through the Telemetry inline gate for one agent."""

    def __init__(self, telemetry: Any, agent_id: UUID) -> None:
        self._telemetry = telemetry
        self._agent_id = agent_id

    async def call(self, fn: AsyncTool, /, **kwargs: Any) -> Any:
        """Gate then run ``fn(**kwargs)``; a DENY raises ``GateDeniedError`` out of here.

        The tool's result is summarized onto the call handle so it rides the ToolCallEnd event - giving
        the auditor visibility into what the agent ingested/produced (untrusted content, exfil payloads).
        """
        meta: ToolMeta = fn.tool_meta  # type: ignore[attr-defined]
        async with self._telemetry.tool_call(
            self._agent_id,
            meta.name,
            kwargs,
            declared_purpose=meta.declared_purpose,
        ) as handle:
            result = await fn(**kwargs)
            if hasattr(handle, "set_result"):
                handle.set_result(_summarize_result(result))
            return result

    def as_autogen_callable(self, fn: AsyncTool) -> AsyncTool:
        """Wrap ``fn`` as a gated ``async def`` carrying its name/docstring for AG2 registration."""

        async def wrapper(**kwargs: Any) -> Any:
            return await self.call(fn, **kwargs)

        meta: ToolMeta = fn.tool_meta  # type: ignore[attr-defined]
        wrapper.__name__ = meta.name
        wrapper.__doc__ = fn.__doc__
        # Preserve the tool's real signature + annotations so AG2 builds the correct tool schema (named
        # params), instead of exposing one opaque **kwargs object the model wraps as {"kwargs": {...}}.
        wrapper.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
        wrapper.__annotations__ = dict(getattr(fn, "__annotations__", {}))
        return wrapper


__all__ = ["ToolMeta", "instrumented_tool", "GatedToolset"]
