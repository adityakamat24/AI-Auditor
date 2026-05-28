"""Generic executor agent (PRD §9) - runs the generic tool set.

General-purpose audited agent wired to the safe generic tools (HTTP get/post, sandboxed file read/write).
``exec_shell`` is deliberately excluded - it is blocked by policy. Every tool call flows through the
Telemetry inline gate via :func:`harness.agents.base.build_gated_agent`.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from harness.agents.base import build_gated_agent
from harness.tools.generic.file_read import file_read
from harness.tools.generic.file_write import file_write
from harness.tools.generic.http_get import http_get
from harness.tools.generic.http_post import http_post

_SYSTEM_MESSAGE = (
    "You are a general-purpose executor agent. Use the available HTTP and file tools to complete tasks."
)


def build_generic_agent(settings: Any, telemetry: Any, agent_id: UUID) -> Any:
    """Build the generic executor ConversableAgent with HTTP and sandboxed file tools."""
    return build_gated_agent(
        name="generic_executor",
        system_message=_SYSTEM_MESSAGE,
        settings=settings,
        telemetry=telemetry,
        agent_id=agent_id,
        tools=[http_get, http_post, file_read, file_write],
    )


__all__ = ["build_generic_agent"]
