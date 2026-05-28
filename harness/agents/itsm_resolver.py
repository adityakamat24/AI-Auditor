"""ITSM resolver agent (PRD §9) — resolves triaged tickets.

Demo agent wired to the resolution Atomicwork tools (reset password, send email, KB search). Every tool
call flows through the Telemetry inline gate via :func:`harness.agents.base.build_gated_agent`.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from harness.agents.base import build_gated_agent
from harness.tools.atomicwork.kb_search import kb_search
from harness.tools.atomicwork.reset_password import reset_password
from harness.tools.atomicwork.send_email import send_email

_SYSTEM_MESSAGE = "You resolve IT tickets: reset passwords, send updates."


def build_resolver_agent(settings: Any, telemetry: Any, agent_id: UUID) -> Any:
    """Build the ITSM resolver ConversableAgent with its reset/email/KB tools."""
    return build_gated_agent(
        name="itsm_resolver",
        system_message=_SYSTEM_MESSAGE,
        settings=settings,
        telemetry=telemetry,
        agent_id=agent_id,
        tools=[reset_password, send_email, kb_search],
    )


__all__ = ["build_resolver_agent"]
