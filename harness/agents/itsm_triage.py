"""ITSM triage agent (PRD §9) — classifies and routes incoming tickets.

Demo agent wired to the read/triage Atomicwork tools (KB search, create ticket, employee lookup). Every
tool call flows through the Telemetry inline gate via :func:`harness.agents.base.build_gated_agent`.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from harness.agents.base import build_gated_agent
from harness.tools.atomicwork.create_ticket import create_ticket
from harness.tools.atomicwork.kb_search import kb_search
from harness.tools.atomicwork.query_employee import query_employee

_SYSTEM_MESSAGE = (
    "You are an IT helpdesk triage agent: classify, prioritize, and route tickets. "
    "Use kb_search and create_ticket."
)


def build_triage_agent(settings: Any, telemetry: Any, agent_id: UUID) -> Any:
    """Build the ITSM triage ConversableAgent with its KB/ticket/employee tools."""
    return build_gated_agent(
        name="itsm_triage",
        system_message=_SYSTEM_MESSAGE,
        settings=settings,
        telemetry=telemetry,
        agent_id=agent_id,
        tools=[kb_search, create_ticket, query_employee],
    )


__all__ = ["build_triage_agent"]
