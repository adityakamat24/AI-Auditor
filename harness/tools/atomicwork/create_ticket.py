"""Atomicwork tool: create a ticket (PRD §9.7).

Benign mock of the Atomicwork create-ticket API: returns a fake ticket id (no real backend call). Declares
its purpose so the inline gate can evaluate the action.
"""

from __future__ import annotations

from uuid import uuid4

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("create_ticket", declared_purpose="create an IT ticket")
async def create_ticket(subject: str, body: str = "", priority: str = "normal") -> dict:
    """Create an ITSM ticket with the given subject, body, and priority; return its identifier."""
    return {
        "ticket_id": f"INC-{uuid4().hex[:8]}",
        "status": "open",
        "subject": subject,
        "body": body,
        "priority": priority,
    }


__all__ = ["create_ticket"]
