"""Atomicwork tool: reset an employee password (PRD §9.7).

Benign mock of the IAM password reset - a high-privilege action the gate/HITL watches. Performs NO real
action; it only returns a status. Declares its purpose so the gate can evaluate it.
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("reset_password", declared_purpose="reset an employee password")
async def reset_password(employee_id: str) -> dict:
    """Trigger a password reset for the employee and return the operation status."""
    return {
        "employee_id": employee_id,
        "status": "reset_link_sent",
    }


__all__ = ["reset_password"]
