"""Atomicwork tool: query an employee record (PRD §9.7).

Benign lookup against a mocked directory: returns a canned employee record. No declared purpose - a
read-only directory lookup.
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("query_employee")
async def query_employee(employee_id: str) -> dict:
    """Look up an employee in the directory and return their record (name, department)."""
    return {
        "employee_id": employee_id,
        "name": "Jane Doe",
        "department": "IT",
    }


__all__ = ["query_employee"]
