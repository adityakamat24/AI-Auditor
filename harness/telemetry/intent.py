"""Intent declaration (PRD §9.1) — agents declare a plan before acting.

A thin wrapper over :meth:`harness.telemetry.sdk.Telemetry.declare_intent` so callers emit a single
``intent.declare`` event (stated intent + plan steps). The auditor later compares declared intent against
observed behavior (ASI01).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID


async def declare_run_intent(
    telemetry: Any,
    agent_id: UUID,
    intent: str,
    plan: list[str],
) -> None:
    """Emit an ``intent.declare`` event for ``agent_id`` via the Telemetry SDK."""
    await telemetry.declare_intent(agent_id, intent, plan)


__all__ = ["declare_run_intent"]
