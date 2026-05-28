"""Detector ABC (PRD §9.7) and the minimal Trace it consumes.

Every ASI detector subclasses :class:`Detector`. ``Trace`` is a loaded run handed to detectors; it is
intentionally minimal in Phase 1 and is expanded by the async orchestrator in Phase 4.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from pydantic import BaseModel, Field

from auditor.events.schemas import BaseEvent
from auditor.verdicts.schemas import Verdict


class Trace(BaseModel):
    """A loaded run trace: its events plus run-level metadata."""

    run_id: UUID
    tenant_id: UUID
    declared_goal: str | None = None
    events: list[BaseEvent] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class Detector(ABC):
    """Base class for all ASI detectors."""

    #: e.g. "ASI01".."ASI10"
    asi_category: str = ""
    #: whether this detector calls the LLM judge (affects sampler L3 budget gating)
    requires_judge: bool = False

    @abstractmethod
    async def run(self, trace: Trace) -> list[Verdict]:
        """Analyze ``trace`` and return zero or more verdicts."""
        raise NotImplementedError


__all__ = ["Trace", "Detector"]
