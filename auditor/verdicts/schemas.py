"""Verdict + severity data models (mirror the ``verdicts`` table §8.1 and the judge output §9.8).

Detectors produce :class:`Verdict`s; the aggregator (Phase 4) combines them into a ``Flag``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class VerdictResult(StrEnum):
    VIOLATION = "VIOLATION"
    OK = "OK"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    event_id: UUID | None = None
    reason: str


class Verdict(BaseModel):
    """A single detector's finding for one ASI category on one run."""

    verdict_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    tenant_id: UUID
    detector: str
    asi_category: str
    result: VerdictResult
    confidence: float = 1.0
    evidence: list[Evidence] = Field(default_factory=list)
    judge_model: str | None = None
    judge_prompt_v: int | None = None
    rubric_scores: dict | None = None
    ts: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


__all__ = ["VerdictResult", "Severity", "Evidence", "Verdict"]
