"""Verdict aggregator (PRD §9.9) - combine a run's detector verdicts into a single Flag.

Groups verdicts by ASI category, takes the max severity across all, computes a confidence as a weighted
average (deterministic detectors weight 1.0; judge-driven weighted by their confidence), and emits one
:class:`Flag` linking back to the source verdicts + deduped evidence. Returns ``None`` when nothing fired.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, Field

from auditor.ids import uuid7
from auditor.verdicts.schemas import Evidence, Severity, Verdict, VerdictResult
from auditor.verdicts.severity import score_severity

# Judge-driven detectors are weighted by their confidence; deterministic detectors count fully.
_JUDGE_DETECTORS = {"asi01_goal_hijack", "asi06_memory_poisoning", "asi09_trust_exploit", "asi10_rogue_agent"}


class Flag(BaseModel):
    """A run-level, actionable aggregation of detector verdicts (mirrors the ``flags`` table §8.1)."""

    flag_id: UUID = Field(default_factory=uuid7)
    run_id: UUID
    tenant_id: UUID
    severity: Severity
    asi_categories: list[str]
    verdict_ids: list[UUID]
    status: str = "open"
    confidence: float = 1.0
    evidence: list[Evidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


def aggregate(run_id: UUID, tenant_id: UUID, verdicts: list[Verdict]) -> Flag | None:
    """Reduce verdicts to a Flag, or None if no verdict is actionable (all OK)."""
    actionable = [v for v in verdicts if v.result != VerdictResult.OK]
    if not actionable:
        return None

    weights, confs = [], []
    for v in actionable:
        weight = float(v.confidence or 0.0) if v.detector in _JUDGE_DETECTORS else 1.0
        weights.append(weight)
        confs.append(float(v.confidence or 1.0) * weight)
    confidence = (sum(confs) / sum(weights)) if sum(weights) else 1.0

    evidence: list[Evidence] = []
    seen: set[tuple] = set()
    for v in actionable:
        for e in v.evidence:
            key = (str(e.event_id), e.reason)
            if key not in seen:
                seen.add(key)
                evidence.append(e)

    return Flag(
        run_id=run_id,
        tenant_id=tenant_id,
        severity=score_severity(actionable),
        asi_categories=sorted({v.asi_category for v in actionable}),
        verdict_ids=[v.verdict_id for v in actionable],
        confidence=round(confidence, 4),
        evidence=evidence,
    )


class VerdictAggregator:
    """Thin OO wrapper around :func:`aggregate` for the orchestrator."""

    async def aggregate(self, run_id: UUID, tenant_id: UUID, verdicts: list[Verdict]) -> Flag | None:
        return aggregate(run_id, tenant_id, verdicts)


__all__ = ["Flag", "aggregate", "VerdictAggregator"]
