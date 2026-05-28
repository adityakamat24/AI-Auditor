"""Nightly calibration run (PRD §9.12.2).

Replays the ground-truth corpus through the current detectors (including the LLM judge at the current
prompt version), computes a per-ASI-category confusion matrix → precision/recall/F1, persists a
``calibration_runs`` row, and - the safety mechanism - **disables a detector's blocking authority** when
its category precision falls below the configured threshold (default 0.85). Run as:

    python -m auditor.calibration.nightly

A bad judge prompt version that starts producing false positives shows up as a precision drop here and
the affected detector is auto-disabled within this one cycle (PRD §15 Phase-6 acceptance).
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from auditor.async_pipeline.orchestrator import ensure_detectors_registered
from auditor.calibration.ground_truth import (
    LABEL_VIOLATION,
    GroundTruthEntry,
    build_default_ground_truth,
)
from auditor.calibration.metrics import ConfusionMatrix, overall_metrics
from auditor.detectors.base import Detector
from auditor.verdicts.schemas import VerdictResult

DEFAULT_PRECISION_THRESHOLD = 0.85

Predictor = Callable[[GroundTruthEntry], Awaitable[bool]]


class BlockingAuthority(Protocol):
    """Sink that neutralizes a detector's blocking authority when calibration says it's unsafe."""

    async def disable(self, category: str, *, reason: str, metrics: dict) -> None: ...


@dataclass
class InMemoryBlockingAuthority:
    """Records categories whose blocking authority was disabled (tests / single-process)."""

    disabled: dict[str, dict] = field(default_factory=dict)

    async def disable(self, category: str, *, reason: str, metrics: dict) -> None:
        self.disabled[category] = {"reason": reason, "metrics": metrics}


@dataclass
class CalibrationReport:
    per_category: dict[str, dict]
    overall: dict
    disabled: list[str]
    judge_model: str
    judge_prompt_v: int
    ts: str


def _detector_index() -> dict[str, Detector]:
    """Map ASI category → a detector instance for that category (from the registry)."""
    registry = ensure_detectors_registered()
    index: dict[str, Detector] = {}
    for registration in registry.values():
        index.setdefault(registration.asi_category, registration.factory())
    return index


async def default_predictor(entry: GroundTruthEntry) -> bool:
    """Run the category's detector over the trace; predict VIOLATION if it returns a VIOLATION verdict."""
    detector = _detector_index().get(entry.asi_category)
    if detector is None:
        return False
    verdicts = await detector.run(entry.trace)
    return any(v.result == VerdictResult.VIOLATION for v in verdicts)


class CalibrationJob:
    """Scores detectors against the ground-truth corpus and disables those whose precision drops."""

    def __init__(
        self,
        *,
        predictor: Predictor = default_predictor,
        precision_threshold: float = DEFAULT_PRECISION_THRESHOLD,
        blocking_authority: BlockingAuthority | None = None,
        judge_model: str = "offline-stub",
        judge_prompt_v: int = 1,
    ) -> None:
        self._predict = predictor
        self._threshold = precision_threshold
        self._authority = blocking_authority
        self._judge_model = judge_model
        self._judge_prompt_v = judge_prompt_v

    async def run(self, ground_truth: list[GroundTruthEntry] | None = None) -> CalibrationReport:
        entries = ground_truth if ground_truth is not None else build_default_ground_truth()

        matrices: dict[str, ConfusionMatrix] = {}
        for entry in entries:
            predicted = await self._predict(entry)
            cm = matrices.setdefault(entry.asi_category, ConfusionMatrix())
            cm.add(labeled_violation=(entry.label == LABEL_VIOLATION), predicted_violation=predicted)

        disabled: list[str] = []
        for category, cm in matrices.items():
            # Precision is only meaningful where there are labeled positives.
            if cm.has_positives and cm.precision < self._threshold:
                disabled.append(category)
                if self._authority is not None:
                    await self._authority.disable(
                        category,
                        reason=f"precision {cm.precision:.2f} < threshold {self._threshold:.2f}",
                        metrics=cm.as_dict(),
                    )

        return CalibrationReport(
            per_category={c: cm.as_dict() for c, cm in matrices.items()},
            overall=overall_metrics(matrices),
            disabled=sorted(disabled),
            judge_model=self._judge_model,
            judge_prompt_v=self._judge_prompt_v,
            ts=datetime.now(tz=UTC).isoformat(),
        )


async def persist_report(report: CalibrationReport) -> None:
    """Write a calibration_runs row (best-effort; requires the DB)."""
    from auditor.db.models import CalibrationRun
    from auditor.db.session import get_sessionmaker
    from auditor.ids import uuid7

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        session.add(
            CalibrationRun(
                cal_id=uuid7(),
                judge_model=report.judge_model,
                judge_prompt_v=report.judge_prompt_v,
                per_category=report.per_category,
                overall=report.overall,
            )
        )


async def _main(*, persist: bool) -> int:
    report = await CalibrationJob(blocking_authority=InMemoryBlockingAuthority()).run()
    print(json.dumps(asdict(report), indent=2))
    if persist:
        from auditor.db.session import dispose_engine

        try:
            await persist_report(report)
        finally:
            await dispose_engine()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the nightly calibration pass.")
    parser.add_argument("--persist", action="store_true", help="write a calibration_runs row to the DB")
    args = parser.parse_args(argv)
    return asyncio.run(_main(persist=args.persist))


# Backwards-compatible alias for the original stub class name.
NightlyCalibration = CalibrationJob


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "CalibrationJob",
    "NightlyCalibration",
    "CalibrationReport",
    "InMemoryBlockingAuthority",
    "BlockingAuthority",
    "default_predictor",
    "persist_report",
    "main",
]
