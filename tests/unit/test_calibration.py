"""Calibration: confusion-matrix metrics, ground-truth corpus, nightly job + auto-disable on drift."""

from __future__ import annotations

import pytest
from auditor.calibration.ground_truth import ASI_CATEGORIES, build_default_ground_truth
from auditor.calibration.metrics import ConfusionMatrix, confusion_from_pairs
from auditor.calibration.nightly import (
    CalibrationJob,
    InMemoryBlockingAuthority,
    default_predictor,
)


def test_confusion_matrix_metrics() -> None:
    # 3 TP, 1 FP, 1 FN, 5 TN.
    cm = confusion_from_pairs(
        [(True, True)] * 3 + [(False, True)] + [(True, False)] + [(False, False)] * 5
    )
    assert cm.precision == pytest.approx(3 / 4)
    assert cm.recall == pytest.approx(3 / 4)
    assert cm.f1 == pytest.approx(0.75)
    assert cm.fp_rate == pytest.approx(1 / 6)
    assert cm.n == 10


def test_confusion_matrix_zero_denominators_are_safe() -> None:
    cm = ConfusionMatrix()
    assert cm.precision == 0.0 and cm.recall == 0.0 and cm.f1 == 0.0 and not cm.has_positives


def test_default_ground_truth_covers_every_category() -> None:
    entries = build_default_ground_truth()
    assert len(entries) == 2 * len(ASI_CATEGORIES)  # one VIOLATION + one OK per category
    by_cat = {c: [e.label for e in entries if e.asi_category == c] for c in ASI_CATEGORIES}
    assert all(sorted(labels) == ["OK", "VIOLATION"] for labels in by_cat.values())


async def test_calibration_job_runs_end_to_end_clean() -> None:
    # Acceptance bullet 1: the job runs end-to-end and produces a report.
    authority = InMemoryBlockingAuthority()
    report = await CalibrationJob(blocking_authority=authority).run()
    assert set(report.per_category) == set(ASI_CATEGORIES)
    assert report.overall["precision"] >= 0.85  # the stub detectors classify the corpus correctly
    assert report.disabled == [] and authority.disabled == {}


async def test_bad_judge_drift_disables_detector_within_one_cycle() -> None:
    # Acceptance bullet 2: a bad judge prompt that produces false positives for ASI01 drops its
    # precision below threshold, so its blocking authority is disabled in this single cycle.
    async def bad_judge_predictor(entry) -> bool:
        if entry.asi_category == "ASI01":
            return True  # mislabels even the OK trace as a violation -> false positive
        return await default_predictor(entry)

    authority = InMemoryBlockingAuthority()
    report = await CalibrationJob(
        predictor=bad_judge_predictor, blocking_authority=authority, judge_prompt_v=2
    ).run()

    assert "ASI01" in report.disabled
    assert "ASI01" in authority.disabled
    assert report.per_category["ASI01"]["precision"] < 0.85
    assert report.judge_prompt_v == 2  # the report records which (bad) prompt version was evaluated
    # Other categories stayed healthy.
    assert "ASI02" not in report.disabled
