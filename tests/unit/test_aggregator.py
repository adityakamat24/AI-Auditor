"""Severity classification + verdict aggregation into a run Flag."""

from __future__ import annotations

from uuid import uuid4

from auditor.verdicts.aggregator import Flag, aggregate
from auditor.verdicts.schemas import Evidence, Severity, Verdict, VerdictResult
from auditor.verdicts.severity import classify, score_severity

RID = uuid4()
TID = uuid4()


def _v(detector: str, asi: str, *, result=VerdictResult.VIOLATION, confidence=1.0, rubric=None, evidence=None) -> Verdict:
    return Verdict(
        run_id=RID, tenant_id=TID, detector=detector, asi_category=asi, result=result,
        confidence=confidence, rubric_scores=rubric, evidence=evidence or [],
    )


def test_classify_ok_is_none() -> None:
    assert classify(_v("d", "ASI02", result=VerdictResult.OK)) is None


def test_classify_needs_review_is_low() -> None:
    assert classify(_v("d", "ASI02", result=VerdictResult.NEEDS_REVIEW)) == Severity.LOW


def test_classify_divergence_uses_explicit_severity() -> None:
    assert classify(_v("channel_divergence", "ASI03", rubric={"severity": "critical"})) == Severity.CRITICAL


def test_classify_supply_chain_is_critical() -> None:
    assert classify(_v("asi04_supply_chain", "ASI04")) == Severity.CRITICAL


def test_classify_judge_confidence_tiers() -> None:
    assert classify(_v("asi01_goal_hijack", "ASI01", confidence=0.9)) == Severity.HIGH
    assert classify(_v("asi01_goal_hijack", "ASI01", confidence=0.5)) == Severity.MEDIUM


def test_score_severity_is_max() -> None:
    verdicts = [_v("asi01_goal_hijack", "ASI01", confidence=0.5), _v("asi04_supply_chain", "ASI04")]
    assert score_severity(verdicts) == Severity.CRITICAL


def test_aggregate_all_ok_returns_none() -> None:
    assert aggregate(RID, TID, [_v("d", "ASI02", result=VerdictResult.OK)]) is None


def test_aggregate_builds_flag_with_dedup_and_max_severity() -> None:
    shared = Evidence(event_id=uuid4(), reason="same evidence")
    v1 = _v("asi04_supply_chain", "ASI04", evidence=[shared])
    v2 = _v("asi01_goal_hijack", "ASI01", confidence=0.8, evidence=[shared])
    flag = aggregate(RID, TID, [v1, v2])
    assert isinstance(flag, Flag)
    assert flag.severity == Severity.CRITICAL
    assert set(flag.asi_categories) == {"ASI01", "ASI04"}
    assert len(flag.verdict_ids) == 2
    assert len(flag.evidence) == 1  # deduped
    assert flag.status == "open"
