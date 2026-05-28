"""Sampler tiers (L1 always-audit / L2 stratified / L3 budget gate) + budget tracker."""

from __future__ import annotations

from uuid import uuid4

import pytest
from auditor.async_pipeline.budget_tracker import InMemoryBudgetTracker
from auditor.async_pipeline.sampler import (
    InMemoryNoveltyIndex,
    RunSignals,
    Sampler,
    StaticPolicyProvider,
)

RID = uuid4()
TID = uuid4()


class _NeverNovel:
    def is_novel(self, tenant_id, tools, egress) -> bool:
        return False


class _NoBudget:
    def has_budget(self, tenant_id) -> bool:
        return False


def _sampler(rate: float = 0.0, novelty=None, budget=None) -> Sampler:
    return Sampler(StaticPolicyProvider(default_rate=rate), budget or InMemoryBudgetTracker(), novelty or _NeverNovel())


def test_l1_channel_divergence() -> None:
    d = _sampler().decide(RID, TID, RunSignals(channel_divergence=True))
    assert d.tier == "L1" and d.audit and d.judge_allowed


def test_l1_critical_risk_score() -> None:
    assert _sampler().decide(RID, TID, RunSignals(cheap_risk_score=80)).tier == "L1"


def test_l1_sensitive_outside_allowlist() -> None:
    d = _sampler().decide(RID, TID, RunSignals(touched_sensitive_data=True, in_allowlisted_path=False))
    assert d.tier == "L1"


def test_l1_novelty() -> None:
    sampler = Sampler(StaticPolicyProvider(0.0), InMemoryBudgetTracker(), InMemoryNoveltyIndex())
    d = sampler.decide(RID, TID, RunSignals(tools_used=frozenset({"never_seen_tool"})))
    assert d.tier == "L1" and "novel" in d.reason


def test_l1_recent_incidents() -> None:
    assert _sampler().decide(RID, TID, RunSignals(tenant_recent_incident_count=2)).tier == "L1"


def test_l2_full_rate_audits_with_judge() -> None:
    d = _sampler(rate=1.0).decide(RID, TID, RunSignals())
    assert d.tier == "L2" and d.audit and d.judge_allowed


def test_zero_rate_not_sampled() -> None:
    d = _sampler(rate=0.0).decide(RID, TID, RunSignals())
    assert d.tier == "NONE" and not d.audit


def test_l3_budget_exhausted_cheap_only() -> None:
    d = _sampler(rate=1.0, budget=_NoBudget()).decide(RID, TID, RunSignals())
    assert d.tier == "L3" and d.audit and not d.judge_allowed


def test_decision_is_deterministic() -> None:
    a = _sampler(rate=0.5).decide(RID, TID, RunSignals())
    b = _sampler(rate=0.5).decide(RID, TID, RunSignals())
    assert a.tier == b.tier  # hash-based stratification is reproducible


def test_budget_tracker_caps() -> None:
    tracker = InMemoryBudgetTracker(daily_cap_usd=1.0)
    assert tracker.has_budget(TID)
    tracker.record_cost(TID, 0.6)
    assert tracker.has_budget(TID)
    tracker.record_cost(TID, 0.6)
    assert not tracker.has_budget(TID)
    assert tracker.spent(TID) == pytest.approx(1.2)
