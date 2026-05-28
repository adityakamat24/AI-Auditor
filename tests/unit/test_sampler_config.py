"""The sample rate + thresholds are config-driven (env), not hardcoded (PRD §5.4 / §9.6.1)."""

from __future__ import annotations

from uuid import uuid4

from auditor.async_pipeline.sampler import DbPolicyProvider, RunSignals, get_sampler
from auditor.config import Settings

RID, TID = uuid4(), uuid4()


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_rate_zero_samples_nothing() -> None:
    decision = get_sampler(_settings(sampler_default_rate=0.0)).decide(RID, TID, RunSignals())
    assert decision.tier == "NONE" and not decision.audit


def test_rate_full_always_samples() -> None:
    decision = get_sampler(_settings(sampler_default_rate=1.0)).decide(RID, TID, RunSignals())
    assert decision.tier == "L2" and decision.audit


def test_one_percent_vs_five_percent_bucketing() -> None:
    # The same deterministic hash bucket is included at 5% but excluded at 1% for some runs - proving the
    # configured rate actually changes selection. Count selection across many runs.
    def sampled_fraction(rate: float) -> float:
        sampler = get_sampler(_settings(sampler_default_rate=rate))
        hits = sum(
            sampler.decide(uuid4(), TID, RunSignals(tool_category="kb_search")).audit
            for _ in range(2000)
        )
        return hits / 2000

    assert sampled_fraction(0.01) < sampled_fraction(0.05)  # 1% selects fewer than 5%
    assert abs(sampled_fraction(0.05) - 0.05) < 0.03  # ~5%


def test_category_override_from_settings() -> None:
    sampler = get_sampler(
        _settings(sampler_default_rate=0.0, sampler_category_rates={"exec_shell": 1.0})
    )
    assert sampler.decide(RID, TID, RunSignals(tool_category="exec_shell")).tier == "L2"  # forced 100%
    assert sampler.decide(RID, TID, RunSignals(tool_category="kb_search")).tier == "NONE"  # default 0%


def test_critical_risk_threshold_from_settings() -> None:
    sampler = get_sampler(_settings(sampler_default_rate=0.0, sampler_critical_risk_threshold=50))
    assert sampler.decide(RID, TID, RunSignals(cheap_risk_score=60)).tier == "L1"  # 60 >= 50 → always audit
    assert sampler.decide(RID, TID, RunSignals(cheap_risk_score=40)).tier == "NONE"  # 40 < 50


def test_db_policy_provider_per_tenant_rates() -> None:
    provider = DbPolicyProvider({str(TID): {"exec_shell": 0.5, "default": 0.02}}, default_rate=0.05)
    assert provider.sample_rate_for(TID, "exec_shell") == 0.5  # explicit per-category
    assert provider.sample_rate_for(TID, "kb_search") == 0.02  # tenant's "default"
    assert provider.sample_rate_for(uuid4(), "kb_search") == 0.05  # unknown tenant → global default
