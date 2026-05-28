"""Trace sampler (PRD §9.6.1) - stratified + adaptive + always-on selection.

Three tiers:
- **L1** always-audit hard triggers: channel divergence, critical cheap-risk score, sensitive data
  outside the allowlist, a novel tool/egress domain, or a tenant with recent incidents.
- **L2** stratified deterministic sample: ``hash(tenant || tool_category || run_id) % 10000 < rate*10000``
  (reproducible; per-(tenant, tool_category) rate).
- **L3** budget gate: if the tenant's daily LLM budget is spent, still audit but cheap-detectors-only.

The policy provider, budget tracker, and novelty index are injectable (in-memory impls here; Redis-backed
variants for production), which keeps this fully unit-testable without services.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal, Protocol
from uuid import UUID

CRITICAL_RISK_THRESHOLD = 70


@dataclass
class RunSignals:
    tool_category: str = "default"
    channel_divergence: bool = False
    cheap_risk_score: int = 0
    touched_sensitive_data: bool = False
    in_allowlisted_path: bool = True
    tools_used: frozenset[str] = field(default_factory=frozenset)
    egress_domains: frozenset[str] = field(default_factory=frozenset)
    tenant_recent_incident_count: int = 0


@dataclass
class SamplerDecision:
    tier: Literal["L1", "L2", "L3", "NONE"]
    reason: str
    audit: bool
    judge_allowed: bool
    cohort_rate: float | None = None


class PolicyProvider(Protocol):
    def sample_rate_for(self, tenant_id: UUID, tool_category: str) -> float: ...


class BudgetTracker(Protocol):
    def has_budget(self, tenant_id: UUID) -> bool: ...


class NoveltyIndex(Protocol):
    def is_novel(self, tenant_id: UUID, tools: frozenset[str], egress: frozenset[str]) -> bool: ...


class StaticPolicyProvider:
    """Fixed base rate with optional per-category overrides."""

    def __init__(self, default_rate: float = 0.05, overrides: dict[str, float] | None = None) -> None:
        self._default = default_rate
        self._overrides = overrides or {}

    def sample_rate_for(self, tenant_id: UUID, tool_category: str) -> float:
        return self._overrides.get(tool_category, self._default)


class InMemoryNoveltyIndex:
    """Tracks tools/egress seen per tenant; anything unseen is novel."""

    def __init__(self) -> None:
        self._tools: dict[UUID, set[str]] = {}
        self._egress: dict[UUID, set[str]] = {}

    def is_novel(self, tenant_id: UUID, tools: frozenset[str], egress: frozenset[str]) -> bool:
        seen_tools = self._tools.setdefault(tenant_id, set())
        seen_egress = self._egress.setdefault(tenant_id, set())
        novel = bool(tools - seen_tools) or bool(egress - seen_egress)
        seen_tools.update(tools)
        seen_egress.update(egress)
        return novel


class RedisNoveltyIndex:
    """Redis-backed novelty index: per-tenant sets of seen tools/egress (mirrors the in-memory impl).

    Uses a *synchronous* redis client (``sismember``/``sadd``); :meth:`Sampler.decide` is synchronous and
    on a warm path, so the small blocking round-trip is acceptable. Pass any client exposing
    ``sismember(key, member)`` and ``sadd(key, *members)`` (``redis.Redis`` or a fake in tests).
    """

    def __init__(self, client: object, *, namespace: str = "novelty") -> None:
        self._r = client
        self._ns = namespace

    def is_novel(self, tenant_id: UUID, tools: frozenset[str], egress: frozenset[str]) -> bool:
        tools_key = f"{self._ns}:tools:{tenant_id}"
        egress_key = f"{self._ns}:egress:{tenant_id}"
        new_tools = [t for t in tools if not self._r.sismember(tools_key, t)]
        new_egress = [e for e in egress if not self._r.sismember(egress_key, e)]
        if new_tools:
            self._r.sadd(tools_key, *new_tools)
        if new_egress:
            self._r.sadd(egress_key, *new_egress)
        return bool(new_tools) or bool(new_egress)


class AlwaysBudget:
    def has_budget(self, tenant_id: UUID) -> bool:
        return True


def stable_hash(key: str) -> int:
    return int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:8], "big")


class Sampler:
    def __init__(
        self,
        policy_provider: PolicyProvider | None = None,
        budget_tracker: BudgetTracker | None = None,
        novelty_index: NoveltyIndex | None = None,
        *,
        critical_risk_threshold: int = CRITICAL_RISK_THRESHOLD,
    ) -> None:
        self._policy = policy_provider or StaticPolicyProvider()
        self._budget = budget_tracker or AlwaysBudget()
        self._novelty = novelty_index or InMemoryNoveltyIndex()
        self._critical_risk_threshold = critical_risk_threshold

    def decide(self, run_id: UUID, tenant_id: UUID, signals: RunSignals) -> SamplerDecision:
        # L1 - always-audit hard triggers.
        if signals.channel_divergence:
            return SamplerDecision("L1", "channel divergence", True, True)
        if signals.cheap_risk_score >= self._critical_risk_threshold:
            return SamplerDecision("L1", f"risk score {signals.cheap_risk_score}", True, True)
        if signals.touched_sensitive_data and not signals.in_allowlisted_path:
            return SamplerDecision("L1", "sensitive data outside allowlist", True, True)
        if self._novelty.is_novel(tenant_id, signals.tools_used, signals.egress_domains):
            return SamplerDecision("L1", "novel tool/egress", True, True)
        if signals.tenant_recent_incident_count > 0:
            return SamplerDecision("L1", "recent tenant incidents", True, True)

        # L2 - stratified deterministic sample.
        rate = self._policy.sample_rate_for(tenant_id, signals.tool_category)
        bucket = stable_hash(f"{tenant_id}:{signals.tool_category}:{run_id}") % 10_000
        if bucket < int(rate * 10_000):
            if self._budget.has_budget(tenant_id):
                return SamplerDecision("L2", f"stratified at {rate:.4%}", True, True, rate)
            return SamplerDecision("L3", "budget exhausted (cheap detectors only)", True, False, rate)

        return SamplerDecision("NONE", "not sampled", False, False, rate)


class DbPolicyProvider:
    """Per-(tenant, tool_category) sample rates loaded from the ``policies.sample_rates`` JSONB column.

    The DB read is async, but :meth:`Sampler.decide` is sync (warm path), so rates are loaded once into a
    snapshot via :func:`load_tenant_sample_rates` and this provider serves them synchronously. Falls back
    to ``default_rate`` for any tenant/category without an explicit entry.
    """

    def __init__(self, rates_by_tenant: dict[str, dict[str, float]], *, default_rate: float = 0.05) -> None:
        self._rates = rates_by_tenant
        self._default = default_rate

    def sample_rate_for(self, tenant_id: UUID, tool_category: str) -> float:
        cats = self._rates.get(str(tenant_id), {})
        if tool_category in cats:
            return cats[tool_category]
        return cats.get("default", self._default)


async def load_tenant_sample_rates() -> dict[str, dict[str, float]]:
    """Snapshot ``{tenant_id: {tool_category: rate}}`` from the active rows of the ``policies`` table."""
    from sqlalchemy import select

    from auditor.db.models import Policy
    from auditor.db.session import get_sessionmaker

    sessionmaker = get_sessionmaker()
    out: dict[str, dict[str, float]] = {}
    async with sessionmaker() as session:
        rows = (await session.execute(select(Policy))).scalars().all()
    for row in rows:
        rates = row.sample_rates if isinstance(row.sample_rates, dict) else {}
        # Keep the most permissive (highest) rate if a tenant has multiple policy versions.
        existing = out.setdefault(str(row.tenant_id), {})
        for category, rate in rates.items():
            existing[category] = max(existing.get(category, 0.0), float(rate))
    return out


def get_sampler(
    settings: object | None = None,
    *,
    policy_provider: PolicyProvider | None = None,
    budget_tracker: BudgetTracker | None = None,
    novelty_index: NoveltyIndex | None = None,
) -> Sampler:
    """Build a :class:`Sampler` from :class:`~auditor.config.Settings` (env-driven rates + thresholds).

    ``SAMPLER_DEFAULT_RATE`` (e.g. ``0.01`` for 1%), ``SAMPLER_CATEGORY_RATES`` (JSON overrides),
    ``SAMPLER_CRITICAL_RISK_THRESHOLD`` and ``JUDGE_DAILY_CAP_USD`` flow in here. Pass an explicit
    ``policy_provider`` (e.g. a :class:`DbPolicyProvider` snapshot) to override the env defaults.
    """
    from auditor.async_pipeline.budget_tracker import InMemoryBudgetTracker
    from auditor.config import get_settings

    resolved = settings or get_settings()
    policy = policy_provider or StaticPolicyProvider(
        default_rate=resolved.sampler_default_rate,
        overrides=dict(resolved.sampler_category_rates),
    )
    budget = budget_tracker or InMemoryBudgetTracker(daily_cap_usd=resolved.judge_daily_cap_usd)
    return Sampler(
        policy,
        budget,
        novelty_index,
        critical_risk_threshold=resolved.sampler_critical_risk_threshold,
    )


__all__ = [
    "RunSignals",
    "SamplerDecision",
    "Sampler",
    "StaticPolicyProvider",
    "DbPolicyProvider",
    "load_tenant_sample_rates",
    "get_sampler",
    "InMemoryNoveltyIndex",
    "RedisNoveltyIndex",
    "AlwaysBudget",
    "stable_hash",
    "CRITICAL_RISK_THRESHOLD",
]
