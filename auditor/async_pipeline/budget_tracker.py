"""Per-tenant daily LLM budget tracker (PRD §9.6) — the sampler's L3 gate.

Tracks judge spend per (tenant, UTC day). ``has_budget`` is synchronous (the sampler calls it on the
decision path); ``record_cost`` is called by the judge after each call. In-memory is correct for a
single auditor process; a Redis-backed mirror (for multi-process) is a drop-in implementing the same
two methods.
"""

from __future__ import annotations

from datetime import date
from uuid import UUID

DEFAULT_DAILY_CAP_USD = 10.0


class InMemoryBudgetTracker:
    def __init__(self, daily_cap_usd: float = DEFAULT_DAILY_CAP_USD) -> None:
        self._cap = daily_cap_usd
        self._spent: dict[tuple[UUID, date], float] = {}

    def _key(self, tenant_id: UUID) -> tuple[UUID, date]:
        return (tenant_id, date.today())

    def has_budget(self, tenant_id: UUID) -> bool:
        return self._spent.get(self._key(tenant_id), 0.0) < self._cap

    def record_cost(self, tenant_id: UUID, usd: float) -> None:
        key = self._key(tenant_id)
        self._spent[key] = self._spent.get(key, 0.0) + usd

    def spent(self, tenant_id: UUID) -> float:
        return self._spent.get(self._key(tenant_id), 0.0)


__all__ = ["InMemoryBudgetTracker", "DEFAULT_DAILY_CAP_USD"]
