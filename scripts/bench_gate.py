"""Micro-benchmark the inline-gate hot path (PRD §16.2: p99 < 5ms steady-state). Requires services up."""

from __future__ import annotations

import asyncio
import statistics
import time
from pathlib import Path
from uuid import uuid4

import redis.asyncio as aioredis
from auditor.config import get_settings
from auditor.inline_gate.budget import BudgetEnforcer
from auditor.inline_gate.decide import decide
from auditor.inline_gate.pii_scanner import PiiScanner
from auditor.inline_gate.policy_engine import OpaClient

_REGO = (Path(__file__).resolve().parents[1] / "opa" / "policies" / "default.rego").read_text(encoding="utf-8")


def _pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


async def _bench(label: str, factory, n: int = 300) -> None:
    for _ in range(5):
        await factory()
    lat = []
    for _ in range(n):
        t = time.perf_counter()
        await factory()
        lat.append((time.perf_counter() - t) * 1000)
    print(f"{label:30} p50={statistics.median(lat):6.2f}ms  p99={_pct(lat, 0.99):6.2f}ms  max={max(lat):6.2f}ms")


async def main() -> None:
    s = get_settings()
    opa = OpaClient(s.opa_url)
    await opa.load_policy(_REGO)
    redis = aioredis.from_url(s.redis_url, decode_responses=True)
    budget = BudgetEnforcer(redis)
    pii = PiiScanner()

    safe_input = {"event_type": "tool_call.start", "tool_name": "kb_search", "tool_args": {"q": "x"}}
    safe_event = {**safe_input, "run_id": str(uuid4()), "tenant_id": str(uuid4())}

    async def opa_uncached() -> None:
        await opa.evaluate({"event_type": "tool_call.start", "tool_name": "kb_search",
                            "tool_args": {"q": str(time.perf_counter_ns())}})

    try:
        await _bench("OPA evaluate (cached)", lambda: opa.evaluate(safe_input))
        await _bench("OPA evaluate (uncached HTTP)", opa_uncached, n=50)
        await _bench("budget.check (Redis Lua)", lambda: budget.check(str(uuid4()), "kb_search"))
        await _bench("decide() steady-state", lambda: decide(safe_event, run_id=str(uuid4()), opa=opa, pii=pii, budget=budget))
    finally:
        await opa.aclose()
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
