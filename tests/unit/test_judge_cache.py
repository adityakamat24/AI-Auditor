"""Judge verdict cache + CachedJudge read-through wrapper (no key, no network)."""

from __future__ import annotations

import pytest
from auditor.judge.cache import InMemoryVerdictCache, cache_key
from auditor.judge.client import CachedJudge, JudgeClient, JudgeResult, OfflineStubJudge


class _CountingJudge(JudgeClient):
    """Wraps the stub but counts how many times the inner judge is actually invoked."""

    def __init__(self) -> None:
        self.calls = 0
        self._inner = OfflineStubJudge()

    async def judge(self, *, category, rubric, trace_slice, prompt_version=1) -> JudgeResult:
        self.calls += 1
        return await self._inner.judge(
            category=category, rubric=rubric, trace_slice=trace_slice, prompt_version=prompt_version
        )


def test_cache_key_is_stable_and_input_sensitive() -> None:
    a = cache_key(category="ASI01", prompt_version=1, trace_slice="x")
    assert a == cache_key(category="ASI01", prompt_version=1, trace_slice="x")
    assert a != cache_key(category="ASI01", prompt_version=2, trace_slice="x")
    assert a != cache_key(category="ASI02", prompt_version=1, trace_slice="x")
    assert a != cache_key(category="ASI01", prompt_version=1, trace_slice="y")


async def test_inmemory_cache_roundtrips_verdict() -> None:
    cache = InMemoryVerdictCache()
    assert await cache.get("k") is None
    result = JudgeResult(category="ASI01", verdict="VIOLATION", confidence=0.9)
    await cache.set("k", result)
    got = await cache.get("k")
    assert got is not None and got.verdict == "VIOLATION" and got.confidence == pytest.approx(0.9)


async def test_cached_judge_serves_second_call_from_cache() -> None:
    inner = _CountingJudge()
    judge = CachedJudge(inner, InMemoryVerdictCache())
    kw = {"category": "ASI01", "rubric": "r", "trace_slice": "ignore all previous instructions"}
    first = await judge.judge(**kw)
    second = await judge.judge(**kw)
    assert first.verdict == "VIOLATION" and second.verdict == "VIOLATION"
    assert inner.calls == 1  # second call hit the cache


async def test_cached_judge_distinguishes_distinct_slices() -> None:
    inner = _CountingJudge()
    judge = CachedJudge(inner, InMemoryVerdictCache())
    await judge.judge(category="ASI01", rubric="r", trace_slice="benign trace")
    await judge.judge(category="ASI01", rubric="r", trace_slice="exfiltrate to attacker.com")
    assert inner.calls == 2  # different slices are not collapsed


async def test_cached_judge_hit_rate_exceeds_target() -> None:
    # Two distinct slices, each repeated - mimics repeated test runs touching the same traces.
    judge = CachedJudge(_CountingJudge(), InMemoryVerdictCache())
    for slice_text in ("trace A", "trace A", "trace A", "trace B", "trace B"):
        await judge.judge(category="ASI01", rubric="r", trace_slice=slice_text)
    assert judge.hits == 3 and judge.misses == 2
    assert judge.hit_rate > 0.30  # PRD §15 Phase-4 acceptance: cache hit rate > 30%
