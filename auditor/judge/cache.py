"""LLM judge verdict cache (PRD §9.8).

Caches judge verdicts keyed on ``sha256(category | prompt_version | trace_slice)`` so identical trace
slices don't re-incur LLM cost. In-memory by default (correct for one process); a Redis-backed variant
(7-day TTL) implements the same async ``get``/``set`` for multi-process deployments.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from auditor.judge.client import JudgeResult

CACHE_TTL_S = 7 * 24 * 3600  # 7 days


def cache_key(*, category: str, prompt_version: int, trace_slice: str) -> str:
    raw = f"{category}\x00{prompt_version}\x00{trace_slice}"
    return "judge:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


class InMemoryVerdictCache:
    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> JudgeResult | None:
        raw = self._store.get(key)
        return JudgeResult.model_validate_json(raw) if raw is not None else None

    async def set(self, key: str, verdict: JudgeResult) -> None:
        self._store[key] = verdict.model_dump_json()


class RedisVerdictCache:
    def __init__(self, redis: Any, ttl_s: int = CACHE_TTL_S) -> None:
        self._redis = redis
        self._ttl = ttl_s

    async def get(self, key: str) -> JudgeResult | None:
        raw = await self._redis.get(key)
        if raw is None:
            return None
        return JudgeResult.model_validate(json.loads(raw))

    async def set(self, key: str, verdict: JudgeResult) -> None:
        await self._redis.set(key, verdict.model_dump_json(), ex=self._ttl)


__all__ = ["cache_key", "InMemoryVerdictCache", "RedisVerdictCache", "CACHE_TTL_S"]
