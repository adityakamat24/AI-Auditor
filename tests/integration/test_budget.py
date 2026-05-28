"""BudgetEnforcer against live Redis: same-tool loop denies; alternating tools stay allowed."""

from __future__ import annotations

import uuid

import pytest
import redis.asyncio as aioredis
from auditor.config import get_settings
from auditor.inline_gate.budget import MAX_SAME_TOOL_STREAK, BudgetEnforcer

pytestmark = pytest.mark.integration


async def test_same_tool_loop_denies() -> None:
    redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    enforcer = BudgetEnforcer(redis)
    run_id = f"test-{uuid.uuid4()}"
    last: dict = {}
    try:
        for _ in range(MAX_SAME_TOOL_STREAK + 2):
            last = await enforcer.check(run_id, "kb_search")
        assert last["decision"] == "DENY"
        assert last["streak"] > MAX_SAME_TOOL_STREAK
    finally:
        await redis.aclose()


async def test_alternating_tools_allow() -> None:
    redis = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    enforcer = BudgetEnforcer(redis)
    run_id = f"test-{uuid.uuid4()}"
    try:
        for i in range(10):
            out = await enforcer.check(run_id, f"tool_{i % 3}")
            assert out["decision"] == "ALLOW"
    finally:
        await redis.aclose()
