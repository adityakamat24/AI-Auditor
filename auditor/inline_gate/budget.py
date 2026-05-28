"""Per-run tool-budget enforcer for the inline gate (PRD §9.4.3), backed by Redis.

Caps: max 200 tool calls/run, max 50 of the same tool in a row (loop detection), burst > 20/10s
(throttle → CONFIRM). All counters update in a single round-trip via a Lua script to keep the gate fast.
"""

from __future__ import annotations

from typing import Any

MAX_CALLS_PER_RUN = 200
MAX_SAME_TOOL_STREAK = 50
BURST_LIMIT = 20  # per 10s window
_TTL = 3600
_BURST_TTL = 10

# KEYS: total, last_tool, streak, burst ; ARGV: tool_name, ttl, burst_ttl -> [total, streak, burst]
_LUA = """
local total = redis.call('INCR', KEYS[1]); redis.call('EXPIRE', KEYS[1], ARGV[2])
local last = redis.call('GET', KEYS[2])
local streak
if last == ARGV[1] then
  streak = redis.call('INCR', KEYS[3])
else
  redis.call('SET', KEYS[2], ARGV[1]); redis.call('SET', KEYS[3], 1); streak = 1
end
redis.call('EXPIRE', KEYS[2], ARGV[2]); redis.call('EXPIRE', KEYS[3], ARGV[2])
local burst = redis.call('INCR', KEYS[4])
if burst == 1 then redis.call('EXPIRE', KEYS[4], ARGV[3]) end
return {total, streak, burst}
"""


class BudgetEnforcer:
    def __init__(self, redis: Any) -> None:
        self._redis = redis
        self._script = redis.register_script(_LUA)

    async def check(self, run_id: str, tool_name: str) -> dict:
        keys = [
            f"budget:{run_id}:total",
            f"budget:{run_id}:last_tool",
            f"budget:{run_id}:streak",
            f"budget:{run_id}:burst",
        ]
        total, streak, burst = await self._script(
            keys=keys, args=[tool_name, _TTL, _BURST_TTL]
        )
        total, streak, burst = int(total), int(streak), int(burst)

        decision, reasons = "ALLOW", []
        if total > MAX_CALLS_PER_RUN:
            decision = "DENY"
            reasons.append(f"run tool budget exceeded ({total} > {MAX_CALLS_PER_RUN})")
        elif streak > MAX_SAME_TOOL_STREAK:
            decision = "DENY"
            reasons.append(f"tool '{tool_name}' called {streak}x in a row (loop > {MAX_SAME_TOOL_STREAK})")
        elif burst > BURST_LIMIT:
            decision = "CONFIRM"
            reasons.append(f"burst {burst}/{_BURST_TTL}s exceeds {BURST_LIMIT} (throttle)")
        return {"decision": decision, "reasons": reasons, "total": total, "streak": streak, "burst": burst}


__all__ = ["BudgetEnforcer", "MAX_CALLS_PER_RUN", "MAX_SAME_TOOL_STREAK", "BURST_LIMIT"]
