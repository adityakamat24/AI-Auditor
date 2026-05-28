"""ASI08 Cascading Failure: repeated tool errors trip the circuit-breaker.

The agent calls ``flaky_tool`` six times in sequence, and every call ends with
``status="error"``. The ASI08 detector counts errors per (agent, tool) pair and trips the
circuit-breaker once the count exceeds the threshold K=5. The violation evidence reason
includes ``"circuit-breaker"``.

``build_attack_trace`` returns the synthetic trace that causes the ASI08 detector to emit a
VIOLATION. No LLM judge is required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from auditor.detectors.base import Trace
from auditor.events.schemas import ToolCallEnd, ToolCallStart


def build_attack_trace(run_id: UUID, tenant_id: UUID) -> Trace:
    """Return a Trace whose events trigger ASI08 (circuit-breaker threshold exceeded)."""
    agent_id = uuid4()
    now = datetime.now(tz=UTC)

    def _base(**kw: object) -> dict:
        return {
            "event_id": kw.pop("event_id", uuid4()),
            "run_id": run_id,
            "tenant_id": tenant_id,
            "span_id": kw.pop("span_id", uuid4()),
            "ts": now,
            **kw,
        }

    def _errored_call(tool_name: str) -> list:
        call_id = uuid4()
        return [
            ToolCallStart(**_base(), agent_id=agent_id, tool_name=tool_name, tool_call_id=call_id),
            ToolCallEnd(**_base(), agent_id=agent_id, tool_call_id=call_id, status="error", error="boom"),
        ]

    # 6 consecutive errors on the same tool — exceeds threshold K=5.
    events: list = []
    for _ in range(6):
        events.extend(_errored_call("flaky_tool"))

    return Trace(
        run_id=run_id,
        tenant_id=tenant_id,
        declared_goal="complete the assigned ITSM task",
        events=events,
        metadata={},
    )
