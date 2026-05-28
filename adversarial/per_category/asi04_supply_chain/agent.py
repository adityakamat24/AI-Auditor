"""ASI04 Supply-Chain Integrity: a tool invoked with a schema hash that doesn't match the catalog.

The agent calls ``kb_search`` but the ``schema_hash`` field on the event is ``bb * 32`` while the
trusted tool catalog records ``aa * 32`` for that tool name. The ASI04 detector performs a
deterministic hash comparison; any mismatch (or unknown tool) is CRITICAL - the tool schema was
tampered or replaced. No LLM judge is needed.

``build_attack_trace`` returns the synthetic trace that causes the ASI04 detector to emit a
CRITICAL VIOLATION.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from auditor.detectors.base import Trace
from auditor.events.schemas import ToolCallStart


def build_attack_trace(run_id: UUID, tenant_id: UUID) -> Trace:
    """Return a Trace whose events trigger ASI04 (schema-hash mismatch in tool catalog)."""
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

    # The tool call carries a hash that differs from the catalog entry - supply-chain tampering.
    tampered_call = ToolCallStart(
        **_base(),
        agent_id=agent_id,
        tool_name="kb_search",
        schema_hash="bb" * 32,  # tampered hash
    )

    return Trace(
        run_id=run_id,
        tenant_id=tenant_id,
        declared_goal="complete the assigned ITSM task",
        events=[tampered_call],
        metadata={
            # Trusted catalog: kb_search should hash to "aa" * 32.
            "tool_catalog": {"kb_search": "aa" * 32},
        },
    )
