"""Async event-log + gate-decision writer (PRD §8.1).

Append-only writes of events and inline-gate decisions to Postgres, plus run upsert (a run row must
exist before its events, due to the FK). Backed by the async SQLAlchemy session from
:mod:`auditor.db.session`. The async detector pipeline's trace loader lands in Phase 4.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from auditor.db.models import Event as EventRow
from auditor.db.models import Flag as FlagRow
from auditor.db.models import GateDecision as GateDecisionRow
from auditor.db.models import Run
from auditor.db.models import Verdict as VerdictRow
from auditor.db.session import get_sessionmaker
from auditor.detectors.base import Trace
from auditor.events.schemas import (
    BaseEvent,
    DnsQueryEvent,
    IntentDeclaration,
    InterAgentMessage,
    LLMCall,
    MemoryOp,
    SyscallConnect,
    SyscallExecve,
    SyscallOpenat,
    SyscallSendto,
    ToolCallEnd,
    ToolCallStart,
)
from auditor.ids import uuid7
from auditor.verdicts.aggregator import Flag
from auditor.verdicts.schemas import Verdict

# Reconstruct a stored row into the right event model, keyed on event_type.
_MODEL_BY_TYPE: dict[str, type[BaseEvent]] = {
    "tool_call.start": ToolCallStart,
    "tool_call.end": ToolCallEnd,
    "llm.call": LLMCall,
    "memory.read": MemoryOp,
    "memory.write": MemoryOp,
    "agent.message": InterAgentMessage,
    "intent.declare": IntentDeclaration,
    "syscall.openat": SyscallOpenat,
    "syscall.connect": SyscallConnect,
    "syscall.execve": SyscallExecve,
    "syscall.sendto": SyscallSendto,
    "syscall.dns": DnsQueryEvent,
}
_HEX_FIELDS = ("messages_hash", "signature", "message_hash")

_BASE_KEYS = {
    "event_id", "run_id", "tenant_id", "span_id", "parent_span_id",
    "channel", "event_type", "ts_unix_ns", "pid",
}


def payload_hash(payload: dict) -> bytes:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).digest()


async def upsert_run(run_id: UUID, tenant_id: UUID, *, declared_goal: str | None = None) -> None:
    """Create the run row if it does not exist (events FK-reference it)."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        if await session.get(Run, run_id) is None:
            session.add(
                Run(run_id=run_id, tenant_id=tenant_id, status="running", declared_goal=declared_goal)
            )


async def mark_run_completed(run_id: UUID) -> None:
    """Mark a run completed (status + ended_at) when the harness disconnects."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        run = await session.get(Run, run_id)
        if run is not None and run.status == "running":
            run.status = "completed"
            run.ended_at = datetime.now(tz=UTC)


async def update_run_declared_goal(run_id: UUID, declared_goal: str) -> None:
    """Record the user's instruction as the run's declared_goal (called on intent.declare)."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        run = await session.get(Run, run_id)
        if run is not None and not run.declared_goal:
            run.declared_goal = declared_goal[:1000]


async def store_event(event: dict, ts: datetime) -> UUID:
    """Persist one event; returns its event_id. Base fields become columns, the rest become payload."""
    payload = {k: v for k, v in event.items() if k not in _BASE_KEYS}
    event_id = UUID(event["event_id"]) if event.get("event_id") else uuid7()
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        session.add(
            EventRow(
                event_id=event_id,
                run_id=UUID(event["run_id"]),
                tenant_id=UUID(event["tenant_id"]),
                span_id=UUID(event["span_id"]),
                parent_span_id=UUID(event["parent_span_id"]) if event.get("parent_span_id") else None,
                channel=event["channel"],
                event_type=event["event_type"],
                ts=ts,
                pid=event.get("pid"),
                payload=payload,
                payload_hash=payload_hash(payload),
            )
        )
    return event_id


async def store_gate_decision(event_id: UUID, decision: str, votes: dict, latency_ms: int) -> UUID:
    """Persist a gate decision row referencing its event."""
    decision_id = uuid7()
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        session.add(
            GateDecisionRow(
                decision_id=decision_id,
                event_id=event_id,
                decision=decision,
                detectors=votes,
                latency_ms=latency_ms,
            )
        )
    return decision_id


def _row_to_event(row: EventRow) -> BaseEvent | None:
    model = _MODEL_BY_TYPE.get(row.event_type)
    if model is None:
        return None
    data: dict = {
        "event_id": str(row.event_id),
        "run_id": str(row.run_id),
        "tenant_id": str(row.tenant_id),
        "span_id": str(row.span_id),
        "parent_span_id": str(row.parent_span_id) if row.parent_span_id else None,
        "channel": row.channel,
        "event_type": row.event_type,
        "ts": row.ts,
        "pid": row.pid,
    }
    allowed = set(model.model_fields)
    for key, value in (row.payload or {}).items():
        if key in allowed:
            data[key] = value
    for field in _HEX_FIELDS:
        if isinstance(data.get(field), str):
            try:
                data[field] = bytes.fromhex(data[field])
            except ValueError:
                data[field] = data[field].encode()
    try:
        return model.model_validate(data)
    except Exception:  # noqa: BLE001 - skip a malformed row rather than fail the whole trace
        return None


async def load_trace(run_id: UUID, tenant_id: UUID) -> Trace:
    """Materialize a run's persisted events into a Trace for the detector pipeline (§9.6.2)."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(
            select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.ts)
        )
        rows = list(result.scalars().all())
        run = await session.get(Run, run_id)
    events = [e for e in (_row_to_event(r) for r in rows) if e is not None]
    metadata = dict(run.run_metadata) if run and run.run_metadata else {}
    declared_goal = run.declared_goal if run else None
    return Trace(
        run_id=run_id, tenant_id=tenant_id, declared_goal=declared_goal, events=events, metadata=metadata
    )


def _verdict_evidence_json(verdict: Verdict) -> list[dict]:
    return [
        {"event_id": str(e.event_id) if e.event_id else None, "reason": e.reason}
        for e in verdict.evidence
    ]


async def store_run_result(verdicts: list[Verdict], flag: Flag | None) -> None:
    """Persist a run's detector verdicts (and the aggregated flag, if any) in one transaction (§9.9)."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        for v in verdicts:
            session.add(
                VerdictRow(
                    verdict_id=v.verdict_id,
                    run_id=v.run_id,
                    tenant_id=v.tenant_id,
                    detector=v.detector,
                    asi_category=v.asi_category,
                    result=v.result.value,
                    confidence=v.confidence,
                    evidence=_verdict_evidence_json(v),
                    judge_model=v.judge_model,
                    judge_prompt_v=v.judge_prompt_v,
                    rubric_scores=v.rubric_scores,
                    ts=v.ts,
                )
            )
        if flag is not None:
            session.add(
                FlagRow(
                    flag_id=flag.flag_id,
                    run_id=flag.run_id,
                    tenant_id=flag.tenant_id,
                    severity=flag.severity.value,
                    asi_categories=list(flag.asi_categories),
                    verdict_ids=list(flag.verdict_ids),
                    status=flag.status,
                    created_at=flag.created_at,
                )
            )
            # A High/Critical flag automatically opens an incident (§9.10.5). SQLAlchemy orders the
            # Flag insert before the Incident (FK dependency), so both commit in this one transaction.
            from auditor.incidents.service import open_incident_for_flag

            incident = open_incident_for_flag(flag)
            if incident is not None:
                session.add(incident)


__all__ = [
    "payload_hash",
    "upsert_run",
    "mark_run_completed",
    "store_event",
    "store_gate_decision",
    "load_trace",
    "store_run_result",
]
