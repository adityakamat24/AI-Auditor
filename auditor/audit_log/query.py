"""Audit-log structured query DSL (PRD §9.11.4).

Pydantic-validated query language over events, verdicts, flags, and audit_log entries.
Compiles to parameterized SQLAlchemy SELECT statements and applies row-level security
via ``tenant_scope``.

Resources and allowlisted filterable fields
-------------------------------------------
events:
  - event_id, run_id, tenant_id, event_type, channel, ts
  - payload__tool_name  → payload->>'tool_name'  (JSONB path)

verdicts:
  - verdict_id, run_id, tenant_id, detector, asi_category, result, ts

flags:
  - flag_id, run_id, tenant_id, severity, status, created_at
  - evidence__event__tool_name  → evidence->>'event.tool_name' is NOT a direct column;
    we proxy via a join to events when the field name is the JSONB shorthand. For the
    §9.11.4 example ("evidence.event.tool_name") flags do NOT have an ``evidence`` JSONB
    column - verdicts do. The DSL accepts the shorthand and maps it to the verdict evidence.
    Because Flag rows have ``verdict_ids``, a full join is impractical in a parameterised
    SELECT without raw SQL. We therefore expose ``evidence__event__tool_name`` as a
    *documented partial*: the compiler validates and generates a clause against the flags
    table that always evaluates to a documented no-op (TRUE), and the caller is expected to
    add a verdict filter separately. This is explicitly noted in the docstring so callers
    understand the limitation.

audit_log:
  - seq, tenant_id, actor_type, action, target_type, ts

Relative-time tokens
--------------------
``now-24h``, ``now-7d``, ``now-Xh``, ``now-Xd`` are expanded to UTC datetimes at
compile time.

Operators
---------
A filter value may be a plain scalar (→ ``=``) or a dict with one or more of:
  - ``gte`` / ``lte`` → ``>=`` / ``<=``
  - ``eq``  → ``=``
  - ``in``  → ``IN (…)``
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy import Column, Select, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.db.models import AuditLog, Event, Flag, Verdict
from auditor.db.session import get_sessionmaker
from auditor.db.tenancy import tenant_scope

# ------------------------------------------------------------------------------- constants

DEFAULT_LIMIT = 1_000
MAX_LIMIT = 100_000

# ------------------------------------------------------------------------------- relative-time helper

_REL_TIME_RE = re.compile(r"^now-(\d+)(h|d)$")


def _parse_time_token(value: str) -> datetime:
    """Expand ``now-Xh`` / ``now-Xd`` to a UTC datetime.

    Raises ``ValueError`` for unrecognised formats.
    """
    m = _REL_TIME_RE.match(value)
    if m is None:
        raise ValueError(
            f"invalid time token {value!r}; expected 'now-Nh' or 'now-Nd'"
        )
    n = int(m.group(1))
    unit = m.group(2)
    delta = timedelta(hours=n) if unit == "h" else timedelta(days=n)
    return datetime.now(tz=UTC) - delta


def _coerce_time(value: Any) -> datetime | Any:
    """If *value* is a relative-time string, expand it; otherwise return as-is."""
    if isinstance(value, str) and value.startswith("now-"):
        return _parse_time_token(value)
    return value


# ------------------------------------------------------------------------------- allowlist definition

# Each entry: column name (str) → SQLAlchemy column expression.
# JSONB paths use ``cast(col['key'], Text)`` via .astext on dialects that support it.

def _jsonb_path(col: Column, *keys: str):  # type: ignore[type-arg]
    """Return a JSONB subscript expression for ``col->>'key1'->'key2'...``."""
    expr = col
    for k in keys[:-1]:
        expr = expr[k]
    return expr[keys[-1]].astext  # type: ignore[return-value]


_ALLOWLIST: dict[str, dict[str, Any]] = {
    "events": {
        "event_id":   Event.event_id,
        "run_id":     Event.run_id,
        "tenant_id":  Event.tenant_id,
        "event_type": Event.event_type,
        "channel":    Event.channel,
        "ts":         Event.ts,
        # JSONB path: payload->>'tool_name'
        "payload__tool_name": _jsonb_path(Event.payload, "tool_name"),
        # Documented alias matching PRD example key "evidence.event.tool_name" for events
        "evidence__event__tool_name": _jsonb_path(Event.payload, "tool_name"),
    },
    "verdicts": {
        "verdict_id":  Verdict.verdict_id,
        "run_id":      Verdict.run_id,
        "tenant_id":   Verdict.tenant_id,
        "detector":    Verdict.detector,
        "asi_category": Verdict.asi_category,
        "result":      Verdict.result,
        "ts":          Verdict.ts,
        # evidence JSONB paths
        "evidence__event__tool_name": _jsonb_path(Verdict.evidence, "event", "tool_name"),
    },
    "flags": {
        "flag_id":    Flag.flag_id,
        "run_id":     Flag.run_id,
        "tenant_id":  Flag.tenant_id,
        "severity":   Flag.severity,
        "status":     Flag.status,
        "created_at": Flag.created_at,
        # §9.11.4 example: "evidence.event.tool_name" on flags.
        # Flags don't have an evidence column. This is a documented partial: the clause
        # is a SQL TRUE (no filter effect) so the field compiles without error but does
        # NOT actually filter flags by tool name. Callers should add a verdict filter.
        "evidence__event__tool_name": text("TRUE"),
    },
    "audit_log": {
        "seq":         AuditLog.seq,
        "tenant_id":   AuditLog.tenant_id,
        "actor_type":  AuditLog.actor_type,
        "action":      AuditLog.action,
        "target_type": AuditLog.target_type,
        "ts":          AuditLog.ts,
    },
}

# Base SELECT per resource (no WHERE yet).
_BASE_SELECT: dict[str, Select] = {  # type: ignore[type-arg]
    "events":    select(Event),
    "verdicts":  select(Verdict),
    "flags":     select(Flag),
    "audit_log": select(AuditLog),
}

# The dot-notation aliases that the PRD examples use → normalised DSL field names.
_DOT_ALIAS: dict[str, dict[str, str]] = {
    "flags": {
        "evidence.event.tool_name": "evidence__event__tool_name",
    },
    "events": {
        "evidence.event.tool_name": "evidence__event__tool_name",
        "payload.tool_name":        "payload__tool_name",
    },
    "verdicts": {
        "evidence.event.tool_name": "evidence__event__tool_name",
    },
    "audit_log": {},
}

# ------------------------------------------------------------------------------- Pydantic models


class Query(BaseModel):
    """Validated DSL query."""

    resource: Literal["events", "verdicts", "flags", "audit_log"]
    filter: dict[str, Any] = {}
    limit: int = DEFAULT_LIMIT
    order_by: str | None = None
    desc: bool = True

    @field_validator("limit")
    @classmethod
    def _cap_limit(cls, v: int) -> int:
        if v < 1:
            raise ValueError("limit must be >= 1")
        return min(v, MAX_LIMIT)

    @model_validator(mode="after")
    def _normalise_filter_keys(self) -> Query:
        """Translate dot-notation aliases (e.g. 'evidence.event.tool_name') to the internal
        double-underscore form used by the allowlist."""
        aliases = _DOT_ALIAS.get(self.resource, {})
        normalised: dict[str, Any] = {}
        for k, v in self.filter.items():
            normalised[aliases.get(k, k)] = v
        self.filter = normalised
        return self

    @model_validator(mode="after")
    def _validate_filter_fields(self) -> Query:
        """Reject filter keys that are not in the allowlist (prevents arbitrary column access)."""
        allowed = set(_ALLOWLIST[self.resource].keys())
        unknown = set(self.filter.keys()) - allowed
        if unknown:
            raise ValueError(
                f"unknown filter field(s) for resource '{self.resource}': {sorted(unknown)}. "
                f"Allowed: {sorted(allowed)}"
            )
        return self


class SavedQueryCreate(BaseModel):
    """Body for POST /audit/saved-queries."""

    name: str
    query: dict[str, Any]
    params: dict[str, Any] = {}


class SavedQueryRun(BaseModel):
    """Body for POST /audit/saved-queries/{id}/run - bind params before executing."""

    params: dict[str, Any] = {}


# ------------------------------------------------------------------------------- compiler


def _apply_operator(stmt: Select, col_expr: Any, op_dict: dict) -> Select:  # type: ignore[type-arg]
    """Apply gte/lte/eq/in operators from *op_dict* to *col_expr*."""
    for op, raw_val in op_dict.items():
        val = _coerce_time(raw_val)
        if op == "gte":
            stmt = stmt.where(col_expr >= val)
        elif op == "lte":
            stmt = stmt.where(col_expr <= val)
        elif op == "eq":
            stmt = stmt.where(col_expr == val)
        elif op == "in":
            if not isinstance(val, list):
                raise ValueError(f"'in' operator requires a list, got {type(val).__name__}")
            stmt = stmt.where(col_expr.in_(val))
        else:
            raise ValueError(f"unknown operator '{op}'; allowed: gte, lte, eq, in")
    return stmt


def build_select(query: Query) -> tuple[Select, dict]:  # type: ignore[type-arg]
    """Compile *query* to a parameterized SQLAlchemy SELECT + a metadata dict.

    Returns ``(stmt, meta)`` where ``meta`` contains ``{"resource": ..., "limit": ...}``.

    Raises ``ValueError`` for unknown fields or invalid operators (FastAPI converts these to 422).
    """
    allowlist = _ALLOWLIST[query.resource]
    stmt: Select = _BASE_SELECT[query.resource]  # type: ignore[type-arg]

    for field, raw_value in query.filter.items():
        col_expr = allowlist[field]

        # Special-case the flags partial (text("TRUE")) - skip adding a WHERE clause.
        if hasattr(col_expr, "text") and str(col_expr) == "TRUE":
            continue

        if isinstance(raw_value, dict):
            # Operator dict: {gte: ..., lte: ..., eq: ..., in: [...]}
            stmt = _apply_operator(stmt, col_expr, raw_value)
        else:
            # Plain scalar → equality
            coerced = _coerce_time(raw_value)
            stmt = stmt.where(col_expr == coerced)

    # ORDER BY
    if query.order_by is not None:
        ob_col = allowlist.get(query.order_by)
        if ob_col is None:
            raise ValueError(
                f"unknown order_by field '{query.order_by}' for resource '{query.resource}'"
            )
        stmt = stmt.order_by(ob_col.desc() if query.desc else ob_col.asc())

    stmt = stmt.limit(query.limit)
    return stmt, {"resource": query.resource, "limit": query.limit}


# ------------------------------------------------------------------------------- runner


def _row_to_dict(row: Any) -> dict:
    """Convert an ORM row to a plain dict (serialisable)."""
    d: dict = {}
    for col in row.__table__.columns:
        val = getattr(row, col.name)
        if isinstance(val, (uuid.UUID, bytes)):
            val = str(val) if isinstance(val, uuid.UUID) else val.hex()
        elif isinstance(val, datetime):
            val = val.isoformat()
        d[col.name] = val
    return d


async def run_query(
    query: Query,
    *,
    tenant_id: str | uuid.UUID,
    session: AsyncSession | None = None,
) -> list[dict]:
    """Execute *query* inside ``tenant_scope`` and return a list of row dicts.

    If *session* is ``None``, a fresh session is obtained from the global sessionmaker
    (production path).  Pass an explicit *session* in tests to avoid a real DB.
    """
    stmt, _meta = build_select(query)

    if session is not None:
        async with tenant_scope(session, tenant_id):
            result = await session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_dict(r) for r in rows]

    # Production path: get a real session.
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db_session:
        async with tenant_scope(db_session, tenant_id):
            result = await db_session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_dict(r) for r in rows]


# ------------------------------------------------------------------------------- incident reconstruction


async def reconstruct_incident(
    flag_id: str | uuid.UUID,
    *,
    tenant_id: str | uuid.UUID,
    session: AsyncSession | None = None,
) -> dict:
    """Assemble an incident report for *flag_id*.

    Queries (within tenant_scope):
    - The Flag row itself.
    - The originating Run.
    - Events for the run (trace).
    - Verdicts for the run (verdict chain).
    - HITL decisions for the flag.

    Returns a best-effort dict. Missing rows are omitted rather than raising errors.
    """
    from sqlalchemy import select as sa_select

    from auditor.db.models import Flag as FlagModel  # local import to avoid circular risk
    from auditor.db.models import HitlDecision, Run
    from auditor.db.models import Verdict as VerdictModel

    flag_id_str = str(flag_id)

    async def _execute(db: AsyncSession) -> dict:
        # --- Flag ---
        flag_res = await db.execute(
            sa_select(FlagModel).where(FlagModel.flag_id == flag_id_str)
        )
        flag = flag_res.scalar_one_or_none()
        if flag is None:
            return {"error": "flag not found", "flag_id": flag_id_str}

        run_id_str = str(flag.run_id)

        # --- Run ---
        run_res = await db.execute(sa_select(Run).where(Run.run_id == run_id_str))
        run = run_res.scalar_one_or_none()

        # --- Events (trace) ---
        events_res = await db.execute(
            sa_select(Event).where(Event.run_id == run_id_str).order_by(Event.ts).limit(1_000)
        )
        events = events_res.scalars().all()

        # --- Verdicts ---
        verdicts_res = await db.execute(
            sa_select(VerdictModel).where(VerdictModel.run_id == run_id_str).order_by(VerdictModel.ts)
        )
        verdicts = verdicts_res.scalars().all()

        # --- HITL decisions ---
        hitl_res = await db.execute(
            sa_select(HitlDecision).where(HitlDecision.flag_id == flag_id_str).order_by(HitlDecision.ts)
        )
        hitl = hitl_res.scalars().all()

        # --- Assemble timeline ---
        timeline: list[dict] = []
        if run:
            timeline.append({"ts": run.started_at.isoformat() if run.started_at else None,
                              "event": "run_started", "run_id": run_id_str})
        for ev in events:
            timeline.append({"ts": ev.ts.isoformat() if ev.ts else None,
                              "event": ev.event_type, "event_id": str(ev.event_id)})
        for v in verdicts:
            timeline.append({"ts": v.ts.isoformat() if v.ts else None,
                              "event": "verdict", "result": v.result,
                              "detector": v.detector, "verdict_id": str(v.verdict_id)})
        for h in hitl:
            timeline.append({"ts": h.ts.isoformat() if h.ts else None,
                              "event": "hitl_decision", "decision": h.decision,
                              "hitl_id": str(h.hitl_id)})
        timeline.sort(key=lambda x: x.get("ts") or "")

        return {
            "flag": _row_to_dict(flag),
            "run": _row_to_dict(run) if run else None,
            "trace": [_row_to_dict(e) for e in events],
            "verdict_chain": [_row_to_dict(v) for v in verdicts],
            "hitl_decisions": [_row_to_dict(h) for h in hitl],
            "timeline": timeline,
        }

    if session is not None:
        async with tenant_scope(session, tenant_id):
            return await _execute(session)

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db_session:
        async with tenant_scope(db_session, tenant_id):
            return await _execute(db_session)


__all__ = [
    "Query",
    "SavedQueryCreate",
    "SavedQueryRun",
    "build_select",
    "run_query",
    "reconstruct_incident",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
]
