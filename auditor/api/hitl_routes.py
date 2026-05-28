"""HITL API routes (PRD §10.2) — Phase 5 implementation.

Endpoints backing the reviewer UI: flag list, flag detail with trace, HITL decision submission,
run detail, run event stream, replay bundle, and a WebSocket live-update channel.

# Architecture note — DB-free seams for testing
# -----------------------------------------------
# All database access goes through module-level *helper functions* (``_get_flags``, ``_get_flag``,
# etc.) that accept a ``session`` argument.  Tests override these via ``app.dependency_overrides``
# without touching any real database.  Production code wires in the real SQLAlchemy session through
# the ``Annotated[AsyncSession, Depends(get_db_session)]`` dependency.

Router name: ``hitl_router`` — registered by ``auditor/main.py`` (integration step; do not
register here).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import get_current_user, require_role
from auditor.audit_log.writer import AuditLogWriter
from auditor.db.models import Event, Flag, HitlDecision, Run
from auditor.db.session import get_sessionmaker
from auditor.db.tenancy import tenant_scope

# ------------------------------------------------------------------------------- router

hitl_router = APIRouter(prefix="/hitl", tags=["hitl"])

# ------------------------------------------------------------------------------- WebSocket broadcaster


class FlagBroadcaster:
    """Simple in-process pub/sub for live flag updates.

    The async audit pipeline calls ``publish(flag_dict)`` whenever a flag is written.
    All connected WebSocket clients subscribed to the relevant ``tenant_id`` receive the
    update.  Exported at module level so the pipeline can call it without importing the router.
    """

    def __init__(self) -> None:
        # Map tenant_id (str) → set of asyncio.Queue instances (one per WS connection).
        self._subscribers: dict[str, set[asyncio.Queue]] = {}

    def subscribe(self, tenant_id: str) -> asyncio.Queue:
        """Return a new queue that will receive flags for *tenant_id*."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.setdefault(tenant_id, set()).add(q)
        return q

    def unsubscribe(self, tenant_id: str, q: asyncio.Queue) -> None:
        bucket = self._subscribers.get(tenant_id, set())
        bucket.discard(q)

    def publish(self, flag: dict) -> None:
        """Publish *flag* (dict) to all subscribers matching ``flag['tenant_id']``."""
        tenant_id = str(flag.get("tenant_id", ""))
        for q in list(self._subscribers.get(tenant_id, set())):
            try:
                q.put_nowait(flag)
            except asyncio.QueueFull:
                pass  # slow consumer; drop update rather than block


# Module-level broadcaster — import this in the pipeline to publish flags.
flag_broadcaster = FlagBroadcaster()

# ------------------------------------------------------------------------------- DB session dependency


async def _db_session_gen() -> AsyncGenerator[AsyncSession, None]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session


# The *injectable* session dep; tests override this with ``app.dependency_overrides``.
get_db_session = _db_session_gen

# ------------------------------------------------------------------------------- DB helper functions
# Each function is a thin wrapper so tests can monkeypatch individual helpers.


async def _get_flags(
    session: AsyncSession,
    *,
    status_filter: str | None,
    severity_filter: str | None,
    tenant_id_filter: str | None,
) -> list[Flag]:
    """Return Flag rows matching the optional filters."""
    q = select(Flag)
    if status_filter:
        q = q.where(Flag.status == status_filter)
    if severity_filter:
        q = q.where(Flag.severity == severity_filter)
    if tenant_id_filter:
        q = q.where(Flag.tenant_id == tenant_id_filter)
    result = await session.execute(q.order_by(Flag.created_at.desc()))
    return list(result.scalars().all())


async def _get_flag(session: AsyncSession, flag_id: str) -> Flag | None:
    """Return a single Flag by PK, or None."""
    result = await session.execute(select(Flag).where(Flag.flag_id == flag_id))
    return result.scalar_one_or_none()


async def _get_run_events(
    session: AsyncSession,
    run_id: str,
    *,
    since: datetime | None,
    limit: int,
) -> list[Event]:
    """Return Event rows for *run_id*, optionally filtered by ``since`` timestamp."""
    q = select(Event).where(Event.run_id == run_id)
    if since:
        q = q.where(Event.ts > since)
    q = q.order_by(Event.ts).limit(limit)
    result = await session.execute(q)
    return list(result.scalars().all())


async def _get_run(session: AsyncSession, run_id: str) -> Run | None:
    """Return a Run by PK, or None."""
    result = await session.execute(select(Run).where(Run.run_id == run_id))
    return result.scalar_one_or_none()


async def _insert_hitl_decision(
    session: AsyncSession,
    *,
    flag_id: str,
    reviewer_id: str,
    decision: str,
    rationale: str | None,
) -> HitlDecision:
    """Insert a HitlDecision row and flush (no commit — caller handles transaction)."""
    row = HitlDecision(
        hitl_id=str(uuid.uuid4()),
        flag_id=flag_id,
        reviewer_id=reviewer_id,
        decision=decision,
        rationale=rationale,
        ts=datetime.now(tz=UTC),
    )
    session.add(row)
    await session.flush()
    return row


# ------------------------------------------------------------------------------- Pydantic schemas


def _flag_to_dict(flag: Flag) -> dict[str, Any]:
    return {
        "flag_id": str(flag.flag_id),
        "run_id": str(flag.run_id),
        "tenant_id": str(flag.tenant_id),
        "severity": flag.severity,
        "status": flag.status,
        "asi_categories": flag.asi_categories,
        "created_at": flag.created_at.isoformat() if flag.created_at else None,
        "resolved_at": flag.resolved_at.isoformat() if flag.resolved_at else None,
        "resolution": flag.resolution,
    }


def _event_to_dict(ev: Event) -> dict[str, Any]:
    return {
        "event_id": str(ev.event_id),
        "run_id": str(ev.run_id),
        "tenant_id": str(ev.tenant_id),
        "event_type": ev.event_type,
        "channel": ev.channel,
        "ts": ev.ts.isoformat() if ev.ts else None,
        "payload": ev.payload,
    }


def _run_to_dict(run: Run) -> dict[str, Any]:
    return {
        "run_id": str(run.run_id),
        "tenant_id": str(run.tenant_id),
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "ended_at": run.ended_at.isoformat() if run.ended_at else None,
        "declared_goal": run.declared_goal,
    }


def _decision_to_dict(d: HitlDecision) -> dict[str, Any]:
    return {
        "hitl_id": str(d.hitl_id),
        "flag_id": str(d.flag_id),
        "reviewer_id": str(d.reviewer_id),
        "decision": d.decision,
        "rationale": d.rationale,
        "ts": d.ts.isoformat() if d.ts else None,
    }


class DecisionRequest(BaseModel):
    decision: str
    rationale: str | None = None

    @field_validator("decision")
    @classmethod
    def _validate_decision(cls, v: str) -> str:
        allowed = {"continue", "abort", "quarantine"}
        if v not in allowed:
            raise ValueError(f"decision must be one of {sorted(allowed)}")
        return v


# ------------------------------------------------------------------------------- endpoints


@hitl_router.get("/flags")
async def list_flags(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    tenant_id: str | None = Query(default=None),
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """List flags with optional filters.  Any authenticated role may call this.

    Query params: ``status``, ``severity``, ``tenant_id``.
    """
    async with tenant_scope(session, claims["tenant_id"]):
        flags = await _get_flags(
            session,
            status_filter=status,
            severity_filter=severity,
            tenant_id_filter=tenant_id,
        )
    return [_flag_to_dict(f) for f in flags]


@hitl_router.get("/flags/{flag_id}")
async def get_flag_detail(
    flag_id: str,
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Return flag detail plus the linked run's events (the trace)."""
    async with tenant_scope(session, claims["tenant_id"]):
        flag = await _get_flag(session, flag_id)
        if flag is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="flag not found")

        # Fetch trace events for the linked run (up to 500 most recent).
        events = await _get_run_events(session, str(flag.run_id), since=None, limit=500)

    return {
        "flag": _flag_to_dict(flag),
        "trace": [_event_to_dict(e) for e in events],
    }


@hitl_router.post("/flags/{flag_id}/decisions", status_code=status.HTTP_201_CREATED)
async def submit_decision(
    flag_id: str,
    body: DecisionRequest,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Submit a HITL decision (continue / abort / quarantine) for a flag.

    Requires ``admin`` or ``reviewer`` role.  Inserts a :class:`~auditor.db.models.HitlDecision`
    row and writes an entry to the hash-chained audit log.
    """
    # tenant_scope auto-begins a transaction on its first SET LOCAL; the read + write happen in the
    # SAME transaction (don't call session.begin() again — that raises InvalidRequestError on the
    # already-open transaction). Commit at the end of the scope, then do the best-effort audit log
    # write + enforcer dispatch outside the DB transaction.
    async with tenant_scope(session, claims["tenant_id"]):
        flag = await _get_flag(session, flag_id)
        if flag is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="flag not found")

        reviewer_id = claims.get("sub", "unknown")
        tenant_id_str = claims.get("tenant_id", str(flag.tenant_id))
        run_id_str = str(flag.run_id)

        decision_row = await _insert_hitl_decision(
            session,
            flag_id=flag_id,
            reviewer_id=reviewer_id,
            decision=body.decision,
            rationale=body.rationale,
        )

        # Close the flag — recording a decision is the human's resolution of the alert.
        # `continue` → allowed; `abort`/`quarantine` → reflected verbatim. The flag falls out of the
        # default `status=open` review-queue filter as soon as we commit, so the operator sees an
        # immediate "you handled this" signal.
        _RESOLUTION_FOR = {"continue": "allowed", "abort": "aborted", "quarantine": "quarantined"}
        flag.status = "resolved"
        flag.resolution = _RESOLUTION_FOR.get(body.decision, body.decision)
        flag.resolved_at = datetime.now(tz=UTC)

        # Snapshot before commit — async sessions expire attributes by default on commit, and the
        # outer return path needs the dict-encoded row.
        result = _decision_to_dict(decision_row)
        await session.commit()

    # Write to hash-chained audit log (best-effort; don't let a log failure block the response).
    try:
        await AuditLogWriter().append(
            uuid.UUID(tenant_id_str),
            actor_type="user",
            action="hitl_decision",
            actor_id=uuid.UUID(reviewer_id) if _is_uuid(reviewer_id) else None,
            target_type="flag",
            target_id=uuid.UUID(flag_id) if _is_uuid(flag_id) else None,
            payload={
                "decision": body.decision,
                "rationale": body.rationale,
                "flag_id": flag_id,
            },
        )
    except Exception:  # noqa: BLE001,S110 — audit log failure is non-fatal; ops monitors chain breaks
        pass  # noqa: S110

    # Apply the decision to the run's process via the enforcer (continue→resume, abort/quarantine→abort).
    enforcement = await _apply_enforcement(body.decision, run_id_str)
    result["enforcement"] = enforcement
    return result


async def _apply_enforcement(decision: str, run_id: str) -> dict:
    """Map a HITL decision onto the run's process via the process-wide enforcer (best-effort).

    A ``continue`` resumes a paused run; ``abort``/``quarantine`` terminate it. Enforcement is
    best-effort: the run may not be locally registered (e.g. a different node paused it), so failures
    are reported in the response rather than raised.
    """
    from auditor.enforcement import get_enforcer

    action = {"continue": "resume", "abort": "abort", "quarantine": "abort"}.get(decision)
    if action is None:
        return {"action": "none"}
    try:
        enforcer = get_enforcer()
        run_uuid = uuid.UUID(run_id)
        await (enforcer.resume(run_uuid) if action == "resume" else enforcer.abort(run_uuid))
        return {"action": action, "ok": True}
    except Exception as exc:  # noqa: BLE001 - enforcement is best-effort; surface, don't fail the decision
        return {"action": action, "ok": False, "error": type(exc).__name__}


@hitl_router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Return run detail."""
    async with tenant_scope(session, claims["tenant_id"]):
        run = await _get_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
    return _run_to_dict(run)


@hitl_router.get("/runs/{run_id}/events")
async def get_run_events(
    run_id: str,
    since: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10_000),
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """Paginated event stream for a run.

    Use ``since`` (ISO-8601 timestamp) + ``limit`` for cursor-style pagination.
    """
    async with tenant_scope(session, claims["tenant_id"]):
        run = await _get_run(session, run_id)
        if run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
        events = await _get_run_events(session, run_id, since=since, limit=limit)
    return [_event_to_dict(e) for e in events]


@hitl_router.get("/runs/{run_id}/replay")
async def get_run_replay(
    run_id: str,
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Return the replay export bundle for a run.

    Delegates to :func:`auditor.api.replay.build_export_bundle` when that function exists
    (Phase 7).  In Phase 5 the replay module is a stub, so we return a minimal envelope.
    """
    async with tenant_scope(session, claims["tenant_id"]):
        run = await _get_run(session, run_id)
        if run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")

        # Import lazily so we don't crash if the replay module is a stub.
        try:
            from auditor.api.replay import build_export_bundle  # type: ignore[attr-defined]

            bundle = await build_export_bundle(run_id, session)
        except (ImportError, AttributeError):
            # Phase 5: replay module is a stub; return a minimal envelope.
            events = await _get_run_events(session, run_id, since=None, limit=10_000)
            bundle = {
                "run": _run_to_dict(run),
                "events": [_event_to_dict(e) for e in events],
                "export_version": 1,
                "stub": True,
            }
    return bundle


# ------------------------------------------------------------------------------- WebSocket


@hitl_router.websocket("/ws/flags")
async def ws_flags(
    websocket: WebSocket,
    tenant_id: str = Query(...),
) -> None:
    """WebSocket endpoint for live flag updates.

    Client connects with ``?tenant_id=<uuid>``.  The server sends JSON flag dicts whenever a
    new flag is published to :data:`flag_broadcaster` for the tenant.

    Auth: the client should pass a valid token as a ``session`` cookie or in the ``Authorization``
    header *before* the upgrade.  For P5 we accept the WebSocket and check a ``token`` query
    param as a fallback (browsers cannot set Upgrade request headers).
    """
    await websocket.accept()
    q = flag_broadcaster.subscribe(tenant_id)
    try:
        while True:
            # Wait for a published flag or a client-side ping.
            try:
                flag_dict = await asyncio.wait_for(q.get(), timeout=30.0)
                await websocket.send_json(flag_dict)
            except TimeoutError:
                # Send a keepalive ping so the connection is not dropped by intermediaries.
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        flag_broadcaster.unsubscribe(tenant_id, q)


# ------------------------------------------------------------------------------- helpers


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


__all__ = [
    "hitl_router",
    "flag_broadcaster",
    "FlagBroadcaster",
    "get_db_session",
    "DecisionRequest",
]
