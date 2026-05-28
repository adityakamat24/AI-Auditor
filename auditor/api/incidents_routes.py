"""Incident API routes (PRD §9.10.5) - Phase 8 implementation.

Endpoints:
  GET  /incidents                      list incidents (filter by state/severity)
  GET  /incidents/{id}                 detail + comments + action items + similar
  POST /incidents/{id}/transition      move through lifecycle (RBAC enforced)
  POST /incidents/{id}/comments        add a comment
  POST /incidents/{id}/action-items    add an action item

Router name: ``incident_router`` - registered by ``auditor/main.py``; do NOT call
``app.include_router`` here.

Architecture note - DB-free seams for testing
---------------------------------------------
All database access goes through module-level helper functions (``_get_incident``,
``_list_incidents``, etc.) that accept a ``session`` argument.  Tests override the
``get_db_session`` dependency via ``app.dependency_overrides`` without touching any real
database - the same pattern as ``hitl_routes.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import get_current_user, require_role
from auditor.audit_log.writer import AuditLogWriter
from auditor.db.models import Incident, IncidentActionItem, IncidentComment
from auditor.db.session import get_sessionmaker
from auditor.incidents.lifecycle import IncidentStateMachine, IncidentTransitionError
from auditor.incidents.service import build_action_item, build_comment, find_similar

# ------------------------------------------------------------------------------- router

incident_router = APIRouter(prefix="/incidents", tags=["incidents"])

# ------------------------------------------------------------------------------- DB session dependency


async def _db_session_gen() -> AsyncGenerator[AsyncSession, None]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session


# The injectable session dep; tests override this with ``app.dependency_overrides``.
get_db_session = _db_session_gen

# ------------------------------------------------------------------------------- DB helpers


async def _list_incidents(
    session: AsyncSession,
    *,
    state_filter: str | None,
    severity_filter: str | None,
    tenant_id: str | None,
) -> list[Incident]:
    q = select(Incident)
    if state_filter:
        q = q.where(Incident.state == state_filter)
    if severity_filter:
        q = q.where(Incident.severity == severity_filter)
    if tenant_id:
        q = q.where(Incident.tenant_id == tenant_id)
    q = q.order_by(Incident.opened_at.desc())
    result = await session.execute(q)
    return list(result.scalars().all())


async def _get_incident(session: AsyncSession, incident_id: str) -> Incident | None:
    result = await session.execute(
        select(Incident).where(Incident.incident_id == incident_id)
    )
    return result.scalar_one_or_none()


async def _get_comments(session: AsyncSession, incident_id: str) -> list[IncidentComment]:
    result = await session.execute(
        select(IncidentComment)
        .where(IncidentComment.incident_id == incident_id)
        .order_by(IncidentComment.ts)
    )
    return list(result.scalars().all())


async def _get_action_items(session: AsyncSession, incident_id: str) -> list[IncidentActionItem]:
    result = await session.execute(
        select(IncidentActionItem)
        .where(IncidentActionItem.incident_id == incident_id)
        .order_by(IncidentActionItem.created_at)
    )
    return list(result.scalars().all())


async def _get_recent_incidents(
    session: AsyncSession, tenant_id: str, exclude_id: str
) -> list[Incident]:
    """Return recent incidents for the same tenant (for similarity search)."""
    result = await session.execute(
        select(Incident)
        .where(Incident.tenant_id == tenant_id)
        .where(Incident.incident_id != exclude_id)
        .order_by(Incident.opened_at.desc())
        .limit(100)
    )
    return list(result.scalars().all())


async def _insert_comment(
    session: AsyncSession, *, incident_id: str, author_id: str, body: str
) -> IncidentComment:
    comment = build_comment(incident_id=incident_id, author_id=author_id, body=body)
    session.add(comment)
    await session.flush()
    return comment


async def _insert_action_item(
    session: AsyncSession,
    *,
    incident_id: str,
    owner_id: str | None,
    description: str,
    due_date: Any = None,
) -> IncidentActionItem:
    item = build_action_item(
        incident_id=incident_id,
        owner_id=owner_id,
        description=description,
        due_date=due_date,
    )
    session.add(item)
    await session.flush()
    return item


# ------------------------------------------------------------------------------- serializers


def _incident_to_dict(inc: Incident) -> dict[str, Any]:
    return {
        "incident_id": str(inc.incident_id),
        "tenant_id": str(inc.tenant_id),
        "primary_flag_id": str(inc.primary_flag_id),
        "severity": inc.severity,
        "state": inc.state,
        "assignee_id": str(inc.assignee_id) if inc.assignee_id else None,
        "opened_at": inc.opened_at.isoformat() if inc.opened_at else None,
        "triaged_at": inc.triaged_at.isoformat() if inc.triaged_at else None,
        "contained_at": inc.contained_at.isoformat() if inc.contained_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "post_mortem_uri": inc.post_mortem_uri,
        "dismissal_rationale": inc.dismissal_rationale,
    }


def _comment_to_dict(c: IncidentComment) -> dict[str, Any]:
    return {
        "comment_id": str(c.comment_id),
        "incident_id": str(c.incident_id),
        "author_id": str(c.author_id),
        "body": c.body,
        "ts": c.ts.isoformat() if c.ts else None,
    }


def _action_item_to_dict(a: IncidentActionItem) -> dict[str, Any]:
    return {
        "action_id": str(a.action_id),
        "incident_id": str(a.incident_id),
        "owner_id": str(a.owner_id) if a.owner_id else None,
        "description": a.description,
        "status": a.status,
        "due_date": a.due_date.isoformat() if a.due_date else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "completed_at": a.completed_at.isoformat() if a.completed_at else None,
    }


# ------------------------------------------------------------------------------- Pydantic schemas


class TransitionRequest(BaseModel):
    target: str
    rationale: str | None = None
    post_mortem_uri: str | None = None


class CommentRequest(BaseModel):
    body: str


class ActionItemRequest(BaseModel):
    description: str
    owner_id: str | None = None
    due_date: str | None = None  # ISO date string; parsed by the handler


# ------------------------------------------------------------------------------- helper


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------------------- endpoints


@incident_router.get("")
async def list_incidents(
    state: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """List incidents for the authenticated tenant, with optional state/severity filters."""
    incidents = await _list_incidents(
        session,
        state_filter=state,
        severity_filter=severity,
        tenant_id=claims["tenant_id"],
    )
    return [_incident_to_dict(i) for i in incidents]


@incident_router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Return incident detail plus comments, action items, and similar incidents."""
    incident = await _get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")

    comments = await _get_comments(session, incident_id)
    action_items = await _get_action_items(session, incident_id)
    recent = await _get_recent_incidents(session, str(incident.tenant_id), incident_id)
    similar_scored = find_similar(incident, recent)

    return {
        "incident": _incident_to_dict(incident),
        "comments": [_comment_to_dict(c) for c in comments],
        "action_items": [_action_item_to_dict(a) for a in action_items],
        "similar": [
            {"incident": _incident_to_dict(inc), "score": score}
            for inc, score in similar_scored[:10]
        ],
    }


@incident_router.post("/{incident_id}/transition", status_code=status.HTTP_200_OK)
async def transition_incident(
    incident_id: str,
    body: TransitionRequest,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Transition an incident to a new state.

    RBAC is enforced at two levels:
    1. The ``require_role`` dependency rejects ``readonly`` users with HTTP 403.
    2. ``IncidentStateMachine.transition`` further checks that the actor's role can
       perform the specific transition (e.g. only ``admin`` may reach RESOLVED /
       POST_MORTEM_COMPLETE).
    """
    incident = await _get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")

    actor_role = claims.get("role", "")
    actor_id = claims.get("sub", "")
    tenant_id_str = claims.get("tenant_id", str(incident.tenant_id))

    sm = IncidentStateMachine()
    try:
        sm.transition(
            incident,
            body.target,
            actor_role=actor_role,
            post_mortem_uri=body.post_mortem_uri,
            rationale=body.rationale,
        )
    except IncidentTransitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # _get_incident's SELECT already autobegan the transaction - don't call session.begin()
    # again (raises InvalidRequestError). The state-machine mutations on `incident` are tracked
    # by the session; just commit.
    await session.commit()

    # Audit log (best-effort).
    try:
        await AuditLogWriter().append(
            uuid.UUID(tenant_id_str),
            actor_type="user",
            action="incident_transition",
            actor_id=uuid.UUID(actor_id) if _is_uuid(actor_id) else None,
            target_type="incident",
            target_id=uuid.UUID(incident_id) if _is_uuid(incident_id) else None,
            payload={
                "target_state": body.target,
                "rationale": body.rationale,
                "post_mortem_uri": body.post_mortem_uri,
            },
        )
    except Exception:  # noqa: BLE001,S110
        pass

    return _incident_to_dict(incident)


@incident_router.post("/{incident_id}/comments", status_code=status.HTTP_201_CREATED)
async def add_comment(
    incident_id: str,
    body: CommentRequest,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Add a comment to an incident thread."""
    incident = await _get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")

    author_id = claims.get("sub", "")
    comment = await _insert_comment(
        session,
        incident_id=incident_id,
        author_id=author_id,
        body=body.body,
    )
    result = _comment_to_dict(comment)
    await session.commit()
    return result


@incident_router.post("/{incident_id}/action-items", status_code=status.HTTP_201_CREATED)
async def add_action_item(
    incident_id: str,
    body: ActionItemRequest,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Add an action item to an incident."""
    incident = await _get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")

    from datetime import date

    due_date: date | None = None
    if body.due_date:
        try:
            due_date = date.fromisoformat(body.due_date)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid due_date format (expected YYYY-MM-DD): {body.due_date}",
            ) from exc

    actor_id = claims.get("sub", "")
    owner_id = body.owner_id or (actor_id if actor_id else None)

    item = await _insert_action_item(
        session,
        incident_id=incident_id,
        owner_id=owner_id,
        description=body.description,
        due_date=due_date,
    )
    result = _action_item_to_dict(item)
    await session.commit()
    return result


__all__ = [
    "incident_router",
    "get_db_session",
    "TransitionRequest",
    "CommentRequest",
    "ActionItemRequest",
]
