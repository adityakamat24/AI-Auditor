"""Audit search API (PRD §9.11.4 §15 Phase-8).

Endpoints:
  POST /audit/search              — run a DSL query scoped to the caller's tenant.
  POST /audit/saved-queries       — save a named (optionally parameterised) query (admin only).
  GET  /audit/saved-queries       — list saved queries for the caller's tenant.
  POST /audit/saved-queries/{id}/run — bind params and run a saved query.

# Architecture note — DB-free seams for testing
# -----------------------------------------------
# All database access goes through module-level helper functions (``_insert_saved_query``,
# ``_list_saved_queries``, ``_get_saved_query``) that accept an AsyncSession argument.
# Tests override ``get_db_session`` via ``app.dependency_overrides`` without touching any
# real database (mirroring the pattern in auditor.api.hitl_routes).

Router name: ``search_router`` — registered by ``auditor/main.py``; do NOT register here.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import get_current_user, require_role
from auditor.audit_log.query import (
    Query,
    SavedQueryCreate,
    SavedQueryRun,
    run_query,
)
from auditor.db.models import SavedQuery
from auditor.db.session import get_sessionmaker
from auditor.db.tenancy import tenant_scope

# ------------------------------------------------------------------------------- router

search_router = APIRouter(prefix="/audit", tags=["audit"])

# ------------------------------------------------------------------------------- DB session seam


async def _db_session_gen() -> AsyncGenerator[AsyncSession, None]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session


# The injectable session dep; tests override via ``app.dependency_overrides``.
get_db_session = _db_session_gen

# ------------------------------------------------------------------------------- DB helpers


async def _insert_saved_query(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    query_dict: dict,
    params: dict,
    created_by: str | None,
) -> SavedQuery:
    """Insert a SavedQuery row and flush (caller owns the transaction)."""
    row = SavedQuery(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        name=name,
        query=query_dict,
        params=params,
        created_by=created_by,
    )
    session.add(row)
    await session.flush()
    return row


async def _list_saved_queries(session: AsyncSession, *, tenant_id: str) -> list[SavedQuery]:
    """Return all SavedQuery rows for *tenant_id* ordered by name."""
    result = await session.execute(
        select(SavedQuery).where(SavedQuery.tenant_id == tenant_id).order_by(SavedQuery.name)
    )
    return list(result.scalars().all())


async def _get_saved_query(session: AsyncSession, *, query_id: str) -> SavedQuery | None:
    """Return a SavedQuery by PK, or None."""
    result = await session.execute(select(SavedQuery).where(SavedQuery.id == query_id))
    return result.scalar_one_or_none()


# ------------------------------------------------------------------------------- serialiser


def _sq_to_dict(sq: SavedQuery) -> dict[str, Any]:
    return {
        "id": str(sq.id),
        "tenant_id": str(sq.tenant_id),
        "name": sq.name,
        "query": sq.query,
        "params": sq.params,
        "created_by": str(sq.created_by) if sq.created_by else None,
        "created_at": sq.created_at.isoformat() if sq.created_at else None,
    }


# ------------------------------------------------------------------------------- endpoints


@search_router.post("/search")
async def search(
    body: Query,
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """Run a DSL query scoped to the caller's tenant.

    The query is automatically RLS-scoped — a reviewer in tenant A sees only tenant A rows.
    """
    tenant_id: str = claims["tenant_id"]
    try:
        rows = await run_query(body, tenant_id=tenant_id, session=session)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return rows


@search_router.post("/saved-queries", status_code=status.HTTP_201_CREATED)
async def create_saved_query(
    body: SavedQueryCreate,
    claims: Annotated[dict, Depends(require_role("admin"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Save a named, optionally parameterised query.  Requires ``admin`` role."""
    tenant_id: str = claims["tenant_id"]
    user_id: str | None = claims.get("sub")

    # Validate that the query dict can be parsed by the DSL.
    try:
        Query.model_validate(body.query)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid query: {exc}",
        ) from exc

    async with session.begin():
        async with tenant_scope(session, tenant_id):
            row = await _insert_saved_query(
                session,
                tenant_id=tenant_id,
                name=body.name,
                query_dict=body.query,
                params=body.params,
                created_by=user_id,
            )
    return _sq_to_dict(row)


@search_router.get("/saved-queries")
async def list_saved_queries(
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """List saved queries for the caller's tenant.  Any authenticated role may call this."""
    tenant_id: str = claims["tenant_id"]
    async with tenant_scope(session, tenant_id):
        rows = await _list_saved_queries(session, tenant_id=tenant_id)
    return [_sq_to_dict(r) for r in rows]


@search_router.post("/saved-queries/{query_id}/run")
async def run_saved_query(
    query_id: str,
    body: SavedQueryRun,
    claims: Annotated[dict, Depends(get_current_user)] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """Bind params and execute a saved query.  Any authenticated role may call this."""
    tenant_id: str = claims["tenant_id"]

    async with tenant_scope(session, tenant_id):
        saved = await _get_saved_query(session, query_id=query_id)

    if saved is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="saved query not found")

    # Merge saved params with caller-supplied overrides.
    merged_params = {**saved.params, **body.params}

    # Build the final query dict, substituting $param placeholders.
    query_dict = _bind_params(saved.query, merged_params)

    try:
        parsed = Query.model_validate(query_dict)
        rows = await run_query(parsed, tenant_id=tenant_id, session=session)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return rows


# ------------------------------------------------------------------------------- param binding


def _bind_params(query_dict: dict, params: dict) -> dict:
    """Recursively substitute ``$param_name`` placeholders in *query_dict* from *params*.

    Only string values are substituted; non-string values pass through unchanged.
    """
    import json

    raw = json.dumps(query_dict)
    for key, val in params.items():
        placeholder = f'"${key}"'
        replacement = json.dumps(val)
        raw = raw.replace(placeholder, replacement)
    return json.loads(raw)


__all__ = [
    "search_router",
    "get_db_session",
    "Query",
]
