"""Shadow-verdict listing endpoint for the UI.

Detectors in ``SHADOW`` lifecycle state write to the ``shadow_verdicts`` table without producing flags
(PRD §9.13). This is the read surface the ``/shadow`` page uses to inspect them. Filterable by detector
name and ASI category. Returns an empty list if no shadow detectors are active.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import require_role
from auditor.api.hitl_routes import get_db_session
from auditor.db.models import ShadowVerdict

shadow_router = APIRouter(prefix="/shadow", tags=["shadow"])


@shadow_router.get("/verdicts")
async def list_shadow_verdicts(
    detector_name: Annotated[str | None, Query()] = None,
    asi_category: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """Return recent shadow verdicts (most recent first), filtered by detector / category if given."""
    query = select(ShadowVerdict).order_by(ShadowVerdict.ts.desc()).limit(limit)
    if detector_name:
        query = query.where(ShadowVerdict.detector == detector_name)
    if asi_category:
        query = query.where(ShadowVerdict.asi_category == asi_category)
    rows = (await session.execute(query)).scalars().all()
    return [
        {
            "verdict_id": str(row.verdict_id),
            "run_id": str(row.run_id),
            "tenant_id": str(row.tenant_id),
            "detector": row.detector,
            "asi_category": row.asi_category,
            "result": row.result,
            "confidence": float(row.confidence) if row.confidence is not None else None,
            "evidence": row.evidence,
            "ts": row.ts.isoformat() if row.ts else None,
        }
        for row in rows
    ]


__all__ = ["shadow_router"]
