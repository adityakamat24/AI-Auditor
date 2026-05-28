"""Admin API routes (PRD §10.1) — calibration endpoints.

Only the two calibration endpoints are implemented here; tenant/policy/user/kill_switch
endpoints are Phase 7 and remain out of scope.

Router name: ``admin_router`` — registered by ``auditor/main.py`` (do NOT register here).

# Architecture note — DB-free seams for testing
# -----------------------------------------------
# All database access goes through ``get_db_session``, an injectable dependency identical in
# pattern to ``hitl_routes.py``.  Tests override it via ``app.dependency_overrides`` without
# touching any real database.  Each helper function (``_get_latest_calibration_run``,
# ``_insert_calibration_run``) accepts an ``AsyncSession`` so they can be unit-tested directly.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import require_role
from auditor.db.session import get_sessionmaker

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------- router

admin_router = APIRouter(prefix="/admin", tags=["admin"])

# Keep the old name as an alias so ``auditor/main.py`` (which imports ``router``) still works.
router = admin_router

# ------------------------------------------------------------------------------- DB session dependency


async def _db_session_gen() -> AsyncGenerator[AsyncSession, None]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session


# The *injectable* session dep; tests override this with ``app.dependency_overrides``.
get_db_session = _db_session_gen

# ------------------------------------------------------------------------------- DB helpers


async def _get_latest_calibration_run(session: AsyncSession) -> Any | None:
    """Return the most recent CalibrationRun row, or None if the table is empty."""
    from auditor.db.models import CalibrationRun

    result = await session.execute(
        select(CalibrationRun).order_by(CalibrationRun.ts.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def _insert_calibration_run(session: AsyncSession, report: Any) -> None:
    """Insert a CalibrationRun row from a CalibrationReport (best-effort; caller handles commit)."""
    from auditor.db.models import CalibrationRun
    from auditor.ids import uuid7

    session.add(
        CalibrationRun(
            cal_id=uuid7(),
            judge_model=report.judge_model,
            judge_prompt_v=report.judge_prompt_v,
            per_category=report.per_category,
            overall=report.overall,
        )
    )


# ------------------------------------------------------------------------------- serialisation helpers


def _calibration_run_to_dict(row: Any) -> dict[str, Any]:
    return {
        "ts": row.ts.isoformat() if row.ts else None,
        "judge_model": row.judge_model,
        "judge_prompt_v": row.judge_prompt_v,
        "per_category": row.per_category,
        "overall": row.overall,
    }


# ------------------------------------------------------------------------------- endpoints


@admin_router.get("/calibration/latest")
async def get_latest_calibration(
    claims: Annotated[dict, Depends(require_role("admin"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Return the most recent calibration_runs row.

    Returns an empty ``{}`` if no calibration run has been persisted yet.
    Requires ``admin`` role.
    """
    row = await _get_latest_calibration_run(session)
    if row is None:
        return {}
    return _calibration_run_to_dict(row)


@admin_router.post("/calibration/run")
async def run_calibration(
    claims: Annotated[dict, Depends(require_role("admin"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Force a calibration pass; persist the result best-effort; return the report dict.

    Runs :class:`~auditor.calibration.nightly.CalibrationJob` with an
    :class:`~auditor.calibration.nightly.InMemoryBlockingAuthority`, then attempts to
    persist the report via :func:`~auditor.calibration.nightly.persist_report`.
    The endpoint always returns the report even if persistence fails.

    Requires ``admin`` role.
    """
    from auditor.calibration.nightly import CalibrationJob, InMemoryBlockingAuthority

    authority = InMemoryBlockingAuthority()
    report = await CalibrationJob(blocking_authority=authority).run()

    # Persist best-effort: don't let a DB error block the response.
    try:
        await _insert_calibration_run(session, report)
        await session.commit()
    except Exception:  # noqa: BLE001 — best-effort persistence; ops monitors DB health separately
        logger.warning("calibration/run: failed to persist report (best-effort; non-fatal)")

    report_dict = asdict(report)
    return report_dict


# ------------------------------------------------------------------------------- role management


_VALID_ROLES: frozenset[str] = frozenset({"admin", "reviewer", "readonly"})


class RoleGrantRequest(BaseModel):
    """Body for POST /admin/users/{user_id}/role."""

    role: str


async def _find_user_by_id(session: AsyncSession, user_id: str):
    """Return the User row for *user_id*, or None."""
    from auditor.db.models import User

    result = await session.execute(select(User).where(User.user_id == user_id).limit(1))
    return result.scalar_one_or_none()


@admin_router.post("/users/{user_id}/role", status_code=status.HTTP_200_OK)
async def grant_role(
    user_id: str,
    body: RoleGrantRequest,
    claims: Annotated[dict, Depends(require_role("admin"))] = None,  # type: ignore[assignment]
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Grant a role to a user — admin only (PRD §11.2 / Phase-7 acceptance).

    Acceptance criterion: "a reviewer cannot escalate to admin without an admin granting the role."

    - Requires ``admin`` role on the caller's token (enforced by ``require_role("admin")``).
    - A reviewer/readonly caller → 403 (handled by ``require_role``).
    - Validates that *role* is one of ``admin``, ``reviewer``, ``readonly``; 422 otherwise.
    - Returns ``{"user_id": ..., "role": ..., "previous_role": ...}`` on success.

    This endpoint updates the ``User.role`` column in-place.  The NEXT token the user
    issues (via /auth/login or OIDC) will carry the new role.  Existing tokens are not
    revoked (token revocation is a Phase-7 extension using Redis allow-lists).
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of {sorted(_VALID_ROLES)}.",
        )

    user = await _find_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )

    previous_role = user.role
    user.role = body.role
    session.add(user)
    await session.commit()

    logger.info(
        "role-grant: user_id=%s %s→%s by admin=%s",
        user_id,
        previous_role,
        body.role,
        claims.get("sub") if claims else "unknown",
    )

    return {"user_id": user_id, "role": body.role, "previous_role": previous_role}


# ─── Sampler runtime config (live-configurable from the UI) ─────────────────


class SamplerSettingsBody(BaseModel):
    """Body for PUT /admin/sampler — all fields optional, omitted = keep current."""

    mode: str | None = None  # percentage | every_nth | interval | always | never
    rate: float | None = None
    every_n: int | None = None
    interval_seconds: float | None = None
    critical_risk_threshold: int | None = None


@admin_router.get("/sampler")
async def get_sampler(
    claims: Annotated[dict, Depends(require_role("admin", "reviewer"))] = None,  # type: ignore[assignment]
) -> dict:
    """Return the current runtime sampler configuration (mode + parameter)."""
    from auditor.async_pipeline.runtime_policy import get_settings_snapshot

    return asdict(get_settings_snapshot())


@admin_router.put("/sampler")
async def update_sampler(
    body: SamplerSettingsBody,
    claims: Annotated[dict, Depends(require_role("admin"))] = None,  # type: ignore[assignment]
) -> dict:
    """Update the sampler configuration. Admin-only — changes apply to the very next run."""
    from auditor.async_pipeline.runtime_policy import SamplerSettings, get_settings_snapshot, set_settings

    current = get_settings_snapshot()
    merged = SamplerSettings(
        mode=body.mode if body.mode is not None else current.mode,  # type: ignore[arg-type]
        rate=body.rate if body.rate is not None else current.rate,
        every_n=body.every_n if body.every_n is not None else current.every_n,
        interval_seconds=body.interval_seconds if body.interval_seconds is not None else current.interval_seconds,
        critical_risk_threshold=(
            body.critical_risk_threshold if body.critical_risk_threshold is not None else current.critical_risk_threshold
        ),
    )
    try:
        applied = set_settings(merged)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("sampler.config.updated by=%s settings=%s", claims.get("sub") if claims else "?", asdict(applied))
    return asdict(applied)


# ─── Reset (wipe per-run demo data) ─────────────────────────────────────────


@admin_router.post("/reset", status_code=status.HTTP_200_OK)
async def reset_demo_data(
    claims: Annotated[dict, Depends(require_role("admin"))] = None,  # type: ignore[assignment]
) -> dict:
    """Truncate all per-run demo data so the next session shows only its own runs.

    Keeps tenants, users, and policies. Audit-log chain restarts from genesis — the verifier will treat
    a fresh tenant chain as ``intact, 0 entries`` until new entries are appended.
    """
    from sqlalchemy import text as sql_text

    from auditor.db.session import get_sessionmaker

    # Single TRUNCATE ... CASCADE: Postgres handles FK ordering atomically in one statement.
    targets = [
        "incident_action_items", "incident_comments", "incidents",
        "hitl_decisions", "shadow_verdicts", "verdicts", "flags",
        "sampler_decisions", "audit_log",
        "memory_embeddings", "memory_entries",
        "events", "runs",
    ]
    stmt = f"TRUNCATE TABLE {', '.join(targets)} RESTART IDENTITY CASCADE"
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        await session.execute(sql_text(stmt))

    logger.info("admin.reset wiped=%d by=%s", len(targets), claims.get("sub") if claims else "?")
    return {"wiped": targets}


__all__ = ["admin_router", "router", "get_db_session"]
