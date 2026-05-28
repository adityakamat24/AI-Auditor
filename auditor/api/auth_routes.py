"""Auth routes for the AI Auditor API (PRD §11.1 / Phase 7).

Provides:
  POST /auth/login  - local-password fallback for dev (role always from DB, never caller-supplied).
  GET  /auth/me     - return the current token's claims (requires any valid token).

Router name: ``auth_router`` - registered by ``auditor/main.py`` (do NOT register here).

# Architecture note - no password column on User
# -----------------------------------------------
# The ``User`` model has NO password / password_hash column (see auditor/db/models.py).
# Dev login is therefore gated by ``Settings.auth_dev_login_enabled`` (default True in dev)
# and issues a token purely from the DB row's ``role``.  In a real deployment, OIDC replaces
# this entirely.  A user cannot influence their token's role - it comes from the DB row.

# Dependency injection seam
# -------------------------
# ``get_db_session`` is a module-level callable, identical in pattern to admin.py.
# Tests replace it via ``app.dependency_overrides`` without touching any real database.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auditor.api.auth import (
    get_current_user,
    issue_token,
)
from auditor.config import get_settings
from auditor.db.session import get_sessionmaker

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------- router

auth_router = APIRouter(prefix="/auth", tags=["auth"])

# ------------------------------------------------------------------------------- DB session dependency


async def _db_session_gen() -> AsyncGenerator[AsyncSession, None]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session


# The injectable session dep; tests override this via app.dependency_overrides.
get_db_session = _db_session_gen

# ------------------------------------------------------------------------------- request / response models


class LoginRequest(BaseModel):
    """Body for POST /auth/login."""

    # Using str instead of EmailStr to avoid the optional email-validator dependency.
    # The User model has no password column (no hash to check against);
    # this accepts the field for API surface compatibility only.
    email: str
    password: str


class LoginResponse(BaseModel):
    """Body returned by POST /auth/login."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105 - "bearer" is an OAuth2 token type, not a password
    role: str
    user_id: str
    tenant_id: str


class MeResponse(BaseModel):
    """Body returned by GET /auth/me."""

    sub: str
    tenant_id: str
    role: str
    iat: int
    exp: int


# ------------------------------------------------------------------------------- DB helpers


async def _find_user_by_email(session: AsyncSession, email: str) -> Any | None:
    """Return the User row for *email*, or None if not found."""
    from auditor.db.models import User

    result = await session.execute(select(User).where(User.email == email).limit(1))
    return result.scalar_one_or_none()


# ------------------------------------------------------------------------------- endpoints


@auth_router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
) -> LoginResponse:
    """Local-password fallback login endpoint (dev / no-IdP mode).

    PRD §11.1: "Local password fallback for dev only."

    Behaviour
    ---------
    - Requires ``Settings.auth_dev_login_enabled`` to be True (default in dev).
    - Looks up the ``User`` by email in the DB.
    - Issues a signed HMAC token whose **role comes from the DB row** - the caller cannot
      choose a role at login time.  A reviewer logging in always gets a reviewer token.
    - Sets the token as an HTTP-only ``session`` cookie AND returns it in the response body.

    The ``User`` model has **no password column** (by design - passwords are an OIDC concern).
    In dev mode the password field is accepted for API surface compatibility but is not
    validated against any stored hash.  When OIDC is configured, use the IdP flow instead.

    Raises
    ------
    HTTP 403  - if ``auth_dev_login_enabled`` is False (prod lockout).
    HTTP 404  - if no user with that email exists.
    HTTP 401  - reserved for OIDC failures (not used in local-fallback path).
    """
    settings = get_settings()

    if not settings.auth_dev_login_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local dev login is disabled. Use OIDC.",
        )

    user = await _find_user_by_email(session, body.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No user with email '{body.email}' found.",
        )

    # Role is ALWAYS from the DB row - the caller has zero influence over it.
    token = issue_token(
        user_id=str(user.user_id),
        tenant_id=str(user.tenant_id),
        role=user.role,
        ttl_s=settings.jwt_ttl_seconds,
    )

    # Set as HTTP-only session cookie so browser clients can use it without JS access.
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.jwt_ttl_seconds,
    )

    logger.info(
        "dev-login issued token: user_id=%s role=%s tenant_id=%s",
        user.user_id,
        user.role,
        user.tenant_id,
    )

    return LoginResponse(
        access_token=token,
        token_type="bearer",  # noqa: S106 - OAuth2 token type, not a password argument
        role=user.role,
        user_id=str(user.user_id),
        tenant_id=str(user.tenant_id),
    )


@auth_router.get("/me", response_model=MeResponse)
async def me(
    claims: Annotated[dict, Depends(get_current_user)],
) -> MeResponse:
    """Return the claims embedded in the caller's token.

    Accepts ``Authorization: Bearer <token>`` or an HTTP-only ``session`` cookie.
    Raises HTTP 401 if the token is absent, malformed, or expired.
    """
    return MeResponse(
        sub=claims["sub"],
        tenant_id=claims["tenant_id"],
        role=claims["role"],
        iat=claims["iat"],
        exp=claims["exp"],
    )


__all__ = ["auth_router", "get_db_session"]
