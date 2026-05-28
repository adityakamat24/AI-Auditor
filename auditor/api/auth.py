"""Minimal P5 auth layer for the HITL API (PRD §11.2).

# P5-MINIMAL: This is a Phase-5 stopgap. Phase 7 replaces this with full OIDC / PyJWT + authlib.
# Do NOT use this module for anything that requires production-grade auth guarantees.

The token format is JWT-shaped (base64url-encoded header.payload.signature) but uses only stdlib
``hmac``, ``hashlib``, ``json``, and ``base64`` — no new dependencies.  Signing uses HMAC-SHA256
over the concatenated header.payload signing input, keyed with ``Settings.jwt_secret``.

Token lifetime defaults to 8 hours (``TTL_DEFAULT_S``).  Tokens carry ``exp`` so expiry is
enforced on verify.

FastAPI dependencies:
  - ``get_current_user`` — reads ``Authorization: Bearer <token>`` or ``session`` cookie; returns
    the decoded claims dict; raises HTTP 401 on missing / invalid token.
  - ``require_role(*roles)`` — factory that returns a FastAPI dependency enforcing RBAC; 403 on
    wrong role, 401 on missing/invalid token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auditor.config import get_settings

# ------------------------------------------------------------------------------- constants

TTL_DEFAULT_S: int = 28_800  # 8 hours

_HEADER_B64: str = base64.urlsafe_b64encode(
    json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
).rstrip(b"=").decode()

_bearer_scheme = HTTPBearer(auto_error=False)


# ------------------------------------------------------------------------------- custom error


class AuthError(ValueError):
    """Raised by :func:`verify_token` on signature failure or expiry."""


# ------------------------------------------------------------------------------- token helpers


def _b64_encode(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decode, tolerating missing padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _sign(signing_input: str) -> str:
    """HMAC-SHA256 over *signing_input*, keyed with the JWT secret from settings."""
    secret = get_settings().jwt_secret.encode()
    digest = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return _b64_encode(digest)


# ------------------------------------------------------------------------------- public API


def issue_token(
    *,
    user_id: str,
    tenant_id: str,
    role: str,
    ttl_s: int = TTL_DEFAULT_S,
) -> str:
    """Issue a signed token for the given user / tenant / role.

    Returns a dot-separated ``header.payload.signature`` string (JWT-shaped, stdlib only).
    The payload includes ``sub`` (user_id), ``tenant_id``, ``role``, ``iat``, and ``exp``.
    """
    now = int(time.time())
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "iat": now,
        "exp": now + ttl_s,
    }
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{_HEADER_B64}.{payload_b64}"
    sig = _sign(signing_input)
    return f"{signing_input}.{sig}"


def verify_token(token: str) -> dict[str, Any]:
    """Verify *token* signature and expiry; return claims dict on success.

    Raises :class:`AuthError` (a ``ValueError`` subclass) on any failure — invalid format,
    bad signature, or expired token.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise AuthError("malformed token: expected 3 dot-separated parts") from exc

    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = _sign(signing_input)
    # Constant-time comparison to resist timing attacks.
    if not hmac.compare_digest(expected_sig, sig_b64):
        raise AuthError("token signature is invalid")

    try:
        claims: dict[str, Any] = json.loads(_b64_decode(payload_b64))
    except Exception as exc:
        raise AuthError("token payload is not valid JSON") from exc

    if int(time.time()) >= claims.get("exp", 0):
        raise AuthError("token has expired")

    return claims


# ------------------------------------------------------------------------------- FastAPI dependencies


def _extract_raw_token(
    bearer: HTTPAuthorizationCredentials | None,
    session: str | None,
) -> str | None:
    """Return the raw token string from bearer header or session cookie."""
    if bearer is not None and bearer.credentials:
        return bearer.credentials
    return session


async def get_current_user(
    bearer: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    """FastAPI dependency: parse + verify token; return claims.

    Accepts either ``Authorization: Bearer <token>`` or an HTTP-only ``session`` cookie.
    Raises HTTP 401 if the token is absent, malformed, or expired.
    """
    raw = _extract_raw_token(bearer, session)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return verify_token(raw)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_role(*roles: str):
    """Return a FastAPI dependency that enforces RBAC.

    Usage::

        @router.post("/flags/{flag_id}/decisions")
        async def submit_decision(
            claims: Annotated[dict, Depends(require_role("admin", "reviewer"))],
        ):
            ...

    Raises HTTP 401 if the token is absent/invalid, HTTP 403 if the token's role is not in
    *roles*.
    """

    async def _check(claims: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if claims.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role '{claims.get('role')}' is not authorised; required: {list(roles)}",
            )
        return claims

    return _check


# ------------------------------------------------------------------------------- OIDC integration point


def verify_oidc_token(token: str) -> dict:  # noqa: ARG001
    """Validate an OIDC JWT against the configured issuer / JWKS endpoint.

    This is the Phase-7 integration seam for Auth0 / Okta / Google OIDC.

    When fully wired (``OIDC_ISSUER`` + ``OIDC_JWKS_URI`` are set in config / env):
      1. Fetch the JWKS from the configured ``oidc_jwks_uri`` (or auto-derive from issuer).
      2. Validate the JWT signature against the matching ``kid`` in the JWKS.
      3. Verify ``iss`` matches ``settings.oidc_issuer``.
      4. Verify ``aud`` matches ``settings.oidc_audience`` (if configured).
      5. Verify ``exp`` / ``nbf``.
      6. Return the decoded claims dict (``sub``, ``email``, ``role`` / custom claims).

    Config fields (all in ``auditor.config.Settings``):
      - ``oidc_issuer``   — e.g. "https://example.us.auth0.com/"
      - ``oidc_jwks_uri`` — e.g. "https://example.us.auth0.com/.well-known/jwks.json"
                            (if empty, auto-derived as ``issuer + "/.well-known/jwks.json"``)
      - ``oidc_audience`` — expected ``aud`` claim (empty = skip audience check)

    Raises:
      NotImplementedError — when ``OIDC_ISSUER`` is not configured (dev / local-HMAC mode).
      AuthError           — when the token fails validation (bad sig, expired, wrong issuer).

    Note: This function intentionally does NOT make network calls when OIDC is unconfigured.
    Tests that import this module will never trigger an HTTP request.
    """
    settings = get_settings()
    if not settings.oidc_issuer:
        raise NotImplementedError(
            "OIDC is not configured. "
            "Set OIDC_ISSUER (and optionally OIDC_JWKS_URI, OIDC_AUDIENCE) to enable. "
            "Until then, use POST /auth/login with local HMAC tokens."
        )
    # --- real implementation goes here (Phase 7 / authlib / PyJWT + PyJWKClient) ---
    # Example (authlib):
    #   from authlib.integrations.requests_client import OAuth2Session
    #   from authlib.jose import jwt as jose_jwt
    #   jwks_uri = settings.oidc_jwks_uri or (settings.oidc_issuer.rstrip("/") + "/.well-known/jwks.json")
    #   jwks = fetch_jwks(jwks_uri)  # cached / periodic refresh
    #   claims = jose_jwt.decode(token, jwks)
    #   claims.validate_iss(settings.oidc_issuer)
    #   if settings.oidc_audience:
    #       claims.validate_aud(settings.oidc_audience)
    #   return dict(claims)
    raise NotImplementedError(  # pragma: no cover — reached only if issuer set but impl missing
        "OIDC issuer is configured but the JWKS validation path is not yet implemented. "
        "Install authlib / PyJWT and replace this placeholder."
    )


__all__ = [
    "AuthError",
    "TTL_DEFAULT_S",
    "issue_token",
    "verify_token",
    "get_current_user",
    "require_role",
    "verify_oidc_token",
]
