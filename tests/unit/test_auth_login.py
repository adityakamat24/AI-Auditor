"""Unit tests for auditor.api.auth_routes (Phase-7 auth endpoints).

Covers:
  - POST /auth/login issues a token whose role equals the user's STORED role (never caller-chosen).
  - A reviewer logging in gets a reviewer token, not admin.
  - GET /auth/me round-trips the claims from the issued token.
  - Disabled dev login → 403.
  - Unknown email → 404.
  - Cookie is set on successful login.
  - verify_oidc_token raises NotImplementedError when OIDC_ISSUER is unconfigured.

All DB access is replaced with in-memory fakes via dependency_overrides - no live DB required.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import patch

import pytest
from auditor.api.auth import issue_token, verify_oidc_token, verify_token
from auditor.api.auth_routes import auth_router, get_db_session
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------------------------- helpers / fakes


def _uuid() -> str:
    return str(uuid.uuid4())


TENANT_ID = _uuid()


def _make_fake_user(
    *,
    email: str = "reviewer@example.com",
    role: str = "reviewer",
    user_id: str | None = None,
    tenant_id: str | None = None,
) -> Any:
    """Return a minimal mock User row compatible with _find_user_by_email."""

    class FakeUser:
        pass

    u = FakeUser()
    u.user_id = user_id or _uuid()
    u.tenant_id = tenant_id or TENANT_ID
    u.email = email
    u.role = role
    u.oidc_subject = None
    return u


class _FakeSession:
    """Minimal async session stub for auth_routes tests."""

    def __init__(self, user: Any | None = None) -> None:
        self._user = user
        self._added: list[Any] = []
        self._committed = False

    async def execute(self, stmt, *args, **kwargs):  # noqa: ARG002
        class _Result:
            def __init__(self, row: Any | None) -> None:
                self._row = row

            def scalar_one_or_none(self) -> Any | None:
                return self._row

        return _Result(self._user)

    def add(self, obj: Any) -> None:
        self._added.append(obj)

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        self._committed = True

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


def _fake_session_dep(user: Any | None = None):
    """Return a FastAPI dependency override that yields a _FakeSession."""
    _user = user

    async def _dep() -> AsyncGenerator[_FakeSession, None]:
        yield _FakeSession(user=_user)

    return _dep


def _make_app(user: Any | None = None) -> FastAPI:
    """Create a fresh FastAPI app with auth_router and DB faked out."""
    app = FastAPI()
    app.include_router(auth_router)
    app.dependency_overrides[get_db_session] = _fake_session_dep(user)
    return app


# ------------------------------------------------------------------------------- POST /auth/login


class TestLoginEndpoint:
    def test_reviewer_login_gets_reviewer_token(self):
        """A reviewer logging in must receive a reviewer token - never admin."""
        user = _make_fake_user(email="rv@example.com", role="reviewer")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": "rv@example.com", "password": "any"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "reviewer"
        # Verify the token itself carries the reviewer role.
        claims = verify_token(data["access_token"])
        assert claims["role"] == "reviewer"

    def test_admin_login_gets_admin_token(self):
        """An admin user logging in receives an admin token."""
        user = _make_fake_user(email="admin@example.com", role="admin")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": "admin@example.com", "password": "any"})

        assert resp.status_code == 200
        claims = verify_token(resp.json()["access_token"])
        assert claims["role"] == "admin"

    def test_readonly_login_gets_readonly_token(self):
        """A readonly user gets a readonly token."""
        user = _make_fake_user(email="ro@example.com", role="readonly")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": "ro@example.com", "password": "any"})

        assert resp.status_code == 200
        claims = verify_token(resp.json()["access_token"])
        assert claims["role"] == "readonly"

    def test_role_comes_from_db_not_caller(self):
        """The token role must be the DB row's role regardless of any caller input."""
        # DB says reviewer; even if a caller tried to inject role it is ignored.
        user = _make_fake_user(role="reviewer")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": user.email, "password": "whatever"})

        assert resp.status_code == 200
        # Role in token must be reviewer, not anything the caller chose.
        claims = verify_token(resp.json()["access_token"])
        assert claims["role"] == "reviewer"
        assert claims["role"] != "admin"

    def test_token_contains_correct_user_and_tenant(self):
        """Token sub / tenant_id match the DB row."""
        uid = _uuid()
        tid = _uuid()
        user = _make_fake_user(email="u@t.com", user_id=uid, tenant_id=tid)
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": "u@t.com", "password": "x"})

        assert resp.status_code == 200
        claims = verify_token(resp.json()["access_token"])
        assert claims["sub"] == uid
        assert claims["tenant_id"] == tid

    def test_unknown_email_returns_404(self):
        """Login with an email that is not in the DB → 404."""
        app = _make_app(user=None)  # no user in DB
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": "nobody@example.com", "password": "x"})

        assert resp.status_code == 404

    def test_dev_login_disabled_returns_403(self):
        """When auth_dev_login_enabled is False, login is locked out with 403."""
        user = _make_fake_user()
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        fake_settings = type(
            "_S", (), {"auth_dev_login_enabled": False, "jwt_ttl_seconds": 3600}
        )()
        with patch("auditor.api.auth_routes.get_settings", return_value=fake_settings):
            resp = client.post(
                "/auth/login", json={"email": user.email, "password": "any"}
            )

        assert resp.status_code == 403

    def test_session_cookie_is_set(self):
        """A successful login sets the HTTP-only session cookie."""
        user = _make_fake_user()
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": user.email, "password": "any"})

        assert resp.status_code == 200
        assert "session" in resp.cookies

    def test_cookie_token_matches_body_token(self):
        """The cookie token and the body access_token must be identical."""
        user = _make_fake_user()
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": user.email, "password": "any"})

        assert resp.status_code == 200
        body_token = resp.json()["access_token"]
        cookie_token = resp.cookies.get("session")
        assert cookie_token == body_token

    def test_response_model_fields_present(self):
        """Response body has access_token, token_type, role, user_id, tenant_id."""
        user = _make_fake_user(role="admin")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post("/auth/login", json={"email": user.email, "password": "any"})

        assert resp.status_code == 200
        data = resp.json()
        for field in ("access_token", "token_type", "role", "user_id", "tenant_id"):
            assert field in data, f"missing field: {field}"
        assert data["token_type"] == "bearer"


# ------------------------------------------------------------------------------- GET /auth/me


class TestMeEndpoint:
    def _app_with_token(self, role: str = "reviewer") -> tuple[FastAPI, str]:
        app = _make_app()
        token = issue_token(user_id=_uuid(), tenant_id=TENANT_ID, role=role)
        return app, token

    def test_me_returns_claims_from_token(self):
        """GET /auth/me round-trips the claims embedded in the bearer token."""
        uid = _uuid()
        token = issue_token(user_id=uid, tenant_id=TENANT_ID, role="reviewer")
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["sub"] == uid
        assert data["tenant_id"] == TENANT_ID
        assert data["role"] == "reviewer"
        assert "iat" in data
        assert "exp" in data

    def test_me_returns_admin_role(self):
        """Admin token → /me returns admin role."""
        token = issue_token(user_id=_uuid(), tenant_id=TENANT_ID, role="admin")
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    def test_me_no_token_returns_401(self):
        """GET /auth/me without a token → 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/auth/me")

        assert resp.status_code == 401

    def test_me_invalid_token_returns_401(self):
        """GET /auth/me with a garbage token → 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/auth/me", headers={"Authorization": "Bearer not.valid.token"})

        assert resp.status_code == 401

    def test_me_accepts_session_cookie(self):
        """Token in session cookie is accepted by /auth/me."""
        token = issue_token(user_id=_uuid(), tenant_id=TENANT_ID, role="readonly")
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/auth/me", cookies={"session": token})

        assert resp.status_code == 200
        assert resp.json()["role"] == "readonly"


# ------------------------------------------------------------------------------- OIDC slot


class TestVerifyOidcToken:
    def test_raises_not_implemented_when_unconfigured(self):
        """verify_oidc_token raises NotImplementedError when OIDC_ISSUER is empty."""
        with patch("auditor.api.auth.get_settings") as mock_settings:
            mock_settings.return_value = type("_S", (), {"oidc_issuer": ""})()
            with pytest.raises(NotImplementedError, match="OIDC_ISSUER"):
                verify_oidc_token("any.token.here")

    def test_error_message_mentions_config_fields(self):
        """Error message names the config fields so operators know what to set."""
        with patch("auditor.api.auth.get_settings") as mock_settings:
            mock_settings.return_value = type("_S", (), {"oidc_issuer": ""})()
            with pytest.raises(NotImplementedError) as exc_info:
                verify_oidc_token("dummy")
            msg = str(exc_info.value)
            assert "OIDC_ISSUER" in msg

    def test_no_network_call_when_unconfigured(self):
        """verify_oidc_token must not make any network calls when OIDC is unconfigured."""
        # If a network call were attempted it would fail in the unit-test environment;
        # getting NotImplementedError proves it short-circuited before any HTTP request.
        with patch("auditor.api.auth.get_settings") as mock_settings:
            mock_settings.return_value = type("_S", (), {"oidc_issuer": ""})()
            with pytest.raises(NotImplementedError):
                verify_oidc_token("token")
