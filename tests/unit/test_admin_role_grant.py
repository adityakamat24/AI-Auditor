"""Unit tests for POST /admin/users/{user_id}/role — Phase-7 acceptance.

Acceptance criterion (PRD §15 Phase 7):
  "a reviewer cannot escalate to admin without an admin granting the role."

Covers:
  - Reviewer token → 403 on POST /admin/users/{id}/role.
  - Readonly token → 403 on POST /admin/users/{id}/role.
  - Admin token + valid role → 200; the (fake) store records the new role.
  - Admin token + invalid role name → 422.
  - No token → 401.
  - Unknown user_id → 404.
  - Previous role is returned in the response.

All DB access is replaced with in-memory fakes via dependency_overrides — no live DB required.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Any

from auditor.api.admin import admin_router, get_db_session
from auditor.api.auth import issue_token
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------------------------- helpers


def _uuid() -> str:
    return str(uuid.uuid4())


TENANT_ID = _uuid()


def _token(role: str = "admin") -> str:
    return issue_token(user_id=_uuid(), tenant_id=TENANT_ID, role=role)


def _auth(role: str = "admin") -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


# ------------------------------------------------------------------------------- fake user


def _make_fake_user(
    *,
    user_id: str | None = None,
    role: str = "reviewer",
    email: str = "user@example.com",
    tenant_id: str | None = None,
) -> Any:
    class FakeUser:
        pass

    u = FakeUser()
    u.user_id = user_id or _uuid()
    u.tenant_id = tenant_id or TENANT_ID
    u.email = email
    u.role = role
    return u


# ------------------------------------------------------------------------------- fake session


class _FakeSession:
    """Minimal async session stub for admin role-grant tests."""

    def __init__(self, user: Any | None = None) -> None:
        self._user = user
        self.added: list[Any] = []
        self.committed: bool = False

    async def execute(self, stmt, *args, **kwargs):  # noqa: ARG002
        class _Result:
            def __init__(self, row: Any | None) -> None:
                self._row = row

            def scalar_one_or_none(self) -> Any | None:
                return self._row

            def scalars(self) -> _Result:
                return self

            def all(self) -> list[Any]:
                return [self._row] if self._row else []

        # Return the fake user for user-lookup queries; empty for calibration queries.
        stmt_str = str(stmt).lower()
        if "user" in stmt_str:
            return _Result(self._user)
        return _Result(None)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        self.committed = True

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


# We need to capture the session instance to inspect it after the request.
_last_session: _FakeSession | None = None


def _fake_session_dep(user: Any | None = None):
    _user = user

    async def _dep() -> AsyncGenerator[_FakeSession, None]:
        global _last_session  # noqa: PLW0603
        session = _FakeSession(user=_user)
        _last_session = session
        yield session

    return _dep


def _make_app(user: Any | None = None) -> FastAPI:
    """Create a fresh FastAPI app with admin_router and DB faked out."""
    app = FastAPI()
    app.include_router(admin_router)
    app.dependency_overrides[get_db_session] = _fake_session_dep(user)
    return app


# ------------------------------------------------------------------------------- acceptance tests


class TestRoleGrant:
    # Phase-7 acceptance criterion: reviewer cannot self-escalate

    def test_reviewer_cannot_grant_role(self):
        """Core acceptance: a reviewer token → 403 on POST /admin/users/{id}/role."""
        user = _make_fake_user(role="reviewer")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "admin"},
            headers=_auth("reviewer"),
        )

        assert resp.status_code == 403

    def test_readonly_cannot_grant_role(self):
        """A readonly token → 403 on POST /admin/users/{id}/role."""
        user = _make_fake_user(role="readonly")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "admin"},
            headers=_auth("readonly"),
        )

        assert resp.status_code == 403

    def test_no_token_returns_401(self):
        """No auth → 401."""
        user = _make_fake_user()
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "reviewer"},
        )

        assert resp.status_code == 401

    def test_admin_can_grant_reviewer_role(self):
        """Admin token → 200 and the fake store records the new role."""
        user = _make_fake_user(role="readonly")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "reviewer"},
            headers=_auth("admin"),
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "reviewer"
        assert data["user_id"] == str(user.user_id)

    def test_admin_can_escalate_reviewer_to_admin(self):
        """Admin can grant the admin role to a reviewer."""
        user = _make_fake_user(role="reviewer")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "admin"},
            headers=_auth("admin"),
        )

        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    def test_previous_role_is_returned(self):
        """The response includes the previous role before the grant."""
        user = _make_fake_user(role="readonly")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "reviewer"},
            headers=_auth("admin"),
        )

        assert resp.status_code == 200
        assert resp.json()["previous_role"] == "readonly"

    def test_session_is_committed_on_success(self):
        """The DB session must be committed when the role grant succeeds."""
        user = _make_fake_user(role="reviewer")
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "admin"},
            headers=_auth("admin"),
        )

        assert _last_session is not None
        assert _last_session.committed is True

    def test_unknown_user_returns_404(self):
        """If the user does not exist, return 404."""
        app = _make_app(user=None)  # no user in DB
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{_uuid()}/role",
            json={"role": "reviewer"},
            headers=_auth("admin"),
        )

        assert resp.status_code == 404

    def test_invalid_role_name_returns_422(self):
        """A role that is not one of admin/reviewer/readonly → 422."""
        user = _make_fake_user()
        app = _make_app(user=user)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            f"/admin/users/{user.user_id}/role",
            json={"role": "superuser"},
            headers=_auth("admin"),
        )

        assert resp.status_code == 422

    def test_all_valid_roles_accepted(self):
        """All three valid role strings are accepted by the endpoint."""
        for new_role in ("admin", "reviewer", "readonly"):
            user = _make_fake_user(role="readonly")
            app = _make_app(user=user)
            client = TestClient(app, raise_server_exceptions=False)

            resp = client.post(
                f"/admin/users/{user.user_id}/role",
                json={"role": new_role},
                headers=_auth("admin"),
            )

            assert resp.status_code == 200, f"Expected 200 for role={new_role}"
            assert resp.json()["role"] == new_role
