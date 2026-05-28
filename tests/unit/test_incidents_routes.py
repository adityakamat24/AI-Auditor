"""Unit tests for auditor.api.incidents_routes.

All database access is replaced with in-memory fakes via ``app.dependency_overrides`` — no live
DB required.  A fresh FastAPI app with ``incident_router`` mounted is created per test class.

Covers:
  - GET /incidents  returns seeded incidents.
  - GET /incidents/{id}  returns detail + comments + action items + similar.
  - POST /incidents/{id}/transition  happy path; RBAC (reviewer 403 on resolve).
  - POST /incidents/{id}/comments  creates comment.
  - POST /incidents/{id}/action-items  creates action item.
  - 404 for missing incident IDs.
  - 401 for missing token.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

from auditor.api.auth import issue_token
from auditor.api.incidents_routes import (
    get_db_session,
    incident_router,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------------------------- constants

TENANT_ID = str(uuid.uuid4())
INCIDENT_ID = str(uuid.uuid4())
FLAG_ID = str(uuid.uuid4())
COMMENT_ID = str(uuid.uuid4())
ACTION_ID = str(uuid.uuid4())
USER_ID = str(uuid.uuid4())


# ------------------------------------------------------------------------------- mock objects


def _make_incident(
    incident_id: str = INCIDENT_ID,
    state: str = "OPEN",
    severity: str = "high",
) -> Any:
    class MockIncident:
        pass

    inc = MockIncident()
    inc.incident_id = incident_id
    inc.tenant_id = TENANT_ID
    inc.primary_flag_id = FLAG_ID
    inc.related_flag_ids = []
    inc.severity = severity
    inc.state = state
    inc.assignee_id = None
    inc.opened_at = datetime(2025, 1, 1, tzinfo=UTC)
    inc.triaged_at = None
    inc.contained_at = None
    inc.resolved_at = None
    inc.post_mortem_uri = None
    inc.dismissal_rationale = None
    # Correlation metadata.
    inc._detector = "asi01_detector"
    inc._asi_categories = ["ASI01"]
    inc._agent_role = ""
    inc._tools = []
    return inc


def _make_comment(comment_id: str = COMMENT_ID) -> Any:
    class MockComment:
        pass

    c = MockComment()
    c.comment_id = comment_id
    c.incident_id = INCIDENT_ID
    c.author_id = USER_ID
    c.body = "Investigating now."
    c.ts = datetime(2025, 1, 1, 1, 0, tzinfo=UTC)
    return c


def _make_action_item(action_id: str = ACTION_ID) -> Any:
    class MockActionItem:
        pass

    a = MockActionItem()
    a.action_id = action_id
    a.incident_id = INCIDENT_ID
    a.owner_id = USER_ID
    a.description = "Patch the policy"
    a.status = "open"
    a.due_date = None
    a.created_at = datetime(2025, 1, 1, tzinfo=UTC)
    a.completed_at = None
    return a


# ------------------------------------------------------------------------------- fake session


class _FakeSession:
    """Minimal async-context-manager stub for SQLAlchemy AsyncSession."""

    def __init__(
        self,
        incidents=(),
        comments=(),
        action_items=(),
    ):
        self._incidents = list(incidents)
        self._comments = list(comments)
        self._action_items = list(action_items)
        self._added: list[Any] = []

    async def execute(self, stmt, *args, **kwargs):  # noqa: ARG002
        stmt_str = str(stmt).lower()

        class _Result:
            def __init__(self, rows):
                self._rows = list(rows)

            def scalars(self):
                return self

            def all(self):
                return self._rows

            def scalar_one_or_none(self):
                return self._rows[0] if self._rows else None

        # Route by table name present in statement string.
        if "incident_action_items" in stmt_str:
            return _Result(self._action_items)
        if "incident_comments" in stmt_str:
            return _Result(self._comments)
        if "incidents" in stmt_str:
            return _Result(self._incidents)
        return _Result([])

    def add(self, obj):
        self._added.append(obj)
        # For comments/action_items: also put them into the relevant list so
        # subsequent reads within the same request see them.
        if hasattr(obj, "comment_id"):
            self._comments.append(obj)
        elif hasattr(obj, "action_id"):
            self._action_items.append(obj)
        elif hasattr(obj, "incident_id") and hasattr(obj, "state"):
            # Updated incident — replace in list.
            self._incidents = [
                o for o in self._incidents
                if str(getattr(o, "incident_id", "")) != str(getattr(obj, "incident_id", ""))
            ]
            self._incidents.append(obj)

    async def flush(self):
        pass

    def begin(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def _fake_session_dep(incidents=(), comments=(), action_items=()):
    """Return a FastAPI dependency override that yields a _FakeSession."""

    async def _dep() -> AsyncGenerator[_FakeSession, None]:
        yield _FakeSession(incidents=incidents, comments=comments, action_items=action_items)

    return _dep


# ------------------------------------------------------------------------------- app factory


def _make_app(*, incidents=(), comments=(), action_items=()) -> FastAPI:
    """Create a fresh FastAPI app with incident_router and DB faked out."""
    app = FastAPI()
    app.include_router(incident_router)
    app.dependency_overrides[get_db_session] = _fake_session_dep(
        incidents=incidents, comments=comments, action_items=action_items
    )

    # Stub AuditLogWriter so tests never hit Postgres.
    import unittest.mock

    import auditor.api.incidents_routes as routes_mod

    class _StubWriter:
        async def append(self, *args, **kwargs):
            return b"\x00" * 32

    app.state._audit_writer_patch = unittest.mock.patch.object(
        routes_mod, "AuditLogWriter", _StubWriter
    )
    return app


# ------------------------------------------------------------------------------- token helpers


def _token(role: str = "reviewer") -> str:
    return issue_token(user_id=USER_ID, tenant_id=TENANT_ID, role=role)


def _auth(role: str = "reviewer") -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


# ------------------------------------------------------------------------------- tests: GET /incidents


class TestListIncidents:
    def test_returns_seeded_incidents(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["incident_id"] == INCIDENT_ID
        assert data[0]["state"] == "OPEN"

    def test_no_token_returns_401(self):
        app = _make_app(incidents=[_make_incident()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents")
        assert resp.status_code == 401

    def test_readonly_can_list(self):
        app = _make_app(incidents=[_make_incident()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents", headers=_auth("readonly"))
        assert resp.status_code == 200

    def test_empty_returns_empty_list(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents", headers=_auth())
        assert resp.status_code == 200
        assert resp.json() == []

    def test_state_filter_passed_as_query_param(self):
        inc = _make_incident(state="TRIAGING")
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents?state=TRIAGING", headers=_auth())
        assert resp.status_code == 200


# ------------------------------------------------------------------------------- tests: GET /incidents/{id}


class TestGetIncident:
    def test_returns_incident_detail(self):
        inc = _make_incident()
        comment = _make_comment()
        action = _make_action_item()
        app = _make_app(incidents=[inc], comments=[comment], action_items=[action])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/incidents/{INCIDENT_ID}", headers=_auth())
        assert resp.status_code == 200
        body = resp.json()
        assert body["incident"]["incident_id"] == INCIDENT_ID
        assert isinstance(body["comments"], list)
        assert isinstance(body["action_items"], list)
        assert isinstance(body["similar"], list)

    def test_missing_incident_returns_404(self):
        app = _make_app(incidents=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/incidents/{uuid.uuid4()}", headers=_auth())
        assert resp.status_code == 404

    def test_no_token_returns_401(self):
        app = _make_app(incidents=[_make_incident()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/incidents/{INCIDENT_ID}")
        assert resp.status_code == 401


# ------------------------------------------------------------------------------- tests: POST /incidents/{id}/transition


class TestTransitionIncident:
    def _post(self, app, incident_id: str, body: dict, role: str = "reviewer") -> Any:
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            f"/incidents/{incident_id}/transition",
            json=body,
            headers=_auth(role),
        )

    def test_reviewer_can_triage(self):
        inc = _make_incident(state="OPEN")
        app = _make_app(incidents=[inc])
        resp = self._post(app, INCIDENT_ID, {"target": "TRIAGING"}, role="reviewer")
        assert resp.status_code == 200
        assert resp.json()["state"] == "TRIAGING"

    def test_admin_can_resolve(self):
        inc = _make_incident(state="CONTAINED")
        app = _make_app(incidents=[inc])
        resp = self._post(app, INCIDENT_ID, {"target": "RESOLVED"}, role="admin")
        assert resp.status_code == 200
        assert resp.json()["state"] == "RESOLVED"

    def test_reviewer_gets_422_on_resolve(self):
        """Reviewer cannot move to RESOLVED — enforced by state machine inside the route."""
        inc = _make_incident(state="CONTAINED")
        app = _make_app(incidents=[inc])
        resp = self._post(app, INCIDENT_ID, {"target": "RESOLVED"}, role="reviewer")
        assert resp.status_code == 422

    def test_readonly_gets_403(self):
        inc = _make_incident(state="OPEN")
        app = _make_app(incidents=[inc])
        resp = self._post(app, INCIDENT_ID, {"target": "TRIAGING"}, role="readonly")
        assert resp.status_code == 403

    def test_no_token_returns_401(self):
        app = _make_app(incidents=[_make_incident()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(f"/incidents/{INCIDENT_ID}/transition", json={"target": "TRIAGING"})
        assert resp.status_code == 401

    def test_missing_incident_returns_404(self):
        app = _make_app(incidents=[])
        resp = self._post(app, str(uuid.uuid4()), {"target": "TRIAGING"})
        assert resp.status_code == 404

    def test_illegal_jump_returns_422(self):
        inc = _make_incident(state="OPEN")
        app = _make_app(incidents=[inc])
        resp = self._post(app, INCIDENT_ID, {"target": "RESOLVED"}, role="admin")
        assert resp.status_code == 422

    def test_dismiss_with_rationale_succeeds(self):
        inc = _make_incident(state="OPEN")
        app = _make_app(incidents=[inc])
        resp = self._post(
            app,
            INCIDENT_ID,
            {"target": "DISMISSED", "rationale": "confirmed false positive"},
            role="reviewer",
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "DISMISSED"

    def test_post_mortem_critical_with_uri(self):
        inc = _make_incident(state="RESOLVED", severity="critical")
        app = _make_app(incidents=[inc])
        resp = self._post(
            app,
            INCIDENT_ID,
            {"target": "POST_MORTEM_COMPLETE", "post_mortem_uri": "s3://pm.md"},
            role="admin",
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "POST_MORTEM_COMPLETE"

    def test_post_mortem_critical_without_uri_returns_422(self):
        inc = _make_incident(state="RESOLVED", severity="critical")
        app = _make_app(incidents=[inc])
        resp = self._post(app, INCIDENT_ID, {"target": "POST_MORTEM_COMPLETE"}, role="admin")
        assert resp.status_code == 422


# ------------------------------------------------------------------------------- tests: POST /incidents/{id}/comments


class TestAddComment:
    def test_reviewer_can_add_comment(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/comments",
            json={"body": "Looks like ASI01 pattern."},
            headers=_auth("reviewer"),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["body"] == "Looks like ASI01 pattern."
        assert "comment_id" in data

    def test_admin_can_add_comment(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/comments",
            json={"body": "Admin review complete."},
            headers=_auth("admin"),
        )
        assert resp.status_code == 201

    def test_readonly_gets_403(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/comments",
            json={"body": "I can see this!"},
            headers=_auth("readonly"),
        )
        assert resp.status_code == 403

    def test_no_token_returns_401(self):
        app = _make_app(incidents=[_make_incident()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(f"/incidents/{INCIDENT_ID}/comments", json={"body": "test"})
        assert resp.status_code == 401

    def test_missing_incident_returns_404(self):
        app = _make_app(incidents=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{uuid.uuid4()}/comments",
            json={"body": "test"},
            headers=_auth("reviewer"),
        )
        assert resp.status_code == 404


# ------------------------------------------------------------------------------- tests: POST /incidents/{id}/action-items


class TestAddActionItem:
    def test_reviewer_can_add_action_item(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/action-items",
            json={"description": "Tighten the Rego policy."},
            headers=_auth("reviewer"),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["description"] == "Tighten the Rego policy."
        assert data["status"] == "open"
        assert "action_id" in data

    def test_with_owner_and_due_date(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/action-items",
            json={
                "description": "Add adversarial test.",
                "owner_id": str(uuid.uuid4()),
                "due_date": "2025-12-31",
            },
            headers=_auth("admin"),
        )
        assert resp.status_code == 201
        assert resp.json()["due_date"] == "2025-12-31"

    def test_invalid_due_date_returns_422(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/action-items",
            json={"description": "Fix it.", "due_date": "not-a-date"},
            headers=_auth("admin"),
        )
        assert resp.status_code == 422

    def test_readonly_gets_403(self):
        inc = _make_incident()
        app = _make_app(incidents=[inc])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/action-items",
            json={"description": "I tried."},
            headers=_auth("readonly"),
        )
        assert resp.status_code == 403

    def test_missing_incident_returns_404(self):
        app = _make_app(incidents=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{uuid.uuid4()}/action-items",
            json={"description": "Fix it."},
            headers=_auth("admin"),
        )
        assert resp.status_code == 404

    def test_no_token_returns_401(self):
        app = _make_app(incidents=[_make_incident()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/incidents/{INCIDENT_ID}/action-items",
            json={"description": "Test."},
        )
        assert resp.status_code == 401
