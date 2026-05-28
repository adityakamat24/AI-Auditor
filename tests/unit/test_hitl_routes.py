"""Unit tests for auditor.api.hitl_routes.

All database access is replaced with in-memory fakes via ``app.dependency_overrides`` - no live
DB required.  A fresh FastAPI app with ``hitl_router`` mounted is created per test class.

Covers:
  - GET /hitl/flags  returns seeded flags.
  - POST /hitl/flags/{id}/decisions  403 for readonly, 201 for reviewer/admin.
  - GET /hitl/flags/{id}  returns flag + trace events.
  - GET /hitl/runs/{id}  run detail.
  - GET /hitl/runs/{id}/events  event list.
  - WS /hitl/ws/flags  receives a published flag.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

from auditor.api.auth import issue_token
from auditor.api.hitl_routes import (
    FlagBroadcaster,
    flag_broadcaster,
    get_db_session,
    hitl_router,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------------------------- in-memory fakes


def _uuid() -> str:
    return str(uuid.uuid4())


TENANT_ID = _uuid()
RUN_ID = _uuid()
FLAG_ID = _uuid()
FLAG_ID_2 = _uuid()
EVENT_ID = _uuid()


def _make_flag(flag_id: str = FLAG_ID, status: str = "open", severity: str = "high") -> Any:
    """Return a minimal mock Flag object compatible with _flag_to_dict."""

    class MockFlag:
        pass

    f = MockFlag()
    f.flag_id = flag_id
    f.run_id = RUN_ID
    f.tenant_id = TENANT_ID
    f.severity = severity
    f.status = status
    f.asi_categories = ["ASI01"]
    f.created_at = datetime(2025, 1, 1, tzinfo=UTC)
    f.resolved_at = None
    f.resolution = None
    return f


def _make_event() -> Any:
    class MockEvent:
        pass

    e = MockEvent()
    e.event_id = EVENT_ID
    e.run_id = RUN_ID
    e.tenant_id = TENANT_ID
    e.event_type = "tool_call.start"
    e.channel = "VOLUNTARY"
    e.ts = datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC)
    e.payload = {"tool_name": "file_read"}
    return e


def _make_run() -> Any:
    class MockRun:
        pass

    r = MockRun()
    r.run_id = RUN_ID
    r.tenant_id = TENANT_ID
    r.status = "running"
    r.started_at = datetime(2025, 1, 1, tzinfo=UTC)
    r.ended_at = None
    r.declared_goal = "test goal"
    return r


# ------------------------------------------------------------------------------- fake session


class _FakeSession:
    """Minimal async-context-manager stub for SQLAlchemy AsyncSession."""

    def __init__(self, flags=(), events=(), runs=()):
        self._flags = list(flags)
        self._events = list(events)
        self._runs = list(runs)
        self._added: list[Any] = []

    async def execute(self, stmt, *args, **kwargs):  # noqa: ARG002
        """Return a fake result based on the query string (duck-typing)."""
        stmt_str = str(stmt)

        class _Result:
            def __init__(self, rows):
                self._rows = rows

            def scalars(self):
                return self

            def all(self):
                return self._rows

            def scalar_one_or_none(self):
                return self._rows[0] if self._rows else None

        # Determine which table the query targets by checking for model class references.
        if "flags" in stmt_str.lower():
            return _Result(self._flags)
        if "events" in stmt_str.lower():
            return _Result(self._events)
        if "runs" in stmt_str.lower():
            return _Result(self._runs)
        return _Result([])

    def add(self, obj):
        self._added.append(obj)

    async def flush(self):
        pass

    def begin(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def _fake_session_dep(flags=(), events=(), runs=()):
    """Return a FastAPI dependency override that yields a _FakeSession."""

    async def _dep() -> AsyncGenerator[_FakeSession, None]:
        yield _FakeSession(flags=flags, events=events, runs=runs)

    return _dep


# ------------------------------------------------------------------------------- app factory


def _make_app(*, flags=(), events=(), runs=(), audit_ok: bool = True) -> FastAPI:
    """Create a fresh FastAPI app with hitl_router and DB faked out."""
    app = FastAPI()
    app.include_router(hitl_router)

    app.dependency_overrides[get_db_session] = _fake_session_dep(
        flags=flags, events=events, runs=runs
    )

    # Stub out AuditLogWriter so tests never hit Postgres.
    import auditor.api.hitl_routes as routes_mod

    class _StubWriter:
        async def append(self, *args, **kwargs):
            return b"\x00" * 32

    import unittest.mock

    app.state._audit_writer_patch = unittest.mock.patch.object(
        routes_mod, "AuditLogWriter", _StubWriter
    )

    return app


# ------------------------------------------------------------------------------- token helpers


def _token(role: str = "reviewer") -> str:
    return issue_token(user_id=_uuid(), tenant_id=TENANT_ID, role=role)


def _auth(role: str = "reviewer") -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


# ------------------------------------------------------------------------------- tests: GET /flags


class TestListFlags:
    def test_returns_seeded_flags(self):
        flag = _make_flag()
        app = _make_app(flags=[flag])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/hitl/flags", headers=_auth())
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["flag_id"] == FLAG_ID
        assert data[0]["severity"] == "high"

    def test_no_token_returns_401(self):
        app = _make_app(flags=[_make_flag()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/hitl/flags")
        assert resp.status_code == 401

    def test_readonly_can_list_flags(self):
        app = _make_app(flags=[_make_flag()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/hitl/flags", headers=_auth("readonly"))
        assert resp.status_code == 200

    def test_empty_db_returns_empty_list(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/hitl/flags", headers=_auth())
        assert resp.status_code == 200
        assert resp.json() == []


# ------------------------------------------------------------------------------- tests: GET /flags/{id}


class TestGetFlagDetail:
    def test_returns_flag_and_trace(self):
        flag = _make_flag()
        event = _make_event()
        # The fake session needs to handle two different queries (flags + events).
        # We load both so the fake can return them based on the stmt string.
        app = _make_app(flags=[flag], events=[event])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/flags/{FLAG_ID}", headers=_auth())
        assert resp.status_code == 200
        body = resp.json()
        assert body["flag"]["flag_id"] == FLAG_ID
        assert isinstance(body["trace"], list)

    def test_missing_flag_returns_404(self):
        app = _make_app(flags=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/flags/{_uuid()}", headers=_auth())
        assert resp.status_code == 404

    def test_no_token_returns_401(self):
        app = _make_app(flags=[_make_flag()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/flags/{FLAG_ID}")
        assert resp.status_code == 401


# ------------------------------------------------------------------------------- tests: POST /flags/{id}/decisions


class TestSubmitDecision:
    def _post(self, app: FastAPI, flag_id: str, role: str, body: dict) -> Any:
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            f"/hitl/flags/{flag_id}/decisions",
            json=body,
            headers=_auth(role),
        )

    def test_reviewer_can_submit_decision(self):
        app = _make_app(flags=[_make_flag()])
        resp = self._post(app, FLAG_ID, "reviewer", {"decision": "continue"})
        assert resp.status_code == 201
        assert resp.json()["decision"] == "continue"

    def test_admin_can_submit_decision(self):
        app = _make_app(flags=[_make_flag()])
        resp = self._post(app, FLAG_ID, "admin", {"decision": "abort", "rationale": "bad run"})
        assert resp.status_code == 201
        assert resp.json()["decision"] == "abort"

    def test_readonly_gets_403(self):
        app = _make_app(flags=[_make_flag()])
        resp = self._post(app, FLAG_ID, "readonly", {"decision": "continue"})
        assert resp.status_code == 403

    def test_no_token_gets_401(self):
        app = _make_app(flags=[_make_flag()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(f"/hitl/flags/{FLAG_ID}/decisions", json={"decision": "continue"})
        assert resp.status_code == 401

    def test_invalid_decision_gets_422(self):
        app = _make_app(flags=[_make_flag()])
        resp = self._post(app, FLAG_ID, "reviewer", {"decision": "invalid_value"})
        assert resp.status_code == 422

    def test_missing_flag_returns_404(self):
        app = _make_app(flags=[])
        resp = self._post(app, _uuid(), "reviewer", {"decision": "quarantine"})
        assert resp.status_code == 404

    def test_decision_with_rationale(self):
        app = _make_app(flags=[_make_flag()])
        resp = self._post(
            app, FLAG_ID, "reviewer", {"decision": "quarantine", "rationale": "Suspicious activity"}
        )
        assert resp.status_code == 201
        assert resp.json()["rationale"] == "Suspicious activity"


# ------------------------------------------------------------------------------- tests: GET /runs/{id}


class TestGetRun:
    def test_returns_run_detail(self):
        run = _make_run()
        app = _make_app(runs=[run])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/runs/{RUN_ID}", headers=_auth())
        assert resp.status_code == 200
        assert resp.json()["run_id"] == RUN_ID

    def test_missing_run_returns_404(self):
        app = _make_app(runs=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/runs/{_uuid()}", headers=_auth())
        assert resp.status_code == 404

    def test_no_token_returns_401(self):
        app = _make_app(runs=[_make_run()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/runs/{RUN_ID}")
        assert resp.status_code == 401


# ------------------------------------------------------------------------------- tests: GET /runs/{id}/events


class TestGetRunEvents:
    def test_returns_events(self):
        run = _make_run()
        event = _make_event()
        app = _make_app(runs=[run], events=[event])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/runs/{RUN_ID}/events", headers=_auth())
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_missing_run_returns_404(self):
        app = _make_app(runs=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/hitl/runs/{_uuid()}/events", headers=_auth())
        assert resp.status_code == 404


# ------------------------------------------------------------------------------- tests: WS /ws/flags


class TestWebSocketFlags:
    def test_receives_published_flag(self):
        """A flag published to flag_broadcaster is delivered to a subscribed WS client."""
        app = _make_app()
        flag_payload = {"flag_id": FLAG_ID, "tenant_id": TENANT_ID, "severity": "critical"}

        with TestClient(app) as client:
            with client.websocket_connect(f"/hitl/ws/flags?tenant_id={TENANT_ID}") as ws:
                # Publish after the WS handler is ready.
                flag_broadcaster.publish(flag_payload)
                # receive_json() in Starlette TestClient does not accept a timeout kwarg.
                data = ws.receive_json()
                # We might receive a keepalive ping first; loop until we see the flag.
                for _ in range(10):
                    if data.get("flag_id") == FLAG_ID:
                        break
                    data = ws.receive_json()
                assert data["flag_id"] == FLAG_ID
                assert data["severity"] == "critical"

    def test_flag_for_other_tenant_not_received(self):
        """A flag for a different tenant is NOT delivered."""
        other_tenant = _uuid()
        flag_payload = {"flag_id": FLAG_ID, "tenant_id": other_tenant, "severity": "high"}

        async def _publish_and_check() -> list:
            q = flag_broadcaster.subscribe(TENANT_ID)
            flag_broadcaster.publish(flag_payload)
            await asyncio.sleep(0.05)
            items = []
            while not q.empty():
                items.append(q.get_nowait())
            flag_broadcaster.unsubscribe(TENANT_ID, q)
            return items

        # asyncio.run() is the modern way; avoids deprecation of get_event_loop().
        result = asyncio.run(_publish_and_check())
        assert result == [], f"expected no items, got {result}"

    def test_broadcaster_subscribe_and_publish(self):
        """Unit test for FlagBroadcaster logic in isolation."""
        broadcaster = FlagBroadcaster()
        q = broadcaster.subscribe("t1")
        broadcaster.publish({"flag_id": "f1", "tenant_id": "t1"})
        broadcaster.publish({"flag_id": "f2", "tenant_id": "t2"})  # different tenant

        items = []
        while not q.empty():
            items.append(q.get_nowait())

        assert len(items) == 1
        assert items[0]["flag_id"] == "f1"

        broadcaster.unsubscribe("t1", q)
        broadcaster.publish({"flag_id": "f3", "tenant_id": "t1"})
        assert q.empty()  # no longer subscribed
