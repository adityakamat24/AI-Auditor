"""Unit tests for auditor.api.admin (calibration endpoints).

All database access is replaced with in-memory fakes via ``app.dependency_overrides`` - no live
DB required.  A fresh FastAPI app with ``admin_router`` mounted is created per test.

Covers:
  - GET /admin/calibration/latest requires admin (403 for reviewer/readonly, 200 for admin).
  - GET /admin/calibration/latest returns the seeded row when one exists.
  - GET /admin/calibration/latest returns {} when the table is empty.
  - POST /admin/calibration/run requires admin (403 for non-admin roles).
  - POST /admin/calibration/run returns a report dict with per_category + overall.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

from auditor.api.admin import admin_router, get_db_session
from auditor.api.auth import issue_token
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------------------------- fixtures / helpers


def _uuid() -> str:
    return str(uuid.uuid4())


TENANT_ID = _uuid()
CAL_ID = _uuid()


def _token(role: str = "admin") -> str:
    return issue_token(user_id=_uuid(), tenant_id=TENANT_ID, role=role)


def _auth(role: str = "admin") -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


# ------------------------------------------------------------------------------- mock CalibrationRun row


def _make_cal_run() -> Any:
    """Return a minimal mock CalibrationRun compatible with _calibration_run_to_dict."""

    class MockCalRun:
        pass

    r = MockCalRun()
    r.cal_id = CAL_ID
    r.ts = datetime(2026, 1, 1, tzinfo=UTC)
    r.judge_model = "offline-stub"
    r.judge_prompt_v = 1
    r.per_category = {"ASI01": {"precision": 1.0, "recall": 1.0, "f1": 1.0}}
    r.overall = {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    return r


# ------------------------------------------------------------------------------- fake session


class _FakeSession:
    """Minimal async-context-manager stub for SQLAlchemy AsyncSession."""

    def __init__(self, cal_runs: list[Any] | None = None) -> None:
        self._cal_runs: list[Any] = cal_runs or []
        self._added: list[Any] = []
        self._committed: bool = False

    async def execute(self, stmt, *args, **kwargs):  # noqa: ARG002
        class _Result:
            def __init__(self, rows: list[Any]) -> None:
                self._rows = rows

            def scalar_one_or_none(self) -> Any | None:
                return self._rows[0] if self._rows else None

            def scalars(self) -> _Result:
                return self

            def all(self) -> list[Any]:
                return self._rows

        stmt_str = str(stmt).lower()
        if "calibration_runs" in stmt_str or "calibrationrun" in stmt_str:
            return _Result(self._cal_runs)
        return _Result([])

    def add(self, obj: Any) -> None:
        self._added.append(obj)

    async def flush(self) -> None:
        pass

    async def commit(self) -> None:
        self._committed = True

    def begin(self) -> _FakeSession:
        return self

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


def _fake_session_dep(cal_runs: list[Any] | None = None):
    """Return a FastAPI dependency override yielding a _FakeSession."""
    _runs = cal_runs or []

    async def _dep() -> AsyncGenerator[_FakeSession, None]:
        yield _FakeSession(cal_runs=_runs)

    return _dep


# ------------------------------------------------------------------------------- app factory


def _make_app(cal_runs: list[Any] | None = None) -> FastAPI:
    """Create a fresh FastAPI app with admin_router and DB faked out."""
    app = FastAPI()
    app.include_router(admin_router)
    app.dependency_overrides[get_db_session] = _fake_session_dep(cal_runs)
    return app


# ------------------------------------------------------------------------------- GET /admin/calibration/latest


class TestGetLatestCalibration:
    def test_admin_gets_200_with_seeded_row(self):
        row = _make_cal_run()
        app = _make_app(cal_runs=[row])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/calibration/latest", headers=_auth("admin"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["judge_model"] == "offline-stub"
        assert data["judge_prompt_v"] == 1
        assert "per_category" in data
        assert "overall" in data
        assert "ts" in data

    def test_admin_gets_empty_dict_when_no_rows(self):
        app = _make_app(cal_runs=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/calibration/latest", headers=_auth("admin"))
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_reviewer_gets_403(self):
        app = _make_app(cal_runs=[_make_cal_run()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/calibration/latest", headers=_auth("reviewer"))
        assert resp.status_code == 403

    def test_readonly_gets_403(self):
        app = _make_app(cal_runs=[_make_cal_run()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/calibration/latest", headers=_auth("readonly"))
        assert resp.status_code == 403

    def test_no_token_gets_401(self):
        app = _make_app(cal_runs=[_make_cal_run()])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/calibration/latest")
        assert resp.status_code == 401

    def test_seeded_row_values_round_trip(self):
        """per_category and overall dicts are returned as-is."""
        row = _make_cal_run()
        app = _make_app(cal_runs=[row])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/calibration/latest", headers=_auth("admin"))
        data = resp.json()
        assert data["per_category"] == row.per_category
        assert data["overall"] == row.overall


# ------------------------------------------------------------------------------- POST /admin/calibration/run


class TestRunCalibration:
    def test_admin_gets_report(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("admin"))
        assert resp.status_code == 200
        data = resp.json()
        assert "per_category" in data
        assert "overall" in data

    def test_report_contains_required_fields(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("admin"))
        assert resp.status_code == 200
        data = resp.json()
        for field in ("per_category", "overall", "disabled", "judge_model", "judge_prompt_v", "ts"):
            assert field in data, f"missing field: {field}"

    def test_reviewer_gets_403(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("reviewer"))
        assert resp.status_code == 403

    def test_readonly_gets_403(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("readonly"))
        assert resp.status_code == 403

    def test_no_token_gets_401(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run")
        assert resp.status_code == 401

    def test_per_category_is_dict(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("admin"))
        data = resp.json()
        assert isinstance(data["per_category"], dict)

    def test_overall_is_dict(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("admin"))
        data = resp.json()
        assert isinstance(data["overall"], dict)

    def test_disabled_is_list(self):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/admin/calibration/run", headers=_auth("admin"))
        data = resp.json()
        assert isinstance(data["disabled"], list)
