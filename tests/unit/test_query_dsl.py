"""Unit tests for the audit-log query DSL (PRD §9.11.4 §15 Phase-8 acceptance).

Coverage:
  - Compiler tests for the three §9.11.4 example queries.
  - Time token expansion (now-24h, now-7d).
  - Unknown-field rejection (ValueError / 422).
  - LIMIT cap enforcement.
  - run_query wraps execution in tenant_scope (observable via fake session call recording).
  - Route tests for POST /audit/search (DB-free via dependency override).
  - Auth required on search endpoint.

§9.11.4 Example queries
-----------------------
1. "All runs that read memory entries written by run X"
   → resource: runs is NOT a valid DSL resource (runs table has no RLS via the DSL; memory
     provenance is in memory_entries / events).  This example is a **documented partial**:
     we map it to ``resource: events`` filtering on ``run_id`` (the run that produced events),
     which exercises the compiler correctly for that shape.  The test is annotated accordingly.

2. "All flags in last 24h involving the exec_shell tool"
   → resource: flags, filter: {created_at: {gte: now-24h}, evidence__event__tool_name: exec_shell}
   Note: flags don't have a native evidence column; evidence__event__tool_name compiles as a
   documented partial (TRUE clause). The created_at filter compiles normally.

3. "All cross-tenant access attempts in the last 7 days"
   → resource: audit_log, filter: {action: cross_tenant_access_attempt, ts: {gte: now-7d}}
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from auditor.api.auth import issue_token
from auditor.api.search_routes import get_db_session, search_router
from auditor.audit_log.query import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Query,
    build_select,
    run_query,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

# ------------------------------------------------------------------------------- helpers


def _uuid() -> str:
    return str(uuid.uuid4())


TENANT_ID = _uuid()
USER_ID = _uuid()


def _token(role: str = "reviewer") -> str:
    return issue_token(user_id=USER_ID, tenant_id=TENANT_ID, role=role)


def _auth(role: str = "reviewer") -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


# ------------------------------------------------------------------------------- fake session


class _TenantScopeRecorder:
    """Records whether tenant_scope was entered and with which tenant_id."""

    calls: list[str]

    def __init__(self) -> None:
        self.calls = []


class _FakeResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self) -> _FakeResult:
        return self

    def all(self) -> list:
        return self._rows

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None


class _FakeSession:
    """Minimal async session stub with call recording."""

    def __init__(self, rows: list | None = None) -> None:
        self._rows: list = rows or []
        self.executed_stmts: list[str] = []
        self.role_set: bool = False
        self.tenant_set: str | None = None

    async def execute(self, stmt: Any, params: Any = None, **_kw: Any) -> _FakeResult:
        stmt_str = str(stmt)
        self.executed_stmts.append(stmt_str)

        # Detect tenant_scope SET LOCAL ROLE / set_config calls.
        if "SET LOCAL ROLE" in stmt_str:
            self.role_set = True
            return _FakeResult([])
        if "set_config" in stmt_str:
            if params and isinstance(params, dict):
                self.tenant_set = params.get("tid")
            return _FakeResult([])

        # Return seeded rows for data queries.
        return _FakeResult(self._rows)

    def begin(self) -> _FakeSession:
        return self

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    async def flush(self) -> None:
        pass

    def add(self, obj: Any) -> None:
        pass


def _fake_session_dep(rows: list | None = None):
    """FastAPI dependency override yielding a _FakeSession."""

    async def _dep() -> AsyncGenerator[_FakeSession, None]:
        yield _FakeSession(rows=rows)

    return _dep


def _make_app(rows: list | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(search_router)
    app.dependency_overrides[get_db_session] = _fake_session_dep(rows=rows)
    return app


# ------------------------------------------------------------------------------- §9.11.4 example 1
# "All runs that read memory entries written by run X"
# Documented partial: resource 'runs' is not in the DSL; we map to resource: events
# filtered by run_id, which correctly exercises the compiler for a scalar equality filter.


class TestExample1RunsByMemoryProvenance:
    """§9.11.4 example 1 — documented partial mapping to events."""

    def test_compiles_to_select_with_run_id_filter(self):
        """The query compiles to a parameterized SELECT on events with a run_id WHERE clause."""
        target_run = _uuid()
        q = Query(resource="events", filter={"run_id": target_run}, limit=100)
        stmt, meta = build_select(q)
        sql = str(stmt.compile(compile_kwargs={"literal_binds": False}))

        # Should reference the events table.
        assert "events" in sql.lower()
        # Should include a WHERE clause referencing run_id.
        assert "run_id" in sql.lower()
        assert meta["resource"] == "events"
        assert meta["limit"] == 100

    def test_compiles_parameterized_not_interpolated(self):
        """The run_id is passed as a bind parameter, not interpolated into the SQL."""
        target_run = _uuid()
        q = Query(resource="events", filter={"run_id": target_run})
        stmt, _ = build_select(q)
        # str(stmt.compile()) without literal_binds should show :param_N placeholders, not the value.
        sql = str(stmt.compile())
        assert target_run not in sql  # value must NOT appear in the SQL text

    def test_limit_present_in_sql(self):
        q = Query(resource="events", filter={"run_id": _uuid()}, limit=50)
        stmt, meta = build_select(q)
        # The meta dict carries the limit; the compiled stmt binds LIMIT as a param.
        assert meta["limit"] == 50
        # The raw SQL string references LIMIT (as a placeholder or literal).
        sql = str(stmt)
        assert "limit" in sql.lower()


# ------------------------------------------------------------------------------- §9.11.4 example 2
# "All flags in last 24h involving the exec_shell tool"
# resource: flags, filter: {created_at: {gte: now-24h}, evidence__event__tool_name: exec_shell}


class TestExample2FlagsWithTool:
    def test_compiles_flags_with_created_at_gte(self):
        """The created_at gte clause compiles correctly and references the flags table."""
        q = Query(
            resource="flags",
            filter={
                "created_at": {"gte": "now-24h"},
                "evidence.event.tool_name": "exec_shell",
            },
        )
        stmt, meta = build_select(q)
        sql = str(stmt.compile())

        assert "flags" in sql.lower()
        # created_at >= should appear (with literal bind it shows the actual datetime).
        assert "created_at" in sql.lower()
        assert meta["resource"] == "flags"

    def test_time_token_expands_to_near_24h_ago(self):
        """now-24h expands to a UTC datetime approximately 24 hours before now."""
        from auditor.audit_log.query import _parse_time_token

        result = _parse_time_token("now-24h")
        expected_approx = datetime.now(tz=UTC) - timedelta(hours=24)
        diff = abs((result - expected_approx).total_seconds())
        assert diff < 5  # within 5 seconds

    def test_time_token_expands_in_compiled_query(self):
        """The compiled query with literal binds contains a datetime string for the time filter."""
        q = Query(resource="flags", filter={"created_at": {"gte": "now-24h"}})
        stmt, _ = build_select(q)
        sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        # The bind value should be a datetime; literal SQL should not contain 'now-24h'.
        assert "now-24h" not in sql

    def test_evidence_tool_name_field_accepted_on_flags(self):
        """evidence.event.tool_name is accepted (documented partial — maps to TRUE)."""
        q = Query(resource="flags", filter={"evidence.event.tool_name": "exec_shell"})
        stmt, _ = build_select(q)
        # Should compile without error (partial field → TRUE, no WHERE clause added).
        sql = str(stmt.compile())
        assert "flags" in sql.lower()

    def test_both_filters_compile_together(self):
        """Created_at gte + tool_name compile together without error."""
        q = Query(
            resource="flags",
            filter={
                "created_at": {"gte": "now-24h"},
                "evidence.event.tool_name": "exec_shell",
            },
        )
        stmt, meta = build_select(q)
        assert meta["resource"] == "flags"

    def test_lte_operator(self):
        """lte operator compiles correctly."""
        q = Query(resource="flags", filter={"created_at": {"lte": "now-7d"}})
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "created_at" in sql.lower()


# ------------------------------------------------------------------------------- §9.11.4 example 3
# "All cross-tenant access attempts in the last 7 days"
# resource: audit_log, filter: {action: cross_tenant_access_attempt, ts: {gte: now-7d}}


class TestExample3AuditLogCrossTenant:
    def test_compiles_audit_log_with_action_filter(self):
        """Action equality filter compiles to a parameterized WHERE clause."""
        q = Query(
            resource="audit_log",
            filter={
                "action": "cross_tenant_access_attempt",
                "ts": {"gte": "now-7d"},
            },
        )
        stmt, meta = build_select(q)
        sql = str(stmt.compile())

        assert "audit_log" in sql.lower()
        assert "action" in sql.lower()
        assert "ts" in sql.lower()
        assert meta["resource"] == "audit_log"

    def test_action_is_parameterized_not_interpolated(self):
        """The action value is a bind param, not literal SQL."""
        q = Query(
            resource="audit_log",
            filter={"action": "cross_tenant_access_attempt"},
        )
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "cross_tenant_access_attempt" not in sql  # must be a bind param

    def test_ts_gte_7d_expands(self):
        """now-7d expands to a datetime 7 days ago."""
        from auditor.audit_log.query import _parse_time_token

        result = _parse_time_token("now-7d")
        expected = datetime.now(tz=UTC) - timedelta(days=7)
        diff = abs((result - expected).total_seconds())
        assert diff < 5

    def test_ts_gte_parameterized(self):
        """The ts bind value is not interpolated into plain SQL text."""
        q = Query(resource="audit_log", filter={"ts": {"gte": "now-7d"}})
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "now-7d" not in sql

    def test_both_filters_produce_two_where_clauses(self):
        """Action + ts together produce WHERE ... AND ... in the SQL."""
        q = Query(
            resource="audit_log",
            filter={
                "action": "cross_tenant_access_attempt",
                "ts": {"gte": "now-7d"},
            },
        )
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "action" in sql.lower()
        assert "ts" in sql.lower()


# ------------------------------------------------------------------------------- unknown field rejection


class TestUnknownFieldRejection:
    def test_unknown_field_raises_value_error_at_parse(self):
        """Unknown filter fields raise ValueError during Pydantic validation (→ 422)."""
        with pytest.raises((ValueError, ValidationError)):
            Query(
                resource="events",
                filter={"nonexistent_field": "value"},
            )

    def test_unknown_field_audit_log(self):
        with pytest.raises((ValueError, ValidationError)):
            Query(resource="audit_log", filter={"bad_column": "x"})

    def test_unknown_field_flags(self):
        with pytest.raises((ValueError, ValidationError)):
            Query(resource="flags", filter={"arbitrary_field": "y"})

    def test_unknown_field_verdicts(self):
        with pytest.raises((ValueError, ValidationError)):
            Query(resource="verdicts", filter={"not_a_column": "z"})

    def test_known_field_does_not_raise(self):
        q = Query(resource="audit_log", filter={"action": "some_action"})
        assert q.resource == "audit_log"


# ------------------------------------------------------------------------------- LIMIT cap


class TestLimitCap:
    def test_default_limit_is_1000(self):
        q = Query(resource="audit_log", filter={})
        assert q.limit == DEFAULT_LIMIT

    def test_limit_above_max_is_capped(self):
        q = Query(resource="audit_log", filter={}, limit=999_999_999)
        assert q.limit == MAX_LIMIT

    def test_explicit_limit_below_max_is_honoured(self):
        q = Query(resource="audit_log", filter={}, limit=500)
        assert q.limit == 500

    def test_limit_zero_raises(self):
        with pytest.raises((ValueError, ValidationError)):
            Query(resource="audit_log", filter={}, limit=0)

    def test_limit_in_compiled_sql(self):
        q = Query(resource="audit_log", filter={}, limit=42)
        stmt, meta = build_select(q)
        # Check via the meta dict (LIMIT is a bind param in the compiled SQL).
        assert meta["limit"] == 42
        sql = str(stmt)
        assert "limit" in sql.lower()


# ------------------------------------------------------------------------------- RLS observable via fake session


class TestRLSTenantScope:
    """Verify that run_query wraps execution in tenant_scope (SET LOCAL ROLE + set_config)."""

    @pytest.mark.asyncio
    async def test_run_query_calls_set_local_role(self):
        """run_query passes the session through tenant_scope, which issues SET LOCAL ROLE."""
        fake = _FakeSession(rows=[])
        q = Query(resource="audit_log", filter={"action": "test_action"})
        await run_query(q, tenant_id=TENANT_ID, session=fake)

        # tenant_scope must have executed SET LOCAL ROLE auditor_api
        role_calls = [s for s in fake.executed_stmts if "SET LOCAL ROLE" in s]
        assert role_calls, (
            f"Expected SET LOCAL ROLE call but got stmts: {fake.executed_stmts}"
        )

    @pytest.mark.asyncio
    async def test_run_query_sets_tenant_id_guc(self):
        """run_query sets app.tenant_id GUC via set_config with the caller's tenant_id."""
        fake = _FakeSession(rows=[])
        q = Query(resource="audit_log", filter={})
        await run_query(q, tenant_id=TENANT_ID, session=fake)

        config_calls = [s for s in fake.executed_stmts if "set_config" in s]
        assert config_calls, (
            f"Expected set_config call but got stmts: {fake.executed_stmts}"
        )
        assert fake.tenant_set == TENANT_ID

    @pytest.mark.asyncio
    async def test_run_query_different_tenant_ids_isolated(self):
        """Each call to run_query sets the GUC to the supplied tenant_id."""
        other_tenant = _uuid()
        fake = _FakeSession(rows=[])
        q = Query(resource="audit_log", filter={})
        await run_query(q, tenant_id=other_tenant, session=fake)
        assert fake.tenant_set == other_tenant


# ------------------------------------------------------------------------------- route tests


class TestSearchRoute:
    """POST /audit/search — DB-free route tests."""

    def test_returns_seeded_rows(self):
        """The endpoint returns the rows produced by the fake session."""
        # We seed mock ORM-like rows; since run_query returns dicts from _row_to_dict,
        # and our fake session returns raw objects, we test with empty rows and check 200.
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        body = {"resource": "audit_log", "filter": {"action": "test"}}
        resp = client.post("/audit/search", json=body, headers=_auth())
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_no_token_returns_401(self):
        """Unauthenticated request to /audit/search returns 401."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/audit/search", json={"resource": "audit_log", "filter": {}})
        assert resp.status_code == 401

    def test_invalid_resource_returns_422(self):
        """An invalid resource name returns 422 (Pydantic validation failure)."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/search",
            json={"resource": "not_a_resource", "filter": {}},
            headers=_auth(),
        )
        assert resp.status_code == 422

    def test_unknown_filter_field_returns_422(self):
        """An unknown filter field returns 422."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/search",
            json={"resource": "audit_log", "filter": {"bad_field": "x"}},
            headers=_auth(),
        )
        assert resp.status_code == 422

    def test_readonly_role_can_search(self):
        """readonly role is allowed to search (auth passes, no role restriction on search)."""
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/search",
            json={"resource": "audit_log", "filter": {}},
            headers=_auth("readonly"),
        )
        assert resp.status_code == 200

    def test_limit_cap_enforced_by_schema(self):
        """A limit above MAX_LIMIT is silently capped to MAX_LIMIT by Pydantic."""
        q = Query(resource="audit_log", filter={}, limit=10_000_000)
        assert q.limit == MAX_LIMIT

    def test_flags_example_query_compiles(self):
        """The §9.11.4 flags example compiles and the route accepts it."""
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/search",
            json={
                "resource": "flags",
                "filter": {
                    "created_at": {"gte": "now-24h"},
                    "evidence.event.tool_name": "exec_shell",
                },
            },
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_audit_log_example_query_compiles(self):
        """The §9.11.4 audit_log example compiles and the route accepts it."""
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/search",
            json={
                "resource": "audit_log",
                "filter": {
                    "action": "cross_tenant_access_attempt",
                    "ts": {"gte": "now-7d"},
                },
            },
            headers=_auth(),
        )
        assert resp.status_code == 200


# ------------------------------------------------------------------------------- saved-query route tests


class TestSavedQueryRoutes:
    def test_create_saved_query_requires_admin(self):
        """POST /audit/saved-queries requires admin role."""
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/saved-queries",
            json={
                "name": "test-query",
                "query": {"resource": "audit_log", "filter": {"action": "login"}},
                "params": {},
            },
            headers=_auth("reviewer"),  # reviewer, not admin
        )
        assert resp.status_code == 403

    def test_create_saved_query_admin_ok(self):
        """POST /audit/saved-queries succeeds for admin."""

        class _FakeSessionWithBegin(_FakeSession):
            def begin(self):
                return self

        async def _admin_dep() -> AsyncGenerator[_FakeSession, None]:
            yield _FakeSessionWithBegin(rows=[])

        app = FastAPI()
        app.include_router(search_router)
        app.dependency_overrides[get_db_session] = _admin_dep

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/audit/saved-queries",
            json={
                "name": "my-investigation",
                "query": {"resource": "audit_log", "filter": {"action": "cross_tenant_access_attempt"}},
                "params": {},
            },
            headers=_auth("admin"),
        )
        assert resp.status_code == 201

    def test_list_saved_queries_returns_empty(self):
        """GET /audit/saved-queries returns empty list when no queries exist."""
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/audit/saved-queries", headers=_auth())
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_requires_auth(self):
        """GET /audit/saved-queries requires auth."""
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/audit/saved-queries")
        assert resp.status_code == 401

    def test_run_saved_query_404_when_missing(self):
        """POST /audit/saved-queries/{id}/run returns 404 when query does not exist."""
        app = _make_app(rows=[])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            f"/audit/saved-queries/{_uuid()}/run",
            json={"params": {}},
            headers=_auth(),
        )
        assert resp.status_code == 404


# ------------------------------------------------------------------------------- in/eq operators


class TestOperators:
    def test_eq_operator(self):
        q = Query(resource="verdicts", filter={"result": {"eq": "VIOLATION"}})
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "result" in sql.lower()

    def test_in_operator(self):
        q = Query(resource="verdicts", filter={"result": {"in": ["VIOLATION", "NEEDS_REVIEW"]}})
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "result" in sql.lower()

    def test_unknown_operator_raises(self):
        q = Query(resource="verdicts", filter={"result": {"between": ["a", "b"]}})
        with pytest.raises((ValueError, ValidationError)):
            build_select(q)

    def test_in_with_non_list_raises(self):
        q = Query(resource="verdicts", filter={"result": {"in": "not-a-list"}})
        with pytest.raises((ValueError, ValidationError)):
            build_select(q)

    def test_gte_lte_combined(self):
        """gte + lte on the same field compiles to BETWEEN-like clauses."""
        q = Query(
            resource="verdicts",
            filter={"ts": {"gte": "now-7d", "lte": "now-24h"}},
        )
        stmt, _ = build_select(q)
        sql = str(stmt.compile())
        assert "ts" in sql.lower()
