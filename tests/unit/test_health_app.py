"""FastAPI app boots via ASGI and /health aggregates probe results — without live services."""

from __future__ import annotations

import auditor.api.health as health_mod
import httpx
import pytest
from asgi_lifespan import LifespanManager
from auditor.main import app


@pytest.fixture(autouse=True)
def _offline_lifespan(monkeypatch: pytest.MonkeyPatch) -> None:
    # Keep the lifespan fully offline: don't connect to MinIO or bind the IPC port in unit tests.
    async def _noop(_app) -> None:
        return None

    monkeypatch.setattr("auditor.main._ensure_buckets", _noop)
    monkeypatch.setattr("auditor.main._build_gate", _noop)
    monkeypatch.setattr("auditor.main._start_ipc_server", _noop)


async def _get(path: str) -> httpx.Response:
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get(path)


async def test_healthz_live_is_dependency_free() -> None:
    resp = await _get("/healthz/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


async def test_root_reports_service() -> None:
    resp = await _get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "ai-auditor"


async def test_health_all_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(_request) -> tuple[bool, str]:
        return True, "ok"

    for name in ("probe_postgres", "probe_redis", "probe_minio", "probe_opa"):
        monkeypatch.setattr(health_mod, name, ok)
    resp = await _get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert set(body["services"]) == {"postgres", "redis", "minio", "opa"}


async def test_health_degraded_when_a_service_down(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(_request) -> tuple[bool, str]:
        return True, "ok"

    async def bad(_request) -> tuple[bool, str]:
        return False, "connection refused"

    monkeypatch.setattr(health_mod, "probe_postgres", ok)
    monkeypatch.setattr(health_mod, "probe_redis", bad)
    monkeypatch.setattr(health_mod, "probe_minio", ok)
    monkeypatch.setattr(health_mod, "probe_opa", ok)
    resp = await _get("/health")
    assert resp.status_code == 503
    assert resp.json()["status"] == "degraded"
    assert resp.json()["services"]["redis"]["ok"] is False
