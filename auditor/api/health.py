"""Health + readiness endpoints.

``/healthz/live`` is dependency-free (liveness). ``/health`` probes every backing service and returns
200 only when all are reachable, else 503 (used by the demo script to gate readiness).
"""

from __future__ import annotations

import asyncio

import httpx
from fastapi import APIRouter, Request, Response
from sqlalchemy import text

from auditor import __version__

router = APIRouter(tags=["health"])


async def probe_postgres(request: Request) -> tuple[bool, str]:
    try:
        async with request.app.state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 - report any failure as unhealthy
        return False, str(exc)


async def probe_redis(request: Request) -> tuple[bool, str]:
    try:
        pong = await request.app.state.redis.ping()
        return bool(pong), "ok" if pong else "no pong"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


async def probe_minio(request: Request) -> tuple[bool, str]:
    try:
        minio = request.app.state.minio
        bucket = request.app.state.settings.minio_bucket_audit
        ok = await asyncio.to_thread(minio.bucket_exists, bucket)
        return bool(ok), "ok" if ok else "audit bucket missing"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


async def probe_opa(request: Request) -> tuple[bool, str]:
    try:
        url = request.app.state.settings.opa_url.rstrip("/") + "/health"
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(url)
        ok = resp.status_code == 200
        return ok, "ok" if ok else f"status {resp.status_code}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


@router.get("/healthz/live")
async def live() -> dict:
    return {"status": "alive", "version": __version__}


@router.get("/health")
async def health(request: Request, response: Response) -> dict:
    probes = {
        "postgres": probe_postgres,
        "redis": probe_redis,
        "minio": probe_minio,
        "opa": probe_opa,
    }
    results = await asyncio.gather(*(probe(request) for probe in probes.values()))
    services: dict[str, dict] = {}
    all_ok = True
    for name, (ok, detail) in zip(probes, results, strict=True):
        services[name] = {"ok": ok, "detail": detail}
        all_ok = all_ok and ok
    if not all_ok:
        response.status_code = 503
    return {"status": "ok" if all_ok else "degraded", "version": __version__, "services": services}
