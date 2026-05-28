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
    # Critical: a down state for these flips /health to 503 (Fly / k8s / load balancer signal).
    critical = {
        "postgres": probe_postgres,
        "redis": probe_redis,
        "opa": probe_opa,
    }
    # Optional: MinIO holds forensic blobs; the auditor + UI run fine without it (the cloud
    # demo container intentionally doesn't ship it). Reported in the body but never flips status.
    optional = {
        "minio": probe_minio,
    }

    crit_results = await asyncio.gather(*(p(request) for p in critical.values()))
    opt_results = await asyncio.gather(*(p(request) for p in optional.values()))

    services: dict[str, dict] = {}
    all_critical_ok = True
    any_optional_down = False
    for name, (ok, detail) in zip(critical, crit_results, strict=True):
        services[name] = {"ok": ok, "detail": detail, "required": True}
        all_critical_ok = all_critical_ok and ok
    for name, (ok, detail) in zip(optional, opt_results, strict=True):
        services[name] = {"ok": ok, "detail": detail, "required": False}
        any_optional_down = any_optional_down or not ok

    if not all_critical_ok:
        response.status_code = 503
        status = "degraded"
    elif any_optional_down:
        status = "ok-optional-down"
    else:
        status = "ok"
    return {"status": status, "version": __version__, "services": services}
