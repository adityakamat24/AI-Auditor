"""Auditor service entrypoint (FastAPI).

Boots, connects Postgres + Redis + MinIO, builds the inline gate (OPA policy + Presidio + tool-budget)
and starts the IPC control-plane server (mTLS when ``ipc_mtls_enabled``) so the harness can stream
telemetry and request gate decisions. Exposes ``/health``, ``/healthz/live``, ``/metrics``.

Startup is resilient: a down backing service is reported by ``/health`` rather than crashing boot.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from minio import Minio
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from auditor import __version__
from auditor.api.admin import admin_router
from auditor.api.agent_routes import agent_router
from auditor.api.auth_routes import auth_router
from auditor.api.health import router as health_router
from auditor.api.hitl_routes import hitl_router
from auditor.api.incidents_routes import incident_router
from auditor.api.search_routes import search_router
from auditor.api.shadow_routes import shadow_router
from auditor.auth.ca import init_ca, mint_leaf_to_files
from auditor.config import Settings, get_settings
from auditor.db.session import dispose_engine, get_engine
from auditor.inline_gate.budget import BudgetEnforcer
from auditor.inline_gate.pii_scanner import PiiScanner
from auditor.inline_gate.policy_engine import OpaClient
from auditor.ipc import IpcServer, select_transport
from auditor.ipc.auth import build_server_context
from auditor.ipc.dispatch import GateDispatcher
from auditor.logging import configure_logging, get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

log = get_logger("auditor.main")

_DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "opa" / "policies" / "default.rego"
_SERVER_HOSTNAME = "auditor.local"
_SERVER_TENANT = "00000000-0000-0000-0000-000000000000"  # the auditor's own (non-tenant) identity


async def _ensure_buckets(app: FastAPI) -> None:
    settings = app.state.settings
    buckets = [
        settings.minio_bucket_audit,
        settings.minio_bucket_checkpoints,
        settings.minio_bucket_ground_truth,
    ]
    minio: Minio = app.state.minio

    def _ensure() -> None:
        for bucket in buckets:
            if not minio.bucket_exists(bucket):
                minio.make_bucket(bucket)

    try:
        await asyncio.to_thread(_ensure)
        log.info("minio.buckets_ready", buckets=buckets)
    except Exception as exc:  # noqa: BLE001 - boot resiliently; /health will report MinIO down
        log.warning("minio.bucket_ensure_failed", error=str(exc))


async def _build_gate(app: FastAPI) -> None:
    """Build the inline-gate dependencies and load the default OPA policy."""
    settings = app.state.settings
    opa = OpaClient(settings.opa_url)
    try:
        await opa.load_policy(_DEFAULT_POLICY.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - boot resiliently; the gate fails closed per-request if OPA is down
        log.warning("opa.policy_load_failed", error=str(exc))
    app.state.opa = opa
    app.state.pii = PiiScanner()
    app.state.budget = BudgetEnforcer(app.state.redis)
    app.state.dispatcher = GateDispatcher(opa=opa, pii=app.state.pii, budget=app.state.budget)


def _server_ssl_context(settings: Settings) -> ssl.SSLContext | None:
    if not settings.ipc_mtls_enabled:
        return None
    init_ca(settings.data_dir)
    cert, key, ca = mint_leaf_to_files(
        settings.data_dir, role="auditor", run_id="server", tenant_id=_SERVER_TENANT,
        hostname=_SERVER_HOSTNAME,
    )
    return build_server_context(cert, key, ca)


async def _start_ipc_server(app: FastAPI) -> None:
    settings = app.state.settings
    if not settings.ipc_server_enabled:
        app.state.ipc_server = None
        return
    transport = select_transport(settings)
    try:
        ssl_context = _server_ssl_context(settings)
        server = IpcServer(transport, ssl_context=ssl_context, dispatcher=app.state.dispatcher)
        await server.start()
        app.state.ipc_server = server
        log.info("ipc.server_listening", endpoint=transport.describe(), mtls=ssl_context is not None)
    except Exception as exc:  # noqa: BLE001 - boot resiliently
        app.state.ipc_server = None
        log.warning("ipc.server_start_failed", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings)
    app.state.settings = settings
    app.state.engine = get_engine(settings)
    app.state.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    app.state.minio = Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )
    await _ensure_buckets(app)
    await _build_gate(app)
    # Reap runs that were 'running' when we last died. The harness children themselves are
    # already terminated by the kernel-level kill-on-parent-death mechanisms (PR_SET_PDEATHSIG /
    # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE); without this sweep their DB rows stay 'running'
    # forever and the UI lists them as "in progress" indefinitely.
    try:
        from auditor.events.store import reap_orphaned_runs

        orphans = await reap_orphaned_runs()
        if orphans:
            log.info("auditor.orphan_runs_reaped", count=orphans)
    except Exception as exc:  # noqa: BLE001 - DB may not be up yet on a brand-new deploy; don't block boot
        log.warning("auditor.orphan_sweep_failed", error=str(exc))
    await _start_ipc_server(app)
    log.info("auditor.started", version=__version__, env=settings.auditor_env)
    try:
        yield
    finally:
        if getattr(app.state, "ipc_server", None) is not None:
            await app.state.ipc_server.stop()
        if getattr(app.state, "opa", None) is not None:
            with contextlib.suppress(Exception):
                await app.state.opa.aclose()
        with contextlib.suppress(Exception):
            await app.state.redis.aclose()
        await dispose_engine()
        log.info("auditor.stopped")


def create_app() -> FastAPI:
    app = FastAPI(title="AI Auditor", version=__version__, lifespan=lifespan)

    # CORS - the Vite dev server runs on a different origin (5173) and sends OPTIONS preflights for
    # any JSON POST. Without this, the preflight 405s and the browser refuses to send the real request.
    # Allowed origins are explicit (no wildcard) so credentials work; tighten further in production.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173", "http://127.0.0.1:5173",  # vite dev
            "http://localhost:4173", "http://127.0.0.1:4173",  # vite preview
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(hitl_router)
    app.include_router(admin_router)
    app.include_router(auth_router)
    app.include_router(incident_router)
    app.include_router(search_router)
    app.include_router(shadow_router)
    app.include_router(agent_router)

    @app.get("/__service")
    async def service_info() -> dict:
        return {"service": "ai-auditor", "version": __version__}

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Serve the React UI from the same origin when a production build is present. The container
    # build runs `npm run build` and drops dist/ here so a single Fly.io app hosts both API and
    # UI. On a fresh local clone with no UI build, this mount is silently skipped and the dev
    # workflow (Vite on :5173 -> auditor on :8000) continues to work.
    import pathlib

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    ui_dist = pathlib.Path(__file__).resolve().parent.parent / "hitl_ui" / "frontend" / "dist"
    ui_index = ui_dist / "index.html"

    if ui_dist.is_dir() and ui_index.is_file():
        # The SPA and the API share URL paths (`/incidents`, `/settings`, ...). Distinguish browser
        # navigation from XHR/fetch by the Accept header: browsers send `text/html,...`; fetch()
        # defaults to `*/*`. When an API router returns 401/403/404 AND the client wanted HTML, we
        # swap the response for the SPA's index.html so react-router can render the right page
        # (which then makes its own fetch calls under the same paths - those fetches lack the
        # text/html Accept and so receive the original JSON error).
        @app.middleware("http")
        async def spa_html_fallback(request: Request, call_next):  # type: ignore[no-untyped-def]
            response = await call_next(request)
            if response.status_code in (401, 403, 404):
                accept = request.headers.get("accept", "")
                if "text/html" in accept:
                    return FileResponse(str(ui_index))
            return response

        # Catch-all static mount for everything else (assets, /favicon.ico, etc.). Order matters:
        # this is added LAST so all routers + middleware sit in front of it.
        app.mount("/", StaticFiles(directory=str(ui_dist), html=True), name="ui")
        log.info("auditor.ui_mounted", path=str(ui_dist))

    return app


app = create_app()


def cli() -> None:
    """Console entrypoint: run the ASGI server."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "auditor.main:app",
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    cli()
