"""Reusable in-process gate session for adversarial attacks + the runner.

Stands up the same wiring as production (OPA policy + Presidio + tool-budget + GateDispatcher behind an
mTLS IpcServer) and connects a harness Telemetry client to it, so a scripted attack can drive gated
tool calls and observe the auditor's decisions. Requires the backing services (Postgres/Redis/OPA) up.
"""

from __future__ import annotations

import socket
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import redis.asyncio as aioredis
from auditor.auth.ca import init_ca, mint_leaf_to_files
from auditor.config import Settings, get_settings
from auditor.db.models import Tenant
from auditor.db.session import dispose_engine, get_sessionmaker
from auditor.ids import uuid7
from auditor.inline_gate.budget import BudgetEnforcer
from auditor.inline_gate.pii_scanner import PiiScanner
from auditor.inline_gate.policy_engine import OpaClient
from auditor.ipc.auth import build_client_context, build_server_context
from auditor.ipc.dispatch import GateDispatcher
from auditor.ipc.server import IpcServer
from auditor.ipc.transport import LoopbackTcpTransport
from harness.telemetry.sdk import Telemetry

DEMO_TENANT = UUID("00000000-0000-0000-0000-000000000001")
_REGO = (
    Path(__file__).resolve().parents[1] / "opa" / "policies" / "default.rego"
).read_text(encoding="utf-8")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _ensure_tenant() -> None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        if await session.get(Tenant, DEMO_TENANT) is None:
            session.add(Tenant(tenant_id=DEMO_TENANT, name="Demo Tenant"))


@asynccontextmanager
async def gate_session():
    """Yield ``(telemetry, run_id, agent_id)`` connected over mTLS to an in-process auditor gate."""
    settings = get_settings()
    await _ensure_tenant()

    opa = OpaClient(settings.opa_url)
    await opa.load_policy(_REGO)
    pii = PiiScanner()
    redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    budget = BudgetEnforcer(redis)
    dispatcher = GateDispatcher(opa=opa, pii=pii, budget=budget)

    data_dir = tempfile.mkdtemp(prefix="adv-certs-")
    init_ca(data_dir)
    run_id = uuid7()
    s_cert, s_key, ca = mint_leaf_to_files(
        data_dir, role="auditor", run_id="server", tenant_id=str(DEMO_TENANT), hostname="auditor.local"
    )
    c_cert, c_key, _ = mint_leaf_to_files(
        data_dir, role="harness", run_id=str(run_id), tenant_id=str(DEMO_TENANT), hostname="harness.local"
    )
    port = _free_port()
    client_settings = Settings(
        ipc_transport="tcp", ipc_tcp_host="127.0.0.1", ipc_tcp_port=port,
        gate_timeout_ms=3000, _env_file=None,
    )
    server = IpcServer(
        LoopbackTcpTransport("127.0.0.1", port),
        ssl_context=build_server_context(s_cert, s_key, ca),
        dispatcher=dispatcher,
    )
    await server.start()
    telemetry = None
    try:
        telemetry = await Telemetry.connect(
            run_id, DEMO_TENANT, client_settings,
            ssl_context=build_client_context(c_cert, c_key, ca), server_hostname="auditor.local",
        )
        yield telemetry, run_id, uuid7()
    finally:
        if telemetry is not None:
            await telemetry.close()
        await server.stop()
        await opa.aclose()
        await redis.aclose()
        await dispose_engine()
