"""End-to-end inline gate over mTLS: harness Telemetry SDK <-> auditor IpcServer + GateDispatcher.

Exercises Phase-2 acceptance on the gate path: a safe tool call is ALLOWed, exec_shell is DENYed,
and a same-tool loop is DENYed by the budget enforcer - all over a real mTLS connection, with the
events + decisions persisted to Postgres.
"""

from __future__ import annotations

import socket
from pathlib import Path
from uuid import UUID

import pytest
import redis.asyncio as aioredis
from auditor.auth.ca import init_ca, mint_leaf_to_files
from auditor.config import Settings, get_settings
from auditor.db.models import Event as EventRow
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
from harness.telemetry.sdk import GateDeniedError, Telemetry
from sqlalchemy import func, select

pytestmark = pytest.mark.integration

DEMO_TENANT = "00000000-0000-0000-0000-000000000001"
_REGO = (
    Path(__file__).resolve().parents[2] / "opa" / "policies" / "default.rego"
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
        if await session.get(Tenant, UUID(DEMO_TENANT)) is None:
            session.add(Tenant(tenant_id=UUID(DEMO_TENANT), name="Demo Tenant"))


async def test_gate_end_to_end_over_mtls(tmp_path) -> None:
    await _ensure_tenant()
    base_settings = get_settings()

    opa = OpaClient(base_settings.opa_url)
    await opa.load_policy(_REGO)
    pii = PiiScanner()
    redis = aioredis.from_url(base_settings.redis_url, decode_responses=True)
    budget = BudgetEnforcer(redis)
    dispatcher = GateDispatcher(opa=opa, pii=pii, budget=budget)

    data_dir = str(tmp_path)
    init_ca(data_dir)
    run_id = uuid7()
    s_cert, s_key, ca = mint_leaf_to_files(
        data_dir, role="auditor", run_id="server", tenant_id=DEMO_TENANT, hostname="auditor.local"
    )
    c_cert, c_key, _ = mint_leaf_to_files(
        data_dir, role="harness", run_id=str(run_id), tenant_id=DEMO_TENANT, hostname="harness.local"
    )
    server_ctx = build_server_context(s_cert, s_key, ca)
    client_ctx = build_client_context(c_cert, c_key, ca)

    port = _free_port()
    client_settings = Settings(
        ipc_transport="tcp", ipc_tcp_host="127.0.0.1", ipc_tcp_port=port,
        gate_timeout_ms=3000, _env_file=None,
    )
    server = IpcServer(LoopbackTcpTransport("127.0.0.1", port), ssl_context=server_ctx, dispatcher=dispatcher)
    await server.start()
    agent_id = uuid7()
    try:
        tel = await Telemetry.connect(
            run_id, UUID(DEMO_TENANT), client_settings,
            ssl_context=client_ctx, server_hostname="auditor.local",
        )

        await tel.declare_intent(agent_id, "triage a ticket", ["search kb", "create ticket"])

        # ALLOW: a benign tool.
        async with tel.tool_call(agent_id, "kb_search", {"q": "vpn setup"}) as decision:
            assert decision in ("ALLOW", "CONFIRM")

        # DENY: exec_shell without a declared purpose (OPA rule).
        with pytest.raises(GateDeniedError):
            async with tel.tool_call(agent_id, "exec_shell", {"cmd": "rm -rf /"}):
                pass

        # DENY: same tool in a tight loop (budget enforcer) - must trip well before 60 calls.
        loop_denied = False
        for _ in range(60):
            try:
                async with tel.tool_call(agent_id, "kb_search", {"q": "x"}):
                    pass
            except GateDeniedError:
                loop_denied = True
                break
        assert loop_denied, "budget enforcer never denied the loop"

        # Verify persistence while the connection is still open.
        async with get_sessionmaker()() as session:
            count = await session.scalar(
                select(func.count()).select_from(EventRow).where(EventRow.run_id == run_id)
            )
        assert count and count > 0

        await tel.close()
    finally:
        await server.stop()
        await opa.aclose()
        await redis.aclose()
        await dispose_engine()
