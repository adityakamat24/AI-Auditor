"""store_run_result opens an incident for a High/Critical flag (PRD §9.10.5, Phase-8 acceptance).

Requires live Postgres (migration 0002 applied). Marked ``integration``. Verifies the wiring added in
the orchestrator persist path: persisting a critical flag automatically creates an OPEN incident, and a
low-severity flag does not.
"""

from __future__ import annotations

import pytest
from auditor.db.models import Incident, Tenant
from auditor.db.session import dispose_engine, get_sessionmaker
from auditor.events.store import store_run_result, upsert_run
from auditor.ids import uuid7
from auditor.verdicts.aggregator import Flag
from auditor.verdicts.schemas import Severity
from sqlalchemy import select

pytestmark = pytest.mark.integration


async def _incident_for(flag_id) -> Incident | None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(
            select(Incident).where(Incident.primary_flag_id == str(flag_id))
        )
        return result.scalar_one_or_none()


async def _ensure_tenant(tenant_id) -> None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        if await session.get(Tenant, tenant_id) is None:
            session.add(Tenant(tenant_id=tenant_id, name="incident wiring tenant"))


async def test_critical_flag_opens_incident_low_does_not() -> None:
    tenant_id = uuid7()
    try:
        await _ensure_tenant(tenant_id)
        # Critical flag → incident opened.
        crit_run = uuid7()
        await upsert_run(crit_run, tenant_id, declared_goal="incident wiring test")
        crit_flag = Flag(
            run_id=crit_run, tenant_id=tenant_id, severity=Severity.CRITICAL,
            asi_categories=["ASI01"], verdict_ids=[],
        )
        await store_run_result([], crit_flag)
        incident = await _incident_for(crit_flag.flag_id)
        assert incident is not None, "a critical flag must open an incident"
        assert incident.state == "OPEN" and incident.severity == "critical"

        # Low flag → no incident.
        low_run = uuid7()
        await upsert_run(low_run, tenant_id, declared_goal="incident wiring test")
        low_flag = Flag(
            run_id=low_run, tenant_id=tenant_id, severity=Severity.LOW,
            asi_categories=["ASI02"], verdict_ids=[],
        )
        await store_run_result([], low_flag)
        assert await _incident_for(low_flag.flag_id) is None, "a low flag must NOT open an incident"
    finally:
        await dispose_engine()
