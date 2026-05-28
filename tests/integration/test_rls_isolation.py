"""Row-level-security tenant isolation (PRD §11.3, Phase 7 acceptance criterion).

Proves that when ``app.tenant_id`` GUC is set:
  - Tenant A can only see its own flags and runs.
  - Tenant B can only see its own flags and runs.
  - A system session (GUC unset) sees all rows from both tenants.

Requires live Postgres with migration 0002 applied.  Marked ``integration`` so it is excluded
from the default unit run.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from auditor.db.models import Flag, Run, Tenant
from auditor.db.session import dispose_engine, get_sessionmaker
from auditor.db.tenancy import tenant_scope
from sqlalchemy import select

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------------------- helpers


async def _ensure_tenant(session, tenant_id: str) -> None:
    """Insert a Tenant row if it does not exist (idempotent)."""
    from uuid import UUID

    existing = await session.get(Tenant, UUID(tenant_id))
    if existing is None:
        session.add(Tenant(tenant_id=UUID(tenant_id), name=f"Test Tenant {tenant_id[:8]}"))


async def _insert_run(session, *, run_id: str, tenant_id: str) -> None:
    """Insert a minimal Run row for the given tenant."""
    from uuid import UUID

    session.add(
        Run(
            run_id=UUID(run_id),
            tenant_id=UUID(tenant_id),
            status="completed",
            declared_goal="rls isolation test",
        )
    )


async def _insert_flag(session, *, flag_id: str, run_id: str, tenant_id: str) -> None:
    """Insert a minimal Flag row for the given tenant."""
    from uuid import UUID

    session.add(
        Flag(
            flag_id=UUID(flag_id),
            run_id=UUID(run_id),
            tenant_id=UUID(tenant_id),
            severity="low",
            asi_categories=["ASI01"],
            verdict_ids=[],
            status="open",
        )
    )


# ------------------------------------------------------------------------------- test


async def test_rls_tenant_isolation() -> None:
    """Tenant A cannot see tenant B's flags or runs, and vice versa.

    Isolation test steps:
    1. Insert tenant rows + one run + one flag per tenant via a *system* session (no GUC).
    2. Scope a session to tenant A; assert only A's flag / run is visible.
    3. Scope a session to tenant B; assert only B's flag / run is visible.
    4. Unscoped (system) session sees both rows for both tables.
    """
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    run_a = str(uuid4())
    run_b = str(uuid4())
    flag_a = str(uuid4())
    flag_b = str(uuid4())

    sessionmaker = get_sessionmaker()

    try:
        # ------------------------------------------------------------------
        # Step 1: system session - insert test data, no GUC set.
        # Flush after each dependency level so FK checks resolve against
        # already-persisted rows (tenants → runs → flags).
        # ------------------------------------------------------------------
        async with sessionmaker() as session, session.begin():
            await _ensure_tenant(session, tenant_a)
            await _ensure_tenant(session, tenant_b)
            await session.flush()  # persist tenants before runs reference them
            await _insert_run(session, run_id=run_a, tenant_id=tenant_a)
            await _insert_run(session, run_id=run_b, tenant_id=tenant_b)
            await session.flush()  # persist runs before flags reference them
            await _insert_flag(session, flag_id=flag_a, run_id=run_a, tenant_id=tenant_a)
            await _insert_flag(session, flag_id=flag_b, run_id=run_b, tenant_id=tenant_b)

        # ------------------------------------------------------------------
        # Step 2: session scoped to tenant A - only A's rows visible.
        # ------------------------------------------------------------------
        async with sessionmaker() as session:
            async with tenant_scope(session, tenant_a):
                flag_rows = (await session.execute(select(Flag))).scalars().all()
                run_rows = (await session.execute(select(Run))).scalars().all()

        flag_ids_a = {str(f.flag_id) for f in flag_rows}
        run_ids_a = {str(r.run_id) for r in run_rows}

        assert flag_a in flag_ids_a, "tenant A should see its own flag"
        assert flag_b not in flag_ids_a, "tenant A must NOT see tenant B's flag"
        assert run_a in run_ids_a, "tenant A should see its own run"
        assert run_b not in run_ids_a, "tenant A must NOT see tenant B's run"

        # ------------------------------------------------------------------
        # Step 3: session scoped to tenant B - only B's rows visible.
        # ------------------------------------------------------------------
        async with sessionmaker() as session:
            async with tenant_scope(session, tenant_b):
                flag_rows = (await session.execute(select(Flag))).scalars().all()
                run_rows = (await session.execute(select(Run))).scalars().all()

        flag_ids_b = {str(f.flag_id) for f in flag_rows}
        run_ids_b = {str(r.run_id) for r in run_rows}

        assert flag_b in flag_ids_b, "tenant B should see its own flag"
        assert flag_a not in flag_ids_b, "tenant B must NOT see tenant A's flag"
        assert run_b in run_ids_b, "tenant B should see its own run"
        assert run_a not in run_ids_b, "tenant B must NOT see tenant A's run"

        # ------------------------------------------------------------------
        # Step 4: system session (no GUC) - both tenants' rows are visible.
        # ------------------------------------------------------------------
        async with sessionmaker() as session:
            all_flag_rows = (await session.execute(select(Flag))).scalars().all()
            all_run_rows = (await session.execute(select(Run))).scalars().all()

        all_flag_ids = {str(f.flag_id) for f in all_flag_rows}
        all_run_ids = {str(r.run_id) for r in all_run_rows}

        assert flag_a in all_flag_ids, "system session should see tenant A's flag"
        assert flag_b in all_flag_ids, "system session should see tenant B's flag"
        assert run_a in all_run_ids, "system session should see tenant A's run"
        assert run_b in all_run_ids, "system session should see tenant B's run"

    finally:
        await dispose_engine()
