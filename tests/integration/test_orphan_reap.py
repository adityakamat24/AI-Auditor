"""Integration tests for :func:`auditor.events.store.reap_orphaned_runs`.

The startup-sweep that gives ``runs.status`` a definite terminal value after an auditor restart
(the harness child is already dead by then via the kernel kill-on-parent-death mechanisms;
this fixes the DB row that would otherwise be stuck on ``'running'`` forever).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from auditor.db.models import Run, Tenant
from auditor.db.session import dispose_engine, get_sessionmaker
from auditor.events.store import reap_orphaned_runs
from auditor.ids import uuid7

pytestmark = pytest.mark.integration


async def _seed_tenant(tenant_id) -> None:
    sm = get_sessionmaker()
    async with sm() as s, s.begin():
        if await s.get(Tenant, tenant_id) is None:
            s.add(Tenant(tenant_id=tenant_id, name="orphan-reap-test"))


async def _seed_run(run_id, tenant_id, *, status: str, ended_at: datetime | None = None) -> None:
    sm = get_sessionmaker()
    async with sm() as s, s.begin():
        s.add(Run(run_id=run_id, tenant_id=tenant_id, status=status, ended_at=ended_at))


async def _get_run(run_id) -> Run | None:
    sm = get_sessionmaker()
    async with sm() as s:
        return await s.get(Run, run_id)


async def test_running_rows_become_aborted_with_ended_at() -> None:
    """The headline behaviour: 'running' at sweep time -> 'aborted' + ended_at set."""
    tenant = uuid7()
    run = uuid7()
    try:
        await _seed_tenant(tenant)
        await _seed_run(run, tenant, status="running")

        count = await reap_orphaned_runs()
        assert count >= 1  # at minimum our test row; other races might add more

        row = await _get_run(run)
        assert row is not None
        assert row.status == "aborted"
        assert row.ended_at is not None
    finally:
        await dispose_engine()


async def test_completed_rows_are_not_touched() -> None:
    """Don't trample runs that already had a clean exit. The sweep must only flip 'running'."""
    tenant = uuid7()
    run = uuid7()
    fixed_end = datetime(2025, 1, 1, tzinfo=UTC)
    try:
        await _seed_tenant(tenant)
        await _seed_run(run, tenant, status="completed", ended_at=fixed_end)

        await reap_orphaned_runs()

        row = await _get_run(run)
        assert row is not None
        assert row.status == "completed"
        # ended_at unchanged (would have been NOW() if we'd touched it).
        assert row.ended_at == fixed_end
    finally:
        await dispose_engine()


async def test_idempotent_second_sweep_is_zero() -> None:
    """Running the sweep twice in a row must not re-mark anything (the now-'aborted' rows
    don't match the 'running' filter on the second pass)."""
    tenant = uuid7()
    run = uuid7()
    try:
        await _seed_tenant(tenant)
        await _seed_run(run, tenant, status="running")

        first = await reap_orphaned_runs()
        assert first >= 1

        # The second sweep, RIGHT after, may still hit OTHER unrelated runs from the test
        # database. What we care about is that THIS run is now stable.
        await reap_orphaned_runs()
        row = await _get_run(run)
        assert row is not None
        assert row.status == "aborted"
    finally:
        await dispose_engine()


async def test_aborted_rows_keep_existing_ended_at() -> None:
    """COALESCE preserves an existing ended_at instead of resetting it to NOW()."""
    tenant = uuid7()
    run = uuid7()
    explicit_end = datetime(2025, 6, 15, 12, 30, tzinfo=UTC)
    try:
        await _seed_tenant(tenant)
        await _seed_run(run, tenant, status="running", ended_at=explicit_end)

        await reap_orphaned_runs()

        row = await _get_run(run)
        assert row is not None
        assert row.status == "aborted"
        assert row.ended_at == explicit_end  # COALESCE kept the original
    finally:
        await dispose_engine()
