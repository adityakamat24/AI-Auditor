"""Row-level-security tenant scoping (PRD §11.3).

Sets the ``app.tenant_id`` GUC for the current transaction via ``set_config(..., is_local=true)``
and switches the session role to the non-superuser ``auditor_api`` role so that the RLS policies
added in Phase 7 filter rows to the active tenant.

Why the role switch is required
--------------------------------
The application connects as the ``auditor`` role which is a PostgreSQL superuser.  Superusers
bypass row-level security unconditionally — even ``FORCE ROW LEVEL SECURITY`` does not apply to
them (the Postgres docs explicitly state: "Superusers ... always bypass the row security system").
By executing ``SET LOCAL ROLE auditor_api`` within the transaction, the effective role drops to
the non-superuser ``auditor_api`` for the remainder of that transaction, making RLS enforcement
apply.  The ``LOCAL`` qualifier means the role reverts to ``auditor`` automatically when the
transaction ends.

Using ``set_config`` (rather than bare ``SET LOCAL``) lets us bind the tenant id as a parameter —
no string interpolation, no injection.  The role name is a fixed constant, not user-supplied, so
it is safe to interpolate in the ``SET LOCAL ROLE`` statement.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# The non-superuser role whose session is subject to RLS (created by migration 0002).
_API_ROLE = "auditor_api"


@asynccontextmanager
async def tenant_scope(session: AsyncSession, tenant_id: UUID | str) -> AsyncIterator[AsyncSession]:
    """Scope ``session`` to ``tenant_id`` for the current transaction.

    Sets the ``app.tenant_id`` GUC (transaction-local) and switches to the non-superuser
    ``auditor_api`` role so that RLS policies are enforced.  Both settings are rolled back
    automatically when the transaction ends (``LOCAL`` semantics).
    """
    # Switch to the non-superuser role so RLS is not bypassed.
    await session.execute(text(f"SET LOCAL ROLE {_API_ROLE}"))
    # Bind the tenant id as a parameter (prevents injection).
    await session.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": str(tenant_id)},
    )
    yield session
