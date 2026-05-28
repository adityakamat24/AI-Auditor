#!/usr/bin/env python
"""Seed a demo tenant + admin user (idempotent). Used by init/demo scripts."""

from __future__ import annotations

import asyncio
from uuid import UUID

from auditor.db.models import Tenant, User
from auditor.db.session import dispose_engine, get_sessionmaker

DEMO_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
DEMO_ADMIN_ID = UUID("00000000-0000-0000-0000-000000000002")


async def main() -> None:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        if await session.get(Tenant, DEMO_TENANT_ID) is None:
            session.add(Tenant(tenant_id=DEMO_TENANT_ID, name="Demo Tenant"))
        if await session.get(User, DEMO_ADMIN_ID) is None:
            session.add(
                User(
                    user_id=DEMO_ADMIN_ID,
                    tenant_id=DEMO_TENANT_ID,
                    email="admin@demo.local",
                    role="admin",
                )
            )
    await dispose_engine()
    print(f"seeded demo tenant {DEMO_TENANT_ID} + admin admin@demo.local")


if __name__ == "__main__":
    asyncio.run(main())
