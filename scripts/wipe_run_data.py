"""Wipe per-run demo data so a fresh session shows only its own runs.

Truncates flags / incidents / verdicts / events / runs / audit_log / etc. Keeps tenants, users, policies.
Run via `reset.bat` or `python scripts/wipe_run_data.py`.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from auditor.db.session import dispose_engine, get_sessionmaker

TABLES = [
    "incident_action_items", "incident_comments", "incidents",
    "hitl_decisions", "shadow_verdicts", "verdicts", "flags",
    "sampler_decisions", "audit_log",
    "memory_embeddings", "memory_entries",
    "events", "runs",
]


async def main() -> None:
    stmt = f"TRUNCATE TABLE {', '.join(TABLES)} RESTART IDENTITY CASCADE"  # noqa: S608 - fixed list
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session, session.begin():
        await session.execute(text(stmt))
    await dispose_engine()
    print(f"wiped {len(TABLES)} tables")


if __name__ == "__main__":
    asyncio.run(main())
