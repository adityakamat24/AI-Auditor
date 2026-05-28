#!/usr/bin/env python
"""Print a summary of the live schema for verification (tables, extensions, vector dim, HNSW, RLS)."""

from __future__ import annotations

import asyncio

import asyncpg
from auditor.config import get_settings

EXPECTED = {
    "tenants", "policies", "users", "runs", "events", "gate_decisions", "sampler_decisions",
    "verdicts", "flags", "hitl_decisions", "audit_log", "ground_truth", "calibration_runs",
    "memory_entries", "memory_embeddings", "incidents", "incident_comments",
    "incident_action_items", "shadow_verdicts", "detector_lifecycle", "agent_baselines",
    "agent_signing_keys", "saved_queries",
}


async def main() -> int:
    dsn = get_settings().postgres_dsn.replace("+asyncpg", "")
    conn = await asyncpg.connect(dsn)
    try:
        tabs = {r["tablename"] for r in await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'")}
        exts = {r["extname"] for r in await conn.fetch("SELECT extname FROM pg_extension")}
        emb = await conn.fetchval(
            "SELECT format_type(atttypid, atttypmod) FROM pg_attribute "
            "WHERE attrelid='memory_embeddings'::regclass AND attname='embedding'")
        idx = await conn.fetch("SELECT indexdef FROM pg_indexes WHERE tablename='memory_embeddings'")
        rls = {r["relname"]: r["relrowsecurity"] for r in await conn.fetch(
            "SELECT relname, relrowsecurity FROM pg_class "
            "WHERE relkind='r' AND relnamespace='public'::regnamespace")}

        missing = EXPECTED - tabs
        print(f"expected tables present : {len(EXPECTED - missing)}/{len(EXPECTED)}")
        print(f"missing                 : {sorted(missing) or 'none'}")
        print(f"extensions (vector/pgcrypto): {sorted(e for e in exts if e in ('vector', 'pgcrypto'))}")
        print(f"memory_embeddings.embedding : {emb}")
        print(f"hnsw index present      : {any('hnsw' in r['indexdef'] for r in idx)}")
        print(f"rls-enabled tables      : {sum(1 for v in rls.values() if v)}")
        print(f"  events RLS={rls.get('events')}  flags RLS={rls.get('flags')}  "
              f"verdicts RLS={rls.get('verdicts')}  memory_entries RLS={rls.get('memory_entries')}")
        ok = not missing and {"vector", "pgcrypto"} <= exts and emb == "vector(384)"
        print(f"ACCEPTANCE A3: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
