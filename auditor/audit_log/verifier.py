"""Audit-log verifier (PRD §9.11.1) — validate a tenant's hash chain.

Walks a tenant's audit-log entries in ``seq`` order and recomputes the chain, detecting any insertion,
deletion, reorder, or mutation. Exposed both programmatically (:class:`AuditLogVerifier`) and as a CLI:

    python -m auditor.audit_log.verifier --tenant <tenant_uuid>

Exit code 0 = chain intact, 1 = break found, 2 = usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from uuid import UUID

from sqlalchemy import select

from auditor.audit_log.chain import ChainVerification, verify_chain
from auditor.db.models import AuditLog as AuditLogRow
from auditor.db.session import dispose_engine, get_sessionmaker


class AuditLogVerifier:
    """Verifies the integrity of the audit-log hash chain for a tenant."""

    async def verify(self, tenant_id: UUID) -> ChainVerification:
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            result = await session.execute(
                select(AuditLogRow)
                .where(AuditLogRow.tenant_id == tenant_id)
                .order_by(AuditLogRow.seq.asc())
            )
            entries = list(result.scalars().all())
        return verify_chain(entries)


async def _main(tenant_id: UUID) -> int:
    try:
        result = await AuditLogVerifier().verify(tenant_id)
    finally:
        await dispose_engine()
    if result.ok:
        print(f"OK: audit-log chain intact for tenant {tenant_id} ({result.count} entries)")
        return 0
    print(f"BREAK: {result.reason} (tenant {tenant_id}, {result.count} entries)", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a tenant's audit-log hash chain.")
    parser.add_argument("--tenant", required=True, help="tenant UUID")
    args = parser.parse_args(argv)
    try:
        tenant_id = UUID(args.tenant)
    except ValueError:
        parser.error(f"invalid tenant UUID: {args.tenant!r}")
        return 2
    return asyncio.run(_main(tenant_id))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["AuditLogVerifier", "main"]
