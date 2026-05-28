"""Audit-log writer→verifier over a live Postgres (PRD §15 Phase-5 acceptance: no chain breaks).

Requires the Docker Postgres (migrated). Marked ``integration`` so it is excluded from the default
unit run. Proves the end-to-end hash chain: appended entries verify intact, and a tampered row is caught.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from auditor.audit_log.verifier import AuditLogVerifier
from auditor.audit_log.writer import AuditLogWriter, chain_length
from auditor.db.session import dispose_engine
from sqlalchemy import text

pytestmark = pytest.mark.integration


async def test_writer_then_verifier_reports_no_breaks() -> None:
    tenant_id = uuid4()
    writer = AuditLogWriter()
    try:
        for i in range(5):
            await writer.append(
                tenant_id, actor_type="system", action="test_event",
                payload={"i": i, "note": "demo flow"},
            )
        assert await chain_length(tenant_id) == 5

        result = await AuditLogVerifier().verify(tenant_id)
        assert result.ok and result.count == 5 and result.first_break_seq is None
    finally:
        await dispose_engine()


async def test_verifier_detects_tampering() -> None:
    from auditor.db.session import get_sessionmaker

    tenant_id = uuid4()
    writer = AuditLogWriter()
    try:
        for i in range(3):
            await writer.append(tenant_id, actor_type="system", action="e", payload={"i": i})

        # Tamper: overwrite one row's chain_hash directly in the DB.
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE audit_log SET chain_hash = :bad WHERE tenant_id = :t "
                    "AND seq = (SELECT min(seq)+1 FROM audit_log WHERE tenant_id = :t)"
                ),
                {"bad": b"\xff" * 32, "t": str(tenant_id)},
            )

        result = await AuditLogVerifier().verify(tenant_id)
        assert not result.ok and result.first_break_seq is not None
    finally:
        await dispose_engine()
