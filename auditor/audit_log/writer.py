"""Audit-log writer (PRD §9.11.1) — append hash-chained, tamper-evident entries.

Each entry's ``chain_hash`` links to the previous entry for the same tenant, so any insertion, deletion,
reorder, or mutation breaks the chain (detected by :mod:`auditor.audit_log.verifier`). Appends are
serialized per tenant with a Postgres transaction-level advisory lock so concurrent writers can't fork
the chain by reading the same predecessor.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select, text

from auditor.audit_log.chain import GENESIS_HASH, compute_chain_hash, compute_payload_hash
from auditor.db.models import AuditLog as AuditLogRow
from auditor.db.session import get_sessionmaker


class AuditLogWriter:
    """Appends tamper-evident, hash-chained entries to the audit log."""

    async def append(
        self,
        tenant_id: UUID,
        *,
        actor_type: str,
        action: str,
        actor_id: UUID | None = None,
        target_type: str | None = None,
        target_id: UUID | None = None,
        payload: dict | None = None,
        blob_uri: str | None = None,
    ) -> bytes:
        """Append one entry; returns its ``chain_hash``.

        ``payload`` is hashed (not stored inline — the redacted blob goes to ``blob_uri``); the rest are
        the structured columns the audit log indexes on.
        """
        body = payload or {}
        body_meta = {"actor_type": actor_type, "action": action, "target_type": target_type,
                     "target_id": str(target_id) if target_id else None}
        p_hash = compute_payload_hash({**body, "__meta__": body_meta})

        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session, session.begin():
            # Serialize per-tenant appends so two writers can't chain off the same predecessor.
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:t, 0))"),
                {"t": str(tenant_id)},
            )
            prev = await session.execute(
                select(AuditLogRow.chain_hash)
                .where(AuditLogRow.tenant_id == tenant_id)
                .order_by(AuditLogRow.seq.desc())
                .limit(1)
            )
            prev_chain = prev.scalar_one_or_none() or GENESIS_HASH
            chain_hash = compute_chain_hash(prev_chain, p_hash)

            session.add(
                AuditLogRow(
                    tenant_id=tenant_id,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    payload_hash=p_hash,
                    chain_hash=chain_hash,
                    blob_uri=blob_uri,
                )
            )
        return chain_hash


async def chain_length(tenant_id: UUID) -> int:
    """Number of audit-log entries for a tenant (helper for tests/CLI)."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(
            select(func.count()).select_from(AuditLogRow).where(AuditLogRow.tenant_id == tenant_id)
        )
        return int(result.scalar_one())


__all__ = ["AuditLogWriter", "chain_length"]
