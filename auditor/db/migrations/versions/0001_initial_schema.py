"""initial schema - full §8.1 + scattered tables, pgvector + pgcrypto extensions, RLS enabled

Revision ID: 0001
Revises:
Create Date: 2026-05-27

Builds the schema from the ORM metadata (single source of truth). The ``vector`` and ``pgcrypto``
extensions are created first; RLS is enabled on tenant-scoped tables (policies are added in Phase 7,
so the table-owning app role still reads rows until then).
"""

from __future__ import annotations

from collections.abc import Sequence

import structlog
from alembic import op
from sqlalchemy import text

from auditor.db.models import RLS_TABLES, Base

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

log = structlog.get_logger()


def _try_create_extension(bind, name: str) -> bool:
    """Attempt CREATE EXTENSION inside a SAVEPOINT so a missing extension doesn't poison the
    outer migration transaction. Returns True if the extension is now installed."""
    sp = bind.begin_nested()
    try:
        bind.execute(text(f"CREATE EXTENSION IF NOT EXISTS {name}"))
        sp.commit()
        return True
    except Exception as exc:  # noqa: BLE001 - extension may not be present on the host
        sp.rollback()
        log.warning("alembic.extension_unavailable", extension=name, error=str(exc))
        return False


def upgrade() -> None:
    # pgcrypto ships with every standard Postgres - if this fails the deployment is broken.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # pgvector is NOT standard - hosted Postgres (e.g. Fly Postgres) often lacks it. We tolerate
    # its absence so the auditor still boots; only the embedding-backed paths (memory similarity,
    # ASI-06 cross-run influence) become unavailable. Demo flows don't exercise those paths.
    bind = op.get_bind()
    has_vector = _try_create_extension(bind, "vector")

    # checkfirst=True so a partial previous run (e.g. an old deploy that crashed mid-creation)
    # can be replayed without "relation already exists" errors. Idempotent.
    if has_vector:
        Base.metadata.create_all(bind=bind, checkfirst=True)
    else:
        # Skip the one table that hard-depends on the vector extension. Everything else loads as
        # normal so flags/incidents/audit log/HITL work end-to-end.
        skipped = {"memory_embeddings"}
        tables = [t for n, t in Base.metadata.tables.items() if n not in skipped]
        Base.metadata.create_all(bind=bind, tables=tables, checkfirst=True)
        log.warning("alembic.vector_skipped_tables", skipped=sorted(skipped))

    # Enable (not FORCE) RLS: the table-owning app role bypasses RLS until Phase 7 adds policies,
    # so Phase 1 boot/seed/migrate are unaffected. Skip RLS for any table that wasn't created.
    existing_tables = {row[0] for row in bind.execute(text(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
    ))}
    for table_name in RLS_TABLES:
        if table_name in existing_tables:
            op.execute(f'ALTER TABLE "{table_name}" ENABLE ROW LEVEL SECURITY')


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
    op.execute("DROP EXTENSION IF EXISTS pgcrypto")
    op.execute("DROP EXTENSION IF EXISTS vector")
