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

from alembic import op
from auditor.db.models import RLS_TABLES, Base

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Extensions must exist before the vector column / pgcrypto usage.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=False)

    # Enable (not FORCE) RLS: the table-owning app role bypasses RLS until Phase 7 adds policies,
    # so Phase 1 boot/seed/migrate are unaffected. # TODO(phase7): CREATE POLICY ... USING tenant_id.
    for table in RLS_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
    op.execute("DROP EXTENSION IF EXISTS pgcrypto")
    op.execute("DROP EXTENSION IF EXISTS vector")
