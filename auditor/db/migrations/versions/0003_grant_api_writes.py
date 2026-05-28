"""Grant write privileges + disable RLS on FK tables the API actually writes to.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-28

0001 enabled RLS on every table in ``RLS_TABLES`` uniformly. 0002 then only created policies for
tables that carry a ``tenant_id`` column (the ``_TENANT_TABLES`` and ``_NULLABLE_TENANT_TABLES``
lists). The tables in ``_FK_TABLES`` (``hitl_decisions``, ``gate_decisions``, …) have **RLS enabled
but no policy** — which Postgres treats as default-deny for non-owner roles. So under
``tenant_scope()`` (which switches to the non-superuser ``auditor_api``), every read and write
against those tables fails with ``permission denied`` / ``new row violates row-level security
policy``.

These tables don't carry ``tenant_id`` themselves; their tenant isolation comes from a foreign key
to a parent (``flags``, ``incidents``, ``runs``) that the API route already filters under the
active tenant before writing. So we:

1. Grant the missing ``INSERT, UPDATE, DELETE`` on the FK tables.
2. Disable RLS on them so the auditor_api role can actually read/write them. (The parent-row
   tenant check in the route is the source of truth for isolation; the FK enforces referential
   integrity at the DB layer.)
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_API_ROLE = "auditor_api"

# Tables the API writes to that don't carry their own tenant_id (isolation via FK to a parent row).
_API_WRITABLE_FK_TABLES: tuple[str, ...] = (
    "hitl_decisions",
    "gate_decisions",
    "sampler_decisions",
    "incident_comments",
    "incident_action_items",
    "ground_truth",
    "memory_embeddings",
    "calibration_runs",
)


def upgrade() -> None:
    for table in _API_WRITABLE_FK_TABLES:
        # Allow DML — 0002 only granted SELECT.
        op.execute(f'GRANT INSERT, UPDATE, DELETE ON "{table}" TO {_API_ROLE}')
        # 0001 enabled RLS uniformly. Since no policy is defined for these tables, default-deny
        # blocks the API. Disable RLS — the FK to the parent row + the route's tenant check provide
        # logical isolation.
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')


def downgrade() -> None:
    for table in _API_WRITABLE_FK_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'REVOKE INSERT, UPDATE, DELETE ON "{table}" FROM {_API_ROLE}')
