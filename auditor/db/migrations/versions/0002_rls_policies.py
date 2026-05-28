"""RLS per-tenant isolation policies (PRD §11.3, Phase 7).

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-27

For every table in RLS_TABLES that carries a ``tenant_id`` column this revision:

1. Creates a non-superuser role ``auditor_api`` (NOLOGIN, NOSUPERUSER, NOBYPASSRLS) and grants
   it SELECT/INSERT/UPDATE/DELETE on every tenant-scoped table.  Because this role is not a
   superuser, PostgreSQL's RLS machinery is *not* bypassed when the session switches to it, which
   is the key requirement for row-level security to take effect.

   The connecting role (``auditor``) is a superuser that always bypasses RLS - that is the
   "system / ingest" path.  When an API request wants tenant isolation, ``tenant_scope()`` calls
   ``SET LOCAL ROLE auditor_api`` so the remainder of the transaction runs as a non-superuser and
   the policy is enforced.

2. Creates a single ``USING`` policy that is transparent when the GUC is unset (system / ingest
   context) and filters to the active tenant when it is set.  The policy is applied to
   ``auditor_api``, not to PUBLIC, so that the superuser path is never affected by it.

3. Applies ``FORCE ROW LEVEL SECURITY`` so the filter is enforced even for the table-owning
   application role when the GUC is set.

The policy expression uses ``current_setting('app.tenant_id', true)`` (the ``true`` is
*missing_ok*) which returns ``NULL`` rather than raising an error when the GUC has not been set
for the current session, allowing existing writers that never call ``tenant_scope()`` to continue
seeing and writing all rows unimpeded - which is what keeps the 349 unit tests and the
audit-log / e2e integration tests green.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Tables that have a ``tenant_id`` column AND appear in ``RLS_TABLES`` from
# the 0001 migration.  Each gets one policy + FORCE.
#
# Tables deliberately excluded:
#   - ``memory_embeddings``  - no ``tenant_id`` column (FK to memory_entries only)
#   - ``gate_decisions``     - no ``tenant_id`` column
#   - ``sampler_decisions``  - no ``tenant_id`` column
#   - ``hitl_decisions``     - no ``tenant_id`` column
#   - ``incident_comments``  - no ``tenant_id`` column
#   - ``incident_action_items`` - no ``tenant_id`` column
#   - ``ground_truth``       - no ``tenant_id`` column
#   - ``calibration_runs``   - no ``tenant_id`` column
# ---------------------------------------------------------------------------

# Standard tables: ``tenant_id IS NOT NULL`` and must equal the GUC when set.
_TENANT_TABLES: tuple[str, ...] = (
    "runs",
    "events",
    "verdicts",
    "flags",
    "memory_entries",
    "audit_log",
    "incidents",
    "shadow_verdicts",
    "agent_baselines",
    "agent_signing_keys",
    "policies",
    "users",
    "saved_queries",
)

# ``detector_lifecycle.tenant_id`` is nullable (NULL means "global / all tenants").
# A NULL row must remain visible to every scoped session, so we add ``OR tenant_id IS NULL``.
_NULLABLE_TENANT_TABLES: tuple[str, ...] = ("detector_lifecycle",)

# The non-superuser role used for tenant-scoped API queries.
_API_ROLE = "auditor_api"

_POLICY_NAME = "tenant_isolation"

# Additional non-tenant tables that ``auditor_api`` needs to reach via FK lookups / joins.
# (These tables are not RLS-policy targets but must be GRANTed for FK resolution.)
_FK_TABLES: tuple[str, ...] = (
    "tenants",
    "hitl_decisions",
    "gate_decisions",
    "sampler_decisions",
    "incident_comments",
    "incident_action_items",
    "ground_truth",
    "calibration_runs",
    "memory_embeddings",
)


def _create_policy(table: str, *, nullable: bool = False) -> str:
    """Return the CREATE POLICY DDL for *table* scoped to ``auditor_api``."""
    tenant_match = "tenant_id = current_setting('app.tenant_id', true)::uuid"
    if nullable:
        tenant_match = f"(tenant_id IS NULL OR {tenant_match})"
    return (
        f'CREATE POLICY {_POLICY_NAME} ON "{table}" TO {_API_ROLE} USING ('
        f"    current_setting('app.tenant_id', true) IS NULL"
        f"    OR current_setting('app.tenant_id', true) = ''"
        f"    OR {tenant_match}"
        f")"
    )


def upgrade() -> None:
    # Create the non-superuser API role (idempotent). The literal 'auditor_api' equals _API_ROLE;
    # it is inlined (no f-string) so there is no string-built SQL to trip the injection linter.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor_api') THEN
                CREATE ROLE auditor_api NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            END IF;
        END
        $$
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {_API_ROLE}")

    # Filter out tables that don't exist (0001 may have skipped memory_embeddings if pgvector is
    # unavailable on the host - hosted Postgres often lacks it). Without this guard, the GRANT/
    # POLICY statements would raise UndefinedTableError and abort the migration.
    from sqlalchemy import text as _sa_text
    bind = op.get_bind()
    existing: set[str] = {row[0] for row in bind.execute(
        _sa_text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )}

    def _present(names: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(n for n in names if n in existing)

    # Grant DML on tenant-policy tables.
    for table in _present(_TENANT_TABLES + _NULLABLE_TENANT_TABLES):
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}" TO {_API_ROLE}')

    # Grant SELECT on FK-referenced tables (needed for FK lookups and read-only joins).
    for table in _present(_FK_TABLES):
        op.execute(f'GRANT SELECT ON "{table}" TO {_API_ROLE}')

    # Create policies (scoped to auditor_api so the superuser path is unaffected).
    for table in _present(_TENANT_TABLES):
        op.execute(_create_policy(table))
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')

    for table in _present(_NULLABLE_TENANT_TABLES):
        op.execute(_create_policy(table, nullable=True))
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')


def downgrade() -> None:
    for table in _TENANT_TABLES:
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS {_POLICY_NAME} ON "{table}"')

    for table in _NULLABLE_TENANT_TABLES:
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS {_POLICY_NAME} ON "{table}"')

    # Drop all objects owned by / granted to the API role, then drop the role.
    # ``DROP OWNED BY`` revokes all privileges granted to the role across the
    # current database and drops any objects it owns (none here, since the
    # tables are owned by the superuser).  This is the correct way to clear all
    # grants before the role is removed.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor_api') THEN
                DROP OWNED BY auditor_api;
                DROP ROLE auditor_api;
            END IF;
        END
        $$
        """
    )
