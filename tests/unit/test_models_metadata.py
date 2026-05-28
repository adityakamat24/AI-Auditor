"""The ORM metadata contains every expected table and the config-driven embedding dimension."""

from __future__ import annotations

from auditor.config import get_settings
from auditor.db.models import RLS_TABLES, Base

EXPECTED_TABLES = {
    "tenants",
    "policies",
    "users",
    "runs",
    "events",
    "gate_decisions",
    "sampler_decisions",
    "verdicts",
    "flags",
    "hitl_decisions",
    "audit_log",
    "ground_truth",
    "calibration_runs",
    "memory_entries",
    "memory_embeddings",
    "incidents",
    "incident_comments",
    "incident_action_items",
    "shadow_verdicts",
    "detector_lifecycle",
    "agent_baselines",
    "agent_signing_keys",
    "saved_queries",
}


def test_all_expected_tables_present() -> None:
    names = set(Base.metadata.tables.keys())
    missing = EXPECTED_TABLES - names
    assert not missing, f"missing tables: {missing}"
    assert len(EXPECTED_TABLES) == 23


def test_memory_embedding_dim_is_config_driven() -> None:
    col = Base.metadata.tables["memory_embeddings"].c.embedding
    assert col.type.dim == get_settings().embedding_dim == 384


def test_rls_tables_are_real_tables() -> None:
    names = set(Base.metadata.tables.keys())
    assert set(RLS_TABLES) <= names


def test_runs_has_metadata_column() -> None:
    # The ORM attribute is `run_metadata` but the DB column must be named `metadata` (§8.1).
    cols = {c.name for c in Base.metadata.tables["runs"].c}
    assert "metadata" in cols
