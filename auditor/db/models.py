"""SQLAlchemy 2.0 ORM models - the full schema (PRD §8.1 plus the tables defined in §9.7.6,
§9.7.10, §9.10.5, §9.11.4, §9.13, §11.4).

These models are the single source of truth for table structure; the Alembic migration creates the
required extensions, builds the schema from this metadata, and enables row-level security. The
``memory_embeddings.embedding`` vector dimension is read from configuration (``EMBEDDING_DIM``),
NOT hardcoded - see plan deviation #2.
"""

from __future__ import annotations

from datetime import date, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from auditor.config import get_settings

# Embedding dimension is config-driven; the migration reads this via the model metadata.
_EMBEDDING_DIM = get_settings().embedding_dim

# Deterministic constraint/index names so future migrations are stable.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _uuid_col(*args: object, **kw: object):  # helper: a postgres UUID column
    return mapped_column(UUID(as_uuid=True), *args, **kw)


def _ts(**kw: object):  # helper: a timezone-aware timestamp column
    return mapped_column(DateTime(timezone=True), **kw)


# ----------------------------------------------------------------------------- tenancy / identity


class Tenant(Base):
    __tablename__ = "tenants"
    tenant_id: Mapped[str] = _uuid_col(primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))


class Policy(Base):
    __tablename__ = "policies"
    tenant_id: Mapped[str] = _uuid_col(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    rego_policy: Mapped[str] = mapped_column(Text, nullable=False)
    sample_rates: Mapped[dict] = mapped_column(JSONB, nullable=False)
    severity_overrides: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    capabilities: Mapped[dict] = mapped_column(  # §9.7.3 capability map
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    created_by: Mapped[str] = _uuid_col(nullable=False)


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(ForeignKey("tenants.tenant_id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    oidc_subject: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        CheckConstraint("role IN ('admin','reviewer','readonly')", name="role"),
        UniqueConstraint("tenant_id", "email", name="tenant_email"),
    )


# ----------------------------------------------------------------------------- runs / events


class Run(Base):
    __tablename__ = "runs"
    run_id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(ForeignKey("tenants.tenant_id"), nullable=False)
    initiated_by: Mapped[str | None] = _uuid_col()
    status: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    ended_at: Mapped[datetime | None] = _ts()
    declared_goal: Mapped[str | None] = mapped_column(Text)
    run_metadata: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    __table_args__ = (
        CheckConstraint(
            "status IN ('running','paused','completed','aborted','quarantined')", name="status"
        ),
        Index("runs_tenant_status_started_idx", "tenant_id", "status", started_at.desc()),
    )


class Event(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = _uuid_col(primary_key=True)
    run_id: Mapped[str] = _uuid_col(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)  # denormalized for RLS
    span_id: Mapped[str] = _uuid_col(nullable=False)
    parent_span_id: Mapped[str | None] = _uuid_col()
    channel: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[datetime] = _ts(nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    __table_args__ = (
        CheckConstraint("channel IN ('VOLUNTARY','INVOLUNTARY')", name="channel"),
        Index("events_run_ts_idx", "run_id", "ts"),
        Index("events_tenant_ts_idx", "tenant_id", ts.desc()),
        Index("events_type_idx", "event_type"),
    )


class GateDecision(Base):
    __tablename__ = "gate_decisions"
    decision_id: Mapped[str] = _uuid_col(primary_key=True)
    event_id: Mapped[str] = _uuid_col(ForeignKey("events.event_id"), nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    detectors: Mapped[dict] = mapped_column(JSONB, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        CheckConstraint("decision IN ('ALLOW','DENY','CONFIRM')", name="decision"),
    )


class SamplerDecision(Base):
    __tablename__ = "sampler_decisions"
    sampler_id: Mapped[str] = _uuid_col(primary_key=True)
    run_id: Mapped[str] = _uuid_col(ForeignKey("runs.run_id"), nullable=False)
    tier_fired: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    cohort_rate: Mapped[float | None] = mapped_column(Numeric(5, 4))
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        CheckConstraint("tier_fired IN ('L1','L2','L3','NONE')", name="tier_fired"),
    )


# ----------------------------------------------------------------------------- verdicts / flags / HITL


class Verdict(Base):
    __tablename__ = "verdicts"
    verdict_id: Mapped[str] = _uuid_col(primary_key=True)
    run_id: Mapped[str] = _uuid_col(ForeignKey("runs.run_id"), nullable=False)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    asi_category: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Numeric(4, 3))
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    judge_model: Mapped[str | None] = mapped_column(Text)
    judge_prompt_v: Mapped[int | None] = mapped_column(Integer)
    rubric_scores: Mapped[dict | None] = mapped_column(JSONB)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        CheckConstraint("result IN ('VIOLATION','OK','NEEDS_REVIEW')", name="result"),
        Index("verdicts_run_idx", "run_id"),
        Index("verdicts_category_ts_idx", "asi_category", ts.desc()),
    )


class Flag(Base):
    __tablename__ = "flags"
    flag_id: Mapped[str] = _uuid_col(primary_key=True)
    run_id: Mapped[str] = _uuid_col(ForeignKey("runs.run_id"), nullable=False)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    asi_categories: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    verdict_ids: Mapped[list[str]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    resolved_at: Mapped[datetime | None] = _ts()
    resolution: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (
        CheckConstraint("severity IN ('critical','high','medium','low')", name="severity"),
        CheckConstraint("status IN ('open','reviewing','resolved','dismissed')", name="status"),
    )


class HitlDecision(Base):
    __tablename__ = "hitl_decisions"
    hitl_id: Mapped[str] = _uuid_col(primary_key=True)
    flag_id: Mapped[str] = _uuid_col(ForeignKey("flags.flag_id"), nullable=False)
    reviewer_id: Mapped[str] = _uuid_col(ForeignKey("users.user_id"), nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        CheckConstraint("decision IN ('continue','abort','quarantine')", name="decision"),
    )


# ----------------------------------------------------------------------------- audit log / calibration


class AuditLog(Base):
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str | None] = _uuid_col()
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = _uuid_col()
    payload_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    chain_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    blob_uri: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (
        CheckConstraint("actor_type IN ('system','user','agent')", name="actor_type"),
        Index("audit_log_tenant_ts_idx", "tenant_id", ts.desc()),
    )


class GroundTruth(Base):
    __tablename__ = "ground_truth"
    gt_id: Mapped[str] = _uuid_col(primary_key=True)
    asi_category: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    trace_uri: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (CheckConstraint("label IN ('VIOLATION','OK')", name="label"),)


class CalibrationRun(Base):
    __tablename__ = "calibration_runs"
    cal_id: Mapped[str] = _uuid_col(primary_key=True)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    judge_model: Mapped[str] = mapped_column(Text, nullable=False)
    judge_prompt_v: Mapped[int] = mapped_column(Integer, nullable=False)
    per_category: Mapped[dict] = mapped_column(JSONB, nullable=False)
    overall: Mapped[dict] = mapped_column(JSONB, nullable=False)


# ----------------------------------------------------------------------------- memory (with provenance)


class MemoryEntry(Base):
    __tablename__ = "memory_entries"
    entry_id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    agent_id: Mapped[str] = _uuid_col(nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_redacted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    sensitivity: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'unknown'"))
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    # §9.7.6 cross-run provenance + quarantine
    created_in_run_id: Mapped[str | None] = _uuid_col()
    distance_from_user: Mapped[int | None] = mapped_column(Integer)
    write_intent_declared: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    flags: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    quarantined: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )


class MemoryEmbedding(Base):
    __tablename__ = "memory_embeddings"
    entry_id: Mapped[str] = _uuid_col(
        ForeignKey("memory_entries.entry_id", ondelete="CASCADE"), primary_key=True
    )
    # Dimension is config-driven (default 384); NOT the PRD's literal 1536 (Anthropic has no embeddings API).
    embedding: Mapped[list[float]] = mapped_column(Vector(_EMBEDDING_DIM), nullable=False)
    __table_args__ = (
        Index(
            "memory_embeddings_hnsw_idx",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_l2_ops"},
        ),
    )


# ----------------------------------------------------------------------------- incidents (§9.10.5)


class Incident(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    primary_flag_id: Mapped[str] = _uuid_col(ForeignKey("flags.flag_id"), nullable=False)
    related_flag_ids: Mapped[list[str]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    assignee_id: Mapped[str | None] = _uuid_col(ForeignKey("users.user_id"))
    opened_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    triaged_at: Mapped[datetime | None] = _ts()
    contained_at: Mapped[datetime | None] = _ts()
    resolved_at: Mapped[datetime | None] = _ts()
    post_mortem_uri: Mapped[str | None] = mapped_column(Text)
    dismissal_rationale: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (
        CheckConstraint(
            "state IN ('OPEN','TRIAGING','INVESTIGATING','CONTAINED','RESOLVED',"
            "'POST_MORTEM_COMPLETE','DISMISSED')",
            name="state",
        ),
    )


class IncidentComment(Base):
    __tablename__ = "incident_comments"
    comment_id: Mapped[str] = _uuid_col(primary_key=True)
    incident_id: Mapped[str] = _uuid_col(ForeignKey("incidents.incident_id"), nullable=False)
    author_id: Mapped[str] = _uuid_col(ForeignKey("users.user_id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)


class IncidentActionItem(Base):
    __tablename__ = "incident_action_items"
    action_id: Mapped[str] = _uuid_col(primary_key=True)
    incident_id: Mapped[str] = _uuid_col(ForeignKey("incidents.incident_id"), nullable=False)
    owner_id: Mapped[str | None] = _uuid_col(ForeignKey("users.user_id"))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = _ts()
    __table_args__ = (
        CheckConstraint(
            "status IN ('open','in_progress','done','cancelled')", name="status"
        ),
    )


# ----------------------------------------------------------------------------- detector lifecycle (§9.13)


class ShadowVerdict(Base):
    __tablename__ = "shadow_verdicts"
    verdict_id: Mapped[str] = _uuid_col(primary_key=True)
    run_id: Mapped[str] = _uuid_col(ForeignKey("runs.run_id"), nullable=False)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    detector_version: Mapped[str | None] = mapped_column(Text)
    asi_category: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Numeric(4, 3))
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    judge_model: Mapped[str | None] = mapped_column(Text)
    judge_prompt_v: Mapped[int | None] = mapped_column(Integer)
    rubric_scores: Mapped[dict | None] = mapped_column(JSONB)
    ts: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)


class DetectorLifecycle(Base):
    __tablename__ = "detector_lifecycle"
    id: Mapped[str] = _uuid_col(primary_key=True)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[str | None] = _uuid_col()  # NULL = global
    canary_partition: Mapped[float | None] = mapped_column(Numeric(5, 4))
    previous_state: Mapped[str | None] = mapped_column(Text)
    rationale: Mapped[str | None] = mapped_column(Text)
    metrics_snapshot: Mapped[dict | None] = mapped_column(JSONB)
    changed_by: Mapped[str | None] = _uuid_col()
    changed_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        CheckConstraint(
            "state IN ('PROPOSED','SHADOW','CANARY','ENFORCING','DISABLED','DEPRECATED','REMOVED')",
            name="state",
        ),
    )


# ----------------------------------------------------------------------------- baselines / signing keys / queries


class AgentBaseline(Base):
    __tablename__ = "agent_baselines"
    id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    agent_role: Mapped[str] = mapped_column(Text, nullable=False)
    axis: Mapped[str] = mapped_column(Text, nullable=False)
    digest: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    trusted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    drift_score: Mapped[float] = mapped_column(Numeric, nullable=False, server_default=text("0"))
    updated_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_role", "axis", name="tenant_role_axis"),
    )


class AgentSigningKey(Base):
    __tablename__ = "agent_signing_keys"
    id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    agent_id: Mapped[str] = _uuid_col(nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    private_key_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # pgcrypto-encrypted
    algorithm: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ed25519'"))
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = _ts()


class SavedQuery(Base):
    __tablename__ = "saved_queries"
    id: Mapped[str] = _uuid_col(primary_key=True)
    tenant_id: Mapped[str] = _uuid_col(nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    query: Mapped[dict] = mapped_column(JSONB, nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_by: Mapped[str | None] = _uuid_col()
    created_at: Mapped[datetime] = _ts(server_default=func.now(), nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="tenant_name"),)


# Tables on which row-level security is enabled by the migration (policies added in Phase 7).
RLS_TABLES: tuple[str, ...] = (
    "events",
    "verdicts",
    "flags",
    "memory_entries",
    "memory_embeddings",
    "runs",
    "gate_decisions",
    "sampler_decisions",
    "hitl_decisions",
    "audit_log",
    "incidents",
    "incident_comments",
    "incident_action_items",
    "shadow_verdicts",
    "detector_lifecycle",
    "agent_baselines",
    "agent_signing_keys",
    "ground_truth",
    "calibration_runs",
    "policies",
    "users",
    "saved_queries",
)

__all__ = ["Base", "RLS_TABLES"]
