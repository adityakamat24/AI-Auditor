"""Central configuration for the auditor and harness.

Single source of truth (pydantic-settings). Every module reads :class:`Settings`; nothing reads
``os.environ`` directly — secret reads go through :mod:`auditor.auth.secrets`. Field names map 1:1
to ``.env`` (case-insensitive). This object intentionally carries the *full* field surface for all
phases so later phases only add values, never restructure.
"""

from __future__ import annotations

import sys
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide settings, loaded from environment and ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core ---
    auditor_env: Literal["dev", "demo", "prod"] = "dev"
    log_level: str = "INFO"
    data_dir: str = "./data"

    # --- API server ---
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # --- Postgres (async DSN) ---
    postgres_dsn: str = "postgresql+asyncpg://auditor:auditor@localhost:5432/auditor"
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- MinIO / object storage ---
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"  # noqa: S105 - MinIO local-dev default; overridden via env
    minio_secure: bool = False
    minio_bucket_audit: str = "audit"
    minio_bucket_checkpoints: str = "checkpoints"
    minio_bucket_ground_truth: str = "ground-truth"

    # --- OPA (policy engine REST base) ---
    opa_url: str = "http://localhost:8181"

    # --- LLM judge (via LiteLLM proxy) ---
    litellm_base_url: str = "http://localhost:4000"
    anthropic_api_key: str | None = None
    judge_model: str = "claude-haiku-4-5-20251001"
    agent_model: str = "claude-sonnet-4-6"
    crosscheck_model: str = "claude-sonnet-4-6"

    # --- Embeddings (LOCAL by default; Anthropic has no embeddings API — see plan deviation #2) ---
    # "stub" is a deterministic offline embedder for tests/CI (no model download).
    embedding_backend: Literal["fastembed", "voyage", "stub"] = "fastembed"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dim: int = 384  # MUST match the model; the Alembic migration reads this for vector(N)

    # --- IPC (auditor <-> harness) ---
    # "" => auto: unix domain socket on POSIX, loopback TCP on Windows (asyncio can't TLS-wrap pipes).
    ipc_transport: Literal["", "unix", "tcp"] = ""
    ipc_unix_path: str = "/tmp/ai-auditor.sock"  # noqa: S108 - dev default; prod uses /var/run/auditor/
    ipc_tcp_host: str = "127.0.0.1"
    ipc_tcp_port: int = 8787
    ipc_mtls_enabled: bool = False  # Phase 2 turns this on
    ipc_server_enabled: bool = True  # auditor starts the IPC listener for the harness
    gate_timeout_ms: int = 100  # SDK inline-gate request timeout; on timeout the SDK fails closed (DENY)

    # --- Audit sampling (PRD §5.4, §9.6.1) — what fraction of runs get the deep async audit ---
    # L2 stratified base rate: 0.05 = 5%, 0.01 = 1%. Set SAMPLER_DEFAULT_RATE in .env to change it.
    # Per-tool-category overrides via SAMPLER_CATEGORY_RATES as JSON, e.g.
    #   SAMPLER_CATEGORY_RATES='{"exec_shell": 0.5, "kb_search": 0.01}'
    # L1 hard triggers (channel divergence, critical risk, sensitive-outside-allowlist, novelty, recent
    # incidents) ALWAYS audit regardless of this rate; L3 drops to cheap-detectors-only when budget is spent.
    sampler_default_rate: float = 0.05
    sampler_category_rates: dict[str, float] = {}  # noqa: RUF012 - pydantic handles the mutable default
    sampler_critical_risk_threshold: int = 70  # cheap risk score (0-100) that forces an L1 always-audit

    # --- Judge cost budget (PRD §9.6.1 L3) ---
    judge_daily_cap_usd: float = 10.0  # per-tenant/day; when spent, sampled runs go cheap-detectors-only

    # --- Calibration (PRD §9.12.2) ---
    # If a category's measured precision falls below this, its detector's blocking authority auto-disables.
    calibration_precision_threshold: float = 0.85

    # --- Secrets backend ---
    secrets_backend: Literal["env", "vault", "aws"] = "env"

    # --- Auth (Phase 7) ---
    jwt_secret: str = "dev-only-change-me"  # noqa: S105 - dev default; set via env/secrets in prod
    jwt_algorithm: str = "HS256"
    jwt_ttl_seconds: int = 3600

    # --- OIDC (Phase 7 integration point — Auth0 / Okta / Google compatible) ---
    # Leave empty in dev; set both to wire a real IdP.
    # OIDC_ISSUER  — e.g. "https://example.us.auth0.com/" or "https://accounts.google.com"
    # OIDC_JWKS_URI — e.g. "https://example.us.auth0.com/.well-known/jwks.json"
    #                 (if empty, auto-derived from issuer + "/.well-known/jwks.json")
    # OIDC_AUDIENCE — expected ``aud`` claim value (required for Auth0, optional for others)
    oidc_issuer: str = ""  # empty = OIDC disabled; dev uses local HMAC tokens
    oidc_jwks_uri: str = ""  # empty = auto-derive from issuer when OIDC is enabled
    oidc_audience: str = ""  # empty = audience check skipped

    # --- Dev-login (Phase 7 local-fallback) ---
    # Enables POST /auth/login with {email, password} when no IdP is configured.
    # Role is ALWAYS read from the DB row — the caller cannot choose their role.
    # Set to False in prod when a real OIDC IdP is in use.
    auth_dev_login_enabled: bool = True

    @property
    def resolved_ipc_transport(self) -> Literal["unix", "tcp"]:
        """The transport actually used on this platform.

        Windows uses loopback TCP because Python ``asyncio`` cannot SSL-wrap a named pipe;
        POSIX uses a Unix domain socket. An explicit ``ipc_transport`` overrides the default.
        """
        if self.ipc_transport in ("unix", "tcp"):
            return self.ipc_transport  # type: ignore[return-value]
        return "tcp" if sys.platform == "win32" else "unix"

    @property
    def judge_live(self) -> bool:
        """True when a real Anthropic key is configured; otherwise the offline stub judge is used."""
        return bool(self.anthropic_api_key)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings` singleton."""
    return Settings()
