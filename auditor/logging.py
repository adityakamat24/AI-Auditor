"""Structured logging via structlog.

Console-rendered in ``dev``, JSON otherwise. Correlation IDs (``run_id``/``tenant_id``/``span_id``)
are carried through ``contextvars`` so every log line within a run is automatically tagged.
"""

from __future__ import annotations

import logging
import sys
from typing import Any
from uuid import UUID

import structlog

from auditor.config import Settings, get_settings


def configure_logging(settings: Settings | None = None) -> None:
    """Configure structlog process-wide. Idempotent enough to call at each entrypoint."""
    settings = settings or get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer: Any = (
        structlog.dev.ConsoleRenderer()
        if settings.auditor_env == "dev"
        else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> Any:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)


def bind_run_context(
    *,
    run_id: UUID | str | None = None,
    tenant_id: UUID | str | None = None,
    span_id: UUID | str | None = None,
) -> None:
    """Bind correlation IDs into contextvars so subsequent logs carry them."""
    ctx: dict[str, str] = {}
    if run_id is not None:
        ctx["run_id"] = str(run_id)
    if tenant_id is not None:
        ctx["tenant_id"] = str(tenant_id)
    if span_id is not None:
        ctx["span_id"] = str(span_id)
    if ctx:
        structlog.contextvars.bind_contextvars(**ctx)


def clear_run_context() -> None:
    """Clear all bound correlation IDs (call at run teardown)."""
    structlog.contextvars.clear_contextvars()
