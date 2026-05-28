"""Structured logging via structlog.

Console-rendered in ``dev``, JSON otherwise. Correlation IDs (``run_id``/``tenant_id``/``span_id``)
are carried through ``contextvars`` so every log line within a run is automatically tagged.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any
from uuid import UUID

import structlog

from auditor.config import Settings, get_settings

# Reserved structlog/context keys that are NOT user data - we never run redaction over them
# (their values are UUIDs, log levels, ISO timestamps, etc. - cheap to skip and safer to avoid
# accidentally clobbering correlation IDs that happen to look like an email address).
_STRUCTLOG_RESERVED: frozenset[str] = frozenset(
    {"event", "level", "timestamp", "logger", "run_id", "tenant_id", "span_id", "exc_info", "stack_info"}
)


def redact_log_processor(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor: redact PII in string values of *event_dict* before emit.

    Runs the process-wide :class:`auditor.audit_log.redactor.Redactor` over every string value in
    the event dict (skipping correlation-id keys, which are UUIDs / timestamps / log levels).
    Without this, an exception traceback or a debug log that happens to include a tool result
    would ship PII to Fly's log shipper - and then to whatever downstream log store consumes it.

    Set ``LOG_REDACT=false`` to disable for local debugging - never in production.
    """
    if os.environ.get("LOG_REDACT", "true").strip().lower() == "false":
        return event_dict

    from auditor.audit_log.redactor import get_log_redactor

    try:
        r = get_log_redactor()
    except Exception:  # noqa: BLE001 - never let logging fail because redactor init failed
        return event_dict

    def _scrub(v: Any) -> Any:
        if isinstance(v, str):
            return r.redact_text(v)
        if isinstance(v, dict):
            return {k: _scrub(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_scrub(val) for val in v]
        return v

    for key, value in list(event_dict.items()):
        if key in _STRUCTLOG_RESERVED:
            continue
        try:
            event_dict[key] = _scrub(value)
        except Exception:  # noqa: BLE001 - never let a malformed value break the log line
            pass
    # The "event" key holds the log message itself; redact it too (but it can legitimately
    # contain a user-supplied string with PII, so we run the scrubber here as well).
    if "event" in event_dict and isinstance(event_dict["event"], str):
        try:
            event_dict["event"] = r.redact_text(event_dict["event"])
        except Exception:  # noqa: BLE001
            pass
    return event_dict


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
        redact_log_processor,
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
