"""Prometheus metrics for the AI Auditor.

All metrics live on the default prometheus_client registry, which is already served
by the ``/metrics`` endpoint in ``auditor/main.py`` via ``generate_latest()``.

Usage (idempotent — safe to call ``init_metrics()`` multiple times or import this
module from multiple places; metrics are module-level singletons):

    from auditor.observability.metrics import record_flag, init_metrics
    init_metrics()          # no-op after first call
    record_flag("high", "ASI01")

The helper functions are deliberately thin wrappers so callers never touch the
prometheus_client internals directly.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Module-level metric singletons
# Defined once at import time on the default registry.  prometheus_client will
# raise ValueError("Duplicated timeseries") on a second identical registration;
# guarding with a module-level flag makes ``init_metrics()`` idempotent even if
# called by multiple code paths.
# ---------------------------------------------------------------------------

# --- Flags -----------------------------------------------------------------

#: Total flags raised, labelled by severity (critical/high/medium/low) and the
#: OWASP ASI category (ASI01 … ASI10).
flags_total = Counter(
    "auditor_flags_total",
    "Total audit flags raised",
    ["severity", "asi_category"],
)

# --- Inline-gate decisions --------------------------------------------------

#: Inline gate decisions labelled by decision (ALLOW / DENY / CONFIRM).
gate_decisions_total = Counter(
    "auditor_gate_decisions_total",
    "Total inline gate decisions",
    ["decision"],
)

# --- LLM judge calls --------------------------------------------------------

#: Judge LLM calls labelled by model name and whether the response was served
#: from cache (cached = "true" / "false").
judge_calls_total = Counter(
    "auditor_judge_calls_total",
    "Total LLM judge calls",
    ["model", "cached"],
)

#: End-to-end latency of a judge call in seconds (buckets tuned for typical
#: Anthropic API response times: 0.1 s up to 30 s).
judge_latency_seconds = Histogram(
    "auditor_judge_latency_seconds",
    "LLM judge call latency in seconds",
    buckets=(0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0),
)

# --- Calibration ------------------------------------------------------------

#: Current precision score for each ASI category detector (0.0–1.0).
calibration_precision = Gauge(
    "auditor_calibration_precision",
    "Current calibration precision score per ASI category",
    ["category"],
)

# --- Active runs ------------------------------------------------------------

#: Gauge tracking how many agent runs are currently being audited (active
#: runs in-flight; useful for load visibility and scaling signals).
active_runs = Gauge(
    "auditor_active_runs",
    "Number of agent runs currently being audited",
)

# ---------------------------------------------------------------------------
# Idempotency guard
# ---------------------------------------------------------------------------

_initialised: bool = False


def init_metrics() -> None:
    """Ensure the metrics module has been imported and all counters exist.

    This is a no-op after the first call.  Callers (e.g. ``main.py``) may call
    it during startup to surface the metrics before any events arrive so that
    Prometheus sees them even on a quiet instance.
    """
    global _initialised  # noqa: PLW0603
    if _initialised:
        return
    # Touch each metric to force label-less zero-value initialisation on the
    # default registry (prometheus_client lazily creates child metrics).
    # We don't pre-initialise the label combinations here — that would require
    # exhaustive cross-products.  Instead, callers emit the first sample.
    _initialised = True


# ---------------------------------------------------------------------------
# Helper functions — the public API used by the rest of the application
# ---------------------------------------------------------------------------


def record_flag(severity: str, asi_category: str) -> None:
    """Increment the flags counter.

    Args:
        severity: One of ``critical``, ``high``, ``medium``, ``low``.
        asi_category: OWASP ASI category string, e.g. ``"ASI01"``.
    """
    flags_total.labels(severity=severity, asi_category=asi_category).inc()


def record_gate_decision(decision: str) -> None:
    """Increment the inline gate decisions counter.

    Args:
        decision: One of ``ALLOW``, ``DENY``, ``CONFIRM``.
    """
    gate_decisions_total.labels(decision=decision).inc()


def record_judge_call(model: str, *, cached: bool, latency_seconds: float | None = None) -> None:
    """Record a single LLM judge call.

    Args:
        model: Model identifier string, e.g. ``"claude-haiku-4-5-20251001"``.
        cached: Whether the result was served from the judge's response cache.
        latency_seconds: Optional end-to-end latency in seconds.  When supplied
            the value is observed on the ``auditor_judge_latency_seconds``
            histogram.
    """
    judge_calls_total.labels(model=model, cached=str(cached).lower()).inc()
    if latency_seconds is not None:
        judge_latency_seconds.observe(latency_seconds)


def set_calibration_precision(category: str, value: float) -> None:
    """Set the current calibration precision gauge for an ASI category.

    Args:
        category: ASI category string, e.g. ``"ASI01"``.
        value: Precision score in [0.0, 1.0].
    """
    calibration_precision.labels(category=category).set(value)


def set_active_runs(count: int) -> None:
    """Set the active runs gauge.

    Args:
        count: Number of runs currently being audited.
    """
    active_runs.set(count)
