"""Observability package - Prometheus metrics for the AI Auditor."""

from auditor.observability.metrics import (
    init_metrics,
    record_flag,
    record_gate_decision,
    record_judge_call,
    set_active_runs,
    set_calibration_precision,
)

__all__ = [
    "init_metrics",
    "record_flag",
    "record_gate_decision",
    "record_judge_call",
    "set_calibration_precision",
    "set_active_runs",
]
