"""Unit tests for auditor.observability.metrics.

Acceptance criteria:
- Importing the module registers metrics without error and is idempotent.
- Calling init_metrics() more than once does not raise.
- Helper functions increment / set the expected metrics.
- prometheus_client.generate_latest() contains every metric name after a call.
"""

from __future__ import annotations

import importlib

from prometheus_client import generate_latest

# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_module_imports_without_error() -> None:
    """Importing the metrics module must not raise."""
    import auditor.observability.metrics  # noqa: F401 - import-only test


def test_double_import_is_idempotent() -> None:
    """Re-importing the module a second time must not raise a duplicate-timeseries error."""
    importlib.import_module("auditor.observability.metrics")
    importlib.import_module("auditor.observability.metrics")  # second import - must be silent


def test_init_metrics_is_idempotent() -> None:
    """Calling init_metrics() repeatedly must not raise."""
    from auditor.observability.metrics import init_metrics

    init_metrics()
    init_metrics()
    init_metrics()


# ---------------------------------------------------------------------------
# Counter / Gauge / Histogram increment checks
# ---------------------------------------------------------------------------


def test_record_flag_increments_counter() -> None:
    from auditor.observability.metrics import flags_total, record_flag

    before = flags_total.labels(severity="high", asi_category="ASI01")._value.get()
    record_flag("high", "ASI01")
    after = flags_total.labels(severity="high", asi_category="ASI01")._value.get()
    assert after == before + 1


def test_record_flag_different_labels_are_independent() -> None:
    from auditor.observability.metrics import flags_total, record_flag

    record_flag("critical", "ASI03")
    record_flag("low", "ASI07")
    # Just asserting no exception and that label sets exist on the registry.
    assert flags_total.labels(severity="critical", asi_category="ASI03") is not None
    assert flags_total.labels(severity="low", asi_category="ASI07") is not None


def test_record_gate_decision_increments_counter() -> None:
    from auditor.observability.metrics import gate_decisions_total, record_gate_decision

    before = gate_decisions_total.labels(decision="ALLOW")._value.get()
    record_gate_decision("ALLOW")
    after = gate_decisions_total.labels(decision="ALLOW")._value.get()
    assert after == before + 1


def test_record_gate_decision_deny() -> None:
    from auditor.observability.metrics import gate_decisions_total, record_gate_decision

    before = gate_decisions_total.labels(decision="DENY")._value.get()
    record_gate_decision("DENY")
    after = gate_decisions_total.labels(decision="DENY")._value.get()
    assert after == before + 1


def test_record_judge_call_increments_counter() -> None:
    from auditor.observability.metrics import judge_calls_total, record_judge_call

    before = judge_calls_total.labels(model="claude-haiku-4-5-20251001", cached="false")._value.get()
    record_judge_call("claude-haiku-4-5-20251001", cached=False)
    after = judge_calls_total.labels(model="claude-haiku-4-5-20251001", cached="false")._value.get()
    assert after == before + 1


def test_record_judge_call_cached_true() -> None:
    from auditor.observability.metrics import judge_calls_total, record_judge_call

    before = judge_calls_total.labels(model="claude-sonnet-4-6", cached="true")._value.get()
    record_judge_call("claude-sonnet-4-6", cached=True, latency_seconds=0.5)
    after = judge_calls_total.labels(model="claude-sonnet-4-6", cached="true")._value.get()
    assert after == before + 1


def test_record_judge_call_with_latency_observes_histogram() -> None:
    from auditor.observability.metrics import judge_latency_seconds, record_judge_call

    before_count = judge_latency_seconds._sum.get()
    record_judge_call("claude-haiku-4-5-20251001", cached=False, latency_seconds=1.23)
    after_count = judge_latency_seconds._sum.get()
    assert after_count > before_count


def test_set_calibration_precision_updates_gauge() -> None:
    from auditor.observability.metrics import calibration_precision, set_calibration_precision

    set_calibration_precision("ASI02", 0.92)
    val = calibration_precision.labels(category="ASI02")._value.get()
    assert abs(val - 0.92) < 1e-9


def test_set_active_runs_updates_gauge() -> None:
    from auditor.observability.metrics import active_runs, set_active_runs

    set_active_runs(7)
    assert active_runs._value.get() == 7
    set_active_runs(0)
    assert active_runs._value.get() == 0


# ---------------------------------------------------------------------------
# generate_latest() contains expected metric names
# ---------------------------------------------------------------------------


def _scrape() -> str:
    return generate_latest().decode()


def test_generate_latest_contains_flags_metric() -> None:
    from auditor.observability.metrics import record_flag

    record_flag("medium", "ASI05")
    assert "auditor_flags_total" in _scrape()


def test_generate_latest_contains_gate_decisions_metric() -> None:
    from auditor.observability.metrics import record_gate_decision

    record_gate_decision("CONFIRM")
    assert "auditor_gate_decisions_total" in _scrape()


def test_generate_latest_contains_judge_calls_metric() -> None:
    from auditor.observability.metrics import record_judge_call

    record_judge_call("claude-haiku-4-5-20251001", cached=False)
    assert "auditor_judge_calls_total" in _scrape()


def test_generate_latest_contains_judge_latency_metric() -> None:
    from auditor.observability.metrics import record_judge_call

    record_judge_call("claude-haiku-4-5-20251001", cached=False, latency_seconds=0.8)
    assert "auditor_judge_latency_seconds" in _scrape()


def test_generate_latest_contains_calibration_precision_metric() -> None:
    from auditor.observability.metrics import set_calibration_precision

    set_calibration_precision("ASI09", 0.88)
    assert "auditor_calibration_precision" in _scrape()


def test_generate_latest_contains_active_runs_metric() -> None:
    from auditor.observability.metrics import set_active_runs

    set_active_runs(3)
    assert "auditor_active_runs" in _scrape()
