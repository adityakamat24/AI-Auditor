"""Cross-run behavioral baseline store (Welford) + its integration with the ASI10 drift detector."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from auditor.async_pipeline.baseline import BaselineStore
from auditor.detectors.asi10_rogue_agent import Asi10RogueAgentDetector
from auditor.detectors.base import Trace
from auditor.events.schemas import ToolCallStart
from auditor.verdicts.schemas import VerdictResult

TENANT = uuid4()
ROLE = "itsm_resolver"


def test_baseline_none_until_observed() -> None:
    store = BaselineStore()
    assert store.baseline(tenant_id=TENANT, role=ROLE) is None


def test_baseline_computes_mean_and_std() -> None:
    store = BaselineStore()
    for value in (9.0, 10.0, 11.0):  # mean 10, sample std 1.0
        store.observe(tenant_id=TENANT, role=ROLE, run_stats={"tool_calls": value})
    base = store.baseline(tenant_id=TENANT, role=ROLE)
    assert base["z_threshold"] == 3.0
    assert base["axes"]["tool_calls"]["mean"] == pytest.approx(10.0)
    assert base["axes"]["tool_calls"]["std"] == pytest.approx(1.0)
    assert store.observation_count(tenant_id=TENANT, role=ROLE, axis="tool_calls") == 3


def _trace_with(baseline: dict, observed_tool_calls: float) -> Trace:
    action = ToolCallStart(
        event_id=uuid4(), run_id=uuid4(), tenant_id=TENANT, span_id=uuid4(),
        ts=datetime(2026, 5, 27, tzinfo=UTC), agent_id=uuid4(),
        tool_name="create_ticket", tool_args={"title": "printer offline"},
    )
    return Trace(
        run_id=action.run_id, tenant_id=TENANT, declared_goal="triage IT tickets",
        events=[action],
        metadata={"mission": "triage IT tickets", "baseline": baseline,
                  "run_stats": {"tool_calls": observed_tool_calls}},
    )


async def test_store_baseline_feeds_asi10_and_flags_drift() -> None:
    # Learn a normal cohort, then score an anomalous run against the produced baseline.
    store = BaselineStore()
    for value in (9.0, 10.0, 11.0, 10.0, 9.0, 11.0):
        store.observe(tenant_id=TENANT, role=ROLE, run_stats={"tool_calls": value})
    baseline = store.baseline(tenant_id=TENANT, role=ROLE)

    anomalous = await Asi10RogueAgentDetector().run(_trace_with(baseline, observed_tool_calls=50.0))
    assert anomalous[0].result == VerdictResult.VIOLATION
    assert any("baseline drift" in e.reason for e in anomalous[0].evidence)

    normal = await Asi10RogueAgentDetector().run(_trace_with(baseline, observed_tool_calls=10.0))
    assert normal[0].result == VerdictResult.OK  # within the learned norm; benign judge
