"""Detector ABC contract + lifecycle registry defaults to PROPOSED (§9.13)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from auditor.detectors import (
    Detector,
    DetectorState,
    Trace,
    clear_registry,
    get_registry,
    register_detector,
)
from auditor.verdicts import Verdict, VerdictResult


def test_detector_abc_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        Detector()  # type: ignore[abstract]


async def test_concrete_detector_runs_and_returns_verdicts() -> None:
    class Dummy(Detector):
        asi_category = "ASI02"

        async def run(self, trace: Trace) -> list[Verdict]:
            return [
                Verdict(
                    run_id=trace.run_id,
                    tenant_id=trace.tenant_id,
                    detector="dummy",
                    asi_category="ASI02",
                    result=VerdictResult.OK,
                )
            ]

    trace = Trace(run_id=uuid4(), tenant_id=uuid4())
    verdicts = await Dummy().run(trace)
    assert verdicts[0].result == VerdictResult.OK


def test_registry_defaults_new_detectors_to_proposed() -> None:
    clear_registry()
    try:

        @register_detector("asi02_tool_misuse", "1.0.0", "ASI02")
        def _factory() -> object:
            return object()

        reg = get_registry()
        assert reg["asi02_tool_misuse"].state == DetectorState.PROPOSED
        assert reg["asi02_tool_misuse"].asi_category == "ASI02"
    finally:
        clear_registry()
