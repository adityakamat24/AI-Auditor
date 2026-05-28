"""Per-category adversarial fixture suite (PRD §12).

For each of the seven newly populated ASI fixture directories this test:
  1. Imports the ``build_attack_trace`` builder and constructs a synthetic trace.
  2. Runs the trace through the full ``Orchestrator`` fan-out (all ten detectors).
  3. Loads the sibling ``expected_flags.json`` and asserts:
     - a Flag was raised (not None),
     - every category listed in ``expected_flags["asi_categories"]`` is in ``flag.asi_categories``,
     - ``flag.severity`` rank >= ``min_severity`` rank,
     - ``reason_contains`` appears in at least one verdict/flag evidence reason string.

All traces are synthetic and key-free; judge-driven detectors use the ``OfflineStubJudge``
(selected automatically when no Anthropic key is configured).
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
from auditor.async_pipeline.orchestrator import Orchestrator
from auditor.verdicts.schemas import Severity

_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_ADVERSARIAL_ROOT = (
    Path(__file__).parent.parent.parent / "adversarial" / "per_category"
)

# The seven newly created fixture directories.
_CATEGORIES = [
    "asi01_goal_hijack",
    "asi04_supply_chain",
    "asi06_memory_poisoning",
    "asi07_inter_agent",
    "asi08_cascading",
    "asi09_trust_exploit",
    "asi10_rogue_agent",
]


def _load_expected(category: str) -> dict:
    path = _ADVERSARIAL_ROOT / category / "expected_flags.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _build_trace(category: str):
    module = importlib.import_module(f"adversarial.per_category.{category}.agent")
    return module.build_attack_trace(uuid4(), uuid4())


@pytest.mark.parametrize("category", _CATEGORIES)
async def test_per_category_fixture(category: str) -> None:
    """Build the synthetic attack trace, run the orchestrator, and verify the expected flag."""
    trace = _build_trace(category)
    result = await Orchestrator().analyze_trace(trace)
    expected = _load_expected(category)

    # 1. A flag must be raised.
    assert result.flag is not None, (
        f"{category}: expected a flag but got none. "
        f"Verdicts: {[v.result for v in result.verdicts]}"
    )

    flag = result.flag

    # 2. Every expected ASI category must be present in the flag.
    for asi_cat in expected["asi_categories"]:
        assert asi_cat in flag.asi_categories, (
            f"{category}: expected {asi_cat!r} in flag.asi_categories, "
            f"got {flag.asi_categories}"
        )

    # 3. Severity must be at least the specified minimum.
    min_sev = Severity(expected["min_severity"])
    assert _RANK[flag.severity] >= _RANK[min_sev], (
        f"{category}: expected severity >= {min_sev!r}, got {flag.severity!r}"
    )

    # 4. The reason_contains substring must appear in at least one evidence reason.
    needle = expected["reason_contains"]
    all_reasons = [e.reason for e in flag.evidence]
    # Also search individual verdict evidence for completeness.
    for v in result.verdicts:
        all_reasons.extend(e.reason for e in v.evidence)

    assert any(needle in reason for reason in all_reasons), (
        f"{category}: expected {needle!r} in some evidence reason, "
        f"but reasons were: {all_reasons}"
    )
