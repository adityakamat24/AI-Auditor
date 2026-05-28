"""Asynchronous detection pipeline (PRD §9.6) — off the critical path. STUB — Phase 4.

After a run completes (or at sample points), the sampler picks traces, the orchestrator fans them out to
the ASI detectors (and the LLM judge), and the budget tracker bounds judge spend. Submodules are stubs.
"""

from __future__ import annotations

# TODO(phase4): sampler -> orchestrator (run detectors + judge) -> aggregator, bounded by budget_tracker.

__all__: list[str] = []
