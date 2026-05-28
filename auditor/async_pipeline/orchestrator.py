"""Async detector orchestrator (PRD §9.6, §9.9).

Loads a run trace, fans the ten ASI detectors out concurrently, and aggregates their verdicts into a
single :class:`~auditor.verdicts.aggregator.Flag`. A detector that raises does NOT fail the run: it is
converted into a conservative ``NEEDS_REVIEW`` verdict so the failure surfaces rather than silently
passing (a detector we cannot trust is not the same as a clean run).

The judge is not injected here - judge-driven detectors call :func:`auditor.judge.client.get_judge`
themselves, so verdict caching and abstain→Sonnet escalation live at that seam.

Lifecycle-aware routing (PRD §9.13)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When a ``state_for`` callable is supplied (maps ``detector_name -> DetectorState``), each detector's
verdicts are partitioned by lifecycle state:

- **ENFORCING**: verdicts count toward the aggregated Flag (normal behaviour).
- **CANARY**: verdicts count toward the Flag for the configured canary partition (tagged ``canary``);
  traffic outside the partition is dropped as SHADOW.
- **SHADOW**: verdicts are written to the shadow store and excluded from the Flag entirely.
- **PROPOSED / DISABLED / DEPRECATED / REMOVED**: the detector is not run.

When no ``state_for`` is supplied (the default), every passed-in detector is treated as ENFORCING so
existing tests stay green without any changes.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from uuid import UUID

from auditor.detectors.base import Detector, Trace
from auditor.detectors.registry import DetectorState, get_registry
from auditor.verdicts.aggregator import Flag, aggregate
from auditor.verdicts.schemas import Evidence, Verdict, VerdictResult

logger = logging.getLogger(__name__)

# Importing each module runs its module-level register_detector(...) call.
_DETECTOR_MODULES = (
    "auditor.detectors.asi01_goal_hijack",
    "auditor.detectors.asi02_tool_misuse",
    "auditor.detectors.asi03_identity_abuse",
    "auditor.detectors.asi04_supply_chain",
    "auditor.detectors.asi05_code_execution",
    "auditor.detectors.asi06_memory_poisoning",
    "auditor.detectors.asi07_inter_agent",
    "auditor.detectors.asi08_cascading",
    "auditor.detectors.asi09_trust_exploit",
    "auditor.detectors.asi10_rogue_agent",
    "auditor.detectors.instruction_following",
)

# States whose detectors should not be run at all.
_SKIP_STATES = frozenset(
    {
        DetectorState.PROPOSED,
        DetectorState.DISABLED,
        DetectorState.DEPRECATED,
        DetectorState.REMOVED,
    }
)


def ensure_detectors_registered() -> dict:
    """Import the ten detector modules so they self-register.

    Robust to a prior ``clear_registry()`` (which some unit tests call): if the registry is short after
    import - meaning the modules were already imported and then cleared - reload them to re-run
    registration.
    """
    modules = [importlib.import_module(name) for name in _DETECTOR_MODULES]
    if len(get_registry()) < len(_DETECTOR_MODULES):
        for module in modules:
            importlib.reload(module)
    return get_registry()


@dataclass
class OrchestratorResult:
    """Outcome of analyzing one run: the aggregated flag (if any), all verdicts, and detector errors."""

    flag: Flag | None
    verdicts: list[Verdict]
    errors: list[tuple[str, str]] = field(default_factory=list)


class Orchestrator:
    """Detector fan-out → verdict aggregation pipeline for a trace or a persisted run.

    Parameters
    ----------
    persist:
        Whether to persist run results to the database via :func:`auditor.events.store.store_run_result`.
    state_for:
        Optional callable ``(detector_name: str) -> DetectorState``.  When supplied, detectors in
        SHADOW state have their verdicts written to ``shadow_store`` and excluded from the Flag;
        detectors in PROPOSED/DISABLED/DEPRECATED/REMOVED are skipped entirely.  When *not* supplied,
        all detectors are treated as ENFORCING (preserves existing behaviour for tests that don't
        pass this argument).
    shadow_store:
        Optional shadow verdict store (must implement ``async write(verdict, detector_version)``).
        Only used when ``state_for`` is provided.
    canary_partition:
        Fraction of traffic routed through CANARY detectors (0.0–1.0).  Defaults to 0.05.
    """

    def __init__(
        self,
        *,
        persist: bool = False,
        state_for: Callable[[str], DetectorState] | None = None,
        shadow_store: object | None = None,
        canary_partition: float = 0.05,
    ) -> None:
        self._persist = persist
        self._state_for = state_for
        self._shadow_store = shadow_store
        self._canary_partition = canary_partition

    def default_detectors(self) -> list[Detector]:
        """Instantiate one of each registered detector (the ten ASI detectors)."""
        registry = ensure_detectors_registered()
        return [registration.factory() for registration in registry.values()]

    async def analyze_trace(
        self, trace: Trace, *, detectors: list[Detector] | None = None
    ) -> OrchestratorResult:
        """Run detectors concurrently over ``trace`` and aggregate their verdicts into a Flag."""
        all_instances = detectors if detectors is not None else self.default_detectors()

        def _detector_key(d: Detector) -> str:
            """Stable lookup key for state_for: prefer asi_category, fall back to class name."""
            return d.asi_category or type(d).__name__

        # Lifecycle partitioning: filter out non-runnable detectors when state_for is set.
        if self._state_for is not None:
            runnable = [
                d for d in all_instances
                if self._state_for(_detector_key(d)) not in _SKIP_STATES
            ]
        else:
            runnable = all_instances

        outcomes = await asyncio.gather(
            *(d.run(trace) for d in runnable), return_exceptions=True
        )

        enforcing_verdicts: list[Verdict] = []
        all_verdicts: list[Verdict] = []
        errors: list[tuple[str, str]] = []

        for detector, outcome in zip(runnable, outcomes, strict=True):
            detector_name = type(detector).__name__
            detector_key = _detector_key(detector)
            if isinstance(outcome, BaseException):
                message = f"{type(outcome).__name__}: {outcome}"
                errors.append((detector.asi_category or detector_name, message))
                logger.warning("detector %s raised: %s", detector_name, message)
                crash = self._crash_verdict(trace, detector, message)
                all_verdicts.append(crash)
                # Crash verdicts go to enforcing bucket regardless of state.
                enforcing_verdicts.append(crash)
                continue

            detector_verdicts: list[Verdict] = list(outcome)
            all_verdicts.extend(detector_verdicts)

            if self._state_for is not None:
                state = self._state_for(detector_key)
                if state == DetectorState.SHADOW:
                    # Write to shadow store; do NOT include in Flag.
                    await self._write_shadow(detector_verdicts)
                elif state == DetectorState.CANARY:
                    # Only include in Flag for the canary partition.
                    from auditor.detectors.lifecycle import is_canary_selected

                    if is_canary_selected(
                        detector_key, str(trace.run_id), self._canary_partition
                    ):
                        # Tag verdicts as canary.
                        tagged = [self._tag_canary(v) for v in detector_verdicts]
                        enforcing_verdicts.extend(tagged)
                    else:
                        # Outside canary partition → treat as shadow.
                        await self._write_shadow(detector_verdicts)
                else:
                    # ENFORCING (or anything else that passed the _SKIP_STATES filter).
                    enforcing_verdicts.extend(detector_verdicts)
            else:
                # No lifecycle awareness: all verdicts count.
                enforcing_verdicts.extend(detector_verdicts)

        flag = aggregate(trace.run_id, trace.tenant_id, enforcing_verdicts)
        result = OrchestratorResult(flag=flag, verdicts=all_verdicts, errors=errors)
        if self._persist:
            from auditor.events.store import store_run_result

            await store_run_result(all_verdicts, flag)
        return result

    async def analyze_run(self, run_id: UUID, tenant_id: UUID) -> OrchestratorResult:
        """Load a persisted run's trace and analyze it (used by the post-run pipeline)."""
        from auditor.events.store import load_trace

        trace = await load_trace(run_id, tenant_id)
        return await self.analyze_trace(trace)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _write_shadow(self, verdicts: list[Verdict]) -> None:
        if self._shadow_store is None:
            return
        for v in verdicts:
            try:
                await self._shadow_store.write(v)
            except Exception:  # noqa: BLE001
                logger.exception("Shadow verdict store write failed for verdict %s", v.verdict_id)

    @staticmethod
    def _tag_canary(verdict: Verdict) -> Verdict:
        """Return a copy of the verdict with a canary tag in evidence."""
        canary_evidence = Evidence(reason="[canary] verdict from CANARY-state detector")
        return verdict.model_copy(
            update={"evidence": [canary_evidence, *verdict.evidence]}
        )

    @staticmethod
    def _crash_verdict(trace: Trace, detector: Detector, message: str) -> Verdict:
        # A detector that errors means we cannot vouch for its category -> conservative NEEDS_REVIEW.
        return Verdict(
            run_id=trace.run_id,
            tenant_id=trace.tenant_id,
            detector=type(detector).__name__,
            asi_category=detector.asi_category or "UNKNOWN",
            result=VerdictResult.NEEDS_REVIEW,
            confidence=0.0,
            evidence=[Evidence(reason=f"detector raised an exception: {message}")],
        )


__all__ = ["Orchestrator", "OrchestratorResult", "ensure_detectors_registered"]
