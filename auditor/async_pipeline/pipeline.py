"""Post-run audit pipeline (PRD §9.6) - the off-hot-path path that ties sampling to detection.

When a run completes, :func:`audit_run` (1) loads its trace, (2) computes cheap signals and asks the
sampler whether to audit (and at what tier), (3) records the sampler decision, and - only if sampled -
(4) runs the detector orchestrator (which persists verdicts + flag and opens an incident for High/Critical),
then (5) routes any flag to the HITL queue and the live UI WebSocket. This is what makes the configured
sampling % actually gate the expensive judge, instead of auditing every run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from uuid import UUID

from auditor.async_pipeline.orchestrator import Orchestrator
from auditor.async_pipeline.runtime_policy import decide as runtime_decide
from auditor.async_pipeline.sampler import Sampler, SamplerDecision
from auditor.async_pipeline.signals import compute_run_signals
from auditor.verdicts.aggregator import Flag
from auditor.verdicts.schemas import Verdict

logger = logging.getLogger(__name__)


@dataclass
class AuditOutcome:
    run_id: UUID
    sampled: bool
    tier: str
    reason: str
    flag: Flag | None = None
    verdicts: list[Verdict] = field(default_factory=list)


async def audit_run(
    run_id: UUID,
    tenant_id: UUID,
    *,
    sampler: Sampler | None = None,
    persist: bool = True,
) -> AuditOutcome:
    """Sample a completed run and, if selected, run the detector pipeline + route any flag."""
    from auditor.events.store import load_trace

    trace = await load_trace(run_id, tenant_id)
    signals = compute_run_signals(trace)
    # Tests can inject a Sampler; production uses the user-configurable runtime policy (mode + params).
    decision = (
        sampler.decide(run_id, tenant_id, signals)
        if sampler is not None
        else runtime_decide(run_id, tenant_id, signals)
    )
    await _persist_sampler_decision(run_id, decision)

    if not decision.audit:
        logger.info("audit.skipped run=%s tier=%s", run_id, decision.tier)
        return AuditOutcome(run_id=run_id, sampled=False, tier=decision.tier, reason=decision.reason)

    result = await Orchestrator(persist=persist).analyze_trace(trace)
    if result.flag is not None:
        await _route_flag(result.flag)
    return AuditOutcome(
        run_id=run_id,
        sampled=True,
        tier=decision.tier,
        reason=decision.reason,
        flag=result.flag,
        verdicts=result.verdicts,
    )


async def _persist_sampler_decision(run_id: UUID, decision: SamplerDecision) -> None:
    """Record the sampler decision (one row per run that entered the pipeline)."""
    try:
        from auditor.db.models import SamplerDecision as SamplerDecisionRow
        from auditor.db.session import get_sessionmaker
        from auditor.ids import uuid7

        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session, session.begin():
            session.add(
                SamplerDecisionRow(
                    sampler_id=uuid7(),
                    run_id=run_id,
                    tier_fired=decision.tier,
                    reason=decision.reason,
                    cohort_rate=decision.cohort_rate,
                )
            )
    except Exception as exc:  # noqa: BLE001 - telemetry write must never break the pipeline
        logger.warning("audit.sampler_decision_persist_failed run=%s error=%s", run_id, exc)


async def _route_flag(flag: Flag) -> None:
    """Publish a flag to the live UI and route it through HITL (queue/notify; pause for finished runs is a no-op)."""
    try:
        from auditor.api.hitl_routes import flag_broadcaster

        flag_broadcaster.publish(
            {
                "flag_id": str(flag.flag_id),
                "run_id": str(flag.run_id),
                "tenant_id": str(flag.tenant_id),
                "severity": flag.severity.value,
                "asi_categories": list(flag.asi_categories),
                "status": flag.status,
            }
        )
    except Exception as exc:  # noqa: BLE001 - UI broadcast is best-effort
        logger.warning("audit.flag_broadcast_failed flag=%s error=%s", flag.flag_id, exc)

    try:
        from auditor.hitl.router import HitlRouter

        await HitlRouter().route(flag)
    except Exception as exc:  # noqa: BLE001 - HITL routing is best-effort off the hot path
        logger.warning("audit.flag_route_failed flag=%s error=%s", flag.flag_id, exc)


__all__ = ["AuditOutcome", "audit_run"]
