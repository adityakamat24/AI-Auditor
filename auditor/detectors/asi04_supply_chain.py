"""ASI04 Agentic Supply-Chain Compromise detector (PRD §9.7.4).

Tool-catalog integrity. Each ``ToolCallStart`` carries a ``schema_hash`` (hex sha256 of the tool's
declared schema). We compare it against the pinned catalog in ``trace.metadata["tool_catalog"]``
(mapping ``tool_name -> expected schema_hash``):

- Unknown tool (not in the catalog) -> VIOLATION (Critical): runtime tool registration is prohibited.
- schema_hash mismatch -> VIOLATION (Critical): the tool's schema was mutated mid-run.
- Missing schema_hash on the event -> VIOLATION (Critical): cannot attest the tool.

Severity is conveyed via the evidence reason and ``rubric_scores`` (the Verdict model has no severity
field). Deterministic, no judge.
"""

from __future__ import annotations

from auditor.detectors.base import Detector, Trace
from auditor.detectors.registry import register_detector
from auditor.events.schemas import ToolCallStart
from auditor.verdicts.schemas import Evidence, Severity, Verdict, VerdictResult


class Asi04SupplyChainDetector(Detector):
    asi_category = "ASI04"
    requires_judge = False

    async def run(self, trace: Trace) -> list[Verdict]:
        catalog: dict[str, str] = trace.metadata.get("tool_catalog", {})
        starts = [e for e in trace.events if isinstance(e, ToolCallStart)]
        if not starts:
            return []
        if not catalog:
            # No pinned tool_catalog → asi04 has nothing to verify (not applicable). The dedicated
            # startup integrity check (asi04_catalog_integrity) handles the published-vs-runtime diff
            # when a catalog IS configured. Emitting NEEDS_REVIEW here floods every catalog-less run
            # with a spurious LOW flag, which is noise - not a real safety signal.
            return []

        evidence: list[Evidence] = []
        for ev in starts:
            expected = catalog.get(ev.tool_name)
            if expected is None:
                evidence.append(
                    Evidence(
                        event_id=ev.event_id,
                        reason=f"[{Severity.CRITICAL}] unknown tool {ev.tool_name!r} not in pinned catalog",
                    )
                )
            elif ev.schema_hash is None:
                evidence.append(
                    Evidence(
                        event_id=ev.event_id,
                        reason=f"[{Severity.CRITICAL}] tool {ev.tool_name!r} carries no schema_hash",
                    )
                )
            elif ev.schema_hash != expected:
                evidence.append(
                    Evidence(
                        event_id=ev.event_id,
                        reason=(
                            f"[{Severity.CRITICAL}] schema_hash mismatch for {ev.tool_name!r}: "
                            f"observed {ev.schema_hash[:12]}.. != catalog {expected[:12]}.."
                        ),
                    )
                )

        result = VerdictResult.VIOLATION if evidence else VerdictResult.OK
        scores = {"severity": "critical"} if evidence else None
        if not evidence:
            evidence = [Evidence(reason=f"all {len(starts)} tool schema hashes match the pinned catalog")]

        return [
            Verdict(
                run_id=trace.run_id,
                tenant_id=trace.tenant_id,
                detector="asi04_supply_chain",
                asi_category="ASI04",
                result=result,
                confidence=0.99 if result == VerdictResult.VIOLATION else 1.0,
                evidence=evidence,
                rubric_scores=scores,
            )
        ]


register_detector("asi04_supply_chain", "1.0.0", "ASI04", requires_judge=False)(Asi04SupplyChainDetector)

__all__ = ["Asi04SupplyChainDetector"]
