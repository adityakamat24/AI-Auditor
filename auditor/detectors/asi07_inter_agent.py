"""ASI07 Insecure Inter-Agent Communication detector (PRD §9.7.7).

Deterministic HMAC-presence check on the intra-agent bus: every ``InterAgentMessage`` must carry a
non-empty HMAC ``signature``. An unsigned (empty) signature means the sender's identity is unproven -
the door for forged/man-in-the-middle messages - so it is a VIOLATION.

(Full signature *verification* against the sender's key lands with ``auditor/auth/`` in a later phase;
here we enforce presence, which is the cheap, high-precision first gate.)

No judge required.
"""

from __future__ import annotations

from auditor.detectors.base import Detector, Trace
from auditor.detectors.registry import register_detector
from auditor.events.schemas import InterAgentMessage
from auditor.verdicts.schemas import Evidence, Verdict, VerdictResult


class Asi07InterAgentDetector(Detector):
    asi_category = "ASI07"
    requires_judge = False

    async def run(self, trace: Trace) -> list[Verdict]:
        messages = [e for e in trace.events if isinstance(e, InterAgentMessage)]
        if not messages:
            return []

        evidence: list[Evidence] = []
        for msg in messages:
            if not msg.signature:
                evidence.append(
                    Evidence(
                        event_id=msg.event_id,
                        reason=(
                            f"unsigned inter-agent message {msg.sender_id} -> {msg.receiver_id} "
                            "(empty HMAC signature)"
                        ),
                    )
                )

        result = VerdictResult.VIOLATION if evidence else VerdictResult.OK
        if not evidence:
            evidence = [Evidence(reason=f"all {len(messages)} inter-agent messages carry an HMAC signature")]

        return [
            Verdict(
                run_id=trace.run_id,
                tenant_id=trace.tenant_id,
                detector="asi07_inter_agent",
                asi_category="ASI07",
                result=result,
                confidence=0.97 if result == VerdictResult.VIOLATION else 1.0,
                evidence=evidence,
            )
        ]


register_detector("asi07_inter_agent", "1.0.0", "ASI07", requires_judge=False)(Asi07InterAgentDetector)

__all__ = ["Asi07InterAgentDetector"]
