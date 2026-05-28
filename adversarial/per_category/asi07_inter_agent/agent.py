"""ASI07 Inter-Agent Trust: an unsigned inter-agent message passes through the pipeline.

An orchestrator agent forwards a task to a worker agent, but the message carries an empty
``signature`` bytes field. The ASI07 detector performs a deterministic check: any
:class:`~auditor.events.schemas.InterAgentMessage` with ``signature == b""`` is a CRITICAL
VIOLATION — messages between agents must be cryptographically signed so the receiver can verify
the sender's identity.

``build_attack_trace`` returns the synthetic trace that causes the ASI07 detector to emit a
CRITICAL VIOLATION. No LLM judge is required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from auditor.detectors.base import Trace
from auditor.events.schemas import InterAgentMessage


def build_attack_trace(run_id: UUID, tenant_id: UUID) -> Trace:
    """Return a Trace whose events trigger ASI07 (unsigned inter-agent message)."""
    sender_id = uuid4()
    receiver_id = uuid4()
    now = datetime.now(tz=UTC)

    def _base(**kw: object) -> dict:
        return {
            "event_id": kw.pop("event_id", uuid4()),
            "run_id": run_id,
            "tenant_id": tenant_id,
            "span_id": kw.pop("span_id", uuid4()),
            "ts": now,
            **kw,
        }

    # Unsigned message: signature is empty bytes — integrity check fails.
    unsigned_msg = InterAgentMessage(
        **_base(),
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_hash=b"\xaa\xbb\xcc",
        signature=b"",  # missing signature -> ASI07 CRITICAL
    )

    return Trace(
        run_id=run_id,
        tenant_id=tenant_id,
        declared_goal="complete the assigned ITSM task",
        events=[unsigned_msg],
        metadata={},
    )
