"""IPC frame dispatcher (PRD §9.3, §9.4): persists telemetry events and answers gate requests.

The IPC server hands each parsed ``Frame`` (and the connection's verified :class:`PeerIdentity`) here.
``event`` frames are stored; ``req`` (GateDecisionRequest) frames run the inline gate and return a
``resp`` (GateDecisionResponse); heartbeats are liveness only.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from auditor.events.proto_bridge import decision_to_proto, event_to_dict, event_ts
from auditor.events.store import (
    mark_run_completed,
    store_event,
    store_gate_decision,
    update_run_declared_goal,
    upsert_run,
)
from auditor.ids import uuid7
from auditor.inline_gate.decide import decide
from auditor.ipc.auth import PeerIdentity
from auditor.logging import get_logger
from auditor.proto_gen.decisions_pb2 import Frame, GateDecisionResponse
from auditor.proto_gen.events_pb2 import Event

log = get_logger("auditor.ipc.dispatch")


class GateDispatcher:
    def __init__(self, *, opa, pii, budget) -> None:
        self.opa = opa
        self.pii = pii
        self.budget = budget
        self._audits: set[asyncio.Task] = set()  # keep refs to background audit tasks (avoid GC)

    async def on_connect(self, identity: PeerIdentity | None) -> None:
        if identity is None:
            return
        await upsert_run(UUID(identity.run_id), UUID(identity.tenant_id))
        log.info("ipc.run_connected", run_id=identity.run_id, role=identity.role)

    async def on_disconnect(self, identity: PeerIdentity | None) -> None:
        """Run ended: mark it completed and schedule the off-hot-path audit (sampler → detectors → flag)."""
        if identity is None:
            return
        run_id, tenant_id = UUID(identity.run_id), UUID(identity.tenant_id)
        try:
            await mark_run_completed(run_id)
        except Exception as exc:  # noqa: BLE001 - never let teardown bookkeeping fail the connection close
            log.warning("ipc.run_complete_failed", run_id=identity.run_id, error=str(exc))
        # Fire-and-forget: the audit (detectors + judge) runs after the connection is torn down.
        task = asyncio.create_task(self._audit(run_id, tenant_id))
        self._audits.add(task)
        task.add_done_callback(self._audits.discard)

    async def _audit(self, run_id: UUID, tenant_id: UUID) -> None:
        try:
            from auditor.async_pipeline.pipeline import audit_run

            outcome = await audit_run(run_id, tenant_id)
            log.info(
                "audit.run_complete",
                run_id=str(run_id),
                sampled=outcome.sampled,
                tier=outcome.tier,
                flagged=outcome.flag is not None,
                severity=outcome.flag.severity.value if outcome.flag else None,
            )
        except Exception as exc:  # noqa: BLE001 - the audit is best-effort and isolated from the server
            log.warning("audit.run_failed", run_id=str(run_id), error=str(exc))

    async def on_frame(self, frame: Frame, identity: PeerIdentity | None) -> Frame | None:
        kind = frame.WhichOneof("kind")
        if kind == "event":
            await self._store(frame.event)
            return None
        if kind == "req":
            return await self._gate(frame.req.event)
        return None  # heartbeat / seccomp_update — no response

    async def _store(self, ev: Event) -> None:
        event_dict = event_to_dict(ev)
        try:
            await store_event(event_dict, event_ts(ev))
        except Exception as exc:  # noqa: BLE001 - never let storage break the channel
            log.warning("ipc.event_store_failed", error=str(exc))
            return
        # An intent.declare records the user's instruction → also surface it as the run's declared_goal
        # so the judge has the instruction text when it scores adherence (Check #1).
        if event_dict.get("event_type") == "intent.declare":
            run_id, intent = event_dict.get("run_id"), event_dict.get("intent")
            if run_id and intent:
                try:
                    await update_run_declared_goal(UUID(run_id), str(intent))
                except Exception as exc:  # noqa: BLE001 - run-goal update is best-effort
                    log.warning("ipc.run_goal_update_failed", error=str(exc))

    async def _gate(self, ev: Event) -> Frame:
        event_dict = event_to_dict(ev)
        run_id = event_dict.get("run_id")
        event_id = None
        try:
            event_id = await store_event(event_dict, event_ts(ev))
        except Exception as exc:  # noqa: BLE001
            log.warning("ipc.gate_event_store_failed", error=str(exc))

        outcome = await decide(event_dict, run_id=run_id, opa=self.opa, pii=self.pii, budget=self.budget)

        if event_id is not None:
            try:
                await store_gate_decision(event_id, outcome.decision, outcome.votes, outcome.latency_ms)
            except Exception as exc:  # noqa: BLE001
                log.warning("ipc.gate_decision_store_failed", error=str(exc))

        log.info(
            "gate.decision",
            decision=outcome.decision,
            tool=event_dict.get("tool_name"),
            reasons=outcome.reasons,
            latency_ms=outcome.latency_ms,
        )
        response = Frame()
        response.resp.CopyFrom(
            GateDecisionResponse(
                decision_id=str(uuid7()),
                decision=decision_to_proto(outcome.decision),
                reasons=outcome.reasons,
                latency_ms=outcome.latency_ms,
            )
        )
        return response


__all__ = ["GateDispatcher"]
