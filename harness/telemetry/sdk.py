"""Telemetry SDK (harness side) - PRD §9.1.

Connects to the auditor over the platform transport (mTLS when an SSLContext is supplied) and provides:
- ``declare_intent`` - one-way intent event.
- ``tool_call`` - async context manager that **gates** the call: emits a ToolCallStart, requests an
  inline-gate decision (100 ms timeout), raises :class:`GateDeniedError` on DENY, yields the decision on
  ALLOW/CONFIRM, and emits a ToolCallEnd on exit. **Fail-closed**: timeout / unreachable auditor → DENY.
- ``llm_call`` / ``memory_op`` - one-way events.

All frames are serialized on one connection guarded by a lock so a request's response can't be
interleaved with another send.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from contextlib import asynccontextmanager
from uuid import UUID

from auditor.config import Settings, get_settings
from auditor.ids import uuid7
from auditor.ipc.protocol import read_frame, write_frame
from auditor.ipc.transport import select_transport
from auditor.logging import get_logger
from auditor.proto_gen.decisions_pb2 import Frame, GateDecision
from auditor.proto_gen.events_pb2 import Channel, Event

log = get_logger("harness.telemetry")

_GATE_TIMEOUT_S = 0.1  # 100 ms (PRD §9.1)
_DECISION_TO_STR = {
    GateDecision.ALLOW: "ALLOW",
    GateDecision.DENY: "DENY",
    GateDecision.CONFIRM: "CONFIRM",
}


class GateDeniedError(RuntimeError):
    """Raised inside a ``tool_call`` block when the inline gate returns DENY (or fails closed)."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__("; ".join(reasons) or "gate denied")


class _ToolCallHandle(str):
    """The gate decision (a plain ``str`` so existing ``as decision`` callers are unaffected) plus a hook
    to attach the tool's result summary, which is sent on the ToolCallEnd event so the auditor can see
    what the agent actually ingested/produced (needed for the exfil / sensitive-data / instruction checks).
    """

    __slots__ = ("_result_summary",)

    def __new__(cls, decision: str) -> _ToolCallHandle:
        obj = super().__new__(cls, decision)
        obj._result_summary = None
        return obj

    def set_result(self, summary: str | None) -> None:
        self._result_summary = summary


class Telemetry:
    def __init__(
        self,
        run_id: UUID,
        tenant_id: UUID,
        reader,
        writer,
        transport_desc: str,
        gate_timeout_s: float = _GATE_TIMEOUT_S,
    ) -> None:
        self.run_id = run_id
        self.tenant_id = tenant_id
        self._reader = reader
        self._writer = writer
        self.transport = transport_desc
        self._gate_timeout_s = gate_timeout_s
        self._lock = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        run_id: UUID,
        tenant_id: UUID,
        settings: Settings | None = None,
        *,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
    ) -> Telemetry:
        settings = settings or get_settings()
        transport = select_transport(settings)
        reader, writer = await transport.connect(
            ssl_context=ssl_context, server_hostname=server_hostname
        )
        log.info(
            "telemetry.connected",
            transport=transport.describe(),
            run_id=str(run_id),
            mtls=ssl_context is not None,
        )
        gate_timeout_s = max(settings.gate_timeout_ms, 1) / 1000
        return cls(run_id, tenant_id, reader, writer, transport.describe(), gate_timeout_s)

    # -- frame helpers --------------------------------------------------------

    def _new_event(self, event_type: str, span_id: UUID | None = None) -> Event:
        ev = Event()
        ev.base.event_id = str(uuid7())
        ev.base.run_id = str(self.run_id)
        ev.base.tenant_id = str(self.tenant_id)
        ev.base.span_id = str(span_id or uuid7())
        ev.base.channel = Channel.VOLUNTARY
        ev.base.event_type = event_type
        ev.base.ts_unix_ns = time.time_ns()
        return ev

    async def _send_event(self, ev: Event) -> None:
        frame = Frame()
        frame.event.CopyFrom(ev)
        async with self._lock:
            await write_frame(self._writer, frame.SerializeToString())

    async def _request_gate(self, ev: Event):
        frame = Frame()
        frame.req.event.CopyFrom(ev)
        frame.req.timeout_ms = int(self._gate_timeout_s * 1000)
        async with self._lock:
            await write_frame(self._writer, frame.SerializeToString())
            while True:
                raw = await asyncio.wait_for(read_frame(self._reader), timeout=self._gate_timeout_s)
                resp = Frame()
                resp.ParseFromString(raw)
                if resp.WhichOneof("kind") == "resp":
                    return resp.resp
                # ignore non-response frames (e.g. heartbeats)

    # -- public API -----------------------------------------------------------

    async def declare_intent(self, agent_id: UUID, intent: str, plan: list[str]) -> None:
        ev = self._new_event("intent.declare")
        ev.intent_declare.agent_id = str(agent_id)
        ev.intent_declare.intent = intent
        ev.intent_declare.plan_steps.extend(plan)
        await self._send_event(ev)

    @asynccontextmanager
    async def tool_call(
        self,
        agent_id: UUID,
        tool_name: str,
        args: dict,
        declared_purpose: str | None = None,
        schema_hash: str | None = None,
    ):
        span_id = uuid7()
        ev = self._new_event("tool_call.start", span_id)
        start = ev.tool_call_start
        start.agent_id = str(agent_id)
        start.tool_name = tool_name
        start.tool_args_json = json.dumps(args, default=str)
        start.tool_call_id = str(span_id)
        if declared_purpose:
            start.declared_purpose = declared_purpose
        if schema_hash:
            start.schema_hash = schema_hash

        try:
            resp = await self._request_gate(ev)
            decision = _DECISION_TO_STR.get(resp.decision, "DENY")
            reasons = list(resp.reasons)
        except (TimeoutError, ConnectionError, OSError) as exc:  # fail-closed
            log.warning("telemetry.gate_failclosed", tool=tool_name, error=str(exc))
            decision, reasons = "DENY", [f"gate unavailable (fail-closed): {exc}"]

        if decision == "DENY":
            await self._send_tool_end(agent_id, span_id, "error", error="; ".join(reasons))
            raise GateDeniedError(reasons)

        status, error = "success", None
        handle = _ToolCallHandle(decision)  # "ALLOW" or "CONFIRM"; carries the result summary
        try:
            yield handle
        except Exception as exc:
            status, error = "error", str(exc)
            raise
        finally:
            await self._send_tool_end(
                agent_id, span_id, status, error=error, result_summary=handle._result_summary
            )

    async def _send_tool_end(
        self,
        agent_id: UUID,
        span_id: UUID,
        status: str,
        *,
        error: str | None = None,
        result_summary: str | None = None,
    ) -> None:
        ev = self._new_event("tool_call.end", span_id)
        end = ev.tool_call_end
        end.agent_id = str(agent_id)
        end.tool_call_id = str(span_id)
        end.status = status
        if error:
            end.error = error
        if result_summary:
            end.result_summary = result_summary[:4000]  # truncated; PII redaction happens auditor-side
        try:
            await self._send_event(ev)
        except (ConnectionError, OSError):
            pass

    async def llm_call(
        self,
        agent_id: UUID,
        model: str,
        messages_hash: bytes = b"",
        tokens_in: int = 0,
        tokens_out: int = 0,
    ) -> None:
        ev = self._new_event("llm.call")
        call = ev.llm_call
        call.agent_id = str(agent_id)
        call.model = model
        call.messages_hash = messages_hash
        call.tokens_in = tokens_in
        call.tokens_out = tokens_out
        await self._send_event(ev)

    async def memory_op(
        self,
        agent_id: UUID,
        op: str,
        store: str,
        keys: list[str],
        source: str | None = None,
    ) -> None:
        ev = self._new_event(f"memory.{op}")
        mem = ev.memory_op
        mem.agent_id = str(agent_id)
        mem.op = op
        mem.store = store
        mem.keys_or_query.extend(keys)
        if source:
            mem.source = source
        await self._send_event(ev)

    async def send_heartbeat(self) -> None:
        frame = Frame()
        frame.hb.ts_unix_ns = time.time_ns()
        frame.hb.run_id = str(self.run_id)
        frame.hb.role = "harness"
        async with self._lock:
            await write_frame(self._writer, frame.SerializeToString())

    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (ConnectionError, OSError):
            pass


__all__ = ["Telemetry", "GateDeniedError"]
