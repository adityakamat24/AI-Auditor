"""Bridge between the protobuf ``Event`` wire type and dict/row representations.

This is the pydantic/proto bridge deferred from Phase 1: it flattens a wire ``Event`` (base header +
payload oneof) into the dict the gate/store consume, and converts gate decisions to/from the enum.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from auditor.proto_gen.decisions_pb2 import GateDecision
from auditor.proto_gen.events_pb2 import Channel, Event

_CHANNEL_TO_STR = {Channel.VOLUNTARY: "VOLUNTARY", Channel.INVOLUNTARY: "INVOLUNTARY"}
_DECISION_FROM_STR = {
    "ALLOW": GateDecision.ALLOW,
    "DENY": GateDecision.DENY,
    "CONFIRM": GateDecision.CONFIRM,
}
_DECISION_TO_STR = {v: k for k, v in _DECISION_FROM_STR.items()}


def decision_to_proto(decision: str) -> int:
    return _DECISION_FROM_STR.get(decision, GateDecision.ALLOW)


def decision_from_proto(value: int) -> str:
    return _DECISION_TO_STR.get(value, "ALLOW")


def event_ts(ev: Event) -> datetime:
    if ev.base.ts_unix_ns:
        return datetime.fromtimestamp(ev.base.ts_unix_ns / 1e9, tz=UTC)
    return datetime.now(tz=UTC)


def _payload(ev: Event) -> dict:
    kind = ev.WhichOneof("payload")
    if kind == "tool_call_start":
        t = ev.tool_call_start
        return {
            "agent_id": t.agent_id or None,
            "tool_name": t.tool_name,
            "tool_args": json.loads(t.tool_args_json) if t.tool_args_json else {},
            "declared_purpose": t.declared_purpose or None,
            "tool_call_id": t.tool_call_id or None,
            "schema_hash": t.schema_hash or None,
        }
    if kind == "tool_call_end":
        t = ev.tool_call_end
        return {
            "agent_id": t.agent_id or None,
            "tool_call_id": t.tool_call_id or None,
            "status": t.status,
            "result_summary": t.result_summary or None,
            "error": t.error or None,
        }
    if kind == "llm_call":
        t = ev.llm_call
        return {
            "agent_id": t.agent_id or None,
            "model": t.model,
            "tokens_in": t.tokens_in,
            "tokens_out": t.tokens_out,
            "messages_hash": t.messages_hash.hex() if t.messages_hash else None,
        }
    if kind == "memory_op":
        t = ev.memory_op
        return {
            "agent_id": t.agent_id or None,
            "op": t.op,
            "store": t.store,
            "keys_or_query": list(t.keys_or_query),
            "source": t.source or None,
        }
    if kind == "intent_declare":
        t = ev.intent_declare
        return {"agent_id": t.agent_id or None, "intent": t.intent, "plan_steps": list(t.plan_steps)}
    if kind == "agent_message":
        t = ev.agent_message
        return {
            "sender_id": t.sender_id or None,
            "receiver_id": t.receiver_id or None,
            "message_hash": t.message_hash.hex() if t.message_hash else None,
            "signature": t.signature.hex() if t.signature else None,
        }
    if kind == "syscall_openat":
        return {"path": ev.syscall_openat.path, "flags": ev.syscall_openat.flags}
    if kind == "syscall_connect":
        c = ev.syscall_connect
        return {"family": c.family, "addr": c.addr, "port": c.port}
    if kind == "syscall_execve":
        return {"binary": ev.syscall_execve.binary, "argv": list(ev.syscall_execve.argv)}
    if kind == "syscall_sendto":
        s = ev.syscall_sendto
        return {"fd": s.fd, "bytes_sent": s.bytes_sent, "dest_addr": s.dest_addr or None}
    if kind == "dns_query":
        return {"query_name": ev.dns_query.query_name, "results": list(ev.dns_query.results)}
    return {}


def event_to_dict(ev: Event) -> dict:
    """Flatten a wire Event into a single dict (base header + payload fields)."""
    base = ev.base
    out = {
        "event_id": base.event_id,
        "run_id": base.run_id,
        "tenant_id": base.tenant_id,
        "span_id": base.span_id,
        "parent_span_id": base.parent_span_id or None,
        "channel": _CHANNEL_TO_STR.get(base.channel, "VOLUNTARY"),
        "event_type": base.event_type,
        "ts_unix_ns": base.ts_unix_ns,
        "pid": base.pid or None,
    }
    out.update(_payload(ev))
    return out


__all__ = ["decision_to_proto", "decision_from_proto", "event_ts", "event_to_dict"]
