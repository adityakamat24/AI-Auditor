"""Pydantic v2 event models — the in-process mirror of ``proto/events.proto`` (PRD §8.2).

The on-the-wire format is the protobuf in :mod:`auditor.proto_gen`; the pydantic<->proto bridge
ships with the Telemetry SDK in Phase 2. Events are immutable observations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Channel = Literal["VOLUNTARY", "INVOLUNTARY"]


class BaseEvent(BaseModel):
    """Common header for every event (voluntary or involuntary)."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    event_id: UUID
    run_id: UUID
    tenant_id: UUID
    span_id: UUID
    parent_span_id: UUID | None = None
    channel: Channel
    event_type: str
    ts: datetime
    pid: int | None = None
    schema_version: int = 1


# ----------------------------- Voluntary events -----------------------------


class ToolCallStart(BaseEvent):
    channel: Literal["VOLUNTARY"] = "VOLUNTARY"
    event_type: Literal["tool_call.start"] = "tool_call.start"
    agent_id: UUID
    tool_name: str
    tool_args: dict = Field(default_factory=dict)
    declared_purpose: str | None = None
    tool_call_id: UUID | None = None
    schema_hash: str | None = None  # hex sha256 of the tool's declared schema (ASI04)


class ToolCallEnd(BaseEvent):
    channel: Literal["VOLUNTARY"] = "VOLUNTARY"
    event_type: Literal["tool_call.end"] = "tool_call.end"
    agent_id: UUID
    tool_call_id: UUID
    status: Literal["success", "error"]
    result_summary: str | None = None
    error: str | None = None


class LLMCall(BaseEvent):
    channel: Literal["VOLUNTARY"] = "VOLUNTARY"
    event_type: Literal["llm.call"] = "llm.call"
    agent_id: UUID
    model: str
    messages_hash: bytes
    tokens_in: int = 0
    tokens_out: int = 0


class MemoryOp(BaseEvent):
    channel: Literal["VOLUNTARY"] = "VOLUNTARY"
    event_type: Literal["memory.read", "memory.write"]
    agent_id: UUID
    store: Literal["session", "long_term"]
    keys_or_query: list[str] = Field(default_factory=list)
    source: str | None = None  # for writes: provenance of the content


class InterAgentMessage(BaseEvent):
    channel: Literal["VOLUNTARY"] = "VOLUNTARY"
    event_type: Literal["agent.message"] = "agent.message"
    sender_id: UUID
    receiver_id: UUID
    message_hash: bytes
    signature: bytes


class IntentDeclaration(BaseEvent):
    channel: Literal["VOLUNTARY"] = "VOLUNTARY"
    event_type: Literal["intent.declare"] = "intent.declare"
    agent_id: UUID
    intent: str
    plan_steps: list[str] = Field(default_factory=list)


# ---------------------------- Involuntary events ----------------------------


class SyscallOpenat(BaseEvent):
    channel: Literal["INVOLUNTARY"] = "INVOLUNTARY"
    event_type: Literal["syscall.openat"] = "syscall.openat"
    path: str
    flags: int = 0


class SyscallConnect(BaseEvent):
    channel: Literal["INVOLUNTARY"] = "INVOLUNTARY"
    event_type: Literal["syscall.connect"] = "syscall.connect"
    family: Literal["AF_INET", "AF_INET6", "AF_UNIX"]
    addr: str
    port: int | None = None


class SyscallExecve(BaseEvent):
    channel: Literal["INVOLUNTARY"] = "INVOLUNTARY"
    event_type: Literal["syscall.execve"] = "syscall.execve"
    binary: str
    argv: list[str] = Field(default_factory=list)


class SyscallSendto(BaseEvent):
    channel: Literal["INVOLUNTARY"] = "INVOLUNTARY"
    event_type: Literal["syscall.sendto"] = "syscall.sendto"
    fd: int
    bytes_sent: int
    dest_addr: str | None = None


class DnsQueryEvent(BaseEvent):
    channel: Literal["INVOLUNTARY"] = "INVOLUNTARY"
    event_type: Literal["syscall.dns"] = "syscall.dns"
    query_name: str
    results: list[str] = Field(default_factory=list)


VoluntaryEvent = (
    ToolCallStart
    | ToolCallEnd
    | LLMCall
    | MemoryOp
    | InterAgentMessage
    | IntentDeclaration
)
InvoluntaryEvent = (
    SyscallOpenat | SyscallConnect | SyscallExecve | SyscallSendto | DnsQueryEvent
)
# Discriminated union over event_type for parsing arbitrary events.
AnyEvent = Annotated[
    VoluntaryEvent | InvoluntaryEvent,
    Field(discriminator="event_type"),
]

__all__ = [
    "Channel",
    "BaseEvent",
    "ToolCallStart",
    "ToolCallEnd",
    "LLMCall",
    "MemoryOp",
    "InterAgentMessage",
    "IntentDeclaration",
    "SyscallOpenat",
    "SyscallConnect",
    "SyscallExecve",
    "SyscallSendto",
    "DnsQueryEvent",
    "VoluntaryEvent",
    "InvoluntaryEvent",
    "AnyEvent",
]
