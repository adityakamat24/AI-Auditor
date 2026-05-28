"""Pydantic event models validate, set channel/event_type, and parse via the discriminated union."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from auditor.events.schemas import AnyEvent, MemoryOp, SyscallOpenat, ToolCallStart
from pydantic import TypeAdapter, ValidationError


def _ids() -> dict:
    return {
        "event_id": uuid4(),
        "run_id": uuid4(),
        "tenant_id": uuid4(),
        "span_id": uuid4(),
        "ts": datetime.now(UTC),
    }


def test_toolcallstart_defaults_channel_and_type() -> None:
    e = ToolCallStart(agent_id=uuid4(), tool_name="file_read", **_ids())
    assert e.channel == "VOLUNTARY"
    assert e.event_type == "tool_call.start"
    assert e.tool_args == {}


def test_syscall_openat_is_involuntary() -> None:
    e = SyscallOpenat(path="/etc/passwd", **_ids())
    assert e.channel == "INVOLUNTARY"
    assert e.event_type == "syscall.openat"


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        SyscallOpenat(path="/x", bogus_field=1, **_ids())


def test_memory_op_allows_both_event_types() -> None:
    r = MemoryOp(event_type="memory.read", agent_id=uuid4(), store="long_term", **_ids())
    w = MemoryOp(event_type="memory.write", agent_id=uuid4(), store="session", source="web", **_ids())
    assert r.event_type == "memory.read"
    assert w.source == "web"


def test_discriminated_union_parses_by_event_type() -> None:
    adapter = TypeAdapter(AnyEvent)
    parsed = adapter.validate_python(
        {"event_type": "syscall.openat", "channel": "INVOLUNTARY", "path": "/etc/shadow", **_ids()}
    )
    assert isinstance(parsed, SyscallOpenat)
    assert parsed.path == "/etc/shadow"
