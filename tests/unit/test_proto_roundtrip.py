"""Protobuf bindings serialize and parse round-trip (PRD §9.1 test requirement)."""

from __future__ import annotations

from auditor.proto_gen.decisions_pb2 import Frame, GateDecision
from auditor.proto_gen.events_pb2 import Channel, Event
from auditor.proto_gen.verdicts_pb2 import Flag, Severity, Verdict, VerdictResult


def test_event_roundtrip_preserves_payload() -> None:
    ev = Event()
    ev.base.event_id = "11111111-1111-1111-1111-111111111111"
    ev.base.run_id = "22222222-2222-2222-2222-222222222222"
    ev.base.tenant_id = "33333333-3333-3333-3333-333333333333"
    ev.base.channel = Channel.VOLUNTARY
    ev.base.event_type = "tool_call.start"
    ev.base.ts_unix_ns = 1_700_000_000_000_000_000
    ev.tool_call_start.tool_name = "file_read"
    ev.tool_call_start.tool_args_json = '{"path": "/tmp/x.csv"}'
    ev.tool_call_start.declared_purpose = "read the input file"

    parsed = Event()
    parsed.ParseFromString(ev.SerializeToString())

    assert parsed == ev
    assert parsed.WhichOneof("payload") == "tool_call_start"
    assert parsed.tool_call_start.tool_name == "file_read"
    assert parsed.base.channel == Channel.VOLUNTARY


def test_frame_oneof_roundtrip() -> None:
    fr = Frame()
    fr.resp.decision_id = "abc"
    fr.resp.decision = GateDecision.DENY
    fr.resp.reasons.append("sensitive path")
    fr.resp.latency_ms = 3

    out = Frame()
    out.ParseFromString(fr.SerializeToString())

    assert out.WhichOneof("kind") == "resp"
    assert out.resp.decision == GateDecision.DENY
    assert list(out.resp.reasons) == ["sensitive path"]


def test_verdict_and_flag_roundtrip() -> None:
    v = Verdict(
        detector="asi01_goal_hijack",
        asi_category="ASI01",
        result=VerdictResult.VIOLATION,
        confidence=0.9,
    )
    out_v = Verdict()
    out_v.ParseFromString(v.SerializeToString())
    assert out_v.detector == "asi01_goal_hijack"
    assert out_v.result == VerdictResult.VIOLATION
    assert abs(out_v.confidence - 0.9) < 1e-9

    flag = Flag(severity=Severity.CRITICAL)
    flag.asi_categories.extend(["ASI01", "ASI02"])
    out_flag = Flag()
    out_flag.ParseFromString(flag.SerializeToString())
    assert out_flag.severity == Severity.CRITICAL
    assert list(out_flag.asi_categories) == ["ASI01", "ASI02"]
