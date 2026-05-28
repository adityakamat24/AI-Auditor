from auditor.proto_gen import events_pb2 as _events_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GateDecision(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DECISION_UNSPECIFIED: _ClassVar[GateDecision]
    ALLOW: _ClassVar[GateDecision]
    DENY: _ClassVar[GateDecision]
    CONFIRM: _ClassVar[GateDecision]
DECISION_UNSPECIFIED: GateDecision
ALLOW: GateDecision
DENY: GateDecision
CONFIRM: GateDecision

class GateDecisionRequest(_message.Message):
    __slots__ = ("event", "timeout_ms")
    EVENT_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    event: _events_pb2.Event
    timeout_ms: int
    def __init__(self, event: _Optional[_Union[_events_pb2.Event, _Mapping]] = ..., timeout_ms: _Optional[int] = ...) -> None: ...

class GateDecisionResponse(_message.Message):
    __slots__ = ("decision_id", "decision", "reasons", "latency_ms")
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    REASONS_FIELD_NUMBER: _ClassVar[int]
    LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    decision_id: str
    decision: GateDecision
    reasons: _containers.RepeatedScalarFieldContainer[str]
    latency_ms: int
    def __init__(self, decision_id: _Optional[str] = ..., decision: _Optional[_Union[GateDecision, str]] = ..., reasons: _Optional[_Iterable[str]] = ..., latency_ms: _Optional[int] = ...) -> None: ...

class Heartbeat(_message.Message):
    __slots__ = ("ts_unix_ns", "run_id", "role")
    TS_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    ts_unix_ns: int
    run_id: str
    role: str
    def __init__(self, ts_unix_ns: _Optional[int] = ..., run_id: _Optional[str] = ..., role: _Optional[str] = ...) -> None: ...

class SeccompUpdate(_message.Message):
    __slots__ = ("policy_json",)
    POLICY_JSON_FIELD_NUMBER: _ClassVar[int]
    policy_json: str
    def __init__(self, policy_json: _Optional[str] = ...) -> None: ...

class Frame(_message.Message):
    __slots__ = ("event", "req", "resp", "hb", "seccomp_update")
    EVENT_FIELD_NUMBER: _ClassVar[int]
    REQ_FIELD_NUMBER: _ClassVar[int]
    RESP_FIELD_NUMBER: _ClassVar[int]
    HB_FIELD_NUMBER: _ClassVar[int]
    SECCOMP_UPDATE_FIELD_NUMBER: _ClassVar[int]
    event: _events_pb2.Event
    req: GateDecisionRequest
    resp: GateDecisionResponse
    hb: Heartbeat
    seccomp_update: SeccompUpdate
    def __init__(self, event: _Optional[_Union[_events_pb2.Event, _Mapping]] = ..., req: _Optional[_Union[GateDecisionRequest, _Mapping]] = ..., resp: _Optional[_Union[GateDecisionResponse, _Mapping]] = ..., hb: _Optional[_Union[Heartbeat, _Mapping]] = ..., seccomp_update: _Optional[_Union[SeccompUpdate, _Mapping]] = ...) -> None: ...
