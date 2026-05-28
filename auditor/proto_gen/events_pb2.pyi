from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Channel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CHANNEL_UNSPECIFIED: _ClassVar[Channel]
    VOLUNTARY: _ClassVar[Channel]
    INVOLUNTARY: _ClassVar[Channel]
CHANNEL_UNSPECIFIED: Channel
VOLUNTARY: Channel
INVOLUNTARY: Channel

class BaseEvent(_message.Message):
    __slots__ = ("event_id", "run_id", "tenant_id", "span_id", "parent_span_id", "channel", "event_type", "ts_unix_ns", "pid", "schema_version")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    TS_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    run_id: str
    tenant_id: str
    span_id: str
    parent_span_id: str
    channel: Channel
    event_type: str
    ts_unix_ns: int
    pid: int
    schema_version: int
    def __init__(self, event_id: _Optional[str] = ..., run_id: _Optional[str] = ..., tenant_id: _Optional[str] = ..., span_id: _Optional[str] = ..., parent_span_id: _Optional[str] = ..., channel: _Optional[_Union[Channel, str]] = ..., event_type: _Optional[str] = ..., ts_unix_ns: _Optional[int] = ..., pid: _Optional[int] = ..., schema_version: _Optional[int] = ...) -> None: ...

class ToolCallStart(_message.Message):
    __slots__ = ("agent_id", "tool_name", "tool_args_json", "declared_purpose", "tool_call_id", "schema_hash")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    TOOL_NAME_FIELD_NUMBER: _ClassVar[int]
    TOOL_ARGS_JSON_FIELD_NUMBER: _ClassVar[int]
    DECLARED_PURPOSE_FIELD_NUMBER: _ClassVar[int]
    TOOL_CALL_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_HASH_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    tool_name: str
    tool_args_json: str
    declared_purpose: str
    tool_call_id: str
    schema_hash: str
    def __init__(self, agent_id: _Optional[str] = ..., tool_name: _Optional[str] = ..., tool_args_json: _Optional[str] = ..., declared_purpose: _Optional[str] = ..., tool_call_id: _Optional[str] = ..., schema_hash: _Optional[str] = ...) -> None: ...

class ToolCallEnd(_message.Message):
    __slots__ = ("agent_id", "tool_call_id", "status", "result_summary", "error")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    TOOL_CALL_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RESULT_SUMMARY_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    tool_call_id: str
    status: str
    result_summary: str
    error: str
    def __init__(self, agent_id: _Optional[str] = ..., tool_call_id: _Optional[str] = ..., status: _Optional[str] = ..., result_summary: _Optional[str] = ..., error: _Optional[str] = ...) -> None: ...

class LLMCall(_message.Message):
    __slots__ = ("agent_id", "model", "messages_hash", "tokens_in", "tokens_out")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_HASH_FIELD_NUMBER: _ClassVar[int]
    TOKENS_IN_FIELD_NUMBER: _ClassVar[int]
    TOKENS_OUT_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    model: str
    messages_hash: bytes
    tokens_in: int
    tokens_out: int
    def __init__(self, agent_id: _Optional[str] = ..., model: _Optional[str] = ..., messages_hash: _Optional[bytes] = ..., tokens_in: _Optional[int] = ..., tokens_out: _Optional[int] = ...) -> None: ...

class MemoryOp(_message.Message):
    __slots__ = ("agent_id", "op", "store", "keys_or_query", "source")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    OP_FIELD_NUMBER: _ClassVar[int]
    STORE_FIELD_NUMBER: _ClassVar[int]
    KEYS_OR_QUERY_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    op: str
    store: str
    keys_or_query: _containers.RepeatedScalarFieldContainer[str]
    source: str
    def __init__(self, agent_id: _Optional[str] = ..., op: _Optional[str] = ..., store: _Optional[str] = ..., keys_or_query: _Optional[_Iterable[str]] = ..., source: _Optional[str] = ...) -> None: ...

class InterAgentMessage(_message.Message):
    __slots__ = ("sender_id", "receiver_id", "message_hash", "signature")
    SENDER_ID_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_HASH_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    sender_id: str
    receiver_id: str
    message_hash: bytes
    signature: bytes
    def __init__(self, sender_id: _Optional[str] = ..., receiver_id: _Optional[str] = ..., message_hash: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class IntentDeclaration(_message.Message):
    __slots__ = ("agent_id", "intent", "plan_steps")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    INTENT_FIELD_NUMBER: _ClassVar[int]
    PLAN_STEPS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    intent: str
    plan_steps: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, agent_id: _Optional[str] = ..., intent: _Optional[str] = ..., plan_steps: _Optional[_Iterable[str]] = ...) -> None: ...

class SyscallOpenat(_message.Message):
    __slots__ = ("path", "flags")
    PATH_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    path: str
    flags: int
    def __init__(self, path: _Optional[str] = ..., flags: _Optional[int] = ...) -> None: ...

class SyscallConnect(_message.Message):
    __slots__ = ("family", "addr", "port")
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    ADDR_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    family: str
    addr: str
    port: int
    def __init__(self, family: _Optional[str] = ..., addr: _Optional[str] = ..., port: _Optional[int] = ...) -> None: ...

class SyscallExecve(_message.Message):
    __slots__ = ("binary", "argv")
    BINARY_FIELD_NUMBER: _ClassVar[int]
    ARGV_FIELD_NUMBER: _ClassVar[int]
    binary: str
    argv: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, binary: _Optional[str] = ..., argv: _Optional[_Iterable[str]] = ...) -> None: ...

class SyscallSendto(_message.Message):
    __slots__ = ("fd", "bytes_sent", "dest_addr")
    FD_FIELD_NUMBER: _ClassVar[int]
    BYTES_SENT_FIELD_NUMBER: _ClassVar[int]
    DEST_ADDR_FIELD_NUMBER: _ClassVar[int]
    fd: int
    bytes_sent: int
    dest_addr: str
    def __init__(self, fd: _Optional[int] = ..., bytes_sent: _Optional[int] = ..., dest_addr: _Optional[str] = ...) -> None: ...

class DnsQuery(_message.Message):
    __slots__ = ("query_name", "results")
    QUERY_NAME_FIELD_NUMBER: _ClassVar[int]
    RESULTS_FIELD_NUMBER: _ClassVar[int]
    query_name: str
    results: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, query_name: _Optional[str] = ..., results: _Optional[_Iterable[str]] = ...) -> None: ...

class Event(_message.Message):
    __slots__ = ("base", "tool_call_start", "tool_call_end", "llm_call", "memory_op", "agent_message", "intent_declare", "syscall_openat", "syscall_connect", "syscall_execve", "syscall_sendto", "dns_query")
    BASE_FIELD_NUMBER: _ClassVar[int]
    TOOL_CALL_START_FIELD_NUMBER: _ClassVar[int]
    TOOL_CALL_END_FIELD_NUMBER: _ClassVar[int]
    LLM_CALL_FIELD_NUMBER: _ClassVar[int]
    MEMORY_OP_FIELD_NUMBER: _ClassVar[int]
    AGENT_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    INTENT_DECLARE_FIELD_NUMBER: _ClassVar[int]
    SYSCALL_OPENAT_FIELD_NUMBER: _ClassVar[int]
    SYSCALL_CONNECT_FIELD_NUMBER: _ClassVar[int]
    SYSCALL_EXECVE_FIELD_NUMBER: _ClassVar[int]
    SYSCALL_SENDTO_FIELD_NUMBER: _ClassVar[int]
    DNS_QUERY_FIELD_NUMBER: _ClassVar[int]
    base: BaseEvent
    tool_call_start: ToolCallStart
    tool_call_end: ToolCallEnd
    llm_call: LLMCall
    memory_op: MemoryOp
    agent_message: InterAgentMessage
    intent_declare: IntentDeclaration
    syscall_openat: SyscallOpenat
    syscall_connect: SyscallConnect
    syscall_execve: SyscallExecve
    syscall_sendto: SyscallSendto
    dns_query: DnsQuery
    def __init__(self, base: _Optional[_Union[BaseEvent, _Mapping]] = ..., tool_call_start: _Optional[_Union[ToolCallStart, _Mapping]] = ..., tool_call_end: _Optional[_Union[ToolCallEnd, _Mapping]] = ..., llm_call: _Optional[_Union[LLMCall, _Mapping]] = ..., memory_op: _Optional[_Union[MemoryOp, _Mapping]] = ..., agent_message: _Optional[_Union[InterAgentMessage, _Mapping]] = ..., intent_declare: _Optional[_Union[IntentDeclaration, _Mapping]] = ..., syscall_openat: _Optional[_Union[SyscallOpenat, _Mapping]] = ..., syscall_connect: _Optional[_Union[SyscallConnect, _Mapping]] = ..., syscall_execve: _Optional[_Union[SyscallExecve, _Mapping]] = ..., syscall_sendto: _Optional[_Union[SyscallSendto, _Mapping]] = ..., dns_query: _Optional[_Union[DnsQuery, _Mapping]] = ...) -> None: ...
