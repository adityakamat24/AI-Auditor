from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class VerdictResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_RESULT_UNSPECIFIED: _ClassVar[VerdictResult]
    VIOLATION: _ClassVar[VerdictResult]
    OK: _ClassVar[VerdictResult]
    NEEDS_REVIEW: _ClassVar[VerdictResult]

class Severity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEVERITY_UNSPECIFIED: _ClassVar[Severity]
    LOW: _ClassVar[Severity]
    MEDIUM: _ClassVar[Severity]
    HIGH: _ClassVar[Severity]
    CRITICAL: _ClassVar[Severity]
VERDICT_RESULT_UNSPECIFIED: VerdictResult
VIOLATION: VerdictResult
OK: VerdictResult
NEEDS_REVIEW: VerdictResult
SEVERITY_UNSPECIFIED: Severity
LOW: Severity
MEDIUM: Severity
HIGH: Severity
CRITICAL: Severity

class Verdict(_message.Message):
    __slots__ = ("verdict_id", "run_id", "tenant_id", "detector", "asi_category", "result", "confidence", "evidence_json", "judge_model", "judge_prompt_v", "rubric_scores_json", "ts_unix_ns")
    VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    DETECTOR_FIELD_NUMBER: _ClassVar[int]
    ASI_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_JSON_FIELD_NUMBER: _ClassVar[int]
    JUDGE_MODEL_FIELD_NUMBER: _ClassVar[int]
    JUDGE_PROMPT_V_FIELD_NUMBER: _ClassVar[int]
    RUBRIC_SCORES_JSON_FIELD_NUMBER: _ClassVar[int]
    TS_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    verdict_id: str
    run_id: str
    tenant_id: str
    detector: str
    asi_category: str
    result: VerdictResult
    confidence: float
    evidence_json: str
    judge_model: str
    judge_prompt_v: int
    rubric_scores_json: str
    ts_unix_ns: int
    def __init__(self, verdict_id: _Optional[str] = ..., run_id: _Optional[str] = ..., tenant_id: _Optional[str] = ..., detector: _Optional[str] = ..., asi_category: _Optional[str] = ..., result: _Optional[_Union[VerdictResult, str]] = ..., confidence: _Optional[float] = ..., evidence_json: _Optional[str] = ..., judge_model: _Optional[str] = ..., judge_prompt_v: _Optional[int] = ..., rubric_scores_json: _Optional[str] = ..., ts_unix_ns: _Optional[int] = ...) -> None: ...

class Flag(_message.Message):
    __slots__ = ("flag_id", "run_id", "tenant_id", "severity", "asi_categories", "verdict_ids", "status", "created_at_unix_ns")
    FLAG_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    TENANT_ID_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    ASI_CATEGORIES_FIELD_NUMBER: _ClassVar[int]
    VERDICT_IDS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_UNIX_NS_FIELD_NUMBER: _ClassVar[int]
    flag_id: str
    run_id: str
    tenant_id: str
    severity: Severity
    asi_categories: _containers.RepeatedScalarFieldContainer[str]
    verdict_ids: _containers.RepeatedScalarFieldContainer[str]
    status: str
    created_at_unix_ns: int
    def __init__(self, flag_id: _Optional[str] = ..., run_id: _Optional[str] = ..., tenant_id: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., asi_categories: _Optional[_Iterable[str]] = ..., verdict_ids: _Optional[_Iterable[str]] = ..., status: _Optional[str] = ..., created_at_unix_ns: _Optional[int] = ...) -> None: ...
