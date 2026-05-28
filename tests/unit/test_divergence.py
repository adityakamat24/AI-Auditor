"""Channel-divergence detector: matched calls are silent; undeclared kernel activity is flagged."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from auditor.events.schemas import (
    LLMCall,
    SyscallConnect,
    SyscallExecve,
    SyscallOpenat,
    ToolCallStart,
)
from auditor.inline_gate.divergence import DivergenceConfig, DivergenceDetector
from auditor.verdicts.schemas import Severity

T0 = datetime(2026, 1, 1, tzinfo=UTC)
RID = uuid4()
TID = uuid4()


def _base(ms: int) -> dict:
    return {"event_id": uuid4(), "run_id": RID, "tenant_id": TID, "span_id": uuid4(),
            "ts": T0 + timedelta(milliseconds=ms)}


def _openat(path: str, ms: int) -> SyscallOpenat:
    return SyscallOpenat(path=path, **_base(ms))


def _execve(binary: str, ms: int) -> SyscallExecve:
    return SyscallExecve(binary=binary, **_base(ms))


def _connect(addr: str, ms: int) -> SyscallConnect:
    return SyscallConnect(family="AF_INET", addr=addr, port=443, **_base(ms))


def _tool(tool: str, args: dict, ms: int) -> ToolCallStart:
    return ToolCallStart(agent_id=uuid4(), tool_name=tool, tool_args=args, **_base(ms))


def _llm(ms: int) -> LLMCall:
    return LLMCall(agent_id=uuid4(), model="claude-haiku-4-5", messages_hash=b"h", **_base(ms))


def _det(**kw) -> DivergenceDetector:
    return DivergenceDetector(DivergenceConfig(window_ms=800, **kw))


def test_declared_file_access_is_not_divergence() -> None:
    events = [_tool("file_read", {"path": "/tmp/data.csv"}, 0), _openat("/tmp/data.csv", 50)]
    assert _det().analyze(events) == []


def test_undeclared_sensitive_file_is_critical() -> None:
    findings = _det().analyze([_openat("/home/u/.ssh/id_rsa", 0)])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].asi_category == "ASI03"


def test_undeclared_execve_is_critical() -> None:
    findings = _det().analyze([_execve("/usr/bin/curl", 0)])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].asi_category == "ASI05"


def test_declared_llm_connect_is_not_divergence() -> None:
    events = [_llm(0), _connect("api.anthropic.com", 40)]
    assert _det().analyze(events) == []


def test_undeclared_egress_is_critical() -> None:
    findings = _det().analyze([_connect("evil.example.com", 0)])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].asi_category == "ASI01"


def test_baseline_absorbs_runtime_syscalls() -> None:
    det = _det(baseline_s=1.0)
    events = [
        _openat("/usr/lib/python3.12/json/__init__.py", 10),   # during baseline -> learned
        _openat("/usr/lib/python3.12/json/__init__.py", 1500),  # after baseline, same sig -> absorbed
    ]
    assert det.analyze(events) == []


def test_correlation_window_miss_is_flagged() -> None:
    # The declaration is 2s before the syscall; outside the 800ms window -> unmatched.
    events = [_tool("file_read", {"path": "/tmp/x"}, 0), _openat("/tmp/x", 2000)]
    findings = _det().analyze(events)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_to_verdicts_carries_severity() -> None:
    det = _det()
    findings = det.analyze([_openat("/home/u/.ssh/id_rsa", 0)])
    verdicts = det.to_verdicts(RID, TID, findings)
    assert verdicts[0].detector == "channel_divergence"
    assert verdicts[0].asi_category == "ASI03"
    assert verdicts[0].rubric_scores["severity"] == "critical"
