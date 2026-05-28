"""Channel correlator - joins voluntary + involuntary events per run (PRD §9.4.4, §5.6).

Matches what an agent *claimed* (voluntary tool-call / llm events) against what the host *observed*
(involuntary syscall events) within a time window. The "expected correlate" allowlist maps voluntary
events to the syscall signatures they legitimately produce (e.g. ``file_read(path=X)`` -> ``openat(X)``;
``llm.call`` -> ``connect(api.anthropic.com)``). Involuntary events with no matching declaration (and
not absorbed by the learned runtime baseline) are returned as *unmatched* - divergence candidates.
"""

from __future__ import annotations

from urllib.parse import urlparse

from auditor.events.schemas import BaseEvent

# A signature is a (kind, value) pair so file/net/exec events compare apples-to-apples.
Signature = tuple[str, str]


def _host(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    if "://" in url_or_host:
        return (urlparse(url_or_host).hostname or "").lower()
    return url_or_host.split(":", 1)[0].lower()


def involuntary_signature(event: BaseEvent) -> Signature:
    et = event.event_type
    if et == "syscall.openat":
        return ("file", getattr(event, "path", ""))
    if et == "syscall.connect":
        return ("net", _host(getattr(event, "addr", "") or ""))
    if et == "syscall.dns":
        return ("net", _host(getattr(event, "query_name", "") or ""))
    if et == "syscall.sendto":
        return ("net", _host(getattr(event, "dest_addr", "") or ""))
    if et == "syscall.execve":
        return ("exec", getattr(event, "binary", ""))
    return ("other", et)


def voluntary_produces(event: BaseEvent) -> set[Signature]:
    """The involuntary signatures a voluntary event may legitimately produce."""
    et = event.event_type
    produced: set[Signature] = set()
    if et == "tool_call.start":
        args = getattr(event, "tool_args", {}) or {}
        tool = getattr(event, "tool_name", "")
        if tool in ("file_read", "file_write") and args.get("path"):
            produced.add(("file", str(args["path"])))
        if tool in ("http_get", "http_post"):
            host = _host(str(args.get("url", "") or args.get("host", "")))
            if host:
                produced.add(("net", host))
        if tool == "exec_shell":
            produced.add(("exec", "*"))  # declares exec intent (gate denies it anyway)
    elif et == "llm.call":
        produced.add(("net", "api.anthropic.com"))
    return produced


def _matches(involuntary_sig: Signature, produced: set[Signature]) -> bool:
    kind, value = involuntary_sig
    for pkind, pvalue in produced:
        if pkind != kind:
            continue
        if pvalue == "*" or pvalue == value:
            return True
        if kind == "net" and value and pvalue and (value in pvalue or pvalue in value):
            return True
        if kind == "file" and value and pvalue and value == pvalue:
            return True
    return False


def unmatched_involuntary(
    events: list[BaseEvent], *, window_ms: int, baseline_s: float = 0.0
) -> list[BaseEvent]:
    """Return involuntary events with no correlating voluntary declaration (divergence candidates).

    Events within the first ``baseline_s`` seconds establish a per-run baseline of expected runtime
    syscalls (interpreter startup, library loads) that are absorbed thereafter.
    """
    if not events:
        return []
    run_start = min(e.ts for e in events)
    window = window_ms / 1000.0

    voluntary = [(e.ts.timestamp(), voluntary_produces(e)) for e in events if e.channel == "VOLUNTARY"]
    involuntary = [e for e in events if e.channel == "INVOLUNTARY"]

    baseline: set[Signature] = set()
    if baseline_s > 0:
        for e in involuntary:
            if (e.ts - run_start).total_seconds() < baseline_s:
                baseline.add(involuntary_signature(e))

    unmatched: list[BaseEvent] = []
    for e in involuntary:
        if baseline_s > 0 and (e.ts - run_start).total_seconds() < baseline_s:
            continue  # still learning
        sig = involuntary_signature(e)
        if sig in baseline:
            continue  # absorbed by runtime baseline
        ets = e.ts.timestamp()
        if any(_matches(sig, produced) and abs(vts - ets) <= window for vts, produced in voluntary):
            continue  # correlated with a declaration
        unmatched.append(e)
    return unmatched


__all__ = [
    "Signature",
    "involuntary_signature",
    "voluntary_produces",
    "unmatched_involuntary",
]
