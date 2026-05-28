"""Cheap pre-audit signals (PRD §9.6.1) - fast heuristics that drive the sampler's tier decision.

The whole point of sampling is that the *expensive* deep audit (detectors + LLM judge) runs on a fraction
of runs, while cheap signals force an always-audit (L1) on anything that looks risky. This computes those
cheap signals from a run's already-stored events without any model calls: which tools/egress were used,
whether sensitive data was touched, and a 0–100 cheap risk score. The full divergence/judge analysis only
happens later, in the orchestrator, when a run is actually sampled.
"""

from __future__ import annotations

import re

from auditor.async_pipeline.sampler import RunSignals
from auditor.detectors.base import Trace
from auditor.events.schemas import (
    DnsQueryEvent,
    MemoryOp,
    SyscallConnect,
    SyscallExecve,
    SyscallOpenat,
    SyscallSendto,
    ToolCallEnd,
    ToolCallStart,
)

_SENSITIVE_PATH = re.compile(r"(\.ssh|id_rsa|/etc/(passwd|shadow)|\.env\b|credentials?|secrets?)", re.IGNORECASE)
_SENSITIVE_ARG = re.compile(r"(password|secret|credential|api[_-]?key|token|private[_-]?key)", re.IGNORECASE)
_INJECTION = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|disregard\s+your\s+instructions|exfiltrate|attacker\.com)",
    re.IGNORECASE,
)
_EGRESS_TOOLS = frozenset({"http_post", "http_get", "send_email"})
_SENSITIVE_TOOLS = frozenset({"read_secret", "reset_password", "query_employee"})
_CODE_EXEC_TOOLS = frozenset({"exec_shell", "eval", "python", "subprocess"})


def _arg_text(args: dict) -> str:
    return " ".join(str(v) for v in args.values())


def _egress_dest(tool_name: str, args: dict) -> str | None:
    """Extract an outbound destination (url host / email recipient) from a tool call's args."""
    if tool_name == "send_email":
        to = str(args.get("to") or args.get("recipient") or "")
        return to.split("@")[-1] if "@" in to else (to or None)
    url = str(args.get("url") or args.get("endpoint") or "")
    if "//" in url:
        return url.split("//", 1)[1].split("/", 1)[0]
    return url or None


def compute_run_signals(trace: Trace) -> RunSignals:
    """Derive the sampler's :class:`RunSignals` from a run's stored events (no model calls)."""
    tools: set[str] = set()
    egress: set[str] = set()
    sensitive = False
    has_exec = False
    injection = False
    saw_secret = False
    secret_then_egress = False

    for event in trace.events:
        if isinstance(event, ToolCallStart):
            tools.add(event.tool_name)
            text = _arg_text(event.tool_args)
            if event.tool_name in _CODE_EXEC_TOOLS:
                has_exec = True
            if event.tool_name in _SENSITIVE_TOOLS or _SENSITIVE_ARG.search(text):
                sensitive = True
                saw_secret = True
            if event.tool_name in _EGRESS_TOOLS:
                dest = _egress_dest(event.tool_name, event.tool_args)
                if dest:
                    egress.add(dest)
                if saw_secret:
                    secret_then_egress = True
            if _INJECTION.search(text):
                injection = True
        elif isinstance(event, ToolCallEnd) and event.result_summary and _INJECTION.search(event.result_summary):
            injection = True
        elif isinstance(event, MemoryOp) and _INJECTION.search(" ".join(event.keys_or_query)):
            injection = True
        elif isinstance(event, SyscallExecve):
            has_exec = True
        elif isinstance(event, SyscallOpenat) and _SENSITIVE_PATH.search(event.path or ""):
            sensitive = True
        elif isinstance(event, (SyscallConnect, SyscallSendto)):
            addr = str(getattr(event, "addr", "") or "")
            if addr:
                egress.add(addr)
        elif isinstance(event, DnsQueryEvent):
            domain = str(getattr(event, "domain", "") or getattr(event, "query", "") or "")
            if domain:
                egress.add(domain)

    risk = min(
        100,
        (40 if has_exec else 0)
        + (30 if egress else 0)
        + (30 if sensitive else 0)
        + (40 if injection else 0)
        + (30 if secret_then_egress else 0),
    )
    category = "code_exec" if has_exec else ("egress" if egress else "generic")

    return RunSignals(
        tool_category=category,
        channel_divergence=False,  # full involuntary↔voluntary divergence is computed in the orchestrator
        cheap_risk_score=risk,
        touched_sensitive_data=sensitive,
        in_allowlisted_path=not sensitive,  # any sensitive touch is treated as outside allowlist (L1)
        tools_used=frozenset(tools),
        egress_domains=frozenset(d for d in egress if d),
    )


__all__ = ["compute_run_signals"]
