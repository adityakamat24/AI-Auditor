"""Inline-gate decision combiner (PRD §9.4.5).

Runs the deterministic sub-checks (OPA policy, Redis tool-budget, Presidio PII on outbound content) and
combines them with DENY > CONFIRM > ALLOW. PII scanning is conditional (only on outbound-content tools)
to keep the hot path fast. OPA errors fail **closed** (DENY) - we won't allow an action we can't evaluate.
Divergence (the involuntary-channel check) joins this combiner in Phase 3.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from auditor.logging import get_logger

log = get_logger("auditor.gate.decide")

_SEVERITY = {"ALLOW": 0, "CONFIRM": 1, "DENY": 2}
_OUTBOUND_TOOLS = {"send_email", "http_post"}


@dataclass
class GateOutcome:
    decision: str
    reasons: list[str]
    votes: dict
    latency_ms: int


def opa_input(event: dict) -> dict:
    """Normalize an event into the flat input the Rego policy expects.

    Null fields are omitted so Rego's ``not input.x`` correctly treats a missing value as absent
    (a present ``null`` would read as defined and silently skip the deny rule).
    """
    args = event.get("tool_args") or {}
    raw = {
        "event_type": event.get("event_type"),
        "tool_name": event.get("tool_name"),
        "tool_args": args,
        "declared_purpose": event.get("declared_purpose"),
        "path": event.get("path") or args.get("path"),
        "dest": event.get("dest") or args.get("url") or args.get("host"),
    }
    return {k: v for k, v in raw.items() if v is not None}


async def decide(event: dict, *, run_id: str, opa, pii, budget) -> GateOutcome:
    start = time.perf_counter()
    votes: dict = {}
    sub: list[tuple[str, list[str]]] = []

    # 1) OPA policy - fail closed on error.
    try:
        opa_out = await opa.evaluate(opa_input(event))
    except Exception as exc:  # noqa: BLE001 - any policy-engine failure denies
        opa_out = {"decision": "DENY", "reasons": [f"policy engine unavailable: {exc}"]}
        log.warning("gate.opa_error", error=str(exc))
    votes["opa"] = opa_out
    sub.append((opa_out["decision"], opa_out["reasons"]))

    event_type = event.get("event_type")
    tool_name = event.get("tool_name")

    # 2) Tool budget - only for tool calls.
    if event_type == "tool_call.start" and tool_name:
        budget_out = await budget.check(run_id, tool_name)
        votes["budget"] = budget_out
        sub.append((budget_out["decision"], budget_out["reasons"]))

    # 3) PII / secrets - only for outbound-content tools (keeps the hot path fast otherwise).
    if event_type == "tool_call.start" and tool_name in _OUTBOUND_TOOLS:
        args = event.get("tool_args") or {}
        text = " ".join(str(v) for v in args.values())
        pii_out = await pii.evaluate_outbound(text)
        votes["pii"] = pii_out
        sub.append((pii_out["decision"], pii_out["reasons"]))

    final = max((d for d, _ in sub), key=lambda d: _SEVERITY[d], default="ALLOW")
    reasons = [r for _, rs in sub for r in rs]
    latency_ms = int((time.perf_counter() - start) * 1000)
    return GateOutcome(decision=final, reasons=reasons, votes=votes, latency_ms=latency_ms)


__all__ = ["GateOutcome", "decide", "opa_input"]
