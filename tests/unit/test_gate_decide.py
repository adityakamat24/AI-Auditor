"""Decision combiner: DENY>CONFIRM>ALLOW, OPA fail-closed, PII only on outbound tools."""

from __future__ import annotations

from auditor.inline_gate.decide import decide


class _Opa:
    def __init__(self, decision: str = "ALLOW", reasons: list[str] | None = None) -> None:
        self.decision, self.reasons = decision, reasons or []

    async def evaluate(self, _inp: dict) -> dict:
        return {"decision": self.decision, "reasons": self.reasons}


class _RaisingOpa:
    async def evaluate(self, _inp: dict) -> dict:
        raise RuntimeError("opa down")


class _Budget:
    def __init__(self, decision: str = "ALLOW", reasons: list[str] | None = None) -> None:
        self.decision, self.reasons = decision, reasons or []

    async def check(self, _run_id: str, _tool: str) -> dict:
        return {"decision": self.decision, "reasons": self.reasons}


class _Pii:
    def __init__(self, decision: str = "ALLOW", reasons: list[str] | None = None) -> None:
        self.decision, self.reasons = decision, reasons or []

    async def evaluate_outbound(self, _text: str, *, allowlisted_dest: bool = False) -> dict:
        return {"decision": self.decision, "reasons": self.reasons, "entities": []}


def _evt(tool: str = "kb_search", **args) -> dict:
    return {"event_type": "tool_call.start", "tool_name": tool, "tool_args": args}


async def test_allow_when_all_allow() -> None:
    out = await decide(_evt(), run_id="r", opa=_Opa(), pii=_Pii(), budget=_Budget())
    assert out.decision == "ALLOW"


async def test_deny_dominates_confirm() -> None:
    out = await decide(_evt(), run_id="r", opa=_Opa("CONFIRM", ["c"]), pii=_Pii(), budget=_Budget("DENY", ["b"]))
    assert out.decision == "DENY"
    assert "b" in out.reasons


async def test_opa_error_fails_closed() -> None:
    out = await decide(_evt(), run_id="r", opa=_RaisingOpa(), pii=_Pii(), budget=_Budget())
    assert out.decision == "DENY"
    assert any("policy engine unavailable" in r for r in out.reasons)


async def test_pii_only_consulted_for_outbound_tools() -> None:
    # kb_search is not outbound -> PII not consulted even though it would DENY.
    out = await decide(_evt("kb_search", body="x"), run_id="r", opa=_Opa(), pii=_Pii("DENY", ["pii"]), budget=_Budget())
    assert out.decision == "ALLOW"
    assert "pii" not in out.votes
    # send_email is outbound -> PII consulted.
    out2 = await decide(_evt("send_email", body="x"), run_id="r", opa=_Opa(), pii=_Pii("DENY", ["pii"]), budget=_Budget())
    assert out2.decision == "DENY"
    assert "pii" in out2.votes


async def test_confirm_when_highest_is_confirm() -> None:
    out = await decide(_evt("send_email", body="confidential"), run_id="r", opa=_Opa("CONFIRM", ["x"]), pii=_Pii(), budget=_Budget())
    assert out.decision == "CONFIRM"
