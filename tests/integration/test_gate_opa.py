"""OpaClient loads the default policy into the live OPA server and evaluates gate decisions."""

from __future__ import annotations

from pathlib import Path

import pytest
from auditor.config import get_settings
from auditor.inline_gate.policy_engine import OpaClient

pytestmark = pytest.mark.integration

_DEFAULT_REGO = (
    Path(__file__).resolve().parents[2] / "opa" / "policies" / "default.rego"
).read_text(encoding="utf-8")


async def test_opa_load_and_decisions() -> None:
    settings = get_settings()
    opa = OpaClient(settings.opa_url)
    await opa.load_policy(_DEFAULT_REGO)
    try:
        deny_exec = await opa.evaluate(
            {"event_type": "tool_call.start", "tool_name": "exec_shell", "tool_args": {}}
        )
        assert deny_exec["decision"] == "DENY"

        deny_path = await opa.evaluate(
            {"event_type": "syscall.openat", "path": "/home/u/.ssh/id_rsa"}
        )
        assert deny_path["decision"] == "DENY"

        confirm_email = await opa.evaluate(
            {
                "event_type": "tool_call.start",
                "tool_name": "send_email",
                "tool_args": {"body": "this is confidential"},
            }
        )
        assert confirm_email["decision"] == "CONFIRM"

        allow_safe = await opa.evaluate(
            {"event_type": "tool_call.start", "tool_name": "kb_search", "tool_args": {"q": "hello"}}
        )
        assert allow_safe["decision"] == "ALLOW"
    finally:
        await opa.aclose()
