"""Red-team: ASI05 exec_shell without a declared purpose must be denied by the OPA policy."""

from __future__ import annotations

import pytest
from adversarial.gate_harness import gate_session
from adversarial.per_category.asi05_code_execution.agent import run_attack

pytestmark = pytest.mark.integration


async def test_asi05_exec_shell_is_denied() -> None:
    async with gate_session() as (telemetry, _run_id, agent_id):
        result = await run_attack(telemetry, agent_id)
    assert result["denied"], "exec_shell was not denied"
    assert any("declared_purpose" in reason for reason in result["reasons"])
