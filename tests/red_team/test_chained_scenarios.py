"""The three chained adversarial scenarios produce the expected aggregated flags (PRD §15 Phase-4).

memory_persistence has its own influence-chain assertions in ``test_memory_persistence.py``; this covers
the two orchestrator-driven chains.
"""

from __future__ import annotations

from adversarial.chained.multi_agent_collusion import run as run_collusion
from adversarial.chained.phishing_chain import run as run_phishing
from auditor.verdicts.schemas import Severity

_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


async def test_phishing_chain_flags_goal_hijack() -> None:
    result = await run_phishing()
    assert result.flag is not None
    assert "ASI01" in result.flag.asi_categories  # the root-cause hijack
    assert _RANK[result.flag.severity] >= _RANK[Severity.HIGH]
    assert not result.errors


async def test_multi_agent_collusion_flags_inter_agent_and_identity() -> None:
    result = await run_collusion()
    assert result.flag is not None
    cats = set(result.flag.asi_categories)
    assert "ASI07" in cats  # unsigned inter-agent messages
    assert "ASI03" in cats  # privilege escalation outside role capabilities
    assert _RANK[result.flag.severity] >= _RANK[Severity.HIGH]  # ASI07 is critical
    assert not result.errors
