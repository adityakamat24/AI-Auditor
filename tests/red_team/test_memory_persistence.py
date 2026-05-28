"""Red-team: the cross-run memory-persistence chained scenario (PRD §15 Phase-4 acceptance).

Asserts the acceptance criterion verbatim: the memory-persistence cross-run test produces the correct
influence-chain walk — *the run that poisoned, the run that read, the entry that was poisoned* — and
quarantines the poisoned entry.
"""

from __future__ import annotations

from adversarial.chained.memory_persistence import run


async def test_memory_persistence_influence_chain() -> None:
    result = await run()
    chain = result.chain

    assert chain.detected, "influence chain was not detected across the two runs"
    assert len(chain.links) == 1
    link = chain.links[0]

    # The acceptance triple.
    assert link.writer_run_id == result.poisoned_run_id  # the run that poisoned (session 1)
    assert link.reader_run_id == result.exploit_run_id  # the run that read (session 2)
    assert link.poisoned_entry_id == result.poisoned_entry_id  # the entry that was poisoned

    # Quarantine workflow engaged on the poisoned entry.
    assert result.poisoned_entry_id in chain.quarantined_entry_ids
    assert result.store.get(result.poisoned_entry_id).quarantined

    # Both sessions are implicated.
    assert {result.poisoned_run_id, result.exploit_run_id} <= chain.runs_involved
