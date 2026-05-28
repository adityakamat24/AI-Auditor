"""Audit-log hash-chain math: intact chains verify; tampering/insertion/deletion are detected."""

from __future__ import annotations

from dataclasses import dataclass

from auditor.audit_log.chain import (
    GENESIS_HASH,
    compute_chain_hash,
    compute_payload_hash,
    verify_chain,
)
from auditor.db.models import AuditLog as AuditLogRow


@dataclass
class _Entry:
    seq: int
    payload_hash: bytes
    chain_hash: bytes


def _build(payloads: list[dict]) -> list[_Entry]:
    prev = GENESIS_HASH
    entries: list[_Entry] = []
    for i, payload in enumerate(payloads, start=1):
        ph = compute_payload_hash(payload)
        ch = compute_chain_hash(prev, ph)
        entries.append(_Entry(seq=i, payload_hash=ph, chain_hash=ch))
        prev = ch
    return entries


def test_payload_hash_is_canonical() -> None:
    assert compute_payload_hash({"a": 1, "b": 2}) == compute_payload_hash({"b": 2, "a": 1})
    assert compute_payload_hash({"a": 1}) != compute_payload_hash({"a": 2})


def test_intact_chain_verifies() -> None:
    entries = _build([{"action": f"step{i}"} for i in range(5)])
    result = verify_chain(entries)
    assert result.ok and result.count == 5 and result.first_break_seq is None


def test_empty_chain_is_ok() -> None:
    assert verify_chain([]).ok


def test_payload_mutation_is_detected() -> None:
    entries = _build([{"action": f"step{i}"} for i in range(5)])
    entries[2].payload_hash = compute_payload_hash({"action": "tampered"})  # break entry 3
    result = verify_chain(entries)
    assert not result.ok and result.first_break_seq == 3


def test_chain_hash_mutation_is_detected() -> None:
    entries = _build([{"action": f"step{i}"} for i in range(4)])
    entries[1].chain_hash = b"\xff" * 32
    result = verify_chain(entries)
    assert not result.ok and result.first_break_seq == 2


def test_deletion_is_detected() -> None:
    entries = _build([{"action": f"step{i}"} for i in range(5)])
    del entries[2]  # removing a middle entry orphans the next one's prev link
    result = verify_chain(entries)
    assert not result.ok and result.first_break_seq == 4


def test_verifier_works_on_real_row_type() -> None:
    # verify_chain is duck-typed on seq/payload_hash/chain_hash - confirm the ORM row satisfies it.
    prev = GENESIS_HASH
    rows: list[AuditLogRow] = []
    for i, payload in enumerate([{"a": 1}, {"a": 2}], start=1):
        ph = compute_payload_hash(payload)
        ch = compute_chain_hash(prev, ph)
        rows.append(AuditLogRow(seq=i, payload_hash=ph, chain_hash=ch))
        prev = ch
    assert verify_chain(rows).ok
