"""Audit-log hash-chain primitives (PRD §9.11.1).

Pure, dependency-free chain math so it is unit-testable without a database:

- ``payload_hash = sha256(canonical_json(payload))``
- ``chain_hash = sha256(prev_chain_hash || payload_hash)``; the genesis entry's ``prev_chain_hash`` is
  32 zero bytes.

:func:`verify_chain` recomputes the chain forward from genesis and reports the first entry whose stored
``chain_hash`` doesn't match — catching any insertion, deletion, reorder, or hash mutation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

GENESIS_HASH = b"\x00" * 32


def compute_payload_hash(payload: dict) -> bytes:
    """sha256 over a canonical (sorted-key) JSON encoding of the entry payload."""
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def compute_chain_hash(prev_chain_hash: bytes, payload_hash: bytes) -> bytes:
    """sha256(prev_chain_hash || payload_hash) — links this entry to the previous one."""
    return hashlib.sha256(prev_chain_hash + payload_hash).digest()


class _ChainEntry(Protocol):
    seq: int
    payload_hash: bytes
    chain_hash: bytes


@dataclass
class ChainVerification:
    """Result of walking an audit-log chain."""

    ok: bool
    count: int
    first_break_seq: int | None = None
    reason: str | None = None


def verify_chain(entries: list[_ChainEntry]) -> ChainVerification:
    """Recompute the chain from genesis; report the first entry whose chain_hash doesn't match.

    ``entries`` must be ordered by ``seq`` ascending.
    """
    prev = GENESIS_HASH
    for entry in entries:
        expected = compute_chain_hash(prev, entry.payload_hash)
        if expected != entry.chain_hash:
            return ChainVerification(
                ok=False,
                count=len(entries),
                first_break_seq=entry.seq,
                reason=(
                    f"chain_hash mismatch at seq={entry.seq}: "
                    f"expected {expected.hex()[:16]}.. got {entry.chain_hash.hex()[:16]}.."
                ),
            )
        prev = entry.chain_hash
    return ChainVerification(ok=True, count=len(entries))


__all__ = [
    "GENESIS_HASH",
    "compute_payload_hash",
    "compute_chain_hash",
    "ChainVerification",
    "verify_chain",
]
