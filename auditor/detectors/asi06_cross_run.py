"""ASI06 cross-run memory-poisoning machinery (PRD §9.7.6 items 5-8).

Single-run scanning lives in :mod:`auditor.detectors.asi06_memory_poisoning`. This module adds the
cross-session part that makes ASI06 actually defensible against the hardest attacks — where memory is
poisoned in run A and the poison fires in a *later* run B:

- **Provenance graph** (item 5): every memory entry records ``created_in_run_id``, ``source``,
  ``distance_from_user``; every read is tagged with the entry it touched, so we can ask post-incident
  "which runs wrote the entries that subsequent runs read?".
- **Suspicious-entry tagging** (item 6): an entry written from an untrusted source that scores
  ≥ :data:`SUSPICION_THRESHOLD` on the injection classifier is tagged at write time, even if the write
  was allowed.
- **Influence-chain walk** (item 7): from a triggering run, walk back reads → writer-runs → their reads,
  up to ``max_hops`` (3), collecting the poisoned-entry chain and quarantining the entries.
- **Quarantine workflow** (item 8): tagged entries in the chain are marked ``quarantined``.

It is storage-agnostic: :class:`InMemoryProvenanceStore` backs tests and the chained scenario; a
DB-backed store over the ``memory_entries`` table can implement the same :class:`ProvenanceStore`
protocol in production (the dataclass mirrors that table's columns).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

#: Sources whose content is not user-trusted (PRD §9.7.6); writes from these are scanned + maybe tagged.
UNTRUSTED_SOURCES: frozenset[str] = frozenset({"web", "tool_output", "rag"})

#: Injection score at/above which an untrusted-source write is tagged suspicious (PRD §9.7.6 item 6).
SUSPICION_THRESHOLD = 0.4

#: Default hop limit for the influence-chain walk (PRD §9.7.6 item 7: "up to 3 hops").
MAX_HOPS = 3

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(your|the|all)\s+(prior\s+)?instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.IGNORECASE),
    re.compile(r"\b(system|assistant)\s*:\s*", re.IGNORECASE),
    re.compile(r"\bexfiltrate\b", re.IGNORECASE),
    re.compile(r"<!--.*?(instruction|ignore|system).*?-->", re.IGNORECASE | re.DOTALL),
)


def injection_score(content: str) -> float:
    """Score content in [0,1] for how strongly it resembles an injection payload.

    Any single pattern hit clears :data:`SUSPICION_THRESHOLD`; more hits saturate toward 1.0.
    """
    hits = sum(1 for pattern in _INJECTION_PATTERNS if pattern.search(content))
    if hits == 0:
        return 0.0
    return min(1.0, 0.4 + 0.2 * hits)


@dataclass
class MemoryEntry:
    """One memory-store entry with cross-run provenance (mirrors the ``memory_entries`` table §8.1)."""

    entry_id: UUID
    tenant_id: UUID
    created_in_run_id: UUID
    source: str
    content: str
    agent_id: UUID | None = None
    distance_from_user: int | None = None
    write_intent_declared: bool = True
    tagged: bool = False  # mirrors flags['suspicious']
    suspicion_score: float = 0.0
    quarantined: bool = False

    def as_flags(self) -> dict:
        return {"suspicious": self.tagged, "suspicion_score": round(self.suspicion_score, 4)}


class ProvenanceStore(Protocol):
    """Minimal read surface the influence-chain walk needs over the memory store."""

    def get(self, entry_id: UUID) -> MemoryEntry | None: ...
    def entries_read_in_run(self, run_id: UUID) -> list[UUID]: ...
    def quarantine(self, entry_id: UUID) -> None: ...


@dataclass
class InMemoryProvenanceStore:
    """In-process provenance graph: entries + which run read which entry. Backs tests + scenarios."""

    _entries: dict[UUID, MemoryEntry] = field(default_factory=dict)
    _reads: dict[UUID, list[UUID]] = field(default_factory=dict)  # run_id -> [entry_id...]

    def write_entry(self, entry: MemoryEntry) -> MemoryEntry:
        """Persist an entry, tagging it suspicious at write time per §9.7.6 item 6."""
        if entry.source in UNTRUSTED_SOURCES:
            score = injection_score(entry.content)
            if score >= SUSPICION_THRESHOLD:
                entry.tagged = True
                entry.suspicion_score = score
        self._entries[entry.entry_id] = entry
        return entry

    def record_read(self, run_id: UUID, entry_id: UUID) -> None:
        reads = self._reads.setdefault(run_id, [])
        if entry_id not in reads:
            reads.append(entry_id)

    def get(self, entry_id: UUID) -> MemoryEntry | None:
        return self._entries.get(entry_id)

    def entries_read_in_run(self, run_id: UUID) -> list[UUID]:
        return list(self._reads.get(run_id, []))

    def quarantine(self, entry_id: UUID) -> None:
        entry = self._entries.get(entry_id)
        if entry is not None:
            entry.quarantined = True


@dataclass
class InfluenceLink:
    """One hop in an influence chain: a poisoned entry written by one run and read by another."""

    poisoned_entry_id: UUID
    writer_run_id: UUID
    reader_run_id: UUID
    source: str
    suspicion_score: float
    hop: int


@dataclass
class InfluenceChain:
    """The poisoned-entry chain discovered by walking back from a triggering run."""

    trigger_run_id: UUID
    links: list[InfluenceLink] = field(default_factory=list)
    quarantined_entry_ids: list[UUID] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.links)

    @property
    def poisoned_entry_ids(self) -> list[UUID]:
        return [link.poisoned_entry_id for link in self.links]

    @property
    def runs_involved(self) -> set[UUID]:
        runs: set[UUID] = set()
        for link in self.links:
            runs.add(link.writer_run_id)
            runs.add(link.reader_run_id)
        return runs


def walk_influence_chain(
    store: ProvenanceStore,
    trigger_run_id: UUID,
    *,
    max_hops: int = MAX_HOPS,
    quarantine: bool = True,
) -> InfluenceChain:
    """Walk back from ``trigger_run_id`` through poisoned entries it read to the runs that wrote them.

    Breadth-first over runs: at each run, every *tagged* entry it read becomes a link (writer→reader),
    and we then inspect the writer run's own reads at the next hop (a poisoner may itself be poisoned),
    up to ``max_hops``. Tagged entries in the chain are quarantined (§9.7.6 item 8) unless disabled.
    """
    chain = InfluenceChain(trigger_run_id=trigger_run_id)
    seen_entries: set[UUID] = set()
    visited_runs: set[UUID] = set()
    frontier: list[tuple[UUID, int]] = [(trigger_run_id, 1)]

    while frontier:
        reader_run, hop = frontier.pop(0)
        if hop > max_hops or reader_run in visited_runs:
            continue
        visited_runs.add(reader_run)
        for entry_id in store.entries_read_in_run(reader_run):
            entry = store.get(entry_id)
            if entry is None or not entry.tagged or entry_id in seen_entries:
                continue
            seen_entries.add(entry_id)
            chain.links.append(
                InfluenceLink(
                    poisoned_entry_id=entry_id,
                    writer_run_id=entry.created_in_run_id,
                    reader_run_id=reader_run,
                    source=entry.source,
                    suspicion_score=entry.suspicion_score,
                    hop=hop,
                )
            )
            if quarantine:
                store.quarantine(entry_id)
                chain.quarantined_entry_ids.append(entry_id)
            # The writer run may itself have read poison — inspect it at the next hop.
            frontier.append((entry.created_in_run_id, hop + 1))

    return chain


__all__ = [
    "UNTRUSTED_SOURCES",
    "SUSPICION_THRESHOLD",
    "MAX_HOPS",
    "injection_score",
    "MemoryEntry",
    "ProvenanceStore",
    "InMemoryProvenanceStore",
    "InfluenceLink",
    "InfluenceChain",
    "walk_influence_chain",
]
