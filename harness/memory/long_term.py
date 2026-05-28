"""Long-term memory (PRD §9) — semantic store over pgvector. STUB — implemented in Phase 4.

Durable semantic memory: text is embedded (via :mod:`auditor.embeddings`) and stored/queried in the
``memory_embeddings`` pgvector table. Writes record provenance and emit ``memory.write`` events; reads emit
``memory.read`` — the core signal for ASI06 (memory poisoning).
"""

from __future__ import annotations

# TODO(phase4): embed + upsert/query memory in the pgvector table; record provenance; emit memory.* telemetry.
from uuid import UUID


class LongTermMemory:
    """Durable semantic memory backed by pgvector."""

    def __init__(self, tenant_id: UUID, *args: object, **kwargs: object) -> None:
        self.tenant_id = tenant_id
        self._args = args
        self._kwargs = kwargs

    async def write(self, content: str, source: str | None = None) -> None:
        """Embed and store ``content`` with its provenance."""
        raise NotImplementedError("Long-term memory lands in Phase 4")

    async def query(self, query: str, k: int = 5) -> list[object]:
        """Return the ``k`` most similar stored memories for ``query``."""
        raise NotImplementedError("Long-term memory lands in Phase 4")


__all__ = ["LongTermMemory"]
