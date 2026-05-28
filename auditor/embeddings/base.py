"""Embedder abstraction.

Memory similarity (ASI06, incident correlation) needs embeddings. Anthropic has no embeddings API
and the system is local-only (PRD §0: the only external call is the Anthropic judge), so the default
embedder runs **locally**. Backends are pluggable behind this ABC; ``dim`` must equal
``Settings.embedding_dim`` (the value the Alembic migration uses for the ``vector(N)`` column).
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Embedder(ABC):
    """Turns text into fixed-dimension vectors."""

    @property
    @abstractmethod
    def dim(self) -> int:
        """Embedding dimensionality. Must match the configured ``EMBEDDING_DIM``."""

    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts, returning one vector per input."""
