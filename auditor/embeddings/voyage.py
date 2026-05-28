"""Optional Voyage AI embedder (external API).

NOT used by default — the system is local-only (PRD §0). This stub exists so the backend is an
additive change. Enable with ``EMBEDDING_BACKEND=voyage`` and a Voyage key once implemented.
"""

from __future__ import annotations

from auditor.embeddings.base import Embedder


class VoyageEmbedder(Embedder):
    def __init__(self, model: str, dim: int, api_key: str | None = None) -> None:
        self._dim = dim
        self._model = model
        self._api_key = api_key

    @property
    def dim(self) -> int:
        return self._dim

    async def embed(self, texts: list[str]) -> list[list[float]]:  # TODO(future): implement Voyage
        raise NotImplementedError(
            "Voyage backend is not implemented in v1 (local-only). Use EMBEDDING_BACKEND=fastembed."
        )
