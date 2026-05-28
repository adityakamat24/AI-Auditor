"""Local ONNX embedder via fastembed (default backend).

fastembed is imported lazily and the model is fetched on first use (at bootstrap, not at import),
so importing this module never triggers a download and unit tests stay offline. fastembed is
synchronous/CPU-bound, so :meth:`embed` offloads to a worker thread.
"""

from __future__ import annotations

import asyncio
from typing import Any

from auditor.embeddings.base import Embedder

# Native vector size for known models, used to validate the configured EMBEDDING_DIM.
_KNOWN_DIMS: dict[str, int] = {
    "BAAI/bge-small-en-v1.5": 384,
    "BAAI/bge-base-en-v1.5": 768,
    "sentence-transformers/all-MiniLM-L6-v2": 384,
}


class LocalFastEmbedEmbedder(Embedder):
    def __init__(self, model: str = "BAAI/bge-small-en-v1.5", dim: int = 384) -> None:
        self._model_name = model
        expected = _KNOWN_DIMS.get(model)
        if expected is not None and expected != dim:
            raise ValueError(
                f"EMBEDDING_DIM={dim} does not match model {model!r} native dim {expected}"
            )
        self._dim = dim
        self._model: Any | None = None

    @property
    def dim(self) -> int:
        return self._dim

    def _ensure_model(self) -> Any:
        if self._model is None:
            from fastembed import TextEmbedding  # lazy: avoids import-time/download cost

            self._model = TextEmbedding(model_name=self._model_name)
        return self._model

    async def embed(self, texts: list[str]) -> list[list[float]]:
        model = self._ensure_model()

        def _run() -> list[list[float]]:
            return [[float(x) for x in vec] for vec in model.embed(texts)]

        return await asyncio.to_thread(_run)
