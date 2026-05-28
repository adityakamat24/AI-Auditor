"""Deterministic offline embedder for tests/CI/dev (no model download).

Produces stable, dimension-correct vectors by hashing the input. Not semantically meaningful —
only used where a real embedder would force a heavy download (CI) or where determinism is required.
"""

from __future__ import annotations

import hashlib

from auditor.embeddings.base import Embedder


class HashEmbedder(Embedder):
    def __init__(self, dim: int = 384) -> None:
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def _vector(self, text: str) -> list[float]:
        out: list[float] = []
        counter = 0
        seed = text.encode("utf-8")
        while len(out) < self._dim:
            block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
            for byte in block:
                out.append((byte / 127.5) - 1.0)  # map 0..255 -> ~[-1, 1]
                if len(out) >= self._dim:
                    break
            counter += 1
        return out

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(t) for t in texts]
