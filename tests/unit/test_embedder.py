"""Embedder contract: dim matches config; stub is deterministic; dim-mismatch guard fires."""

from __future__ import annotations

import pytest
from auditor.config import Settings
from auditor.embeddings import get_embedder
from auditor.embeddings.local_fastembed import LocalFastEmbedEmbedder
from auditor.embeddings.stub import HashEmbedder


async def test_stub_embedder_dim_matches_config() -> None:
    s = Settings(embedding_backend="stub", embedding_dim=384, _env_file=None)
    emb = get_embedder(s)
    assert emb.dim == s.embedding_dim == 384
    vecs = await emb.embed(["hello", "world"])
    assert len(vecs) == 2
    assert all(len(v) == 384 for v in vecs)


async def test_stub_embedder_is_deterministic() -> None:
    emb = HashEmbedder(16)
    assert emb.dim == 16
    assert await emb.embed(["same input"]) == await emb.embed(["same input"])
    assert await emb.embed(["a"]) != await emb.embed(["b"])


def test_fastembed_rejects_dim_mismatch() -> None:
    # Constructor validates against the model's native dim WITHOUT importing fastembed.
    with pytest.raises(ValueError):
        LocalFastEmbedEmbedder("BAAI/bge-small-en-v1.5", dim=999)
