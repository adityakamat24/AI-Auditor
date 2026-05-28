"""Embeddings: pluggable backends with a local default (fastembed) and an offline stub."""

from __future__ import annotations

from auditor.config import Settings, get_settings
from auditor.embeddings.base import Embedder


def get_embedder(settings: Settings | None = None) -> Embedder:
    """Return the configured embedder. Default is the local fastembed backend."""
    settings = settings or get_settings()
    backend = settings.embedding_backend
    if backend == "stub":
        from auditor.embeddings.stub import HashEmbedder

        return HashEmbedder(settings.embedding_dim)
    if backend == "voyage":
        from auditor.embeddings.voyage import VoyageEmbedder

        return VoyageEmbedder(settings.embedding_model, settings.embedding_dim)
    from auditor.embeddings.local_fastembed import LocalFastEmbedEmbedder

    return LocalFastEmbedEmbedder(settings.embedding_model, settings.embedding_dim)


__all__ = ["Embedder", "get_embedder"]
