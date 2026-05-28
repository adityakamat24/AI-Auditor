"""Session memory (PRD §9) - short-lived per-run KV store. STUB - implemented in Phase 4.

Per-run working memory backed by Redis (TTL-scoped). Reads/writes emit voluntary ``memory.read`` /
``memory.write`` events tagged ``store="session"``. ``redis`` is a base dep, imported lazily in the methods.
"""

from __future__ import annotations

# TODO(phase4): Redis-backed per-run KV with TTL; emit memory.* telemetry on read/write.
from uuid import UUID


class SessionMemory:
    """Short-lived per-run memory backed by Redis."""

    def __init__(self, run_id: UUID, *args: object, **kwargs: object) -> None:
        self.run_id = run_id
        self._args = args
        self._kwargs = kwargs

    async def get(self, key: str) -> object | None:
        """Read a value from session memory."""
        raise NotImplementedError("Session memory lands in Phase 4")

    async def set(self, key: str, value: object) -> None:
        """Write a value to session memory."""
        raise NotImplementedError("Session memory lands in Phase 4")


__all__ = ["SessionMemory"]
