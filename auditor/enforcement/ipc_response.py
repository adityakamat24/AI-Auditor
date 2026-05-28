"""Cooperative IPC enforcer (PRD §9.5.1). STUB — implemented in Phase 3.

The first, cooperative enforcement layer: signals the harness over the existing IPC channel to pause,
resume, or abort, relying on the SDK to obey a BLOCK/abort frame. The OS-level enforcers are the backstop
for an SDK that does not comply.
"""

from __future__ import annotations

# TODO(phase3): send pause/resume/abort control frames to the harness over IPC.
from uuid import UUID

from auditor.enforcement.base import Enforcer


class IpcResponseEnforcer(Enforcer):
    """Enforces decisions by signalling the cooperating harness SDK over IPC."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._args = args
        self._kwargs = kwargs

    async def pause(self, run_id: UUID) -> None:
        raise NotImplementedError("IPC enforcement lands in Phase 3")

    async def resume(self, run_id: UUID) -> None:
        raise NotImplementedError("IPC enforcement lands in Phase 3")

    async def abort(self, run_id: UUID) -> None:
        raise NotImplementedError("IPC enforcement lands in Phase 3")


__all__ = ["IpcResponseEnforcer"]
