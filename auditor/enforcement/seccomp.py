"""Linux seccomp syscall-deny enforcer (PRD §9.5.2). STUB — implemented in Phase 3 (Linux).

OS-level backstop on Linux: installs/updates a seccomp-bpf filter for the harness so denied syscalls
(e.g. ``connect``, ``execve``) are blocked at the kernel boundary regardless of SDK cooperation. The
filter is applied to the harness at launch; this enforcer toggles deny rules per run.
"""

from __future__ import annotations

# TODO(phase3): apply/adjust the harness seccomp-bpf filter to deny target syscalls per run.
from uuid import UUID

from auditor.enforcement.base import Enforcer


class SeccompEnforcer(Enforcer):
    """Blocks syscalls for a run via a seccomp-bpf filter (Linux only)."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._args = args
        self._kwargs = kwargs

    async def pause(self, run_id: UUID) -> None:
        raise NotImplementedError("seccomp enforcement lands in Phase 3 (Linux)")

    async def resume(self, run_id: UUID) -> None:
        raise NotImplementedError("seccomp enforcement lands in Phase 3 (Linux)")

    async def abort(self, run_id: UUID) -> None:
        raise NotImplementedError("seccomp enforcement lands in Phase 3 (Linux)")


__all__ = ["SeccompEnforcer"]
