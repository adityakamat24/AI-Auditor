"""Enforcer ABC (PRD §9.5) — the pause/resume/abort contract every backend implements.

The inline gate (cooperative) and the OS-level backstops (cgroup/seccomp on Linux, Job Object on Windows)
all satisfy this interface so the decision layer is agnostic to *how* a run is halted.
"""

from __future__ import annotations

# TODO(phase3): concrete enforcers (ipc_response, cgroup, seccomp, windows_jobobject) implement this ABC.
from abc import ABC, abstractmethod
from uuid import UUID


class Enforcer(ABC):
    """Contract for halting and resuming a run's harness process."""

    @abstractmethod
    async def pause(self, run_id: UUID) -> None:
        """Suspend execution of the run's harness (freeze, no termination)."""

    @abstractmethod
    async def resume(self, run_id: UUID) -> None:
        """Resume a previously paused run."""

    @abstractmethod
    async def abort(self, run_id: UUID) -> None:
        """Terminate the run's harness and release its resources."""


__all__ = ["Enforcer"]
