"""Involuntary telemetry observer ABC (PRD §9.2).

The involuntary channel observes the harness independently of what it chooses to report. Both the
Linux eBPF backend and the Windows Sysmon backend implement this interface and yield events
conforming to the ``Syscall*`` schemas (``channel = INVOLUNTARY``). Everything downstream (the
channel-divergence detector, the pipeline) is agnostic to which backend produced an event.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from uuid import UUID

from auditor.events.schemas import BaseEvent


class InvoluntaryObserver(ABC):
    @abstractmethod
    async def start(self, harness_pid: int, run_id: UUID) -> None:
        """Begin observing the given harness process (and descendants) for a run."""

    @abstractmethod
    async def stop(self, run_id: UUID) -> None:
        """Stop observing and release resources for a run."""

    @abstractmethod
    def events(self) -> AsyncIterator[BaseEvent]:
        """Yield normalized involuntary events as they are observed."""


__all__ = ["InvoluntaryObserver"]
