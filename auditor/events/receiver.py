"""Voluntary event receiver - ingests SDK frames over IPC (PRD §9). STUB - implemented in Phase 2/3.

The receiver terminates the harness IPC connection, decodes protobuf event frames, validates them into
the pydantic event models, and hands them to the event store + inline gate. Phase 2 wires the voluntary
path; Phase 3 also feeds involuntary events from the platform observer through the same normalization.
"""

from __future__ import annotations

# TODO(phase2): decode protobuf event frames -> auditor.events.schemas, validate, dispatch to store/gate.
from uuid import UUID

from auditor.events.schemas import BaseEvent


class EventReceiver:
    """Receives and normalizes voluntary events from a harness connection."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._args = args
        self._kwargs = kwargs

    async def ingest(self, raw_frame: bytes, run_id: UUID, tenant_id: UUID) -> BaseEvent:
        """Decode and validate one raw event frame into a typed event."""
        raise NotImplementedError("EventReceiver lands in Phase 2")


__all__ = ["EventReceiver"]
