"""Intra-agent message bus (PRD §9) - signed inter-agent comms (ASI07). STUB - Phase 2/4.

The channel agents use to message each other. Every message is signed (and verified on receipt) so the
auditor can detect forged/injected inter-agent traffic (ASI07); each send emits an ``agent.message`` event.
Signing uses ``cryptography`` (a base dep), imported lazily inside the methods.
"""

from __future__ import annotations

# TODO(phase2): sign/verify inter-agent messages (cryptography); emit agent.message telemetry per send (ASI07).
from uuid import UUID


class IntraAgentBus:
    """Signed message bus connecting agents within a run."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._args = args
        self._kwargs = kwargs

    async def send(self, sender_id: UUID, receiver_id: UUID, message: bytes) -> None:
        """Sign and deliver a message from one agent to another."""
        raise NotImplementedError("Intra-agent bus lands in Phase 2")

    async def verify(self, sender_id: UUID, message: bytes, signature: bytes) -> bool:
        """Verify a received message's signature."""
        raise NotImplementedError("Intra-agent bus lands in Phase 2")


__all__ = ["IntraAgentBus"]
