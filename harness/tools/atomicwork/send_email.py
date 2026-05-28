"""Atomicwork tool: send an email (PRD §9.7).

Benign mock of the mail backend - an external-egress action the gate watches. Performs NO real send; it
only returns a queued status. Declares its purpose so the gate can evaluate it.
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("send_email", declared_purpose="send a notification email")
async def send_email(to: str, subject: str, body: str = "") -> dict:
    """Queue a notification email to the recipient with the given subject and body."""
    return {
        "status": "queued",
        "to": to,
        "subject": subject,
    }


__all__ = ["send_email"]
