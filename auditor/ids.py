"""Identifier helpers. ``run_id``/``event_id`` are UUIDv7 (time-ordered) per PRD §5.1."""

from __future__ import annotations

import os
import time
from uuid import UUID


def uuid7() -> UUID:
    """Generate a UUIDv7 (48-bit Unix-ms timestamp + random), per RFC 9562.

    Time-ordered so primary keys sort by creation time - good for index locality on the event log.
    """
    unix_ms = int(time.time() * 1000)
    data = bytearray(unix_ms.to_bytes(6, "big") + os.urandom(10))
    data[6] = (data[6] & 0x0F) | 0x70  # version 7
    data[8] = (data[8] & 0x3F) | 0x80  # RFC 4122 variant
    return UUID(bytes=bytes(data))
