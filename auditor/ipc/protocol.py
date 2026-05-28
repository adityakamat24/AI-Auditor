"""Length-prefixed framing for the IPC control plane (PRD §9.3).

Each frame = a 4-byte big-endian uint32 length, then that many bytes of a serialized
``auditor.v1.Frame`` protobuf. These helpers are transport-agnostic (Unix socket on POSIX,
loopback TCP on Windows).
"""

from __future__ import annotations

import asyncio
import struct

_LEN = struct.Struct(">I")  # 4-byte big-endian unsigned length prefix
MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB safety cap to bound memory on a hostile peer


class FrameError(Exception):
    """Raised on malformed or oversized frames."""


def encode_frame(payload: bytes) -> bytes:
    """Prefix ``payload`` with its big-endian length."""
    if len(payload) > MAX_FRAME_BYTES:
        raise FrameError(f"frame too large to send: {len(payload)} > {MAX_FRAME_BYTES}")
    return _LEN.pack(len(payload)) + payload


def decode_frame(buf: bytes) -> tuple[bytes | None, bytes]:
    """Pure-bytes decode helper (used by tests and buffered readers).

    Returns ``(payload, remainder)``. If a full frame is not yet present, returns ``(None, buf)``.
    """
    if len(buf) < _LEN.size:
        return None, buf
    (length,) = _LEN.unpack(buf[: _LEN.size])
    if length > MAX_FRAME_BYTES:
        raise FrameError(f"frame too large: {length} > {MAX_FRAME_BYTES}")
    end = _LEN.size + length
    if len(buf) < end:
        return None, buf
    return buf[_LEN.size : end], buf[end:]


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read exactly one frame from an asyncio stream. Raises on EOF mid-frame."""
    header = await reader.readexactly(_LEN.size)
    (length,) = _LEN.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise FrameError(f"frame too large: {length} > {MAX_FRAME_BYTES}")
    return await reader.readexactly(length)


async def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Write one length-prefixed frame and flush."""
    writer.write(encode_frame(payload))
    await writer.drain()
