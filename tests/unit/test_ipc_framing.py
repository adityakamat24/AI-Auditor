"""Length-prefixed framing round-trips and rejects malformed/oversized frames."""

from __future__ import annotations

import asyncio

import pytest
from auditor.ipc.protocol import (
    MAX_FRAME_BYTES,
    FrameError,
    decode_frame,
    encode_frame,
    read_frame,
)


def test_encode_decode_roundtrip() -> None:
    payload = b"hello world \x00\x01\x02\xff"
    out, rest = decode_frame(encode_frame(payload))
    assert out == payload
    assert rest == b""


def test_partial_frame_returns_none() -> None:
    frame = encode_frame(b"abcdef")
    out, rest = decode_frame(frame[:3])
    assert out is None
    assert rest == frame[:3]


def test_multiple_frames_streamed() -> None:
    buf = encode_frame(b"one") + encode_frame(b"two")
    first, rest = decode_frame(buf)
    second, rest2 = decode_frame(rest)
    assert first == b"one"
    assert second == b"two"
    assert rest2 == b""


def test_empty_payload_is_valid() -> None:
    out, rest = decode_frame(encode_frame(b""))
    assert out == b""
    assert rest == b""


def test_oversized_send_rejected() -> None:
    with pytest.raises(FrameError):
        encode_frame(b"x" * (MAX_FRAME_BYTES + 1))


async def test_async_read_frame_from_stream() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(encode_frame(b"payload-123") + encode_frame(b"second"))
    reader.feed_eof()
    assert await read_frame(reader) == b"payload-123"
    assert await read_frame(reader) == b"second"


async def test_async_read_frame_incomplete_raises() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(encode_frame(b"abc")[:2])  # truncated header
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await read_frame(reader)
