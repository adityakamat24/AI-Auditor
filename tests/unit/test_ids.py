"""UUIDv7 helper: correct version/variant and time-ordering."""

from __future__ import annotations

import time

from auditor.ids import uuid7


def test_uuid7_version_and_variant() -> None:
    u = uuid7()
    assert u.version == 7
    assert (u.bytes[8] & 0xC0) == 0x80  # RFC 4122 variant


def test_uuid7_is_time_ordered() -> None:
    a = uuid7()
    time.sleep(0.005)
    b = uuid7()
    assert a < b  # later timestamp -> larger 128-bit value
