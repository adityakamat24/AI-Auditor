"""Platform selection of the IPC transport (Windows -> loopback TCP; POSIX -> Unix socket)."""

from __future__ import annotations

import sys

import pytest
from auditor.config import Settings
from auditor.ipc.transport import (
    LoopbackTcpTransport,
    UnixSocketTransport,
    select_transport,
)


def test_select_matches_platform() -> None:
    t = select_transport(Settings(_env_file=None))
    if sys.platform == "win32":
        assert isinstance(t, LoopbackTcpTransport)
    else:
        assert isinstance(t, UnixSocketTransport)


def test_explicit_tcp_override() -> None:
    t = select_transport(Settings(ipc_transport="tcp", ipc_tcp_port=9999, _env_file=None))
    assert isinstance(t, LoopbackTcpTransport)
    assert t.port == 9999
    assert t.describe() == "tcp://127.0.0.1:9999"


@pytest.mark.skipif(sys.platform == "win32", reason="unix sockets unavailable on Windows asyncio")
def test_explicit_unix_override() -> None:
    t = select_transport(Settings(ipc_transport="unix", ipc_unix_path="/tmp/x.sock", _env_file=None))
    assert isinstance(t, UnixSocketTransport)
    assert t.describe() == "unix:///tmp/x.sock"


@pytest.mark.skipif(sys.platform != "win32", reason="guard is Windows-specific")
def test_unix_on_windows_raises() -> None:
    with pytest.raises(RuntimeError):
        select_transport(Settings(ipc_transport="unix", _env_file=None))
