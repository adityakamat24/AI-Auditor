"""IPC transport abstraction (PRD §9.3, with the documented Windows deviation).

- **POSIX**: Unix domain socket (``asyncio.start_unix_server`` / ``open_unix_connection``).
- **Windows**: loopback TCP on 127.0.0.1 (``asyncio.start_server`` / ``open_connection``).

Why not a named pipe on Windows? Python ``asyncio`` cannot SSL-wrap a Windows named pipe, and the
PRD's hard requirement (§6) is *real mTLS*, not the specific transport. Loopback TCP keeps mTLS real
and the call sites identical. Both methods accept an optional ``ssl_context`` so Phase 2 layers mTLS
without touching callers. # TODO(phase2): pass a real mutual-auth SSLContext here.
"""

from __future__ import annotations

import asyncio
import ssl
import sys
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from auditor.config import Settings, get_settings

ConnectionHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


class Transport(ABC):
    """A bidirectional local IPC transport. The server serves; the client connects."""

    @abstractmethod
    async def serve(
        self,
        handler: ConnectionHandler,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> asyncio.AbstractServer:
        """Start accepting connections, dispatching each to ``handler``."""

    @abstractmethod
    async def connect(
        self,
        *,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a client connection."""

    @abstractmethod
    def describe(self) -> str:
        """Human-readable endpoint, e.g. ``unix:///path`` or ``tcp://127.0.0.1:8787``."""


class UnixSocketTransport(Transport):
    """POSIX Unix-domain-socket transport."""

    def __init__(self, path: str) -> None:
        self.path = path

    async def serve(self, handler, *, ssl_context=None):
        return await asyncio.start_unix_server(handler, path=self.path, ssl=ssl_context)

    async def connect(self, *, ssl_context=None, server_hostname=None):
        return await asyncio.open_unix_connection(
            path=self.path, ssl=ssl_context, server_hostname=server_hostname
        )

    def describe(self) -> str:
        return f"unix://{self.path}"


class LoopbackTcpTransport(Transport):
    """Windows (and generic) loopback-TCP transport, bound to 127.0.0.1."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8787) -> None:
        self.host = host
        self.port = port

    async def serve(self, handler, *, ssl_context=None):
        return await asyncio.start_server(handler, host=self.host, port=self.port, ssl=ssl_context)

    async def connect(self, *, ssl_context=None, server_hostname=None):
        return await asyncio.open_connection(
            host=self.host, port=self.port, ssl=ssl_context, server_hostname=server_hostname
        )

    def describe(self) -> str:
        return f"tcp://{self.host}:{self.port}"


def select_transport(settings: Settings | None = None) -> Transport:
    """Pick the platform-appropriate transport (see module docstring)."""
    settings = settings or get_settings()
    kind = settings.resolved_ipc_transport
    if kind == "unix":
        if sys.platform == "win32":
            raise RuntimeError(
                "unix IPC transport requested but unsupported on Windows asyncio; use tcp"
            )
        return UnixSocketTransport(settings.ipc_unix_path)
    return LoopbackTcpTransport(settings.ipc_tcp_host, settings.ipc_tcp_port)
