"""IPC control-plane server (PRD §9.3).

Accepts connections over the platform transport (mTLS when an ``SSLContext`` is supplied), reads
length-prefixed frames, and either:
- hands a parsed ``Frame`` + verified ``PeerIdentity`` to a :class:`GateDispatcher` (Phase 2+), writing
  back any response frame it returns; or
- hands raw frame bytes to an ``on_frame`` callback (used by the Phase-1 framing tests).
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import Awaitable, Callable
from typing import Protocol

from auditor.ipc.auth import PeerIdentity, parse_peer_identity
from auditor.ipc.protocol import read_frame, write_frame
from auditor.logging import get_logger
from auditor.proto_gen.decisions_pb2 import Frame

log = get_logger("auditor.ipc.server")

FrameHandler = Callable[[bytes], None]


class Dispatcher(Protocol):
    async def on_connect(self, identity: PeerIdentity | None) -> None: ...
    async def on_frame(self, frame: Frame, identity: PeerIdentity | None) -> Frame | None: ...


class IpcServer:
    def __init__(
        self,
        transport,
        *,
        ssl_context: ssl.SSLContext | None = None,
        dispatcher: Dispatcher | None = None,
        on_frame: FrameHandler | None = None,
    ) -> None:
        self._transport = transport
        self._ssl = ssl_context
        self._dispatcher = dispatcher
        self._on_frame = on_frame
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> asyncio.AbstractServer:
        self._server = await self._transport.serve(self._handle, ssl_context=self._ssl)
        return self._server

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        identity = parse_peer_identity(writer.get_extra_info("ssl_object")) if self._ssl else None
        try:
            if self._dispatcher is not None:
                await self._dispatcher.on_connect(identity)
            while True:
                raw = await read_frame(reader)
                if self._dispatcher is not None:
                    frame = Frame()
                    frame.ParseFromString(raw)
                    response = await self._dispatcher.on_frame(frame, identity)
                    if response is not None:
                        await write_frame(writer, response.SerializeToString())
                elif self._on_frame is not None:
                    self._on_frame(raw)
                else:
                    log.info("ipc.frame_received", nbytes=len(raw))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass  # peer closed
        except Exception as exc:  # noqa: BLE001 - isolate one bad connection from the server
            log.warning("ipc.handler_error", error=str(exc))
        finally:
            # Run ended (peer closed): let the dispatcher trigger the post-run audit, off the hot path.
            if self._dispatcher is not None and hasattr(self._dispatcher, "on_disconnect"):
                with contextlib.suppress(Exception):
                    await self._dispatcher.on_disconnect(identity)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            # Bound the wait: on some platforms Server.wait_closed() can stall if a connection
            # is mid-teardown. A shutdown must never hang.
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            self._server = None


# Re-exported for callers that build dispatchers.
GateConnectionHandler = Callable[[PeerIdentity | None], Awaitable[None]]
