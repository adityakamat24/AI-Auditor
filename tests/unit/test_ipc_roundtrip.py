"""End-to-end IPC over loopback (no external services): server <- client frames, harness heartbeat."""

from __future__ import annotations

import asyncio
import socket

from auditor.config import Settings
from auditor.ids import uuid7
from auditor.ipc import IpcServer, select_transport
from auditor.ipc.protocol import write_frame
from auditor.proto_gen.decisions_pb2 import Frame
from harness.telemetry import Telemetry


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _tcp_settings(port: int) -> Settings:
    return Settings(ipc_transport="tcp", ipc_tcp_host="127.0.0.1", ipc_tcp_port=port, _env_file=None)


async def _wait_for(predicate, tries: int = 100) -> None:
    for _ in range(tries):
        if predicate():
            return
        await asyncio.sleep(0.01)


async def test_server_receives_client_frames() -> None:
    settings = _tcp_settings(_free_port())
    received: list[bytes] = []
    server = IpcServer(select_transport(settings), on_frame=received.append)
    await server.start()
    try:
        _reader, writer = await select_transport(settings).connect()
        await write_frame(writer, b"hello-ipc")
        await write_frame(writer, b"second")
        await _wait_for(lambda: len(received) >= 2)
        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()
    assert received == [b"hello-ipc", b"second"]


async def test_harness_heartbeat_reaches_server() -> None:
    settings = _tcp_settings(_free_port())
    received: list[bytes] = []
    server = IpcServer(select_transport(settings), on_frame=received.append)
    await server.start()
    try:
        telemetry = await Telemetry.connect(uuid7(), uuid7(), settings)
        await telemetry.send_heartbeat()
        await _wait_for(lambda: len(received) >= 1)
        await telemetry.close()
    finally:
        await server.stop()
    assert received, "server received no frame from harness"
    frame = Frame()
    frame.ParseFromString(received[0])
    assert frame.WhichOneof("kind") == "hb"
    assert frame.hb.role == "harness"
