"""IPC layer: transport abstraction + length-prefixed framing. mTLS + server land in Phase 2."""

from auditor.ipc.protocol import (
    FrameError,
    decode_frame,
    encode_frame,
    read_frame,
    write_frame,
)
from auditor.ipc.server import IpcServer
from auditor.ipc.transport import (
    LoopbackTcpTransport,
    Transport,
    UnixSocketTransport,
    select_transport,
)

__all__ = [
    "FrameError",
    "decode_frame",
    "encode_frame",
    "read_frame",
    "write_frame",
    "Transport",
    "UnixSocketTransport",
    "LoopbackTcpTransport",
    "select_transport",
    "IpcServer",
]
