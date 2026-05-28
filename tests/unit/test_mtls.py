"""mTLS over loopback: minted cert SANs, a real handshake + peer-identity extraction, reject untrusted."""

from __future__ import annotations

import asyncio
import socket
import ssl

from auditor.auth.ca import encode_san, init_ca, mint_leaf, mint_leaf_to_files
from auditor.ipc.auth import build_client_context, build_server_context, parse_peer_identity
from cryptography import x509

RUN_ID = "019e0000-0000-7000-8000-000000000abc"
TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_minted_cert_has_uri_and_dns_san(tmp_path) -> None:
    init_ca(str(tmp_path))
    bundle = mint_leaf(str(tmp_path), role="harness", run_id=RUN_ID, tenant_id=TENANT_ID, hostname="harness.local")
    cert = x509.load_pem_x509_certificate(bundle.cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert encode_san("harness", RUN_ID, TENANT_ID) in san.get_values_for_type(x509.UniformResourceIdentifier)
    assert "harness.local" in san.get_values_for_type(x509.DNSName)


async def test_mtls_handshake_extracts_peer_identity(tmp_path) -> None:
    data_dir = str(tmp_path)
    init_ca(data_dir)
    s_cert, s_key, ca = mint_leaf_to_files(
        data_dir, role="auditor", run_id="server", tenant_id=TENANT_ID, hostname="auditor.local"
    )
    c_cert, c_key, _ = mint_leaf_to_files(
        data_dir, role="harness", run_id=RUN_ID, tenant_id=TENANT_ID, hostname="harness.local"
    )
    server_ctx = build_server_context(s_cert, s_key, ca)
    client_ctx = build_client_context(c_cert, c_key, ca)

    seen: dict = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen["id"] = parse_peer_identity(writer.get_extra_info("ssl_object"))
        writer.close()

    port = _free_port()
    server = await asyncio.start_server(handle, "127.0.0.1", port, ssl=server_ctx)
    try:
        _reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_ctx, server_hostname="auditor.local"
        )
        for _ in range(100):
            if "id" in seen:
                break
            await asyncio.sleep(0.01)
        writer.close()
    finally:
        server.close()
        await server.wait_closed()

    assert seen.get("id") is not None
    assert seen["id"].role == "harness"
    assert seen["id"].run_id == RUN_ID
    assert seen["id"].tenant_id == TENANT_ID


async def test_mtls_rejects_client_from_untrusted_ca(tmp_path) -> None:
    server_dir = str(tmp_path / "server")
    client_dir = str(tmp_path / "client")
    init_ca(server_dir)
    init_ca(client_dir)  # a different CA
    s_cert, s_key, s_ca = mint_leaf_to_files(
        server_dir, role="auditor", run_id="server", tenant_id=TENANT_ID, hostname="auditor.local"
    )
    # Client cert signed by the OTHER CA -> server must reject it.
    c_cert, c_key, _ = mint_leaf_to_files(
        client_dir, role="harness", run_id=RUN_ID, tenant_id=TENANT_ID, hostname="harness.local"
    )
    server_ctx = build_server_context(s_cert, s_key, s_ca)
    client_ctx = build_client_context(c_cert, c_key, s_ca)  # client trusts server's CA (so it can verify the server)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Only runs if the client cert verified; a successful session would receive data.
        writer.write(b"ok")
        await writer.drain()
        writer.close()

    port = _free_port()
    server = await asyncio.start_server(handle, "127.0.0.1", port, ssl=server_ctx)
    rejected = False
    try:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", port, ssl=client_ctx, server_hostname="auditor.local"
                ),
                timeout=5,
            )
            data = await asyncio.wait_for(reader.read(100), timeout=5)
            rejected = data == b""  # server dropped us mid/after handshake (no data delivered)
            writer.close()
        except (TimeoutError, ssl.SSLError, ConnectionError, OSError):
            rejected = True
    finally:
        server.close()
        await server.wait_closed()
    assert rejected, "untrusted client was NOT rejected by the server"
