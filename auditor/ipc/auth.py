"""mTLS SSLContext builders + peer-certificate identity parsing for IPC (PRD §9.3, §11.1).

The server requires + verifies a client certificate (mTLS); the auditor then reads the client's URI SAN
(``x-auditor:role=...;run_id=...;tenant_id=...``) to identify the connecting run. The client verifies the
server cert against the CA and its hostname.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path

from auditor.auth.ca import SAN_SCHEME


@dataclass(frozen=True)
class PeerIdentity:
    role: str
    run_id: str
    tenant_id: str


def build_server_context(cert_path: str | Path, key_path: str | Path, ca_path: str | Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_path))
    ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS: require + verify the client cert
    return ctx


def build_client_context(cert_path: str | Path, key_path: str | Path, ca_path: str | Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_path))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def parse_peer_identity(ssl_object: ssl.SSLObject | None) -> PeerIdentity | None:
    """Extract ``(role, run_id, tenant_id)`` from the verified peer cert's URI SAN, or None."""
    if ssl_object is None:
        return None
    cert = ssl_object.getpeercert()
    if not cert:
        return None
    for san_type, san_value in cert.get("subjectAltName", ()):
        if san_type == "URI" and san_value.startswith(SAN_SCHEME + ":"):
            fields: dict[str, str] = {}
            for part in san_value[len(SAN_SCHEME) + 1 :].split(";"):
                key, sep, value = part.partition("=")
                if sep:
                    fields[key] = value
            if {"role", "run_id", "tenant_id"} <= fields.keys():
                return PeerIdentity(fields["role"], fields["run_id"], fields["tenant_id"])
    return None
