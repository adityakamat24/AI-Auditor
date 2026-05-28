"""Local private CA + per-run leaf certificates for mTLS over IPC (PRD §9.3, §11.1).

The auditor mints a short-lived leaf cert per run whose SubjectAltName encodes the connecting party's
``role``/``run_id``/``tenant_id`` (as a URI SAN) plus a DNS name for hostname verification. The CA key
is generated once and stored under ``<data_dir>/certs`` with best-effort 0600 perms.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SAN_SCHEME = "x-auditor"  # URI SAN: x-auditor:role=<role>;run_id=<uuid>;tenant_id=<uuid>


@dataclass
class CertBundle:
    cert_pem: bytes
    key_pem: bytes
    ca_pem: bytes


def certs_dir(data_dir: str) -> Path:
    path = Path(data_dir) / "certs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 on POSIX; best-effort on Windows
    except OSError:
        pass


def encode_san(role: str, run_id: str, tenant_id: str) -> str:
    return f"{SAN_SCHEME}:role={role};run_id={run_id};tenant_id={tenant_id}"


def init_ca(data_dir: str) -> tuple[Path, Path]:
    """Create the CA key+cert if absent. Returns (ca_cert_path, ca_key_path)."""
    directory = certs_dir(data_dir)
    ca_cert_path = directory / "ca.pem"
    ca_key_path = directory / "ca.key"
    if ca_cert_path.exists() and ca_key_path.exists():
        return ca_cert_path, ca_key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ai-auditor-ca")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(
        ca_key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return ca_cert_path, ca_key_path


def load_ca(data_dir: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    directory = certs_dir(data_dir)
    cert = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
    key = serialization.load_pem_private_key((directory / "ca.key").read_bytes(), password=None)
    return cert, key  # type: ignore[return-value]


def mint_leaf(
    data_dir: str,
    *,
    role: str,
    run_id: str,
    tenant_id: str,
    hostname: str,
    ttl_minutes: int = 240,
) -> CertBundle:
    """Mint a CA-signed leaf cert (usable for both server and client auth)."""
    ca_cert, ca_key = load_ca(data_dir)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{role}-{run_id}")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(minutes=ttl_minutes))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(hostname),
                    x509.UniformResourceIdentifier(encode_san(role, run_id, tenant_id)),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return CertBundle(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        ca_pem=ca_cert.public_bytes(serialization.Encoding.PEM),
    )


def mint_leaf_to_files(
    data_dir: str,
    *,
    role: str,
    run_id: str,
    tenant_id: str,
    hostname: str,
    ttl_minutes: int = 240,
) -> tuple[Path, Path, Path]:
    """Mint a leaf and write cert/key files. Returns (cert_path, key_path, ca_path)."""
    bundle = mint_leaf(
        data_dir,
        role=role,
        run_id=run_id,
        tenant_id=tenant_id,
        hostname=hostname,
        ttl_minutes=ttl_minutes,
    )
    directory = certs_dir(data_dir)
    cert_path = directory / f"{role}-{run_id}.pem"
    key_path = directory / f"{role}-{run_id}.key"
    cert_path.write_bytes(bundle.cert_pem)
    _write_private(key_path, bundle.key_pem)
    return cert_path, key_path, directory / "ca.pem"
