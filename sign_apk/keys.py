"""Loading and generating signing key material.

Supports:
  - PKCS#12 keystore (.p12/.pfx) with password
  - Separate PEM private key + PEM certificate files
  - On-the-fly generation of a self-signed RSA debug key/cert (like
    Android's debug.keystore), optionally saved to PEM files for reuse.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


@dataclass
class KeyMaterial:
    private_key: object  # cryptography private key object
    certificate: x509.Certificate


def load_pkcs12(path: str, password: bytes | None) -> KeyMaterial:
    with open(path, "rb") as f:
        data = f.read()
    private_key, certificate, _additional_certs = pkcs12.load_key_and_certificates(
        data, password
    )
    if private_key is None or certificate is None:
        raise ValueError("PKCS#12 file did not contain both a private key and a certificate")
    return KeyMaterial(private_key=private_key, certificate=certificate)


def load_pem(key_path: str, cert_path: str, password: bytes | None) -> KeyMaterial:
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=password)
    with open(cert_path, "rb") as f:
        certificate = x509.load_pem_x509_certificate(f.read())
    return KeyMaterial(private_key=private_key, certificate=certificate)


def generate_debug_key(
    common_name: str = "Android Debug",
    key_size: int = 2048,
    valid_days: int = 10000,
) -> KeyMaterial:
    """Generate a self-signed RSA key/cert pair, similar in spirit to the
    auto-generated Android debug.keystore used by standard tooling."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return KeyMaterial(private_key=private_key, certificate=certificate)


def save_pem(key_material: KeyMaterial, key_path: str, cert_path: str) -> None:
    with open(key_path, "wb") as f:
        f.write(
            key_material.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(key_material.certificate.public_bytes(serialization.Encoding.PEM))
