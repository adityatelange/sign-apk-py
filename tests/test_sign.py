"""End-to-end tests for sign-apk.

The authoritative check is Android's own `apksigner`, which is used when it
is present on PATH; the tests otherwise fall back to this package's own
verifier. Run with: python -m pytest tests/
"""
from __future__ import annotations

import datetime
import shutil
import subprocess
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from sign_apk import keys
from sign_apk.signer import sign_apk
from sign_apk.verify import VerificationError, verify_apk

APKSIGNER = shutil.which("apksigner")


def apksigner_verifies_v2(path) -> bool:
    """True if Android's apksigner confirms a valid v2 signature."""
    result = subprocess.run(
        [
            APKSIGNER, "verify", "--verbose",
            "--min-sdk-version", "24", "--max-sdk-version", "30",
            str(path),
        ],
        capture_output=True, text=True,
    )
    return "Verified using v2 scheme (APK Signature Scheme v2): true" in result.stdout


requires_apksigner = pytest.mark.skipif(
    APKSIGNER is None, reason="apksigner not installed"
)


@pytest.fixture
def unsigned_apk(tmp_path):
    """A minimal APK-shaped zip, including a STORED entry to exercise alignment."""
    path = tmp_path / "unsigned.apk"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("AndroidManifest.xml", "<manifest/>")
        z.writestr("resources.arsc", b"\x00" * 5000, compress_type=zipfile.ZIP_STORED)
        z.writestr("classes.dex", b"\x01" * 20000)
    return path


@pytest.fixture
def rsa_key():
    return keys.generate_debug_key(common_name="Test RSA")


@pytest.fixture
def ec_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test EC")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    return keys.KeyMaterial(private_key=private_key, certificate=cert)


def test_sign_rsa(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "signed.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key)
    assert verify_apk(str(out))["signers"][0]["subject"] == "CN=Test RSA"


def test_sign_ec(unsigned_apk, ec_key, tmp_path):
    out = tmp_path / "signed_ec.apk"
    sign_apk(str(unsigned_apk), str(out), ec_key)
    assert verify_apk(str(out))["signers"][0]["subject"] == "CN=Test EC"


def test_sign_pkcs12(unsigned_apk, rsa_key, tmp_path):
    p12_path = tmp_path / "key.p12"
    p12_path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"alias", rsa_key.private_key, rsa_key.certificate, None,
            BestAvailableEncryption(b"pw"),
        )
    )
    loaded = keys.load_pkcs12(str(p12_path), b"pw")
    out = tmp_path / "signed_p12.apk"
    sign_apk(str(unsigned_apk), str(out), loaded)
    assert verify_apk(str(out))["signers"]


def test_pem_roundtrip(unsigned_apk, rsa_key, tmp_path):
    key_path, cert_path = tmp_path / "k.pem", tmp_path / "c.crt"
    keys.save_pem(rsa_key, str(key_path), str(cert_path))
    loaded = keys.load_pem(str(key_path), str(cert_path), None)
    out = tmp_path / "signed_pem.apk"
    sign_apk(str(unsigned_apk), str(out), loaded)
    assert verify_apk(str(out))["signers"]


def test_resigning_replaces_previous_signature(unsigned_apk, rsa_key, ec_key, tmp_path):
    first, second = tmp_path / "a.apk", tmp_path / "b.apk"
    sign_apk(str(unsigned_apk), str(first), rsa_key)
    sign_apk(str(first), str(second), ec_key)
    signers = verify_apk(str(second))["signers"]
    assert len(signers) == 1
    assert signers[0]["subject"] == "CN=Test EC"


def test_tampering_is_detected(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "signed.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key)

    data = bytearray(out.read_bytes())
    data[200] ^= 0xFF
    tampered = tmp_path / "tampered.apk"
    tampered.write_bytes(bytes(data))

    with pytest.raises(VerificationError):
        verify_apk(str(tampered))


def test_entry_contents_are_preserved(unsigned_apk, rsa_key, tmp_path):
    """Signing must not recompress or alter any entry payload."""
    out = tmp_path / "signed.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key)

    with zipfile.ZipFile(unsigned_apk) as src, zipfile.ZipFile(out) as dst:
        for info in src.infolist():
            assert src.read(info.filename) == dst.read(info.filename)
            assert info.compress_type == dst.getinfo(info.filename).compress_type


def test_stored_entries_stay_aligned(unsigned_apk, rsa_key, tmp_path):
    """Uncompressed entries must start at 4-byte aligned offsets, since
    Android memory-maps them directly."""
    out = tmp_path / "signed.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key)

    with zipfile.ZipFile(out) as z:
        for info in z.infolist():
            if info.compress_type != zipfile.ZIP_STORED:
                continue
            header = info.header_offset
            data = out.read_bytes()
            name_len, extra_len = int.from_bytes(
                data[header + 26 : header + 28], "little"
            ), int.from_bytes(data[header + 28 : header + 30], "little")
            data_start = header + 30 + name_len + extra_len
            assert data_start % 4 == 0, f"{info.filename} misaligned at {data_start}"


@requires_apksigner
def test_apksigner_accepts_rsa(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "signed.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key)
    assert apksigner_verifies_v2(out)


@requires_apksigner
def test_apksigner_accepts_ec(unsigned_apk, ec_key, tmp_path):
    out = tmp_path / "signed_ec.apk"
    sign_apk(str(unsigned_apk), str(out), ec_key)
    assert apksigner_verifies_v2(out)


@requires_apksigner
def test_apksigner_rejects_tampered(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "signed.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key)
    data = bytearray(out.read_bytes())
    data[200] ^= 0xFF
    tampered = tmp_path / "tampered.apk"
    tampered.write_bytes(bytes(data))
    assert not apksigner_verifies_v2(tampered)
