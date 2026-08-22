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


def apksigner_report(path, v4_file=None, min_sdk="24", max_sdk="34") -> str:
    """Run apksigner verify and return its stdout."""
    cmd = [
        APKSIGNER, "verify", "--verbose",
        "--min-sdk-version", min_sdk, "--max-sdk-version", max_sdk,
    ]
    if v4_file is not None:
        cmd += ["--v4-signature-file", str(v4_file)]
    cmd.append(str(path))
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def apksigner_verifies(path, scheme, v4_file=None, min_sdk="24", max_sdk="34") -> bool:
    """True if apksigner confirms the given scheme ('v2'/'v3'/'v4')."""
    names = {
        "v2": "Verified using v2 scheme (APK Signature Scheme v2): true",
        "v3": "Verified using v3 scheme (APK Signature Scheme v3): true",
        "v4": "Verified using v4 scheme (APK Signature Scheme v4): true",
    }
    return names[scheme] in apksigner_report(path, v4_file, min_sdk, max_sdk)


def apksigner_verifies_v2(path) -> bool:
    """True if apksigner confirms a valid v2 signature (v2-only range)."""
    return apksigner_verifies(path, "v2", min_sdk="24", max_sdk="27")


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
    # One signer entry per emitted scheme (v2 and v3 by default), all of
    # which must be the new key: re-signing replaces rather than appends.
    signers = verify_apk(str(second))["signers"]
    assert signers
    assert {s["subject"] for s in signers} == {"CN=Test EC"}


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


# --- v3 ---------------------------------------------------------------


def test_v3_requires_a_scheme_to_be_enabled(unsigned_apk, rsa_key, tmp_path):
    with pytest.raises(ValueError):
        sign_apk(str(unsigned_apk), str(tmp_path / "x.apk"), rsa_key, v2=False, v3=False)


def test_v3_rejects_inverted_sdk_range(unsigned_apk, rsa_key, tmp_path):
    from sign_apk.v3sign import build_v3_signature_scheme_block

    with pytest.raises(ValueError):
        build_v3_signature_scheme_block(
            rsa_key.private_key, rsa_key.certificate, [b"a", b"b", b"c"],
            min_sdk_version=30, max_sdk_version=28,
        )


@requires_apksigner
def test_apksigner_accepts_v3(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "v3.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key, v2=False, v3=True)
    assert apksigner_verifies(out, "v3", min_sdk="28")


@requires_apksigner
def test_apksigner_accepts_v2_and_v3_together(unsigned_apk, rsa_key, tmp_path):
    """Both blocks must be independently valid: v2 governs pre-P platforms,
    v3 governs P and later."""
    out = tmp_path / "v23.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key, v2=True, v3=True)
    assert apksigner_verifies(out, "v2", min_sdk="24", max_sdk="27")
    assert apksigner_verifies(out, "v3", min_sdk="28", max_sdk="34")


@requires_apksigner
def test_apksigner_accepts_v3_with_ec(unsigned_apk, ec_key, tmp_path):
    out = tmp_path / "v3ec.apk"
    sign_apk(str(unsigned_apk), str(out), ec_key, v2=False, v3=True)
    assert apksigner_verifies(out, "v3", min_sdk="28")


# --- v4 ---------------------------------------------------------------


def test_v4_requires_v2_or_v3(unsigned_apk, rsa_key, tmp_path):
    with pytest.raises(ValueError):
        sign_apk(
            str(unsigned_apk), str(tmp_path / "x.apk"), rsa_key,
            v2=False, v3=False, v4=True,
        )


def test_v4_writes_sidecar(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "v4.apk"
    result = sign_apk(str(unsigned_apk), str(out), rsa_key, v4=True)
    idsig = tmp_path / "v4.apk.idsig"
    assert idsig.exists()
    assert result["idsig_path"] == str(idsig)
    # version 2 header
    assert idsig.read_bytes()[:4] == (2).to_bytes(4, "little")


def test_verity_tree_root_is_over_padded_block():
    """The root hash covers the whole first 4096-byte block including its
    zero padding, not just the first digest."""
    import hashlib

    from sign_apk.v4sign import build_verity_tree

    tree, root = build_verity_tree(b"hello world")
    assert len(tree) == 4096
    assert root == hashlib.sha256(tree[:4096]).digest()
    assert root != hashlib.sha256(tree[:32]).digest()


def test_verity_tree_pads_final_partial_block():
    """A partial final block is zero-padded to 4096 before hashing."""
    import hashlib

    from sign_apk.v4sign import build_verity_tree

    data = b"\x01" * 100
    tree, _ = build_verity_tree(data)
    expected_leaf = hashlib.sha256(data + b"\x00" * (4096 - len(data))).digest()
    assert tree[:32] == expected_leaf


def test_verity_tree_grows_levels_for_large_input():
    """Inputs beyond one block's worth of digests need multiple levels."""
    from sign_apk.v4sign import build_verity_tree

    # 128 blocks -> 128 digests -> still one level; 200000 blocks needs more.
    small, _ = build_verity_tree(b"\x00" * (4096 * 4))
    assert len(small) == 4096
    big, _ = build_verity_tree(b"\x00" * (4096 * 200))
    assert len(big) > 4096
    assert len(big) % 4096 == 0


@requires_apksigner
def test_apksigner_accepts_v4(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "v4.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key, v4=True)
    assert apksigner_verifies(
        out, "v4", v4_file=tmp_path / "v4.apk.idsig", min_sdk="28"
    )


@requires_apksigner
def test_v4_tree_matches_apksigner_exactly(unsigned_apk, rsa_key, tmp_path):
    """Our Merkle tree must reproduce apksigner's byte-for-byte for the
    same input file."""
    import struct

    out = tmp_path / "v4.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key, v4=True)

    from sign_apk.v4sign import build_verity_tree

    tree, root = build_verity_tree(out.read_bytes())

    idsig = (tmp_path / "v4.apk.idsig").read_bytes()
    pos = 4
    (n,) = struct.unpack_from("<I", idsig, pos)
    hashing_info = idsig[pos + 4 : pos + 4 + n]
    pos += 4 + n
    (n,) = struct.unpack_from("<I", idsig, pos)
    pos += 4 + n
    (n,) = struct.unpack_from("<I", idsig, pos)
    stored_tree = idsig[pos + 4 : pos + 4 + n]

    p = 5  # uint32 hash_algorithm + uint8 log2_blocksize
    (salt_len,) = struct.unpack_from("<I", hashing_info, p)
    p += 4 + salt_len
    (root_len,) = struct.unpack_from("<I", hashing_info, p)
    stored_root = hashing_info[p + 4 : p + 4 + root_len]

    assert stored_root == root
    assert stored_tree == tree


@requires_apksigner
def test_apksigner_rejects_tampered_apk_with_valid_v4(unsigned_apk, rsa_key, tmp_path):
    out = tmp_path / "v4.apk"
    sign_apk(str(unsigned_apk), str(out), rsa_key, v4=True)

    data = bytearray(out.read_bytes())
    data[300] ^= 0xFF
    out.write_bytes(bytes(data))

    assert not apksigner_verifies(
        out, "v4", v4_file=tmp_path / "v4.apk.idsig", min_sdk="28"
    )
