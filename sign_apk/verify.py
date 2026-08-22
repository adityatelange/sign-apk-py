"""Self-check verification of a signed APK.

Re-locates the signing block, recomputes the content digest, and checks
each signer's signature against its embedded certificate, for the v2 and v3
schemes. This is a sanity check on this tool's own output, not a
reimplementation of Android's verifier: it does not validate certificate
chains, expiry, SDK range coverage across signers, rotation lineages, or v4
sidecars. Use `apksigner verify` for an authoritative answer.
"""
from __future__ import annotations

import struct

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from . import digest as digestmod
from . import zipdata
from .v2sign import (
    APK_SIGNATURE_SCHEME_V2_BLOCK_ID,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA512,
    RSA_PKCS1_V1_5_WITH_SHA256,
    RSA_PKCS1_V1_5_WITH_SHA512,
)
from .v3sign import APK_SIGNATURE_SCHEME_V3_BLOCK_ID

ALGO_DIGEST_NAME = {
    RSA_PKCS1_V1_5_WITH_SHA256: "sha256",
    RSA_PKCS1_V1_5_WITH_SHA512: "sha512",
    ECDSA_WITH_SHA256: "sha256",
    ECDSA_WITH_SHA512: "sha512",
}


class VerificationError(Exception):
    pass


def _read_u32_prefixed_list(buf: bytes) -> list:
    """Split a buffer of consecutive uint32-length-prefixed elements."""
    items = []
    pos = 0
    n = len(buf)
    while pos < n:
        length = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        items.append(buf[pos : pos + length])
        pos += length
    return items


def _take_u32_prefixed(buf: bytes, count: int) -> tuple:
    """Read exactly `count` length-prefixed elements, returning them along
    with the remaining bytes. Used where a structure mixes length-prefixed
    elements with bare fields, as v3's signer does."""
    items = []
    pos = 0
    for _ in range(count):
        length = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        items.append(buf[pos : pos + length])
        pos += length
    return items, buf[pos:]


def verify_apk(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()

    sections = zipdata.find_eocd(data)
    block = zipdata.find_existing_signing_block(data, sections)
    if block is None:
        raise VerificationError("No APK Signing Block found")

    blocks = {}
    for pair_id, value in block.id_value_pairs:
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            blocks["v2"] = value
        elif pair_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
            blocks["v3"] = value
    if not blocks:
        raise VerificationError("No APK Signature Scheme v2 or v3 block found")

    before_central_dir = data[: block.offset]
    central_dir = data[
        sections.central_dir_offset : sections.central_dir_offset + sections.central_dir_size
    ]
    eocd_for_digest = zipdata.set_eocd_cd_offset(sections.eocd, block.offset)
    content_sections = [before_central_dir, central_dir, eocd_for_digest]

    results = []
    schemes = []
    for scheme in ("v2", "v3"):
        value = blocks.get(scheme)
        if value is None:
            continue
        signers = _read_u32_prefixed_list(_read_u32_prefixed_list(value)[0])
        if not signers:
            raise VerificationError(f"No signers present in {scheme} block")
        for signer_blob in signers:
            results.append(_verify_signer(signer_blob, scheme, content_sections))
        schemes.append(scheme)

    return {"signers": results, "schemes": schemes}


def _parse_signer(signer_blob: bytes, scheme: str) -> dict:
    """Split a signer into its parts.

    v2: signed_data, signatures, public_key — all length-prefixed.
    v3: signed_data, bare uint32 min/max SDK, signatures, public_key; and
    the signed data likewise carries bare min/max SDK between its
    certificates and additional attributes.
    """
    if scheme == "v3":
        (signed_data_blob,), rest = _take_u32_prefixed(signer_blob, 1)
        min_sdk, max_sdk = struct.unpack_from("<II", rest, 0)
        signatures_blob, public_key_der = _read_u32_prefixed_list(rest[8:])

        (digests_blob, certificates_blob), sd_rest = _take_u32_prefixed(
            signed_data_blob, 2
        )
        sd_min, sd_max = struct.unpack_from("<II", sd_rest, 0)
        if (sd_min, sd_max) != (min_sdk, max_sdk):
            raise VerificationError(
                "v3 SDK version range differs between signer and signed data"
            )
        sdk_range = (min_sdk, max_sdk)
    else:
        signed_data_blob, signatures_blob, public_key_der = _read_u32_prefixed_list(
            signer_blob
        )
        digests_blob, certificates_blob = _read_u32_prefixed_list(signed_data_blob)[:2]
        sdk_range = None

    return {
        "signed_data": signed_data_blob,
        "signatures": signatures_blob,
        "public_key": public_key_der,
        "digests": digests_blob,
        "certificates": certificates_blob,
        "sdk_range": sdk_range,
    }


def _verify_signer(signer_blob: bytes, scheme: str, content_sections: list) -> dict:
    parts = _parse_signer(signer_blob, scheme)

    cert_ders = _read_u32_prefixed_list(parts["certificates"])
    if not cert_ders:
        raise VerificationError(f"No certificate in {scheme} signer")
    certificate = x509.load_der_x509_certificate(cert_ders[0])
    public_key = certificate.public_key()

    signed_data = parts["signed_data"]
    verified_any = False
    for sig_entry in _read_u32_prefixed_list(parts["signatures"]):
        algo_id = struct.unpack_from("<I", sig_entry, 0)[0]
        digest_name = ALGO_DIGEST_NAME.get(algo_id)
        if digest_name is None:
            continue
        sig_bytes = _read_u32_prefixed_list(sig_entry[4:])[0]
        hash_alg = hashes.SHA256() if digest_name == "sha256" else hashes.SHA512()

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    sig_bytes, signed_data, padding.PKCS1v15(), hash_alg
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(sig_bytes, signed_data, ec.ECDSA(hash_alg))
            else:
                continue
            verified_any = True
        except InvalidSignature:
            continue

    if not verified_any:
        raise VerificationError(f"Signature verification failed for a {scheme} signer")

    digest_ok = False
    for digest_entry in _read_u32_prefixed_list(parts["digests"]):
        algo_id = struct.unpack_from("<I", digest_entry, 0)[0]
        digest_name = ALGO_DIGEST_NAME.get(algo_id)
        if digest_name is None:
            continue
        digest_value = _read_u32_prefixed_list(digest_entry[4:])[0]
        if digest_value == digestmod.compute_content_digest(
            digest_name, content_sections
        ):
            digest_ok = True

    if not digest_ok:
        raise VerificationError("Content digest mismatch")

    result = {
        "scheme": scheme,
        "subject": certificate.subject.rfc4514_string(),
        "serial_number": certificate.serial_number,
    }
    if parts["sdk_range"] is not None:
        result["min_sdk_version"], result["max_sdk_version"] = parts["sdk_range"]
    return result
