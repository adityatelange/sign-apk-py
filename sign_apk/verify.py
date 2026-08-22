"""Basic self-check verification of a v2-signed APK: re-locates the signing
block, recomputes the content digest, and checks the signature against the
embedded certificate's public key. This is a sanity check for this tool's
own output, not a full reimplementation of Android's verifier.
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

ALGO_DIGEST_NAME = {
    RSA_PKCS1_V1_5_WITH_SHA256: "sha256",
    RSA_PKCS1_V1_5_WITH_SHA512: "sha512",
    ECDSA_WITH_SHA256: "sha256",
    ECDSA_WITH_SHA512: "sha512",
}


class VerificationError(Exception):
    pass


def _read_u32_prefixed_list(buf: bytes):
    items = []
    pos = 0
    n = len(buf)
    while pos < n:
        length = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        items.append(buf[pos : pos + length])
        pos += length
    return items


def verify_apk(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()

    sections = zipdata.find_eocd(data)
    block = zipdata.find_existing_signing_block(data, sections)
    if block is None:
        raise VerificationError("No APK Signing Block found")

    v2_value = None
    for pair_id, value in block.id_value_pairs:
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            v2_value = value
            break
    if v2_value is None:
        raise VerificationError("No APK Signature Scheme v2 Block found")

    signer_sequence_blob = _read_u32_prefixed_list(v2_value)[0]
    signers = _read_u32_prefixed_list(signer_sequence_blob)
    if not signers:
        raise VerificationError("No signers present in v2 block")

    results = []
    before_central_dir = data[: block.offset]
    central_dir = data[
        sections.central_dir_offset : sections.central_dir_offset + sections.central_dir_size
    ]
    eocd_for_digest = zipdata.set_eocd_cd_offset(sections.eocd, block.offset)
    content_sections = [before_central_dir, central_dir, eocd_for_digest]

    for signer_blob in signers:
        signed_data_blob, signatures_blob, public_key_der = _read_u32_prefixed_list(
            signer_blob
        )
        signatures = _read_u32_prefixed_list(signatures_blob)

        digests_blob, certificates_blob, _attrs, _pad = _read_u32_prefixed_list(
            signed_data_blob
        )
        cert_ders = _read_u32_prefixed_list(certificates_blob)
        certificate = x509.load_der_x509_certificate(cert_ders[0])
        public_key = certificate.public_key()

        verified_any = False
        for sig_entry in signatures:
            algo_id = struct.unpack_from("<I", sig_entry, 0)[0]
            sig_bytes = _read_u32_prefixed_list(sig_entry[4:])[0]
            digest_name = ALGO_DIGEST_NAME.get(algo_id)
            if digest_name is None:
                continue

            try:
                if isinstance(public_key, rsa.RSAPublicKey):
                    hash_alg = hashes.SHA256() if digest_name == "sha256" else hashes.SHA512()
                    public_key.verify(
                        sig_bytes, signed_data_blob, padding.PKCS1v15(), hash_alg
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    hash_alg = hashes.SHA256() if digest_name == "sha256" else hashes.SHA512()
                    public_key.verify(sig_bytes, signed_data_blob, ec.ECDSA(hash_alg))
                else:
                    continue
                verified_any = True
            except InvalidSignature:
                continue

        if not verified_any:
            raise VerificationError("Signature verification failed for a signer")

        expected_digest = digestmod.compute_content_digest("sha256", content_sections) \
            if any(ALGO_DIGEST_NAME.get(struct.unpack_from("<I", d, 0)[0]) == "sha256"
                   for d in _read_u32_prefixed_list(digests_blob)) \
            else digestmod.compute_content_digest("sha512", content_sections)

        digest_ok = False
        for digest_entry in _read_u32_prefixed_list(digests_blob):
            algo_id = struct.unpack_from("<I", digest_entry, 0)[0]
            digest_value = _read_u32_prefixed_list(digest_entry[4:])[0]
            if digest_value == expected_digest:
                digest_ok = True

        if not digest_ok:
            raise VerificationError("Content digest mismatch")

        results.append(
            {
                "subject": certificate.subject.rfc4514_string(),
                "serial_number": certificate.serial_number,
            }
        )

    return {"signers": results}
