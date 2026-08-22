"""APK Signature Scheme v2 block construction.

References
----------
Scheme overview and file layout:
    https://source.android.com/docs/security/features/apksigning/v2

Byte layouts below are ported from AOSP apksig
(https://android.googlesource.com/platform/tools/apksig/), under
src/main/java/com/android/apksig/:

    internal/apk/v2/V2SchemeSigner.java
        generateApkSignatureSchemeV2Block(), generateSignerBlock() —
        signer / signed_data layout, including the trailing zero-length
        element of signed_data
    internal/apk/v2/V2SchemeConstants.java
        APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
    internal/apk/ApkSigningBlockUtils.java
        generateApkSigningBlock() — outer block framing, magic bytes,
        VERITY_PADDING_BLOCK_ID (0x42726577) 4096-byte alignment padding
        and its minimum-12-byte pair rule
    internal/apk/ApkSigningBlockUtilsLite.java
        encodeAsSequenceOfLengthPrefixedElements() and
        encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes()
        — the length-prefix conventions reproduced by the helpers here
    internal/apk/SignatureAlgorithm.java
        signature algorithm IDs and the modulus/curve-size based choice
        between SHA-256 and SHA-512

Note the two distinct length-prefix widths: the outer APK Signing Block's
ID-value pairs are uint64-prefixed, while every length inside a scheme
block's payload is uint32.

Byte-level structure (all integers little-endian; see module docstring in
zipdata.py for the outer APK Signing Block framing):

APK Signature Scheme v2 Block (ID 0x7109871a), value:
    uint32 len(signer-sequence)
    signer-sequence := { uint32 len(signer) ; signer }*

signer:
    uint32 len(signed_data) ; signed_data
    uint32 len(signatures)  ; signatures
    uint32 len(public_key)  ; public_key   (X.509 SubjectPublicKeyInfo DER)

signed_data (sequence of exactly 4 length-prefixed elements):
    uint32 len(digests)               ; digests
    uint32 len(certificates)          ; certificates
    uint32 len(additional_attributes) ; additional_attributes
    uint32 len(zero_padding)=0        ; (empty)

digests / signatures: sequence of { uint32 pair_len ; uint32 algo_id ; uint32 len(bytes) ; bytes }
certificates: sequence of { uint32 len(der) ; der }
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from . import digest as digestmod

APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871A
APK_SIGNING_BLOCK_MAGIC = b"APK Sig Block 42"
VERITY_PADDING_BLOCK_ID = 0x42726577
PAGE_ALIGNMENT_BYTES = 4096

# Signature algorithm IDs, from apksig SignatureAlgorithm.java. All of these
# digest content in 1MB chunks (CHUNKED_SHA256 / CHUNKED_SHA512). Only the
# PKCS#1 v1.5 and ECDSA variants are emitted by this signer; the PSS IDs are
# defined for completeness when parsing blocks written by other tools.
# The 0x03xx (DSA) and 0x04xx (verity/fsverity, v3+) IDs are not handled.
RSA_PSS_WITH_SHA256 = 0x0101
RSA_PSS_WITH_SHA512 = 0x0102
RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103
RSA_PKCS1_V1_5_WITH_SHA512 = 0x0104
ECDSA_WITH_SHA256 = 0x0201
ECDSA_WITH_SHA512 = 0x0202


def _u32_prefixed(*blobs: bytes) -> bytes:
    """Concatenate blobs, each preceded by its own uint32LE length."""
    out = bytearray()
    for b in blobs:
        out += struct.pack("<I", len(b))
        out += b
    return bytes(out)


def _sequence_of_length_prefixed(items: list) -> bytes:
    return _u32_prefixed(*items)


def _sequence_of_id_value_pairs(pairs: list) -> bytes:
    """pairs: list[(uint32 id, bytes value)] -> sequence of
    { uint32 pair_len ; uint32 id ; uint32 len(value) ; value }
    where pair_len = 4 + 4 + len(value).

    Used for the digests and signatures lists *inside* the v2 signature
    scheme block. Note the value carries its own uint32 length prefix in
    addition to the enclosing pair length — omitting it silently shifts the
    reader by 4 bytes into the value."""
    out = bytearray()
    for pair_id, value in pairs:
        entry = struct.pack("<I", pair_id) + struct.pack("<I", len(value)) + value
        out += struct.pack("<I", len(entry))
        out += entry
    return bytes(out)


def _sequence_of_id_value_pairs_u64(pairs: list) -> bytes:
    """Same shape as _sequence_of_id_value_pairs, but with uint64 length
    prefixes. Used for the outer APK Signing Block's ID-value pairs, which
    are length-prefixed with uint64 (distinct from the uint32 prefixes used
    everywhere inside an individual scheme block's payload)."""
    out = bytearray()
    for pair_id, value in pairs:
        entry = struct.pack("<I", pair_id) + value
        out += struct.pack("<Q", len(entry))
        out += entry
    return bytes(out)


def _select_algorithm(private_key):
    """Pick a signature algorithm ID + signing function for the given key,
    following apksig's RSA-modulus-size / EC-curve-size based SHA256 vs
    SHA512 selection."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        modulus_bits = private_key.key_size
        if modulus_bits > 3072:
            algo_id = RSA_PKCS1_V1_5_WITH_SHA512
            hash_alg = hashes.SHA512()
            digest_name = "sha512"
        else:
            algo_id = RSA_PKCS1_V1_5_WITH_SHA256
            hash_alg = hashes.SHA256()
            digest_name = "sha256"

        def sign(data: bytes) -> bytes:
            return private_key.sign(data, padding.PKCS1v15(), hash_alg)

        return algo_id, digest_name, sign

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_bits = private_key.curve.key_size
        if curve_bits > 256:
            algo_id = ECDSA_WITH_SHA512
            hash_alg = hashes.SHA512()
            digest_name = "sha512"
        else:
            algo_id = ECDSA_WITH_SHA256
            hash_alg = hashes.SHA256()
            digest_name = "sha256"

        def sign(data: bytes) -> bytes:
            return private_key.sign(data, ec.ECDSA(hash_alg))

        return algo_id, digest_name, sign

    raise ValueError(f"Unsupported private key type: {type(private_key)!r}")


def build_v2_signature_scheme_block(
    private_key, certificate, content_sections: list
) -> bytes:
    """Build the value bytes for the APK Signature Scheme v2 Block (ID
    0x7109871a), given the private key, X.509 certificate, and the three
    ordered content sections (before-central-dir, central-dir, eocd) to
    digest."""
    algo_id, digest_name, sign_fn = _select_algorithm(private_key)

    content_digest = digestmod.compute_content_digest(digest_name, content_sections)

    digests = _sequence_of_id_value_pairs([(algo_id, content_digest)])
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    certificates = _sequence_of_length_prefixed([cert_der])
    additional_attributes = b""  # empty sequence

    signed_data = _sequence_of_length_prefixed(
        [digests, certificates, additional_attributes, b""]
    )

    signature_bytes = sign_fn(signed_data)
    signatures = _sequence_of_id_value_pairs([(algo_id, signature_bytes)])

    public_key_der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signer = _sequence_of_length_prefixed([signed_data, signatures, public_key_der])
    # signers-sequence: concatenation of length-prefixed signer entries (one per signer)
    signers_sequence = _sequence_of_length_prefixed([signer])
    # block value: a length-prefixed sequence containing exactly one element,
    # that element being the signers-sequence itself
    return _sequence_of_length_prefixed([signers_sequence])


def assemble_apk_signing_block(id_value_pairs: list) -> bytes:
    """Assemble the full APK Signing Block from a list of (id, value) pairs,
    adding the verity 4KB-alignment padding pair, per apksig's
    generateApkSigningBlock."""
    pairs_region = _sequence_of_id_value_pairs_u64(id_value_pairs)

    result_size = 8 + len(pairs_region) + 8 + 16  # leading size + pairs + trailing size + magic

    padding_pair = b""
    if result_size % PAGE_ALIGNMENT_BYTES != 0:
        padding = PAGE_ALIGNMENT_BYTES - (result_size % PAGE_ALIGNMENT_BYTES)
        if padding < 12:
            padding += PAGE_ALIGNMENT_BYTES
        padding_value = b"\x00" * (padding - 12)
        padding_entry = struct.pack("<I", VERITY_PADDING_BLOCK_ID) + padding_value
        padding_pair = struct.pack("<Q", len(padding_entry)) + padding_entry
        result_size += padding

    block_size_field = result_size - 8

    out = bytearray()
    out += struct.pack("<Q", block_size_field)
    out += pairs_region
    out += padding_pair
    out += struct.pack("<Q", block_size_field)
    out += APK_SIGNING_BLOCK_MAGIC
    return bytes(out)
