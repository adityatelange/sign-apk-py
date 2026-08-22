"""APK Signature Scheme v3 block construction.

v3 is v2 plus an SDK version range on each signer, and an optional
proof-of-rotation lineage in the signed data's additional attributes. This
module emits a single signer with no lineage, which is the common case for
apps that are not rotating signing keys.

Structure (all integers little-endian; LP = uint32 length prefix):

    signer:
        LP signed_data
        uint32 min_sdk_version      (bare, NOT length-prefixed)
        uint32 max_sdk_version      (bare)
        LP signatures
        LP public_key

    signed_data:
        LP digests
        LP certificates
        uint32 min_sdk_version      (bare)
        uint32 max_sdk_version      (bare)
        LP additional_attributes

The min/max SDK fields are bare uint32s in both structures; adding a length
prefix shifts every following field. The values must match between the
signer and its signed_data, or apksig reports
V3_MIN/MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD.

The content digest is computed exactly as for v2, over the same three
sections, so this module reuses the v2 digest code unchanged.

References
----------
Scheme overview:
    https://source.android.com/docs/security/features/apksigning/v3

Checked against AOSP apksig
(https://android.googlesource.com/platform/tools/apksig/), Android's
reference implementation, under src/main/java/com/android/apksig/:

    internal/apk/v3/V3SchemeSigner.java
        encodeSigner(), encodeSignedData(), generateAdditionalAttributes() —
        field order, bare uint32 SDK fields, and the empty-attributes case
    internal/apk/v3/V3SchemeConstants.java
        APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0,
        PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c
    internal/apk/v3/V3SchemeVerifier.java
        the signer/signed-data SDK cross-check and the requirement that
        signer SDK ranges be contiguous
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import serialization

from . import digest as digestmod
from .v2sign import (
    _select_algorithm,
    _sequence_of_id_value_pairs,
    _sequence_of_length_prefixed,
)

APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xF05368C0

# Proof-of-rotation lineage attribute. Not emitted by this module: it only
# applies when rotating to a new signing key.
PROOF_OF_ROTATION_ATTR_ID = 0x3BA06F8C

# v3 verification was introduced in Android P (API 28); a v3 block declaring
# a lower minSdk than this is pointless but not invalid.
MIN_SDK_WITH_V3_SUPPORT = 28

# Integer.MAX_VALUE - "no upper bound" for the newest signer.
MAX_SDK_VERSION = 0x7FFFFFFF


def build_v3_signature_scheme_block(
    private_key,
    certificate,
    content_sections: list,
    min_sdk_version: int = MIN_SDK_WITH_V3_SUPPORT,
    max_sdk_version: int = MAX_SDK_VERSION,
) -> tuple:
    """Build the value bytes for the APK Signature Scheme v3 Block (ID
    0xf05368c0) for a single signer with no rotation lineage.

    Returns (block_value, content_digest, algo_id); the digest is reused by
    the v4 signer, which prefers the v3 digest when anchoring.
    """
    if min_sdk_version < 0 or min_sdk_version > max_sdk_version:
        raise ValueError(
            f"Invalid SDK range for v3 signer: {min_sdk_version}..{max_sdk_version}"
        )

    algo_id, digest_name, sign_fn = _select_algorithm(private_key)

    content_digest = digestmod.compute_content_digest(digest_name, content_sections)

    digests = _sequence_of_id_value_pairs([(algo_id, content_digest)])
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    certificates = _sequence_of_length_prefixed([cert_der])

    # No rotation, so no proof-of-rotation attribute. apksig emits an empty
    # attributes sequence in this case, and its verifier's parse loop simply
    # never runs.
    additional_attributes = b""

    signed_data = (
        _sequence_of_length_prefixed([digests, certificates])
        + struct.pack("<II", min_sdk_version, max_sdk_version)
        + _sequence_of_length_prefixed([additional_attributes])
    )

    signature_bytes = sign_fn(signed_data)
    signatures = _sequence_of_id_value_pairs([(algo_id, signature_bytes)])

    public_key_der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signer = (
        _sequence_of_length_prefixed([signed_data])
        + struct.pack("<II", min_sdk_version, max_sdk_version)
        + _sequence_of_length_prefixed([signatures, public_key_der])
    )

    signers_sequence = _sequence_of_length_prefixed([signer])
    block_value = _sequence_of_length_prefixed([signers_sequence])
    return block_value, content_digest, algo_id
