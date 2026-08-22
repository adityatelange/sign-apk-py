"""High-level orchestration: take an input APK, a key/certificate, and
produce a v2-signed output APK.

The output layout is:

    [ zip entries ] [ APK Signing Block ] [ central directory ] [ EOCD ]

with the EOCD's central-directory-offset field pointing past the inserted
signing block. Note that the digest is computed over the EOCD with that
field set to the signing block's start offset, which is the same value the
final EOCD carries.

References
----------
File layout and signing procedure:
    https://source.android.com/docs/security/features/apksigning/v2

Assembly order and EOCD offset patching follow apksig ApkSigner.java:
    platform/tools/apksig/src/main/java/com/android/apksig/ApkSigner.java
    https://android.googlesource.com/platform/tools/apksig/
"""
from __future__ import annotations

import struct

from . import rezip, zipdata
from .keys import KeyMaterial
from .v2sign import (
    APK_SIGNATURE_SCHEME_V2_BLOCK_ID,
    assemble_apk_signing_block,
    build_v2_signature_scheme_block,
)


def _find_v1_signature_files(data: bytes, central_dir_offset: int) -> set:
    """Names of stale v1 (JAR) signature entries to drop before re-signing.

    MANIFEST.MF is left in place: it is not itself a signature, and some
    apps read it at runtime.
    """
    strip_suffixes = (".SF", ".RSA", ".DSA", ".EC")
    names = set()
    for name in _iter_entry_names(data, central_dir_offset):
        if name == "META-INF/MANIFEST.MF":
            continue
        if name.startswith("META-INF/") and name.upper().endswith(strip_suffixes):
            names.add(name)
    return names


def _iter_entry_names(data: bytes, central_dir_offset: int):
    """Yield entry names by walking the central directory."""
    pos = central_dir_offset
    while pos + 46 <= len(data):
        if struct.unpack_from("<I", data, pos)[0] != 0x02014B50:
            break
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        name = data[pos + 46 : pos + 46 + name_len]
        yield name.decode("utf-8", "replace")
        pos += 46 + name_len + extra_len + comment_len


def sign_apk(input_path: str, output_path: str, key_material: KeyMaterial) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    sections = zipdata.find_eocd(data)

    # Rebuild the zip: drops stale v1 signature entries and any previous APK
    # Signing Block, re-emits entries at aligned offsets, and leaves the
    # entry payloads byte-identical (never recompressed).
    drop_names = _find_v1_signature_files(data, sections.central_dir_offset)
    data = rezip.rebuild_zip(data, sections.central_dir_offset, drop_names)

    sections = zipdata.find_eocd(data)
    before_central_dir = data[: sections.central_dir_offset]
    central_dir = data[
        sections.central_dir_offset : sections.central_dir_offset + sections.central_dir_size
    ]

    signing_block_start_offset = len(before_central_dir)

    eocd_for_digest = zipdata.set_eocd_cd_offset(sections.eocd, signing_block_start_offset)

    content_sections = [before_central_dir, central_dir, eocd_for_digest]

    v2_block_value = build_v2_signature_scheme_block(
        key_material.private_key, key_material.certificate, content_sections
    )

    signing_block = assemble_apk_signing_block(
        [(APK_SIGNATURE_SCHEME_V2_BLOCK_ID, v2_block_value)]
    )

    new_central_dir_offset = signing_block_start_offset + len(signing_block)
    final_eocd = zipdata.set_eocd_cd_offset(sections.eocd, new_central_dir_offset)

    with open(output_path, "wb") as f:
        f.write(before_central_dir)
        f.write(signing_block)
        f.write(central_dir)
        f.write(final_eocd)
