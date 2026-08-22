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

from . import rezip, v4sign, zipdata
from .keys import KeyMaterial
from .v2sign import (
    APK_SIGNATURE_SCHEME_V2_BLOCK_ID,
    assemble_apk_signing_block,
    build_v2_signature_scheme_block,
)
from .v3sign import (
    APK_SIGNATURE_SCHEME_V3_BLOCK_ID,
    build_v3_signature_scheme_block,
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


def sign_apk(
    input_path: str,
    output_path: str,
    key_material: KeyMaterial,
    v2: bool = True,
    v3: bool = True,
    v4: bool = False,
    v4_output_path: str = None,
    min_sdk_version: int = None,
) -> dict:
    """Sign an APK with the selected signature schemes.

    v2 and v3 are blocks inside the APK. v4 is a detached `.apk.idsig`
    sidecar that anchors to the v2/v3 content digest, so it requires at
    least one of them.

    Returns a summary dict describing what was written.
    """
    if not (v2 or v3):
        raise ValueError("At least one of the v2 or v3 schemes must be enabled")
    if v4 and not (v2 or v3):
        raise ValueError("v4 signing requires a v2 or v3 signature to anchor to")

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

    id_value_pairs = []
    v2_digest = v3_digest = None
    algo_id = None

    if v2:
        v2_block_value, v2_digest, algo_id = build_v2_signature_scheme_block(
            key_material.private_key,
            key_material.certificate,
            content_sections,
            v3_signing_enabled=v3,
        )
        id_value_pairs.append((APK_SIGNATURE_SCHEME_V2_BLOCK_ID, v2_block_value))

    if v3:
        v3_kwargs = {}
        if min_sdk_version is not None:
            v3_kwargs["min_sdk_version"] = min_sdk_version
        v3_block_value, v3_digest, algo_id = build_v3_signature_scheme_block(
            key_material.private_key,
            key_material.certificate,
            content_sections,
            **v3_kwargs,
        )
        id_value_pairs.append((APK_SIGNATURE_SCHEME_V3_BLOCK_ID, v3_block_value))

    signing_block = assemble_apk_signing_block(id_value_pairs)

    new_central_dir_offset = signing_block_start_offset + len(signing_block)
    final_eocd = zipdata.set_eocd_cd_offset(sections.eocd, new_central_dir_offset)

    with open(output_path, "wb") as f:
        f.write(before_central_dir)
        f.write(signing_block)
        f.write(central_dir)
        f.write(final_eocd)

    result = {"v2": v2, "v3": v3, "v4": False, "idsig_path": None}

    if v4:
        # v4 covers the finished APK, so it must be computed after the file
        # is written. It prefers the v3 digest when both are available.
        idsig_path = v4_output_path or (output_path + ".idsig")
        apk_digest = v3_digest if v3_digest is not None else v2_digest
        v4sign.write_v4_signature(
            output_path,
            idsig_path,
            key_material.private_key,
            key_material.certificate,
            apk_digest,
            algo_id,
        )
        result["v4"] = True
        result["idsig_path"] = idsig_path

    return result
