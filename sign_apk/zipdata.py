"""Low-level ZIP structure parsing: locate EOCD, Central Directory, and an
existing APK Signing Block (if any) within an APK/ZIP file's raw bytes.

Implements the backward-scan EOCD search, guarding against comment bytes
that coincidentally contain the EOCD signature.

References
----------
Record layouts (EOCD sections 4.3.16, central directory 4.3.12):
    PKWARE .ZIP File Format Specification, APPNOTE 6.3.1
    https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT

EOCD scan and field offsets, ported from:
    apksig ZipUtils.findZipEndOfCentralDirectoryRecord()
    platform/tools/apksig/src/main/java/com/android/apksig/internal/zip/ZipUtils.java

Signing block location and header/footer size validation, ported from:
    apksig ApkUtilsLite.findApkSigningBlock()
    platform/tools/apksig/src/main/java/com/android/apksig/apk/ApkUtilsLite.java

    apksig sources: https://android.googlesource.com/platform/tools/apksig/
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

EOCD_SIG = 0x06054B50
EOCD_MIN_SIZE = 22
EOCD_COMMENT_LEN_OFFSET = 20
EOCD_CD_OFFSET_OFFSET = 16
EOCD_CD_SIZE_OFFSET = 12

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIG_BLOCK_MIN_SIZE = 32


class ZipFormatError(Exception):
    pass


@dataclass
class ZipSections:
    """Byte offsets/sizes of the three logical regions of a ZIP/APK file."""

    central_dir_offset: int
    central_dir_size: int
    eocd_offset: int
    eocd: bytes  # raw EOCD record bytes (including comment)


def find_eocd(data: bytes) -> ZipSections:
    """Locate the End of Central Directory record via backward scan.

    Mirrors apksig's ZipUtils.findZipEndOfCentralDirectoryRecord: scan
    backwards allowing for a comment of increasing assumed length, and only
    accept a signature match whose own comment-length field agrees with the
    number of trailing bytes actually implied.
    """
    archive_size = len(data)
    if archive_size < EOCD_MIN_SIZE:
        raise ZipFormatError("File too small to contain an EOCD record")

    max_comment_length = min(archive_size - EOCD_MIN_SIZE, 0xFFFF)
    eocd_with_empty_comment_start = archive_size - EOCD_MIN_SIZE

    for expected_comment_length in range(0, max_comment_length + 1):
        eocd_start = eocd_with_empty_comment_start - expected_comment_length
        sig = struct.unpack_from("<I", data, eocd_start)[0]
        if sig == EOCD_SIG:
            actual_comment_length = struct.unpack_from(
                "<H", data, eocd_start + EOCD_COMMENT_LEN_OFFSET
            )[0]
            if actual_comment_length == expected_comment_length:
                eocd_bytes = data[eocd_start:]
                cd_size, cd_offset = struct.unpack_from(
                    "<II", eocd_bytes, EOCD_CD_SIZE_OFFSET
                )
                return ZipSections(
                    central_dir_offset=cd_offset,
                    central_dir_size=cd_size,
                    eocd_offset=eocd_start,
                    eocd=eocd_bytes,
                )

    raise ZipFormatError("Could not find End of Central Directory record")


def set_eocd_cd_offset(eocd: bytes, new_offset: int) -> bytes:
    """Return a copy of an EOCD record with the central-dir-offset field patched."""
    patched = bytearray(eocd)
    struct.pack_into("<I", patched, EOCD_CD_OFFSET_OFFSET, new_offset)
    return bytes(patched)


@dataclass
class ExistingSigningBlock:
    offset: int
    total_size: int
    id_value_pairs: list  # list[tuple[int, bytes]]


def find_existing_signing_block(data: bytes, sections: ZipSections):
    """Locate an existing APK Signing Block immediately preceding the Central
    Directory, if present. Returns None if there is no valid signing block
    (i.e. the region before the CD is plain zip entry content).
    """
    cd_start = sections.central_dir_offset
    if cd_start < 24:
        return None

    footer = data[cd_start - 24 : cd_start]
    size_in_footer, magic = struct.unpack_from("<Q16s", footer, 0)
    if magic != APK_SIG_BLOCK_MAGIC:
        return None

    total_size = size_in_footer + 8
    block_offset = cd_start - total_size
    if block_offset < 0:
        return None

    size_in_header = struct.unpack_from("<Q", data, block_offset)[0]
    if size_in_header != size_in_footer:
        return None

    pairs = []
    pos = block_offset + 8
    pairs_end = cd_start - 24
    while pos < pairs_end:
        pair_len = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
        pair_id = struct.unpack_from("<I", data, pos)[0]
        value = data[pos + 4 : pos + pair_len]
        pairs.append((pair_id, value))
        pos += pair_len

    return ExistingSigningBlock(
        offset=block_offset, total_size=total_size, id_value_pairs=pairs
    )
