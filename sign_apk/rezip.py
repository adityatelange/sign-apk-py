"""Rebuild a ZIP/APK while dropping selected entries, preserving each
surviving entry's raw (already-compressed) bytes and honouring Android's
alignment requirements.

This deliberately avoids Python's zipfile writer for the output: zipfile
recompresses entries and does not insert the local-header padding that
Android relies on. Entries stored uncompressed must begin at an aligned
file offset because Android memory-maps them directly - 4 bytes in
general, and 4096/16384 for uncompressed native libraries so they can be
mapped on devices with larger page sizes.

References
----------
Record layouts (local file header 4.3.7, central directory 4.3.12,
data descriptor 4.3.9):
    PKWARE .ZIP File Format Specification, APPNOTE 6.3.1
    https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT

Alignment behaviour mirrors the zipalign tool, which pads via a local
header extra field; ALIGNMENT_EXTRA_ID (0xd935) is apksig's
ALIGNMENT_EXTRA_FIELD_HEADER_ID / zipalign's padding field:
    platform/tools/apksig/src/main/java/com/android/apksig/ApkSigner.java
    (see also ANDROID_COMMON_PAGE_ALIGNMENT_BYTES and
    LIBRARY_PAGE_ALIGNMENT_BYTES in internal/apk/ApkSigningBlockUtils.java
    and Constants.java)
    https://android.googlesource.com/platform/tools/apksig/

16KB page-size requirement for uncompressed native libraries:
    https://developer.android.com/guide/practices/page-sizes
"""
from __future__ import annotations

import struct

LFH_SIG = 0x04034B50
CFH_SIG = 0x02014B50

STORED = 0

DEFAULT_ALIGNMENT = 4
# Uncompressed native libraries are mapped directly; align them to the
# largest common Android page size so 4KB and 16KB page devices both work.
SO_ALIGNMENT = 16384

ALIGNMENT_EXTRA_ID = 0xD935  # Android "zipalign" padding extra field


def _alignment_for(name: str, compress_type: int) -> int:
    """Return the required start alignment for an entry's data."""
    if compress_type != STORED:
        # Compressed entries are streamed, not mapped, so they need no alignment.
        return 1
    if name.endswith(".so"):
        return SO_ALIGNMENT
    return DEFAULT_ALIGNMENT


def _strip_alignment_extra(extra: bytes) -> bytes:
    """Drop any existing zipalign padding extra fields, keeping other extras.

    Padding must be recomputed for the new offsets, and stale padding
    fields would otherwise accumulate on repeated re-signing.
    """
    out = bytearray()
    pos = 0
    while pos + 4 <= len(extra):
        field_id, size = struct.unpack_from("<HH", extra, pos)
        field = extra[pos : pos + 4 + size]
        if field_id != ALIGNMENT_EXTRA_ID:
            out += field
        pos += 4 + size
    return bytes(out)


def rebuild_zip(data: bytes, central_dir_offset: int, drop_names: set) -> bytes:
    """Rebuild the zip in `data`, omitting entries named in `drop_names`.

    Entry data is copied verbatim from the source (never recompressed), and
    local headers are re-emitted with padding so that stored entries land on
    aligned offsets. Returns the bytes up to (but excluding) the central
    directory, followed by a freshly written central directory and EOCD.
    """
    out = bytearray()
    central_records = []
    entries_written = 0

    pos = 0
    while pos < central_dir_offset:
        sig = struct.unpack_from("<I", data, pos)[0]
        if sig != LFH_SIG:
            break

        (
            version_needed,
            flags,
            compress_type,
            mod_time,
            mod_date,
            crc,
            comp_size,
            uncomp_size,
            name_len,
            extra_len,
        ) = struct.unpack_from("<HHHHHIIIHH", data, pos + 4)

        name = data[pos + 30 : pos + 30 + name_len]
        extra = data[pos + 30 + name_len : pos + 30 + name_len + extra_len]
        data_start = pos + 30 + name_len + extra_len
        data_end = data_start + comp_size

        # Advance past this entry (plus any data descriptor) before deciding
        # whether to keep it, so `continue` still lands on the next entry.
        next_pos = data_end
        if flags & 0x08:
            # Data descriptor: optional signature, then crc/sizes.
            if struct.unpack_from("<I", data, next_pos)[0] == 0x08074B50:
                next_pos += 4
            next_pos += 12

        decoded_name = name.decode("utf-8", "replace")
        if decoded_name in drop_names:
            pos = next_pos
            continue

        payload = data[data_start:data_end]

        base_extra = _strip_alignment_extra(extra)
        alignment = _alignment_for(decoded_name, compress_type)

        local_header_offset = len(out)
        header_end = local_header_offset + 30 + name_len + len(base_extra)

        pad = 0
        if alignment > 1:
            misalign = header_end % alignment
            if misalign:
                pad = alignment - misalign
            if pad and pad < 4:
                # An extra field needs a 4-byte header, so a sub-4-byte gap
                # cannot be expressed; take a full extra alignment step.
                pad += alignment

        if pad:
            new_extra = base_extra + struct.pack(
                "<HH", ALIGNMENT_EXTRA_ID, pad - 4
            ) + b"\x00" * (pad - 4)
        else:
            new_extra = base_extra

        out += struct.pack(
            "<IHHHHHIIIHH",
            LFH_SIG,
            version_needed,
            flags,
            compress_type,
            mod_time,
            mod_date,
            crc,
            comp_size,
            uncomp_size,
            name_len,
            len(new_extra),
        )
        out += name
        out += new_extra
        out += payload

        if flags & 0x08:
            out += data[data_end:next_pos]

        central_records.append(
            {
                "name": name,
                "local_header_offset": local_header_offset,
                "version_needed": version_needed,
                "flags": flags,
                "compress_type": compress_type,
                "mod_time": mod_time,
                "mod_date": mod_date,
                "crc": crc,
                "comp_size": comp_size,
                "uncomp_size": uncomp_size,
            }
        )
        entries_written += 1
        pos = next_pos

    # Carry over per-entry central directory metadata that has no local
    # header equivalent (attributes, comments) by reading the original CD.
    cd_meta = _read_central_directory(data, central_dir_offset)

    cd = bytearray()
    for rec in central_records:
        meta = cd_meta.get(rec["name"], {})
        cd_extra = _strip_alignment_extra(meta.get("extra", b""))
        comment = meta.get("comment", b"")
        cd += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            CFH_SIG,
            meta.get("version_made_by", 20),
            rec["version_needed"],
            rec["flags"],
            rec["compress_type"],
            rec["mod_time"],
            rec["mod_date"],
            rec["crc"],
            rec["comp_size"],
            rec["uncomp_size"],
            len(rec["name"]),
            len(cd_extra),
            len(comment),
            0,
            meta.get("internal_attrs", 0),
            meta.get("external_attrs", 0),
            rec["local_header_offset"],
        )
        cd += rec["name"]
        cd += cd_extra
        cd += comment

    cd_start = len(out)
    out += cd

    out += struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        entries_written,
        entries_written,
        len(cd),
        cd_start,
        0,
    )
    return bytes(out)


def _read_central_directory(data: bytes, central_dir_offset: int) -> dict:
    """Map entry name -> central directory metadata from the original zip."""
    meta = {}
    pos = central_dir_offset
    while pos + 46 <= len(data):
        if struct.unpack_from("<I", data, pos)[0] != CFH_SIG:
            break
        (
            version_made_by,
            _version_needed,
            _flags,
            _compress_type,
            _mod_time,
            _mod_date,
            _crc,
            _comp_size,
            _uncomp_size,
            name_len,
            extra_len,
            comment_len,
            _disk,
            internal_attrs,
            external_attrs,
            _lho,
        ) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, pos + 4)

        name = data[pos + 46 : pos + 46 + name_len]
        extra = data[pos + 46 + name_len : pos + 46 + name_len + extra_len]
        comment_start = pos + 46 + name_len + extra_len
        comment = data[comment_start : comment_start + comment_len]

        meta[name] = {
            "version_made_by": version_made_by,
            "extra": extra,
            "comment": comment,
            "internal_attrs": internal_attrs,
            "external_attrs": external_attrs,
        }
        pos = comment_start + comment_len
    return meta
