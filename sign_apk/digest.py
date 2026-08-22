"""APK v2 chunked content digest algorithm.

Per-chunk digest:  HASH(0xa5 || uint32LE(chunk_len) || chunk_bytes)
Top-level digest:  HASH(0x5a || uint32LE(chunk_count) || concat(chunk digests))

Applied independently across three ordered sections: the zip entries content
(everything before the signing block), the central directory, and the EOCD
record (with its central-directory-offset field patched to the signing
block's start offset).

References
----------
Algorithm description ("Integrity-protected contents"):
    https://source.android.com/docs/security/features/apksigning/v2

Checked against apksig ApkSigningBlockUtils.computeOneMbChunkContentDigests(),
including the CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES = 1024 * 1024 constant
and the 0xa5 / 0x5a prefix bytes:
    platform/tools/apksig/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java
    https://android.googlesource.com/platform/tools/apksig/
"""
from __future__ import annotations

import hashlib
import struct

CHUNK_SIZE = 1024 * 1024


def _hash_new(algo_name: str):
    return hashlib.new(algo_name)


def _chunk_digest(algo_name: str, chunk: bytes) -> bytes:
    h = _hash_new(algo_name)
    h.update(b"\xa5")
    h.update(struct.pack("<I", len(chunk)))
    h.update(chunk)
    return h.digest()


def compute_content_digest(algo_name: str, sections: list) -> bytes:
    """sections: list of bytes-like objects digested in order."""
    chunk_digests = []
    for section in sections:
        n = len(section)
        offset = 0
        if n == 0:
            continue
        while offset < n:
            chunk = section[offset : offset + CHUNK_SIZE]
            chunk_digests.append(_chunk_digest(algo_name, chunk))
            offset += len(chunk)

    h = _hash_new(algo_name)
    h.update(b"\x5a")
    h.update(struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        h.update(d)
    return h.digest()
