"""APK Signature Scheme v4: detached `.apk.idsig` sidecar.

Unlike v2 and v3, v4 stores nothing inside the APK. It writes a separate
file containing an fs-verity Merkle tree over the APK plus a signature, and
anchors to the APK's v2/v3 content digest. Android uses it for incremental
installation (`adb install --incremental`).

File format (all integers little-endian; LP = uint32 length prefix):

    uint32 version = 2
    LP hashing_info
    LP signing_infos
    LP verity_tree

    hashing_info:
        uint32 hash_algorithm = 1      (SHA-256)
        uint8  log2_blocksize = 12     (4096; ONE byte, not uint32)
        LP     salt                    (empty for fs-verity compatibility)
        LP     raw_root_hash           (32 bytes)

    signing_info:
        LP     apk_digest
        LP     certificate             (X.509 DER)
        LP     additional_data         (empty)
        LP     public_key              (SubjectPublicKeyInfo DER)
        uint32 signature_algorithm_id  (bare)
        LP     signature

Two details differ from the v2/v3 conventions and are easy to get wrong:

  * The Merkle tree covers the entire APK file verbatim, including the APK
    Signing Block, with no EOCD offset substitution. This is the opposite of
    the v2/v3 content digest, which excludes the signing block and rewrites
    the EOCD central-directory offset.
  * v4's tree uses NO salt, while the v2/v3 VERITY_CHUNKED_SHA256 content
    digest uses 8 zero bytes as salt. Same tree construction, different salt.

What gets signed is not signing_info minus the signature; it is a distinct
structure built by getSignedData() - see _build_signed_data below.

References
----------
Scheme overview:
    https://source.android.com/docs/security/features/apksigning/v4

Checked against AOSP apksig
(https://android.googlesource.com/platform/tools/apksig/), Android's
reference implementation, under src/main/java/com/android/apksig/:

    internal/apk/v4/V4SchemeSigner.java
        generateV4Signature() - tree construction, null salt, digest choice
    internal/apk/v4/V4Signature.java
        writeTo(), HashingInfo.toByteArray(), SigningInfo.toByteArray(),
        and getSignedData() - the signed structure
    internal/util/VerityTreeBuilder.java
        level sizing, 4096-byte chunking, zero padding, and
        getRootHashFromTree()

fs-verity itself:
    https://www.kernel.org/doc/html/latest/filesystems/fsverity.html
"""
from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives import serialization

from .v2sign import _select_algorithm

CURRENT_VERSION = 2

HASH_ALGORITHM_SHA256 = 1
LOG2_BLOCK_SIZE = 12
BLOCK_SIZE = 1 << LOG2_BLOCK_SIZE  # 4096
DIGEST_SIZE = 32  # SHA-256 output


def _lp(data: bytes) -> bytes:
    """uint32 length prefix followed by the bytes. None encodes as length 0."""
    if data is None:
        return struct.pack("<I", 0)
    return struct.pack("<I", len(data)) + data


def _digest_data_by_chunks(src: bytes) -> bytes:
    """Hash `src` in 4096-byte blocks, zero-padding the final partial block.

    Returns the concatenated 32-byte digests. The final block is padded to a
    full 4096 bytes before hashing, matching VerityTreeBuilder's use of a
    zero-filled buffer.
    """
    out = bytearray()
    for offset in range(0, len(src), BLOCK_SIZE):
        chunk = src[offset : offset + BLOCK_SIZE]
        if len(chunk) < BLOCK_SIZE:
            chunk = chunk + b"\x00" * (BLOCK_SIZE - len(chunk))
        out += hashlib.sha256(chunk).digest()
    return bytes(out)


def _calculate_level_sizes(data_size: int) -> list:
    """Sizes in bytes of each Merkle tree level, ordered root level first.

    Each level is padded up to a whole number of 4096-byte blocks.
    """
    levels = []
    size = data_size
    while True:
        chunk_count = (size + BLOCK_SIZE - 1) // BLOCK_SIZE
        level_bytes = chunk_count * DIGEST_SIZE
        # Round the level up to whole blocks.
        padded = ((level_bytes + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        levels.append(padded)
        if level_bytes <= BLOCK_SIZE:
            break
        size = level_bytes
    levels.reverse()  # root level first
    return levels


def build_verity_tree(data: bytes) -> tuple:
    """Build the fs-verity Merkle tree over `data`.

    Returns (tree_bytes, root_hash). The tree is laid out root level first;
    the root hash is SHA-256 over the whole first 4096-byte block, including
    its zero padding - not merely over the first 32 bytes.
    """
    level_sizes = _calculate_level_sizes(len(data))
    total = sum(level_sizes)
    tree = bytearray(total)

    # Offsets of each level within the buffer.
    offsets = []
    running = 0
    for size in level_sizes:
        offsets.append(running)
        running += size
    offsets.append(running)

    # Build bottom-up: the last level hashes the file, each level above
    # hashes the padded bytes of the level below it.
    for level in range(len(level_sizes) - 1, -1, -1):
        if level == len(level_sizes) - 1:
            src = data
        else:
            src = bytes(tree[offsets[level + 1] : offsets[level + 2]])
        digests = _digest_data_by_chunks(src)
        tree[offsets[level] : offsets[level] + len(digests)] = digests

    root_hash = hashlib.sha256(bytes(tree[:BLOCK_SIZE])).digest()
    return bytes(tree), root_hash


def _build_hashing_info(root_hash: bytes, salt: bytes = None) -> bytes:
    return (
        struct.pack("<I", HASH_ALGORITHM_SHA256)
        + struct.pack("<B", LOG2_BLOCK_SIZE)
        + _lp(salt)
        + _lp(root_hash)
    )


def _build_signed_data(
    file_size: int,
    root_hash: bytes,
    apk_digest: bytes,
    cert_der: bytes,
    salt: bytes = None,
    additional_data: bytes = None,
) -> bytes:
    """The bytes actually signed for v4.

    This is a purpose-built structure, not signing_info with the signature
    omitted: it interleaves hashing_info and signing_info fields, prepends a
    self-inclusive uint32 size, and carries the file size as an int64. The
    public key, algorithm ID, and signature are deliberately excluded.
    """
    body = (
        struct.pack("<q", file_size)
        + struct.pack("<I", HASH_ALGORITHM_SHA256)
        + struct.pack("<B", LOG2_BLOCK_SIZE)
        + _lp(salt)
        + _lp(root_hash)
        + _lp(apk_digest)
        + _lp(cert_der)
        + _lp(additional_data)
    )
    # The size field counts itself.
    return struct.pack("<I", len(body) + 4) + body


def build_v4_signature(
    apk_bytes: bytes,
    private_key,
    certificate,
    apk_digest: bytes,
    algo_id: int,
) -> bytes:
    """Build the full `.idsig` file contents for `apk_bytes`.

    `apk_digest` is the APK's v2/v3 content digest (v3 preferred), and
    `algo_id` the signature algorithm ID that produced it.
    """
    tree, root_hash = build_verity_tree(apk_bytes)

    cert_der = certificate.public_bytes(serialization.Encoding.DER)

    signed_data = _build_signed_data(
        file_size=len(apk_bytes),
        root_hash=root_hash,
        apk_digest=apk_digest,
        cert_der=cert_der,
    )

    _sig_algo_id, _digest_name, sign_fn = _select_algorithm(private_key)
    signature = sign_fn(signed_data)

    public_key_der = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signing_info = (
        _lp(apk_digest)
        + _lp(cert_der)
        + _lp(None)  # additional_data
        + _lp(public_key_der)
        + struct.pack("<I", algo_id)
        + _lp(signature)
    )

    hashing_info = _build_hashing_info(root_hash)

    return (
        struct.pack("<I", CURRENT_VERSION)
        + _lp(hashing_info)
        + _lp(signing_info)
        + _lp(tree)
    )


def write_v4_signature(
    apk_path: str,
    idsig_path: str,
    private_key,
    certificate,
    apk_digest: bytes,
    algo_id: int,
) -> None:
    """Write the `.idsig` sidecar for an already-signed APK."""
    with open(apk_path, "rb") as f:
        apk_bytes = f.read()

    idsig = build_v4_signature(
        apk_bytes, private_key, certificate, apk_digest, algo_id
    )

    with open(idsig_path, "wb") as f:
        f.write(idsig)
