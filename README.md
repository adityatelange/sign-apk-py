# sign-apk-py

Sign Android APKs with **APK Signature Schemes v2, v3, and v4**, in pure Python.

No `apksigner`, `jarsigner`, `zipalign`, `keytool`, `openssl`, or Android SDK
required — the only dependency is [`cryptography`](https://cryptography.io)
for RSA/EC primitives and X.509 handling. The ZIP surgery, APK Signing Block
construction, and the chunked content-digest algorithm are all implemented
here directly.

Output is verified by Android's own `apksigner`.

## Install

```bash
pip install -e .
```

## Usage

### Sign an APK

```bash
# With an existing PEM key + certificate
sign-apk sign app-unsigned.apk app-signed.apk --key release.pem --cert release.crt

# With a PKCS#12 / .p12 keystore (prompts for the password if omitted)
sign-apk sign app-unsigned.apk app-signed.apk --p12 release.p12

# With no key at all: generates a throwaway self-signed debug key
sign-apk sign app-unsigned.apk app-signed.apk
```

By default both **v2 and v3** blocks are written. Select schemes explicitly
with `--v2` / `--v3` / `--v4`:

```bash
# v2 only (for compatibility with Android 7-8 tooling)
sign-apk sign in.apk out.apk --key k.pem --cert c.crt --v2

# v2 + v3 + a v4 sidecar for incremental install
sign-apk sign in.apk out.apk --key k.pem --cert c.crt --v2 --v3 --v4
# -> writes out.apk and out.apk.idsig
```

`--v4` writes a detached `out.apk.idsig` alongside the APK. It anchors to
the v2/v3 content digest, so it cannot be used on its own.

### Generate a signing key

```bash
sign-apk generate-key release.pem release.crt --common-name "My Release Key"
```

### Verify a signature

```bash
sign-apk verify app-signed.apk
```

```
VALID (APK Signature Scheme v2+v3)
  v2 signer: CN=My Release Key
  v3 signer: CN=My Release Key (SDK 28-2147483647)
```

To verify a v4 sidecar, use apksigner:

```bash
apksigner verify --v4-signature-file app-signed.apk.idsig app-signed.apk
```

## What it does

Signing rewrites the APK into the layout the v2 scheme requires:

```
[ ZIP entries ]  [ APK Signing Block ]  [ Central Directory ]  [ EOCD ]
                          ^                                      ^
                   signature lives here          central-dir offset patched to match
```

Along the way it:

- **Strips stale signatures** — old `META-INF/*.SF` / `*.RSA` / `*.DSA` / `*.EC`
  entries and any previous APK Signing Block (v2 or v3) are removed, so
  re-signing replaces rather than accumulates. `MANIFEST.MF` is left alone.
- **Never recompresses** — entry payloads are copied verbatim, so contents and
  compression methods are bit-for-bit preserved.
- **Preserves alignment** — uncompressed entries are re-emitted at 4-byte
  aligned offsets, and uncompressed `.so` libraries at 16 KB, matching
  `zipalign -P 16`. Android memory-maps these directly, so misalignment can
  break native library loading at runtime.

Key selection follows apksigner's rules: RSA keys ≤3072 bits use
SHA-256 (`0x0103`), larger ones SHA-512 (`0x0104`); EC keys use SHA-256
(`0x0201`) or SHA-512 (`0x0202`) by curve size.

## Scope and limitations

- **No v1 (JAR) signing**, so APKs installing on **Android 6 and below will
  not verify**. v2 covers Android 7+, v3 Android 9+.
- **No key rotation.** The v3 block is written with a single signer and no
  proof-of-rotation lineage, which is the common case for apps that are not
  rotating keys. Rotation (and the v3.1 block that targets it at a minimum
  SDK) is not implemented.
- **One signer per APK.** The format allows several; this writes a single one.
- **Whole file is read into memory.** Fine for typical APKs (an 89 MB app
  signs in about half a second), but not suited to very large files on
  memory-constrained machines.
- **No ZIP64.** APKs above 4 GB, or with more than 65535 entries, are not
  supported.
- `sign-apk verify` is a self-check, not a full reimplementation of Android's
  verifier. It checks v2 and v3 signatures and content digests, but does not
  validate certificate chains, expiry, SDK-range coverage across signers,
  rotation lineages, or v4 sidecars. Use `apksigner verify` when you need an
  authoritative answer.

## References

The binary formats implemented here are specified by Android and PKWARE.
Where this code reproduces a layout, constant, or algorithm, the relevant
module docstring cites the specific upstream file and function.

- **APK Signature Scheme v2** —
  [source.android.com/docs/security/features/apksigning/v2](https://source.android.com/docs/security/features/apksigning/v2)
  — scheme overview, file layout, and the integrity-protected-contents
  digest algorithm.
- **APK Signature Scheme v3** —
  [source.android.com/docs/security/features/apksigning/v3](https://source.android.com/docs/security/features/apksigning/v3)
  — the SDK version range and proof-of-rotation additions to v2.
- **APK Signature Scheme v4** —
  [source.android.com/docs/security/features/apksigning/v4](https://source.android.com/docs/security/features/apksigning/v4)
  — the detached `.idsig` sidecar and its fs-verity Merkle tree.
- **fs-verity** —
  [kernel.org/doc/html/latest/filesystems/fsverity.html](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html)
  — the Merkle tree construction v4 builds on.
- **AOSP `apksig`** —
  [android.googlesource.com/platform/tools/apksig](https://android.googlesource.com/platform/tools/apksig/)
  — the reference implementation, and the authority for every byte layout
  used here. Chiefly `V2SchemeSigner.java` and `V3SchemeSigner.java`
  (signer and signed-data structure), `V4SchemeSigner.java` /
  `V4Signature.java` (sidecar format and signed data),
  `VerityTreeBuilder.java` (Merkle tree), `ApkSigningBlockUtils.java`
  (signing block framing, chunked digests, alignment padding),
  `SignatureAlgorithm.java` (algorithm IDs), `ZipUtils.java` (EOCD scan),
  and `ApkUtilsLite.java` (signing block location).
- **PKWARE `.ZIP` File Format Specification, APPNOTE 6.3.1** —
  [pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT)
  — local file header, central directory, data descriptor, and EOCD
  record layouts.
- **Android 16 KB page sizes** —
  [developer.android.com/guide/practices/page-sizes](https://developer.android.com/guide/practices/page-sizes)
  — why uncompressed native libraries are aligned to 16 KB.

This project is an independent implementation written against those
specifications. It is not affiliated with or endorsed by Google or PKWARE.

## Testing

```bash
python -m pytest tests/
```

The suite covers RSA and EC signing across v2/v3/v4, PKCS#12 and PEM
loading, re-signing, content preservation, alignment, Merkle tree
construction, and tamper detection. Where `apksigner` is on `PATH`, tests
additionally assert that it accepts the output and rejects tampered files;
those tests skip when it is absent.

One test asserts that our Merkle tree reproduces `apksigner`'s **byte for
byte** — given the same input file, the tree bytes and root hash match
exactly.

Verified against Android `apksigner` on a real 89 MB production APK
(originally v3-signed): all 1622 entries byte-identical after re-signing,
`zipalign -c -P 16` clean, `v2 scheme: true` on SDK 24-27, and
`v3 scheme: true` / `v4 scheme: true` on SDK 28+.
