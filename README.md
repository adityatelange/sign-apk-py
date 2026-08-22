# sign-apk-py

[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)

Sign Android APKs with **APK Signature Schemes v2, v3, and v4**, in pure Python.

No `apksigner`, `jarsigner`, `zipalign`, `keytool`, `openssl`, or Android SDK
required. The only dependency is [`cryptography`](https://cryptography.io)
for RSA/EC primitives and X.509 handling. The ZIP surgery, APK Signing Block
construction, and the chunked content-digest algorithm are all implemented
here directly, and the output is verified against Android's own `apksigner`.

## Features

- **v2, v3, and v4 signing** in one tool, no JDK or Android SDK install
- **Zero-config debug signing**: generates a throwaway self-signed key if you
  don't have one
- **PKCS#12 and PEM key support** for release signing
- **Byte-for-byte preservation** of entry contents and compression, so
  signing never touches your app's actual payload
- **zipalign-compatible output**: 4-byte and 16 KB alignment are preserved,
  so a separate `zipalign` pass isn't needed
- **Built-in verifier** for a fast sanity check without shelling out

## Install

Requires Python 3.9+. Not published on PyPI yet, so install straight from
the git repo as a standalone CLI:

```bash
# uv
uv tool install git+https://github.com/adityatelange/sign-apk-py

# pipx
pipx install git+https://github.com/adityatelange/sign-apk-py
```

Either way, this puts `sign-apk` on your `PATH`, isolated from your other
Python environments.

To hack on it instead, clone and install editable:

```bash
git clone https://github.com/adityatelange/sign-apk-py.git
cd sign-apk-py
uv pip install -e ".[dev]"   # or: pip install -e ".[dev]"
```

## Usage

Three subcommands: `sign`, `generate-key`, and `verify`.

### Quickstart

No key yet? Just sign. A throwaway debug key is generated on the fly:

```bash
sign-apk sign app-unsigned.apk app-signed.apk
```

For a real release, pass a key and certificate:

```bash
sign-apk sign app-unsigned.apk app-signed.apk --key release.pem --cert release.crt
```

### Sign an APK

```
sign-apk sign INPUT OUTPUT [key options] [scheme options]
```

**Key options**, in priority order (first match wins):

| Flag | Description |
| --- | --- |
| `--p12 PATH` | PKCS#12 keystore (`.p12`/`.pfx`) |
| `--p12-password PASS` | Password for `--p12` (prompted if omitted) |
| `--key PATH --cert PATH` | PEM private key + PEM certificate pair |
| `--key-password PASS` | Password for an encrypted `--key` |
| *(none of the above)* | Generates a throwaway self-signed debug key |
| `--save-debug-key PREFIX` | Saves the generated debug key as `PREFIX.pem` / `PREFIX.crt`, for reuse across builds |

```bash
# PKCS#12 / .p12 keystore (prompts for the password if omitted)
sign-apk sign app-unsigned.apk app-signed.apk --p12 release.p12

# Debug key, saved for next time
sign-apk sign app-unsigned.apk app-signed.apk --save-debug-key debug
sign-apk sign app-unsigned.apk app-signed.apk --key debug.pem --cert debug.crt
```

**Scheme options**, all optional:

| Flag | Description |
| --- | --- |
| `--v2` | Emit an APK Signature Scheme v2 block |
| `--v3` | Emit an APK Signature Scheme v3 block |
| `--v4` | Write a detached `.apk.idsig` sidecar (requires `--v2` and/or `--v3`) |
| `--v4-out PATH` | Path for the v4 sidecar (default: `OUTPUT.idsig`) |
| `--min-sdk-version N` | `minSdkVersion` recorded in the v3 signer (default: 28) |

With none of `--v2`/`--v3`/`--v4` given, **both v2 and v3 are written**.
Pass any of them explicitly to take full control:

```bash
# v2 only, for compatibility with Android 7-8 tooling
sign-apk sign in.apk out.apk --key k.pem --cert c.crt --v2

# v2 + v3 + a v4 sidecar for incremental install
sign-apk sign in.apk out.apk --key k.pem --cert c.crt --v2 --v3 --v4
# -> writes out.apk and out.apk.idsig
```

`--v4` anchors to the v2/v3 content digest, so it cannot be used on its own.

### Generate a signing key

Generates a self-signed RSA key/certificate pair, independent of signing:

```bash
sign-apk generate-key release.pem release.crt --common-name "My Release Key"
```

| Flag | Description |
| --- | --- |
| `--common-name NAME` | Certificate CN (default: `Android Debug`) |
| `--key-size BITS` | RSA key size (default: `2048`) |

### Verify a signature

```bash
sign-apk verify app-signed.apk
```

```
VALID (APK Signature Scheme v2+v3)
  v2 signer: CN=My Release Key
  v3 signer: CN=My Release Key (SDK 28-2147483647)
```

Exits with status 1 and prints `INVALID: <reason>` on failure, so it's
usable directly in CI.

This is a self-check on this tool's own output, not a full
reimplementation of Android's verifier (see [Scope and
limitations](#scope-and-limitations)), and it doesn't cover v4 sidecars.
To verify one of those, use apksigner instead:

```bash
apksigner verify --v4-signature-file app-signed.apk.idsig app-signed.apk
```

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

## Testing

```bash
python -m pytest tests/
```

The suite covers RSA and EC signing across v2/v3/v4, PKCS#12 and PEM
loading, re-signing, content preservation, alignment, Merkle tree
construction, and tamper detection. Where `apksigner` is on `PATH`, tests
additionally assert that it accepts the output and rejects tampered files;
those tests skip when it is absent.

One test asserts that this project's Merkle tree reproduces `apksigner`'s
**byte for byte**: given the same input file, the tree bytes and root hash
match exactly.

Verified against Android `apksigner` on a real 89 MB production APK
(originally v3-signed): all 1622 entries byte-identical after re-signing,
`zipalign -c -P 16` clean, `v2 scheme: true` on SDK 24-27, and
`v3 scheme: true` / `v4 scheme: true` on SDK 28+.

## How it works

Signing rewrites the APK into the layout the v2/v3 schemes require:

```
[ ZIP entries ]  [ APK Signing Block ]  [ Central Directory ]  [ EOCD ]
                          ^                                      ^
                   signature lives here          central-dir offset patched to match
```

Along the way it:

- **Strips stale signatures**: old `META-INF/*.SF` / `*.RSA` / `*.DSA` / `*.EC`
  entries and any previous APK Signing Block (v2 or v3) are removed, so
  re-signing replaces rather than accumulates. `MANIFEST.MF` is left alone.
- **Never recompresses**: entry payloads are copied verbatim, so contents and
  compression methods are bit-for-bit preserved.
- **Preserves alignment**: uncompressed entries are re-emitted at 4-byte
  aligned offsets, and uncompressed `.so` libraries at 16 KB, matching
  `zipalign -P 16`. Android memory-maps these directly, so misalignment can
  break native library loading at runtime.

Key selection follows apksigner's rules: RSA keys under 3072 bits use
SHA-256 (`0x0103`), larger ones SHA-512 (`0x0104`); EC keys use SHA-256
(`0x0201`) or SHA-512 (`0x0202`) by curve size.

## References

The binary formats implemented here are specified by Android and PKWARE.
Each module docstring cites the specification for the layout, constants,
and algorithms it implements, along with the corresponding upstream file
and function for cross-checking.

- **APK Signature Scheme v2**:
  [source.android.com/docs/security/features/apksigning/v2](https://source.android.com/docs/security/features/apksigning/v2),
  scheme overview, file layout, and the integrity-protected-contents
  digest algorithm.
- **APK Signature Scheme v3**:
  [source.android.com/docs/security/features/apksigning/v3](https://source.android.com/docs/security/features/apksigning/v3),
  the SDK version range and proof-of-rotation additions to v2.
- **APK Signature Scheme v4**:
  [source.android.com/docs/security/features/apksigning/v4](https://source.android.com/docs/security/features/apksigning/v4),
  the detached `.idsig` sidecar and its fs-verity Merkle tree.
- **fs-verity**:
  [kernel.org/doc/html/latest/filesystems/fsverity.html](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html),
  the Merkle tree construction v4 builds on.
- **AOSP `apksig`**:
  [android.googlesource.com/platform/tools/apksig](https://android.googlesource.com/platform/tools/apksig/),
  Android's reference implementation (Apache 2.0). Consulted where the
  prose specifications are ambiguous, and the interoperability target this
  code has to match — no code from it is copied or translated here. The
  corresponding files, useful for checking this implementation against, are
  chiefly `V2SchemeSigner.java` and `V3SchemeSigner.java`
  (signer and signed-data structure), `V4SchemeSigner.java` /
  `V4Signature.java` (sidecar format and signed data),
  `VerityTreeBuilder.java` (Merkle tree), `ApkSigningBlockUtils.java`
  (signing block framing, chunked digests, alignment padding),
  `SignatureAlgorithm.java` (algorithm IDs), `ZipUtils.java` (EOCD scan),
  and `ApkUtilsLite.java` (signing block location).
- **PKWARE `.ZIP` File Format Specification, APPNOTE 6.3.1**:
  [pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT),
  local file header, central directory, data descriptor, and EOCD
  record layouts.
- **Android 16 KB page sizes**:
  [developer.android.com/guide/practices/page-sizes](https://developer.android.com/guide/practices/page-sizes),
  why uncompressed native libraries are aligned to 16 KB.

This project is an independent implementation written against those
specifications. It is not affiliated with or endorsed by Google or PKWARE.
