# sign-apk-py

Sign Android APKs with **APK Signature Scheme v2**, in pure Python.

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

### Generate a signing key

```bash
sign-apk generate-key release.pem release.crt --common-name "My Release Key"
```

### Verify a signature

```bash
sign-apk verify app-signed.apk
```

```
VALID (APK Signature Scheme v2)
  Signer: CN=My Release Key (serial 160075826959434796134124628523294791694)
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

- **v2 only.** No v1 (JAR) signing, so APKs installing on **Android 6 and
  below will not verify**. No v3 (key rotation) or v4 (incremental install).
- **One signer per APK.** The format allows several; this writes a single one.
- **Whole file is read into memory.** Fine for typical APKs (an 89 MB app
  signs in about half a second), but not suited to very large files on
  memory-constrained machines.
- **No ZIP64.** APKs above 4 GB, or with more than 65535 entries, are not
  supported.
- `sign-apk verify` is a self-check, not a full reimplementation of Android's
  verifier — it does not validate certificate chains, expiry, or v3/v4 blocks.
  Use `apksigner verify` when you need an authoritative answer.

## References

The binary formats implemented here are specified by Android and PKWARE.
Where this code reproduces a layout, constant, or algorithm, the relevant
module docstring cites the specific upstream file and function.

- **APK Signature Scheme v2** —
  [source.android.com/docs/security/features/apksigning/v2](https://source.android.com/docs/security/features/apksigning/v2)
  — scheme overview, file layout, and the integrity-protected-contents
  digest algorithm.
- **AOSP `apksig`** —
  [android.googlesource.com/platform/tools/apksig](https://android.googlesource.com/platform/tools/apksig/)
  — the reference implementation, and the authority for every byte layout
  used here. Chiefly `V2SchemeSigner.java` (signer and signed-data
  structure), `ApkSigningBlockUtils.java` (signing block framing, chunked
  digests, alignment padding), `SignatureAlgorithm.java` (algorithm IDs),
  `ZipUtils.java` (EOCD scan), and `ApkUtilsLite.java` (signing block
  location).
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

The suite covers RSA and EC signing, PKCS#12 and PEM loading, re-signing,
content preservation, alignment, and tamper detection. Where `apksigner` is
on `PATH`, tests additionally assert that it accepts the output and rejects
tampered files; those tests skip when it is absent.

Verified against Android `apksigner` on a real 89 MB production APK
(originally v3-signed): all 1622 entries byte-identical after re-signing,
`zipalign -c -P 16` clean, and `Verified using v2 scheme: true`.
