"""Command-line interface for sign-apk."""
from __future__ import annotations

import argparse
import getpass
import sys

from . import keys as keysmod
from .signer import sign_apk
from .verify import VerificationError, verify_apk


def _load_key_material(args) -> keysmod.KeyMaterial:
    if args.p12:
        password = args.p12_password
        if password is None:
            password = getpass.getpass("PKCS#12 password: ")
        return keysmod.load_pkcs12(args.p12, password.encode() if password else None)

    if args.key and args.cert:
        password = args.key_password
        return keysmod.load_pem(
            args.key, args.cert, password.encode() if password else None
        )

    print("Generating a new self-signed debug key (no --p12 or --key/--cert given)...",
          file=sys.stderr)
    key_material = keysmod.generate_debug_key()
    if args.save_debug_key:
        keysmod.save_pem(key_material, args.save_debug_key + ".pem",
                          args.save_debug_key + ".crt")
        print(f"Saved debug key to {args.save_debug_key}.pem / .crt", file=sys.stderr)
    return key_material


def cmd_sign(args) -> int:
    key_material = _load_key_material(args)

    # Default to v2+v3 unless the user selects schemes explicitly.
    if args.v2 or args.v3 or args.v4:
        v2, v3, v4 = args.v2, args.v3, args.v4
    else:
        v2, v3, v4 = True, True, False

    if v4 and not (v2 or v3):
        print(
            "error: --v4 requires --v2 or --v3; a v4 signature anchors to the "
            "v2/v3 content digest",
            file=sys.stderr,
        )
        return 2

    result = sign_apk(
        args.input,
        args.output,
        key_material,
        v2=v2,
        v3=v3,
        v4=v4,
        v4_output_path=args.v4_out,
        min_sdk_version=args.min_sdk_version,
    )

    schemes = ", ".join(s for s in ("v2", "v3", "v4") if result[s])
    print(f"Signed APK written to {args.output} ({schemes})")
    if result["idsig_path"]:
        print(f"v4 signature written to {result['idsig_path']}")
    return 0


def cmd_generate_key(args) -> int:
    key_material = keysmod.generate_debug_key(
        common_name=args.common_name, key_size=args.key_size
    )
    keysmod.save_pem(key_material, args.key_out, args.cert_out)
    print(f"Wrote private key to {args.key_out}")
    print(f"Wrote certificate to {args.cert_out}")
    return 0


def cmd_verify(args) -> int:
    try:
        result = verify_apk(args.apk)
    except VerificationError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    schemes = "+".join(result["schemes"])
    print(f"VALID (APK Signature Scheme {schemes})")
    for signer in result["signers"]:
        line = f"  {signer['scheme']} signer: {signer['subject']}"
        if "min_sdk_version" in signer:
            line += (
                f" (SDK {signer['min_sdk_version']}"
                f"-{signer['max_sdk_version']})"
            )
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sign-apk",
        description=(
            "Sign an APK using APK Signature Schemes v2, v3, and v4, "
            "no external tools required."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser(
        "sign", help="Sign an APK (v2+v3 unless schemes are given)"
    )
    sign_parser.add_argument("input", help="Path to the unsigned (or re-signable) input APK")
    sign_parser.add_argument("output", help="Path to write the signed output APK")
    sign_parser.add_argument("--p12", help="Path to a PKCS#12 keystore (.p12/.pfx)")
    sign_parser.add_argument("--p12-password", help="PKCS#12 password (prompted if omitted)")
    sign_parser.add_argument("--key", help="Path to a PEM private key")
    sign_parser.add_argument("--cert", help="Path to a PEM certificate")
    sign_parser.add_argument("--key-password", help="Password for an encrypted PEM private key")
    sign_parser.add_argument(
        "--save-debug-key",
        metavar="PREFIX",
        help="If generating a debug key (no --p12/--key given), save it as PREFIX.pem/.crt for reuse",
    )
    sign_parser.add_argument(
        "--v2", action="store_true", help="Emit an APK Signature Scheme v2 block"
    )
    sign_parser.add_argument(
        "--v3", action="store_true", help="Emit an APK Signature Scheme v3 block"
    )
    sign_parser.add_argument(
        "--v4",
        action="store_true",
        help="Write a v4 .apk.idsig sidecar (requires v2 or v3)",
    )
    sign_parser.add_argument(
        "--v4-out",
        metavar="PATH",
        help="Path for the v4 signature (default: <output>.idsig)",
    )
    sign_parser.add_argument(
        "--min-sdk-version",
        type=int,
        help="minSdkVersion recorded in the v3 signer (default: 28)",
    )
    sign_parser.set_defaults(func=cmd_sign)

    genkey_parser = subparsers.add_parser(
        "generate-key", help="Generate a self-signed RSA key/certificate pair"
    )
    genkey_parser.add_argument("key_out", help="Output path for the PEM private key")
    genkey_parser.add_argument("cert_out", help="Output path for the PEM certificate")
    genkey_parser.add_argument("--common-name", default="Android Debug")
    genkey_parser.add_argument("--key-size", type=int, default=2048)
    genkey_parser.set_defaults(func=cmd_generate_key)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a v2/v3-signed APK"
    )
    verify_parser.add_argument("apk", help="Path to the APK to verify")
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
